use alloc::vec;
use alloc::vec::Vec;

use alloc::boxed::Box;

use crate::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkeSuite, HpkeSymmetricCipherSuite,
};
use crate::error::{Error, PeerMisbehaved};
use crate::log::debug;
use crate::msgs::{
    ClientHelloPayload, Codec, EchConfigPayload, EncryptedClientHello, EncryptedClientHelloOuter,
    ExtensionType, Reader, SizedPayload,
};

/// A server-side ECH key, pairing a published ECH config with the corresponding
/// HPKE private key.
///
/// Multiple keys can be configured on a server to support key rotation: publish
/// new configs in DNS while still accepting connections encrypted to old configs
/// during the DNS TTL transition period.
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-7.1> for the
/// server-side ECH decryption procedure.
pub struct EchServerKey {
    /// The public ECH config (published in DNS HTTPS records).
    pub(crate) config: EchConfigPayload,

    /// The HPKE private key corresponding to the config's public key.
    pub(crate) private_key: HpkePrivateKey,

    /// Available HPKE implementations.
    pub(crate) hpke_suites: Vec<&'static dyn Hpke>,

    /// Whether this config should be included in retry_configs on ECH rejection.
    pub(crate) is_retry_config: bool,
}

impl EchServerKey {
    /// Create a new ECH server key from an ECH config, private key, and HPKE suite.
    ///
    /// The `config` should be a V18 `EchConfigPayload` published in DNS.
    /// The `private_key` must correspond to the public key in `config`.
    /// By default the key is marked as a retry config (sent to clients on ECH rejection).
    pub(crate) fn new(
        config: EchConfigPayload,
        private_key: HpkePrivateKey,
        suite: &'static dyn Hpke,
    ) -> Self {
        Self {
            config,
            private_key,
            hpke_suites: vec![suite],
            is_retry_config: true,
        }
    }

    /// Create an ECH server key from a raw ECHConfig and private key bytes.
    ///
    /// `config_bytes` should be a single serialized ECHConfig (not an ECHConfigList).
    /// All suites from `hpke_suites` matching the config's KEM and cipher suites
    /// are retained.
    ///
    /// Returns an error if the config cannot be parsed or no matching HPKE suite
    /// is found.
    pub fn from_raw(
        config_bytes: &[u8],
        private_key_bytes: Vec<u8>,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<Self, Error> {
        let mut reader = Reader::new(config_bytes);
        let config = EchConfigPayload::read(&mut reader)
            .map_err(|_| Error::General("invalid ECH config".into()))?;

        let EchConfigPayload::V18(contents) = &config else {
            return Err(Error::General("unsupported ECH config version".into()));
        };

        let matching_suites: Vec<&'static dyn Hpke> = hpke_suites
            .iter()
            .filter(|s| {
                let suite = s.suite();
                suite.kem == contents.key_config.kem_id
                    && contents
                        .key_config
                        .symmetric_cipher_suites
                        .contains(&suite.sym)
            })
            .copied()
            .collect();

        if matching_suites.is_empty() {
            return Err(Error::General(
                "no matching HPKE suite for ECH config".into(),
            ));
        }

        Ok(Self {
            config,
            private_key: HpkePrivateKey::from(private_key_bytes),
            hpke_suites: matching_suites,
            is_retry_config: true,
        })
    }

    /// Set whether this config should be included in retry_configs on ECH rejection.
    ///
    /// Non-retry configs are still used for decryption but not sent to clients
    /// on rejection (useful for old keys being rotated out).
    pub fn with_retry(mut self, is_retry: bool) -> Self {
        self.is_retry_config = is_retry;
        self
    }

    pub(crate) fn config_id(&self) -> Option<u8> {
        match &self.config {
            EchConfigPayload::V18(contents) => Some(contents.key_config.config_id),
            _ => None,
        }
    }

    /// Compute the HPKE info parameter: `"tls ech" || 0x00 || ECHConfig`.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc9849#section-6.1>.
    pub(crate) fn hpke_info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(128);
        info.extend_from_slice(b"tls ech\0");
        self.config.encode(&mut info);
        info
    }
}

impl core::fmt::Debug for EchServerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EchServerKey")
            .field("config", &self.config)
            .field("private_key", &"[redacted]")
            .finish()
    }
}

/// The server's view of ECH status for the connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum EchStatus {
    /// The client offered ECH and the server successfully decrypted the inner
    /// ClientHello.
    Accepted,
    /// The client did not offer ECH.
    #[default]
    NotOffered,
    /// The client offered ECH but the server could not decrypt it (e.g. config
    /// mismatch). The handshake proceeds on the outer ClientHello and
    /// retry_configs are sent in EncryptedExtensions.
    Rejected,
}

/// Result of attempting to decrypt an ECH offer.
pub(crate) enum EchDecryptResult {
    /// ECH was successfully decrypted.
    Accepted {
        inner_hello: ClientHelloPayload,
        inner_hello_raw: Vec<u8>,
        opener: Box<dyn HpkeOpener>,
    },
    /// HPKE decryption succeeded but the inner ClientHello is malformed.
    /// This is fatal per RFC 9849 Section 7.1.
    Fatal(Error),
    /// The ClientHello contains an ECH inner marker (type=1), indicating the
    /// hello IS the inner ClientHello (e.g. split-mode frontend forwarded it).
    InnerDirect,
    /// No ECH extension was present.
    NotOffered,
    /// ECH was offered but decryption failed.
    Rejected,
}

/// Attempt to decrypt ECH from a ClientHello, trying all configured server keys.
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-7.1>.
pub(crate) fn decrypt_ech(
    outer_hello: &ClientHelloPayload,
    outer_encoded: &[u8],
    outer_extensions_raw: &[u8],
    ech_keys: &[EchServerKey],
) -> EchDecryptResult {
    let ech_ext = match &outer_hello.encrypted_client_hello {
        Some(EncryptedClientHello::Outer(outer)) => outer,
        Some(EncryptedClientHello::Inner) => return EchDecryptResult::InnerDirect,
        None => return EchDecryptResult::NotOffered,
    };

    if ech_keys.is_empty() {
        return EchDecryptResult::Rejected;
    }

    debug!(
        "ECH offer: config_id={}, cipher_suite={:?}",
        ech_ext.config_id, ech_ext.cipher_suite
    );

    for key in ech_keys {
        let Some(key_config_id) = key.config_id() else {
            continue;
        };

        if key_config_id != ech_ext.config_id {
            continue;
        }

        let EchConfigPayload::V18(contents) = &key.config else {
            continue;
        };

        if !contents
            .key_config
            .symmetric_cipher_suites
            .contains(&ech_ext.cipher_suite)
        {
            continue;
        }

        let expected_suite = HpkeSuite {
            kem: contents.key_config.kem_id,
            sym: ech_ext.cipher_suite,
        };

        let Some(hpke_suite) = key
            .hpke_suites
            .iter()
            .find(|s| s.suite() == expected_suite)
            .copied()
        else {
            continue;
        };

        match try_decrypt_ech(
            outer_hello,
            outer_encoded,
            outer_extensions_raw,
            ech_ext,
            key,
            hpke_suite,
        ) {
            TryDecryptResult::Ok(inner_hello, inner_hello_raw, opener) => {
                return EchDecryptResult::Accepted {
                    inner_hello,
                    inner_hello_raw,
                    opener,
                };
            }
            TryDecryptResult::InnerInvalid(e) => {
                return EchDecryptResult::Fatal(e);
            }
            TryDecryptResult::HpkeFailed => {
                continue;
            }
        }
    }

    EchDecryptResult::Rejected
}

/// Outcome of a single decryption attempt against one key.
enum TryDecryptResult {
    HpkeFailed,
    InnerInvalid(Error),
    Ok(ClientHelloPayload, Vec<u8>, Box<dyn HpkeOpener>),
}

/// Try to decrypt an ECH offer using a specific server key and HPKE suite.
fn try_decrypt_ech(
    outer_hello: &ClientHelloPayload,
    outer_encoded: &[u8],
    outer_extensions_raw: &[u8],
    ech_ext: &EncryptedClientHelloOuter,
    key: &EchServerKey,
    suite: &'static dyn Hpke,
) -> TryDecryptResult {
    let info = key.hpke_info();
    let enc = EncapsulatedSecret(ech_ext.enc.bytes().to_vec());

    let Ok(mut opener) = suite.setup_opener(&enc, &info, &key.private_key) else {
        return TryDecryptResult::HpkeFailed;
    };

    let aad = compute_client_hello_outer_aad(outer_encoded, ech_ext);

    let Ok(encoded_inner) = opener.open(&aad, ech_ext.payload.bytes()) else {
        return TryDecryptResult::HpkeFailed;
    };

    match decode_client_hello_inner(&encoded_inner, outer_hello, outer_extensions_raw) {
        Ok((inner_hello, inner_hello_raw)) => {
            TryDecryptResult::Ok(inner_hello, inner_hello_raw, opener)
        }
        Err(e) => TryDecryptResult::InnerInvalid(e),
    }
}

/// Construct the ClientHelloOuterAAD: the ClientHello body with the ECH payload
/// replaced by zeros.
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-5.2>.
fn compute_client_hello_outer_aad(
    outer_encoded: &[u8],
    ech_ext: &EncryptedClientHelloOuter,
) -> Vec<u8> {
    // Skip the 4-byte handshake header to get the ClientHello body.
    let body = &outer_encoded[4..];
    let mut aad = body.to_vec();

    // Zero out the ECH ciphertext in the AAD by scanning for the
    // encrypted_client_hello extension and zeroing its payload field.
    // We walk extensions rather than using find_subsequence to avoid
    // false matches against ciphertext that happens to appear elsewhere.
    zero_ech_payload_in_extensions(&mut aad, ech_ext.payload.bytes().len());

    aad
}

/// Walk the extensions in a ClientHello body and zero the ECH ciphertext payload.
///
/// `body` is the full ClientHello body (starting at version). We skip to the
/// extensions, find the encrypted_client_hello extension, and zero its payload
/// field (the last `payload_len` bytes of the extension data).
fn zero_ech_payload_in_extensions(body: &mut [u8], payload_len: usize) {
    // Skip to extensions: version(2) + random(32) + session_id(1+N) +
    // cipher_suites(2+N) + compression(1+N) + extensions_length(2)
    let mut pos = 2 + 32; // version + random
    if pos >= body.len() {
        return;
    }
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > body.len() {
        return;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= body.len() {
        return;
    }
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > body.len() {
        return;
    }
    let _ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    // Walk extensions
    while pos + 4 <= body.len() {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let ext_data_start = pos + 4;
        let ext_data_end = ext_data_start + ext_len;

        if ext_type == u16::from(ExtensionType::EncryptedClientHello) {
            // The payload is the last `payload_len` bytes of the extension data.
            if ext_data_end <= body.len() && payload_len <= ext_len {
                let payload_start = ext_data_end - payload_len;
                body[payload_start..ext_data_end].fill(0);
            }
            return;
        }

        pos = ext_data_end;
    }
}

// --- Wire-level ClientHello helpers ---
//
// ECH requires working with the raw wire encoding of the ClientHello rather
// than the parsed `ClientHelloPayload`. This is because:
//
// - The AAD for HPKE decryption is the ClientHello body with the ECH
//   ciphertext zeroed out (RFC 9849 Section 5.2), which must match the
//   exact byte layout the client sent.
// - The inner ClientHello is reconstructed by splicing raw extension bytes
//   from the outer hello (RFC 9849 Section 5.1), preserving wire ordering.
// - The transcript hash must cover the reconstructed bytes, not a
//   re-encoding from parsed structures.
//
// The raw bytes come from `MessagePayload::Handshake { encoded, .. }`,
// which retains the original wire encoding alongside the parsed message.
// Storing raw bytes inside `ClientHelloPayload` would require adding a
// lifetime parameter that would propagate through much of the codebase.

/// Extract the raw extensions bytes from a ClientHello handshake message encoding.
///
/// `encoded` is the full handshake message (type + length + body).
pub(crate) fn extract_extensions_from_client_hello(encoded: &[u8]) -> Result<&[u8], Error> {
    let err = || -> Error { PeerMisbehaved::InvalidEchClientHelloInner.into() };

    let mut r = Reader::new(encoded);

    // Skip handshake header: type (1) + length (3)
    let _hs_type = u8::read(&mut r).map_err(|_| err())?;
    let _len = u24_read(&mut r).ok_or_else(err)?;

    // Skip ClientHello fixed fields
    let _ = u16::read(&mut r).map_err(|_| err())?; // version
    let _ = r.take(32).ok_or_else(err)?; // random
    let sid_len = u8::read(&mut r).map_err(|_| err())? as usize;
    let _ = r.take(sid_len).ok_or_else(err)?;
    let cs_len = u16::read(&mut r).map_err(|_| err())? as usize;
    let _ = r.take(cs_len).ok_or_else(err)?;
    let comp_len = u8::read(&mut r).map_err(|_| err())? as usize;
    let _ = r.take(comp_len).ok_or_else(err)?;
    let ext_len = u16::read(&mut r).map_err(|_| err())? as usize;
    r.take(ext_len).ok_or_else(err)
}

fn u24_read(r: &mut Reader<'_>) -> Option<usize> {
    let bytes = r.take(3)?;
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | (bytes[2] as usize))
}

/// Decode an EncodedClientHelloInner and reconstruct the full inner ClientHello.
///
/// Returns both a parsed `ClientHelloPayload` and the raw bytes (for the
/// transcript hash).
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-5.1>.
pub(crate) fn decode_client_hello_inner(
    encoded: &[u8],
    outer_hello: &ClientHelloPayload,
    outer_extensions_raw: &[u8],
) -> Result<(ClientHelloPayload, Vec<u8>), Error> {
    if encoded.is_empty() {
        return Err(PeerMisbehaved::InvalidEchClientHelloInner.into());
    }

    let raw_inner = reconstruct_inner_bytes(encoded, outer_hello, outer_extensions_raw)?;

    let mut reader = Reader::new(&raw_inner);
    let inner_hello = ClientHelloPayload::read(&mut reader)
        .map_err(|_| Error::from(PeerMisbehaved::InvalidEchClientHelloInner))?;

    // Per RFC 9849 Section 7.1, the inner hello MUST contain the ECH inner marker.
    if !matches!(
        inner_hello.encrypted_client_hello,
        Some(EncryptedClientHello::Inner)
    ) {
        return Err(PeerMisbehaved::InvalidEchClientHelloInner.into());
    }

    // Per RFC 9849 Section 7.1, the inner hello MUST contain supported_versions
    // offering only TLS 1.3 or higher.
    match &inner_hello
        .extensions
        .supported_versions
    {
        Some(versions) if !versions.tls12 => {}
        _ => return Err(PeerMisbehaved::InvalidEchClientHelloInner.into()),
    }

    Ok((inner_hello, raw_inner))
}

/// Reconstruct the inner ClientHello as raw bytes by splicing extensions at
/// the byte level.
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-5.1>.
fn reconstruct_inner_bytes(
    content: &[u8],
    outer_hello: &ClientHelloPayload,
    outer_extensions_raw: &[u8],
) -> Result<Vec<u8>, Error> {
    let err = || -> Error { PeerMisbehaved::InvalidEchClientHelloInner.into() };

    let mut r = Reader::new(content);

    let client_version = u16::read(&mut r).map_err(|_| err())?;
    let random = r.take(32).ok_or_else(err)?;

    // EncodedClientHelloInner has an empty session_id
    let session_id_len = u8::read(&mut r).map_err(|_| err())?;
    if session_id_len != 0 {
        return Err(err());
    }

    let cs_len = u16::read(&mut r).map_err(|_| err())? as usize;
    let cipher_suites = r.take(cs_len).ok_or_else(err)?;
    let comp_len = u8::read(&mut r).map_err(|_| err())? as usize;
    let compression = r.take(comp_len).ok_or_else(err)?;
    let ext_len = u16::read(&mut r).map_err(|_| err())? as usize;
    let inner_extensions = r.take(ext_len).ok_or_else(err)?;

    // Remaining bytes must be all-zero padding
    let padding = r.rest();
    if !padding.iter().all(|&b| b == 0) {
        return Err(PeerMisbehaved::InvalidEchPadding.into());
    }

    // Rebuild with outer session_id and expanded extensions
    let expanded_extensions = expand_extensions_raw(inner_extensions, outer_extensions_raw)?;

    let mut out =
        Vec::with_capacity(2 + 32 + 33 + 2 + cs_len + 1 + comp_len + 2 + expanded_extensions.len());
    out.extend_from_slice(&client_version.to_be_bytes());
    out.extend_from_slice(random);
    outer_hello.session_id.encode(&mut out);
    out.extend_from_slice(&(cs_len as u16).to_be_bytes());
    out.extend_from_slice(cipher_suites);
    out.push(comp_len as u8);
    out.extend_from_slice(compression);
    out.extend_from_slice(&(expanded_extensions.len() as u16).to_be_bytes());
    out.extend_from_slice(&expanded_extensions);

    Ok(out)
}

/// Expand ech_outer_extensions references in the inner hello's extensions.
///
/// Walks `inner_extensions` and replaces any `ech_outer_extensions` marker with
/// the referenced extensions copied from `outer_extensions_raw`. The spec
/// requires references to be listed in the same order as the outer hello.
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-5.1>.
fn expand_extensions_raw(
    inner_extensions: &[u8],
    outer_extensions_raw: &[u8],
) -> Result<Vec<u8>, Error> {
    let err = || -> Error { PeerMisbehaved::InvalidEchOuterExtension.into() };

    let mut out = Vec::with_capacity(inner_extensions.len() + 128);
    let mut r = Reader::new(inner_extensions);

    while r.any_left() {
        let ext_type = u16::read(&mut r).map_err(|_| err())?;
        let ext_len = u16::read(&mut r).map_err(|_| err())? as usize;
        let ext_data = r.take(ext_len).ok_or_else(err)?;

        if ext_type == u16::from(ExtensionType::EncryptedClientHelloOuterExtensions) {
            let mut list_reader = Reader::new(ext_data);
            let list_len = u8::read(&mut list_reader).map_err(|_| err())? as usize;
            let list_data = list_reader
                .take(list_len)
                .ok_or_else(err)?;

            if list_len == 0 || list_reader.any_left() {
                return Err(err());
            }

            let mut type_reader = Reader::new(list_data);
            let mut outer_reader = Reader::new(outer_extensions_raw);

            while type_reader.any_left() {
                let want = u16::read(&mut type_reader).map_err(|_| err())?;

                // Must not reference encrypted_client_hello
                if want == u16::from(ExtensionType::EncryptedClientHello) {
                    return Err(err());
                }

                // Seek forward (references must be in outer-hello order)
                loop {
                    if !outer_reader.any_left() {
                        return Err(err());
                    }
                    let found_type = u16::read(&mut outer_reader).map_err(|_| err())?;
                    let found_len = u16::read(&mut outer_reader).map_err(|_| err())? as usize;
                    let found_data = outer_reader
                        .take(found_len)
                        .ok_or_else(err)?;

                    if found_type == want {
                        out.extend_from_slice(&found_type.to_be_bytes());
                        out.extend_from_slice(&(found_len as u16).to_be_bytes());
                        out.extend_from_slice(found_data);
                        break;
                    }
                }
            }
        } else {
            out.extend_from_slice(&ext_type.to_be_bytes());
            out.extend_from_slice(&(ext_len as u16).to_be_bytes());
            out.extend_from_slice(ext_data);
        }
    }

    Ok(out)
}

/// Generate an ECH server key and the corresponding serialized ECHConfigList.
///
/// The returned `EchServerKey` should be stored in `ServerConfig::ech_keys`.
/// The returned `Vec<u8>` is an ECHConfigList that should be published in DNS
/// (base64-encoded in the HTTPS record's `ech` parameter).
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-4>.
pub fn generate_ech_config(
    suite: &'static dyn Hpke,
    config_id: u8,
    public_name: pki_types::DnsName<'static>,
    maximum_name_length: u8,
) -> Result<(EchServerKey, Vec<u8>), Error> {
    use crate::crypto::cipher::Payload;
    use crate::msgs::{EchConfigContents, HpkeKeyConfig};

    let (public_key, private_key) = suite.generate_key_pair()?;
    let suite_info = suite.suite();

    let config = EchConfigPayload::V18(EchConfigContents {
        key_config: HpkeKeyConfig {
            config_id,
            kem_id: suite_info.kem,
            public_key: SizedPayload::from(Payload::new(public_key.0)),
            symmetric_cipher_suites: vec![suite_info.sym],
        },
        maximum_name_length,
        public_name,
        extensions: Vec::new(),
    });

    let mut config_list_bytes = Vec::new();
    vec![config.clone()].encode(&mut config_list_bytes);

    Ok((
        EchServerKey::new(config, private_key, suite),
        config_list_bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hpke::*;

    #[test]
    fn hpke_info_starts_with_prefix() {
        let key = EchServerKey {
            config: make_v18_config(1),
            private_key: HpkePrivateKey::from(vec![0u8; 32]),
            hpke_suites: vec![],
            is_retry_config: true,
        };

        let info = key.hpke_info();
        assert!(info.starts_with(b"tls ech\0"));
    }

    fn make_v18_config(config_id: u8) -> EchConfigPayload {
        use pki_types::DnsName;

        EchConfigPayload::V18(crate::msgs::EchConfigContents {
            key_config: crate::msgs::HpkeKeyConfig {
                config_id,
                kem_id: HpkeKem::DHKEM_X25519_HKDF_SHA256,
                public_key: SizedPayload::from(crate::crypto::cipher::Payload::new(vec![0u8; 32])),
                symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite::default()],
            },
            maximum_name_length: 128,
            public_name: DnsName::try_from("example.com")
                .unwrap()
                .to_owned(),
            extensions: Vec::new(),
        })
    }

    #[test]
    fn config_id_returns_id_for_v18() {
        let key = EchServerKey {
            config: make_v18_config(42),
            private_key: HpkePrivateKey::from(vec![0u8; 32]),
            hpke_suites: vec![],
            is_retry_config: true,
        };
        assert_eq!(key.config_id(), Some(42));
    }

    #[test]
    fn with_retry_toggles_flag() {
        let key = EchServerKey {
            config: make_v18_config(1),
            private_key: HpkePrivateKey::from(vec![0u8; 32]),
            hpke_suites: vec![],
            is_retry_config: true,
        };
        assert!(key.is_retry_config);
        let key = key.with_retry(false);
        assert!(!key.is_retry_config);
    }

    #[test]
    fn from_raw_rejects_invalid_bytes() {
        let result = EchServerKey::from_raw(&[0xFF, 0x01], vec![0u8; 32], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn from_raw_rejects_no_matching_suite() {
        // Encode a valid V18 config, then call from_raw with an empty suite list
        let config = make_v18_config(1);
        let mut config_bytes = Vec::new();
        config.encode(&mut config_bytes);

        let result = EchServerKey::from_raw(&config_bytes, vec![0u8; 32], &[]);
        assert!(matches!(result, Err(Error::General(msg)) if msg.contains("no matching HPKE suite")));
    }

    fn make_hello(random: [u8; 32]) -> ClientHelloPayload {
        use alloc::boxed::Box;

        use crate::crypto::CipherSuite;
        use crate::enums::ProtocolVersion;
        use crate::msgs::SupportedProtocolVersions;
        use crate::msgs::{ClientExtensions, Compression, Random, SessionId};

        let extensions = ClientExtensions {
            supported_versions: Some(SupportedProtocolVersions {
                tls13: true,
                tls12: false,
            }),
            ..Default::default()
        };
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random(random),
            session_id: SessionId::empty(),
            cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            compression_methods: vec![Compression::Null],
            extensions: Box::new(extensions),
        }
    }

    #[test]
    fn inner_hello_strips_padding() {
        let mut inner = make_hello([0x42u8; 32]);
        inner.encrypted_client_hello = Some(EncryptedClientHello::Inner);

        let mut encoded = inner.get_encoding();
        encoded.extend_from_slice(&[0u8; 31]);

        let mut outer = make_hello([0x11u8; 32]);
        let sid_bytes = {
            let mut b = vec![32u8];
            b.extend_from_slice(&[0xAB; 32]);
            b
        };
        outer.session_id = crate::msgs::SessionId::read(&mut Reader::new(&sid_bytes)).unwrap();

        let (decoded, _raw) = decode_client_hello_inner(&encoded, &outer, &[]).unwrap();

        assert_eq!(decoded.session_id, outer.session_id);
        assert_eq!(decoded.random.0, [0x42u8; 32]);
        assert!(matches!(
            decoded.encrypted_client_hello,
            Some(EncryptedClientHello::Inner)
        ));
    }

    #[test]
    fn inner_hello_rejects_truly_empty() {
        let outer = make_hello([0x11u8; 32]);
        assert!(decode_client_hello_inner(&[], &outer, &[]).is_err());
    }

    #[test]
    fn inner_hello_rejects_garbage() {
        let encoded = vec![0u8; 32];
        let outer = make_hello([0x11u8; 32]);
        assert!(decode_client_hello_inner(&encoded, &outer, &[]).is_err());
    }

    #[test]
    fn inner_hello_rejects_missing_marker() {
        let inner = make_hello([0x42u8; 32]);
        let encoded = inner.get_encoding();
        let outer = make_hello([0x11u8; 32]);
        assert!(decode_client_hello_inner(&encoded, &outer, &[]).is_err());
    }

    #[test]
    fn inner_hello_rejects_nonzero_padding() {
        let mut inner = make_hello([0x42u8; 32]);
        inner.encrypted_client_hello = Some(EncryptedClientHello::Inner);
        let mut encoded = inner.get_encoding();
        // Append non-zero padding
        encoded.extend_from_slice(&[0x01; 4]);

        let outer = make_hello([0x11u8; 32]);
        let err = decode_client_hello_inner(&encoded, &outer, &[]).unwrap_err();
        assert!(matches!(
            err,
            Error::PeerMisbehaved(PeerMisbehaved::InvalidEchPadding)
        ));
    }

    // --- expand_extensions_raw tests ---

    /// Build a raw extension: type(2) || length(2) || data
    fn raw_ext(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_type.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// Build an ech_outer_extensions extension referencing the given types.
    fn outer_ext_ref(types: &[u16]) -> Vec<u8> {
        // list_len(1) || type_id(2) * N
        let list_len = (types.len() * 2) as u8;
        let mut data = vec![list_len];
        for &t in types {
            data.extend_from_slice(&t.to_be_bytes());
        }
        raw_ext(0xfd00, &data)
    }

    #[test]
    fn expand_extensions_copies_outer_extension() {
        // Inner has an ech_outer_extensions reference to type 0x0033 (key_share)
        let inner_exts = outer_ext_ref(&[0x0033]);

        // Outer has key_share with some data
        let outer_exts = raw_ext(0x0033, &[0xAA, 0xBB, 0xCC]);

        let result = expand_extensions_raw(&inner_exts, &outer_exts).unwrap();

        // Result should be the outer key_share extension
        assert_eq!(result, raw_ext(0x0033, &[0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn expand_extensions_preserves_non_referenced() {
        // Inner has a regular extension followed by an outer reference
        let mut inner_exts = raw_ext(0x0001, &[0x11]);
        inner_exts.extend_from_slice(&outer_ext_ref(&[0x0033]));

        let outer_exts = raw_ext(0x0033, &[0xAA]);

        let result = expand_extensions_raw(&inner_exts, &outer_exts).unwrap();

        let mut expected = raw_ext(0x0001, &[0x11]);
        expected.extend_from_slice(&raw_ext(0x0033, &[0xAA]));
        assert_eq!(result, expected);
    }

    #[test]
    fn expand_extensions_rejects_out_of_order() {
        // Reference types 0x0033 then 0x002b, but outer has 0x002b before 0x0033
        let inner_exts = outer_ext_ref(&[0x0033, 0x002b]);

        let mut outer_exts = raw_ext(0x002b, &[0x01]);
        outer_exts.extend_from_slice(&raw_ext(0x0033, &[0x02]));

        assert!(expand_extensions_raw(&inner_exts, &outer_exts).is_err());
    }

    #[test]
    fn expand_extensions_rejects_ech_reference() {
        // Reference to EncryptedClientHello (0xfe0d) is forbidden
        let inner_exts = outer_ext_ref(&[0xfe0d]);
        let outer_exts = raw_ext(0xfe0d, &[0x01]);

        assert!(expand_extensions_raw(&inner_exts, &outer_exts).is_err());
    }

    #[test]
    fn expand_extensions_rejects_missing_outer() {
        // Reference type 0x0033, but outer doesn't have it
        let inner_exts = outer_ext_ref(&[0x0033]);

        assert!(expand_extensions_raw(&inner_exts, &[]).is_err());
    }

    #[test]
    fn aad_zeros_ech_payload() {
        use crate::msgs::HandshakeMessagePayload;
        use crate::msgs::HandshakePayload;

        let ech_outer = EncryptedClientHelloOuter {
            cipher_suite: HpkeSymmetricCipherSuite::default(),
            config_id: 42,
            enc: SizedPayload::from(crate::crypto::cipher::Payload::new(vec![1, 2, 3])),
            payload: SizedPayload::from(crate::crypto::cipher::Payload::new(vec![0xAA; 32])),
        };

        let mut outer_hello = make_hello([0u8; 32]);
        outer_hello.encrypted_client_hello = Some(EncryptedClientHello::Outer(ech_outer.clone()));

        let hmp = HandshakeMessagePayload(HandshakePayload::ClientHello(outer_hello));
        let encoded = hmp.get_encoding();

        let aad = compute_client_hello_outer_aad(&encoded, &ech_outer);

        assert!(!aad.is_empty());
        // The AAD should not contain the original 0xAA payload bytes
        let has_aa_run = aad
            .windows(32)
            .any(|w| w.iter().all(|&b| b == 0xAA));
        assert!(!has_aa_run, "AAD should have zeroed ECH payload");

        // The AAD should contain zeroed bytes where the payload was
        let has_zero_run = aad
            .windows(32)
            .any(|w| w.iter().all(|&b| b == 0x00));
        assert!(has_zero_run, "AAD should contain zeroed payload");
    }

    #[test]
    fn not_offered() {
        let hello = make_hello([0u8; 32]);
        assert!(matches!(
            decrypt_ech(&hello, &[], &[], &[]),
            EchDecryptResult::NotOffered
        ));
    }

    #[test]
    fn inner_direct() {
        let mut hello = make_hello([0u8; 32]);
        hello.encrypted_client_hello = Some(EncryptedClientHello::Inner);

        assert!(matches!(
            decrypt_ech(&hello, &[], &[], &[]),
            EchDecryptResult::InnerDirect
        ));
    }

    #[test]
    fn rejected_no_keys() {
        let mut hello = make_hello([0u8; 32]);
        hello.encrypted_client_hello =
            Some(EncryptedClientHello::Outer(EncryptedClientHelloOuter {
                cipher_suite: HpkeSymmetricCipherSuite::default(),
                config_id: 1,
                enc: SizedPayload::from(crate::crypto::cipher::Payload::new(vec![0u8; 32])),
                payload: SizedPayload::from(crate::crypto::cipher::Payload::new(vec![0u8; 64])),
            }));

        assert!(matches!(
            decrypt_ech(&hello, &[], &[], &[]),
            EchDecryptResult::Rejected
        ));
    }

    #[test]
    fn rejected_config_id_mismatch() {
        let mut hello = make_hello([0u8; 32]);
        hello.encrypted_client_hello =
            Some(EncryptedClientHello::Outer(EncryptedClientHelloOuter {
                cipher_suite: HpkeSymmetricCipherSuite::default(),
                config_id: 99,
                enc: SizedPayload::from(crate::crypto::cipher::Payload::new(vec![0u8; 32])),
                payload: SizedPayload::from(crate::crypto::cipher::Payload::new(vec![0u8; 64])),
            }));

        // Key has config_id=1, hello has config_id=99, so should be rejected
        let key = EchServerKey {
            config: make_v18_config(1),
            private_key: HpkePrivateKey::from(vec![0u8; 32]),
            hpke_suites: vec![],
            is_retry_config: true,
        };

        assert!(matches!(
            decrypt_ech(&hello, &[], &[], &[key]),
            EchDecryptResult::Rejected
        ));
    }
}
