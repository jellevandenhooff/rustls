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

    /// Return the raw private key bytes.
    ///
    /// This is useful for persisting the key to disk so it can be reloaded
    /// later with [`EchServerKey::from_raw`].
    pub fn private_key_bytes(&self) -> &[u8] {
        self.private_key.secret_bytes()
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
    /// The ClientHello arrived with the `ech_is_inner` (type=1) marker,
    /// indicating a split-mode frontend already decrypted and forwarded it.
    AcceptedInnerDirect,
    /// The client did not offer ECH.
    #[default]
    NotOffered,
    /// The client offered ECH but the server could not decrypt it (e.g. config
    /// mismatch). The handshake proceeds on the outer ClientHello and
    /// retry_configs are sent in EncryptedExtensions.
    Rejected,
}

/// Server-side ECH state carried across the handshake.
pub(crate) struct EchServerState {
    /// The random from the inner ClientHello, needed for confirmation computation.
    pub(crate) inner_random: crate::msgs::Random,
    /// HPKE opener context, kept alive for decrypting a second ClientHello after HRR.
    pub(crate) opener: Box<dyn HpkeOpener>,
    /// Retry configs to send on rejection.
    pub(crate) retry_configs: Vec<EchConfigPayload>,
    /// Whether ECH was accepted or rejected.
    pub(crate) status: EchStatus,
    /// The config_id from the outer ClientHello (for validating the second after HRR).
    pub(crate) config_id: Option<u8>,
    /// The cipher suite from the outer ClientHello (for validating the second after HRR).
    pub(crate) cipher_suite: Option<HpkeSymmetricCipherSuite>,
}

impl EchServerState {
    /// Build state for an accepted ECH handshake.
    pub(crate) fn accepted(
        inner_random: crate::msgs::Random,
        opener: Box<dyn HpkeOpener>,
        retry_configs: Vec<EchConfigPayload>,
        config_id: Option<u8>,
        cipher_suite: Option<HpkeSymmetricCipherSuite>,
    ) -> Self {
        Self {
            inner_random,
            opener,
            retry_configs,
            status: EchStatus::Accepted,
            config_id,
            cipher_suite,
        }
    }

    /// Build state for a rejected ECH handshake.
    pub(crate) fn rejected(retry_configs: Vec<EchConfigPayload>) -> Self {
        Self {
            inner_random: crate::msgs::Random([0u8; 32]),
            opener: Box::new(NoOpOpener),
            retry_configs,
            status: EchStatus::Rejected,
            config_id: None,
            cipher_suite: None,
        }
    }

    /// Build state for an inner-direct handshake (split-mode or type=1 marker).
    pub(crate) fn inner_direct(inner_random: crate::msgs::Random) -> Self {
        Self {
            inner_random,
            opener: Box::new(NoOpOpener),
            retry_configs: Vec::new(),
            status: EchStatus::AcceptedInnerDirect,
            config_id: None,
            cipher_suite: None,
        }
    }
}

/// A no-op HPKE opener used when no HPKE context is available (rejection path,
/// inner-direct).
#[derive(Debug)]
pub(crate) struct NoOpOpener;

impl HpkeOpener for NoOpOpener {
    fn open(&mut self, _aad: &[u8], _ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::General("no HPKE context available".into()))
    }
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

/// Outcome of ECH resolution on a ClientHello.
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-7.1>.
pub(crate) enum EchOffer<'m> {
    /// First ClientHello: ECH was resolved. Use `inner_input` (if present)
    /// instead of the outer, and install the given state.
    Resolved {
        inner_input: Option<crate::conn::Input<'m>>,
        state: EchServerState,
    },
    /// Second ClientHello (HRR): use this inner input. The existing
    /// `ech_state` was updated in place (inner_random set).
    ResolvedHrr(crate::conn::Input<'m>),
    /// No ECH processing needed.
    None,
}

/// Resolve ECH on a ClientHello, handling both first and second (HRR) attempts.
///
/// On the first ClientHello, attempts ECH decryption using the server's
/// configured keys. On the second ClientHello after HRR, decrypts using the
/// saved HPKE opener context (mutating `ech_state` in place).
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-7.1>.
pub(crate) fn resolve_ech<'m>(
    input: &crate::conn::Input<'m>,
    ech_keys: &[EchServerKey],
    ech_state: Option<&mut EchServerState>,
    done_retry: bool,
) -> Result<EchOffer<'m>, Error> {
    use crate::enums::HandshakeType;
    use crate::msgs::{HandshakePayload, MessagePayload};

    let outer_hello = require_handshake_msg!(
        input.message,
        HandshakeType::ClientHello,
        HandshakePayload::ClientHello
    )?;

    // Second ClientHello after HRR with accepted ECH: decrypt using saved opener.
    if done_retry {
        if let Some(ech_state) = ech_state.filter(|s| matches!(s.status, EchStatus::Accepted | EchStatus::AcceptedInnerDirect)) {
            return resolve_ech_hrr(input, outer_hello, ech_state);
        }
        return Ok(EchOffer::None);
    }

    // Check for inner marker (split-mode support).
    if matches!(
        outer_hello.encrypted_client_hello,
        Some(EncryptedClientHello::Inner)
    ) {
        return Ok(EchOffer::Resolved {
            inner_input: None,
            state: EchServerState::inner_direct(outer_hello.random),
        });
    }

    if ech_keys.is_empty() {
        return Ok(EchOffer::None);
    }

    let outer_encoded = match &input.message.payload {
        MessagePayload::Handshake { encoded, .. } => encoded.bytes(),
        _ => unreachable!(),
    };
    let outer_extensions_raw = extract_extensions_from_client_hello(outer_encoded)?;

    let ech_result = decrypt_ech(outer_hello, outer_encoded, outer_extensions_raw, ech_keys);
    let retry_configs = collect_retry_configs(ech_keys);

    match ech_result {
        EchDecryptResult::Fatal(e) => Err(e),
        EchDecryptResult::Accepted {
            inner_hello,
            inner_hello_raw,
            opener,
        } => {
            let (config_id, cipher_suite) = match &outer_hello.encrypted_client_hello {
                Some(EncryptedClientHello::Outer(o)) => (Some(o.config_id), Some(o.cipher_suite)),
                _ => (None, None),
            };
            let random = inner_hello.random;
            Ok(EchOffer::Resolved {
                inner_input: Some(make_inner_input(input, inner_hello, &inner_hello_raw)),
                state: EchServerState::accepted(
                    random,
                    opener,
                    retry_configs,
                    config_id,
                    cipher_suite,
                ),
            })
        }
        EchDecryptResult::Rejected => Ok(EchOffer::Resolved {
            inner_input: None,
            state: EchServerState::rejected(retry_configs),
        }),
        EchDecryptResult::NotOffered | EchDecryptResult::InnerDirect => Ok(EchOffer::None),
    }
}

/// Decrypt the second ClientHello's ECH payload after a HelloRetryRequest.
///
/// The second ClientHello reuses the HPKE context from the first. A decryption
/// failure here is fatal (unlike the first ClientHello, where it's non-fatal).
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-7.1>.
pub(crate) fn decrypt_ech_hrr(
    outer_hello: &ClientHelloPayload,
    outer_encoded: &[u8],
    outer_extensions_raw: &[u8],
    opener: &mut Box<dyn HpkeOpener>,
    expected_config_id: Option<u8>,
    expected_cipher_suite: Option<HpkeSymmetricCipherSuite>,
) -> Result<(ClientHelloPayload, Vec<u8>), Error> {
    let ech_ext = match &outer_hello.encrypted_client_hello {
        Some(EncryptedClientHello::Outer(outer)) => outer,
        None => return Err(PeerMisbehaved::MissingEchExtension.into()),
        _ => return Err(PeerMisbehaved::InvalidEchClientHelloInner.into()),
    };

    // The second ClientHello's ECH must have empty enc (RFC 9849 Section 7.1)
    if !ech_ext.enc.bytes().is_empty() {
        return Err(PeerMisbehaved::InvalidEchClientHelloInner.into());
    }

    // Verify config_id and cipher suite match the first ClientHello
    if let Some(expected) = expected_config_id {
        if ech_ext.config_id != expected {
            return Err(PeerMisbehaved::EchHrrMismatch.into());
        }
    }
    if let Some(expected) = expected_cipher_suite {
        if ech_ext.cipher_suite != expected {
            return Err(PeerMisbehaved::EchHrrMismatch.into());
        }
    }

    let aad = compute_client_hello_outer_aad(outer_encoded, ech_ext);
    let encoded_inner = opener
        .open(&aad, ech_ext.payload.bytes())
        .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::EchHrrDecryptionFailed))?;

    decode_client_hello_inner(&encoded_inner, outer_hello, outer_extensions_raw)
}

/// Handle ECH on the second ClientHello after HRR.
///
/// Decrypts using the saved HPKE opener, updating `ech_state` in place.
fn resolve_ech_hrr<'m>(
    input: &crate::conn::Input<'m>,
    outer_hello: &ClientHelloPayload,
    ech_state: &mut EchServerState,
) -> Result<EchOffer<'m>, Error> {
    use crate::msgs::MessagePayload;

    // Inner-direct on HRR: no decryption needed, just update inner_random.
    if matches!(
        outer_hello.encrypted_client_hello,
        Some(EncryptedClientHello::Inner)
    ) {
        ech_state.inner_random = outer_hello.random;
        return Ok(EchOffer::None);
    }

    let outer_encoded = match &input.message.payload {
        MessagePayload::Handshake { encoded, .. } => encoded.bytes(),
        _ => unreachable!(),
    };
    let outer_extensions_raw = extract_extensions_from_client_hello(outer_encoded)?;

    let (inner_hello, inner_hello_raw) = decrypt_ech_hrr(
        outer_hello,
        outer_encoded,
        outer_extensions_raw,
        &mut ech_state.opener,
        ech_state.config_id,
        ech_state.cipher_suite,
    )?;
    ech_state.inner_random = inner_hello.random;

    Ok(EchOffer::ResolvedHrr(make_inner_input(
        input,
        inner_hello,
        &inner_hello_raw,
    )))
}

/// Collect retry_configs from all keys marked as retry configs.
fn collect_retry_configs(ech_keys: &[EchServerKey]) -> Vec<EchConfigPayload> {
    ech_keys
        .iter()
        .filter(|k| k.is_retry_config)
        .map(|k| k.config.clone())
        .collect()
}

/// Build an `Input` wrapping a decrypted inner ClientHello.
fn make_inner_input<'m>(
    outer_input: &crate::conn::Input<'m>,
    inner_hello: ClientHelloPayload,
    inner_hello_raw: &[u8],
) -> crate::conn::Input<'m> {
    use crate::crypto::cipher::Payload;
    use crate::msgs::{HandshakeMessagePayload, HandshakePayload, Message, MessagePayload};

    let inner_payload = encode_inner_hello(inner_hello_raw);
    crate::conn::Input {
        message: Message {
            version: outer_input.message.version,
            payload: MessagePayload::Handshake {
                encoded: Payload::Owned(inner_payload),
                parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(inner_hello)),
            },
        },
        aligned_handshake: outer_input.aligned_handshake,
    }
}

/// Build a handshake-encoded ClientHello from raw bytes.
///
/// Constructs the `type(1) || length(3) || body` encoding needed for the
/// transcript hash.
fn encode_inner_hello(raw: &[u8]) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(4 + raw.len());
    hdr.push(0x01); // HandshakeType::ClientHello
    let len = raw.len();
    hdr.push((len >> 16) as u8);
    hdr.push((len >> 8) as u8);
    hdr.push(len as u8);
    hdr.extend_from_slice(raw);
    hdr
}

/// Compute the ECH acceptance confirmation for the last 8 bytes of
/// ServerHello.random.
///
/// See <https://datatracker.ietf.org/doc/html/rfc9849#section-7.2>.
pub(crate) fn server_ech_confirmation(
    hkdf_provider: &'static dyn crate::crypto::tls13::Hkdf,
    inner_random: &[u8; 32],
    transcript_ech_conf: crate::crypto::hash::Output,
) -> [u8; 8] {
    crate::tls13::key_schedule::server_ech_confirmation_secret(
        hkdf_provider,
        inner_random,
        transcript_ech_conf,
    )
}

// --- Split-mode frontend proxy ---

/// TLS record header length: content_type(1) + version(2) + length(2).
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Result of processing a ClientHello for ECH split-mode proxying.
///
/// Returned by [`EchProxy::process_client_hello_msg`].
#[derive(Debug)]
pub enum EchProxyResult {
    /// ECH was successfully decrypted. Contains the inner ClientHello as a
    /// handshake message (`type(1) || length(3) || body`), ready to be placed
    /// in a QUIC CRYPTO frame or TLS record for forwarding to the backend.
    Decrypted(Vec<u8>),
    /// No ECH extension was present. The original ClientHello should be
    /// forwarded unchanged.
    NotOffered,
    /// ECH decryption failed (config mismatch, wrong key, etc). The original
    /// ClientHello should be forwarded unchanged. Contains serialized
    /// retry\_configs that the backend may send in EncryptedExtensions.
    Rejected(Vec<u8>),
}

/// ECH split-mode proxy for a client-facing frontend server.
///
/// In ECH split mode ([RFC 9849 Section 3.1]), a client-facing frontend holds
/// the ECH private keys and decrypts the outer ClientHello. It forwards the
/// reconstructed inner ClientHello (with the `ech_is_inner` type=1 marker)
/// to the backend server, then acts as a TCP proxy. The backend completes
/// the TLS handshake without needing the ECH keys.
///
/// This type handles the full proxy flow, including HelloRetryRequest. Feed
/// it every client-to-server TLS record via [`process_client_record`]; it
/// decrypts ECH from ClientHello records and returns everything else unchanged.
/// Server-to-client records are always forwarded unchanged (the proxy does not
/// need to inspect them).
///
/// # Example
///
/// ```text
/// use rustls::server::EchProxy;
///
/// let mut proxy = EchProxy::new(&ech_keys);
///
/// // During the handshake, process each client-to-server TLS record:
/// loop {
///     let record = read_tls_record(&mut client)?;
///     let forward = proxy.process_client_record(&record)?;
///     backend.write_all(&forward)?;
///
///     if proxy.is_done() {
///         break;
///     }
///
///     // Forward server-to-client data unchanged.
///     relay(&mut backend, &mut client)?;
/// }
///
/// // Handshake complete, splice bidirectionally.
/// splice(&mut client, &mut backend);
/// ```
///
/// To read one TLS record from a socket:
///
/// ```text
/// fn read_tls_record(rd: &mut impl Read) -> io::Result<Vec<u8>> {
///     let mut header = [0u8; 5];
///     rd.read_exact(&mut header)?;
///     let len = u16::from_be_bytes([header[3], header[4]]) as usize;
///     let mut record = vec![0u8; 5 + len];
///     record[..5].copy_from_slice(&header);
///     rd.read_exact(&mut record[5..])?;
///     Ok(record)
/// }
/// ```
///
/// [`process_client_record`]: EchProxy::process_client_record
/// [RFC 9849 Section 3.1]: https://datatracker.ietf.org/doc/html/rfc9849#section-3.1
pub struct EchProxy {
    keys: alloc::sync::Arc<[EchServerKey]>,
    frontend: Option<EchFrontend>,
    done: bool,
}

impl EchProxy {
    /// Create a new ECH proxy with the given server keys.
    pub fn new(keys: alloc::sync::Arc<[EchServerKey]>) -> Self {
        Self {
            keys,
            frontend: None,
            done: false,
        }
    }

    /// Process a client-to-server TLS record.
    ///
    /// If the record contains a ClientHello with ECH, decrypts it and returns
    /// a TLS record containing the inner ClientHello. All other records are
    /// returned unchanged.
    ///
    /// Call this for every client-to-server TLS record during the handshake.
    /// After `is_done()` returns true, the proxy is no longer needed and the
    /// caller should splice the streams bidirectionally.
    pub fn process_client_record(&mut self, tls_record: &[u8]) -> Result<Vec<u8>, Error> {
        // Only process Handshake records containing a ClientHello.
        if !is_client_hello_record(tls_record) {
            self.done = true;
            return Ok(tls_record.to_vec());
        }

        if let Some(ref mut frontend) = self.frontend {
            // Second ClientHello after HRR.
            let inner = frontend.decrypt_client_hello_record_hrr(tls_record)?;
            self.done = true;
            Ok(inner)
        } else {
            // First ClientHello.
            match EchFrontend::decrypt_client_hello_record(tls_record, &self.keys)? {
                EchFrontendResult::Decrypted(inner, frontend) => {
                    self.frontend = Some(frontend);
                    Ok(inner)
                }
                EchFrontendResult::NotOffered => {
                    self.done = true;
                    Ok(tls_record.to_vec())
                }
                EchFrontendResult::Rejected(retry_configs) => {
                    self.done = true;
                    // Forward the original record; the caller can use retry_configs
                    // if they need them (e.g. for logging).
                    let _ = retry_configs;
                    Ok(tls_record.to_vec())
                }
            }
        }
    }

    /// Process raw ClientHello handshake message bytes (without TLS record framing).
    ///
    /// This is the QUIC counterpart of [`process_client_record`]. Use it when
    /// the ClientHello arrives in a QUIC CRYPTO frame rather than a TLS record.
    ///
    /// The input `hs_msg` should be the raw handshake message bytes starting with
    /// the ClientHello type byte (0x01), as extracted from QUIC CRYPTO frame data.
    ///
    /// On success with [`EchProxyResult::Decrypted`], the returned bytes are the
    /// inner ClientHello handshake message (including the `ech_is_inner` marker),
    /// ready to be placed in a CRYPTO frame for forwarding to the backend.
    ///
    /// [`process_client_record`]: EchProxy::process_client_record
    pub fn process_client_hello_msg(&mut self, hs_msg: &[u8]) -> Result<EchProxyResult, Error> {
        if let Some(ref mut frontend) = self.frontend {
            // Second ClientHello after HRR.
            let inner = frontend.decrypt_handshake_msg_hrr(hs_msg)?;
            self.done = true;
            Ok(EchProxyResult::Decrypted(inner))
        } else {
            // First ClientHello.
            match EchFrontend::decrypt_handshake_msg(hs_msg, &self.keys)? {
                EchFrontendResult::Decrypted(inner, frontend) => {
                    self.frontend = Some(frontend);
                    Ok(EchProxyResult::Decrypted(inner))
                }
                EchFrontendResult::NotOffered => {
                    self.done = true;
                    Ok(EchProxyResult::NotOffered)
                }
                EchFrontendResult::Rejected(retry_configs) => {
                    self.done = true;
                    Ok(EchProxyResult::Rejected(retry_configs))
                }
            }
        }
    }

    /// Whether ECH processing is complete.
    ///
    /// After this returns true, all subsequent client-to-server and
    /// server-to-client data should be forwarded unchanged (the proxy
    /// becomes a TCP splice).
    pub fn is_done(&self) -> bool {
        self.done
    }
}

/// Check if a TLS record is a Handshake record containing a ClientHello.
fn is_client_hello_record(record: &[u8]) -> bool {
    // ContentType::Handshake (0x16) and first payload byte is HandshakeType::ClientHello (0x01).
    record.len() > TLS_RECORD_HEADER_LEN
        && record[0] == 0x16
        && record[TLS_RECORD_HEADER_LEN] == 0x01
}

/// Low-level HPKE state from decrypting a ClientHello, needed to handle
/// a potential second ClientHello after HelloRetryRequest.
///
/// Most callers should use [`EchProxy`] instead.
struct EchFrontend {
    opener: Box<dyn HpkeOpener>,
    config_id: u8,
    cipher_suite: HpkeSymmetricCipherSuite,
}

/// Result of decrypting ECH from a ClientHello in the split-mode frontend.
enum EchFrontendResult {
    /// ECH was successfully decrypted. The `Vec<u8>` contains the inner
    /// ClientHello as a handshake message (`type || length || body`).
    Decrypted(Vec<u8>, EchFrontend),

    /// ECH decryption failed (config mismatch, wrong key, etc).
    /// The `Vec<u8>` contains the serialized retry_configs.
    Rejected(Vec<u8>),

    /// No ECH extension present.
    NotOffered,
}

impl EchFrontend {
    /// Core ECH decryption on raw handshake message bytes (no TLS record framing).
    fn decrypt_handshake_msg(
        handshake_message: &[u8],
        ech_keys: &[EchServerKey],
    ) -> Result<EchFrontendResult, Error> {
        let outer_hello = parse_client_hello(handshake_message)?;
        let outer_extensions_raw = extract_extensions_from_client_hello(handshake_message)?;

        let result = decrypt_ech(&outer_hello, handshake_message, outer_extensions_raw, ech_keys);
        let retry_configs = collect_retry_configs(ech_keys);

        match result {
            EchDecryptResult::Accepted {
                inner_hello_raw,
                opener,
                ..
            } => {
                let ech_ext = match &outer_hello.encrypted_client_hello {
                    Some(EncryptedClientHello::Outer(o)) => o,
                    _ => unreachable!(),
                };

                let inner_msg = encode_inner_hello(&inner_hello_raw);
                let frontend = EchFrontend {
                    opener,
                    config_id: ech_ext.config_id,
                    cipher_suite: ech_ext.cipher_suite,
                };

                Ok(EchFrontendResult::Decrypted(inner_msg, frontend))
            }
            EchDecryptResult::Fatal(e) => Err(e),
            EchDecryptResult::Rejected => {
                let mut retry_bytes = Vec::new();
                retry_configs.encode(&mut retry_bytes);
                Ok(EchFrontendResult::Rejected(retry_bytes))
            }
            EchDecryptResult::NotOffered => Ok(EchFrontendResult::NotOffered),
            EchDecryptResult::InnerDirect => {
                // A client should never send the inner marker to the frontend.
                Err(PeerMisbehaved::InvalidEchClientHelloInner.into())
            }
        }
    }

    /// Decrypt ECH from a ClientHello TLS record.
    fn decrypt_client_hello_record(
        tls_record: &[u8],
        ech_keys: &[EchServerKey],
    ) -> Result<EchFrontendResult, Error> {
        let (record_version, handshake_message) = parse_tls_record(tls_record)?;
        match Self::decrypt_handshake_msg(handshake_message, ech_keys)? {
            EchFrontendResult::Decrypted(inner_msg, frontend) => {
                let inner_record = wrap_handshake_in_record(record_version, &inner_msg);
                Ok(EchFrontendResult::Decrypted(inner_record, frontend))
            }
            other => Ok(other),
        }
    }

    /// Core ECH HRR decryption on raw handshake message bytes.
    fn decrypt_handshake_msg_hrr(
        &mut self,
        handshake_message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let outer_hello = parse_client_hello(handshake_message)?;
        let outer_extensions_raw = extract_extensions_from_client_hello(handshake_message)?;

        let (_inner_hello, inner_hello_raw) = decrypt_ech_hrr(
            &outer_hello,
            handshake_message,
            outer_extensions_raw,
            &mut self.opener,
            Some(self.config_id),
            Some(self.cipher_suite),
        )?;

        Ok(encode_inner_hello(&inner_hello_raw))
    }

    /// Decrypt ECH from a second ClientHello TLS record after HelloRetryRequest.
    fn decrypt_client_hello_record_hrr(
        &mut self,
        tls_record: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (record_version, handshake_message) = parse_tls_record(tls_record)?;
        let inner_msg = self.decrypt_handshake_msg_hrr(handshake_message)?;
        Ok(wrap_handshake_in_record(record_version, &inner_msg))
    }
}

/// Parse a TLS record, returning (version, payload).
fn parse_tls_record(record: &[u8]) -> Result<(u16, &[u8]), Error> {
    if record.len() < TLS_RECORD_HEADER_LEN {
        return Err(Error::General("TLS record too short".into()));
    }

    if record[0] != 0x16 {
        return Err(Error::General(
            "not a Handshake TLS record".into(),
        ));
    }

    let version = u16::from_be_bytes([record[1], record[2]]);
    let payload_len = u16::from_be_bytes([record[3], record[4]]) as usize;

    if record.len() < TLS_RECORD_HEADER_LEN + payload_len {
        return Err(Error::General("TLS record truncated".into()));
    }

    Ok((version, &record[TLS_RECORD_HEADER_LEN..TLS_RECORD_HEADER_LEN + payload_len]))
}

/// Wrap a handshake message in a TLS record.
fn wrap_handshake_in_record(version: u16, handshake_message: &[u8]) -> Vec<u8> {
    let len = handshake_message.len();
    let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + len);
    record.push(0x16); // ContentType::Handshake
    record.extend_from_slice(&version.to_be_bytes());
    record.extend_from_slice(&(len as u16).to_be_bytes());
    record.extend_from_slice(handshake_message);
    record
}

/// Parse a ClientHello from raw handshake message bytes.
///
/// `handshake_message` is `HandshakeType(1) || length(3) || ClientHello body`.
fn parse_client_hello(handshake_message: &[u8]) -> Result<ClientHelloPayload, Error> {
    let err = || -> Error { PeerMisbehaved::InvalidEchClientHelloInner.into() };

    let mut r = Reader::new(handshake_message);

    // Skip handshake header: type (1) + length (3)
    let hs_type = u8::read(&mut r).map_err(|_| err())?;
    if hs_type != 0x01 {
        return Err(Error::General("not a ClientHello handshake message".into()));
    }
    let _len = u24_read(&mut r).ok_or_else(err)?;

    ClientHelloPayload::read(&mut r).map_err(|_| err())
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

    // --- Split-mode proxy helper tests ---

    #[test]
    fn is_client_hello_record_accepts_valid() {
        // 0x16 = Handshake, version, length, then 0x01 = ClientHello
        let record = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        assert!(is_client_hello_record(&record));
    }

    #[test]
    fn is_client_hello_record_rejects_non_handshake() {
        // 0x17 = Application data
        let record = [0x17, 0x03, 0x01, 0x00, 0x01, 0x01];
        assert!(!is_client_hello_record(&record));
    }

    #[test]
    fn is_client_hello_record_rejects_non_client_hello() {
        // Handshake but type 0x02 = ServerHello
        let record = [0x16, 0x03, 0x01, 0x00, 0x01, 0x02];
        assert!(!is_client_hello_record(&record));
    }

    #[test]
    fn is_client_hello_record_rejects_too_short() {
        let record = [0x16, 0x03, 0x01, 0x00];
        assert!(!is_client_hello_record(&record));
    }

    #[test]
    fn parse_tls_record_valid() {
        let record = [0x16, 0x03, 0x01, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let (version, payload) = parse_tls_record(&record).unwrap();
        assert_eq!(version, 0x0301);
        assert_eq!(payload, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn parse_tls_record_rejects_too_short() {
        assert!(parse_tls_record(&[0x16, 0x03]).is_err());
    }

    #[test]
    fn parse_tls_record_rejects_non_handshake() {
        let record = [0x17, 0x03, 0x01, 0x00, 0x01, 0x00];
        assert!(parse_tls_record(&record).is_err());
    }

    #[test]
    fn parse_tls_record_rejects_truncated_payload() {
        // Claims 10 bytes of payload but only has 3
        let record = [0x16, 0x03, 0x01, 0x00, 0x0A, 0x01, 0x02, 0x03];
        assert!(parse_tls_record(&record).is_err());
    }

    #[test]
    fn wrap_handshake_round_trips() {
        let msg = &[0x01, 0x02, 0x03];
        let record = wrap_handshake_in_record(0x0301, msg);
        let (version, payload) = parse_tls_record(&record).unwrap();
        assert_eq!(version, 0x0301);
        assert_eq!(payload, msg);
    }
}
