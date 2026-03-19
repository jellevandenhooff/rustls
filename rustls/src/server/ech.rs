use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::hpke::{Hpke, HpkePrivateKey};
use crate::error::Error;
use crate::msgs::{Codec, EchConfigPayload, Reader, SizedPayload};

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
}
