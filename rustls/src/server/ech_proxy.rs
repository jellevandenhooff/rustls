use alloc::vec::Vec;

use super::ech::{EchKeyIndex, EchServerState};
use crate::conn::Input;
use crate::crypto::cipher::Payload;
use crate::enums::{HandshakeType, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::{
    Codec, EncryptedClientHello, HandshakeMessagePayload, HandshakePayload, Message,
    MessagePayload, Reader,
};
use crate::sync::Arc;

/// ECH split-mode proxy for a client-facing frontend server.
///
/// In ECH split mode ([RFC 9849 Section 3.1]), a client-facing frontend holds
/// the ECH private keys and decrypts the outer ClientHello. It forwards the
/// reconstructed inner ClientHello (with the `ech_is_inner` type=1 marker)
/// to the backend server, then acts as a TCP/QUIC proxy. The backend completes
/// the TLS handshake without needing the ECH keys.
///
/// This type handles the full proxy flow, including HelloRetryRequest. Feed
/// it each client-to-server ClientHello handshake message via [`process`];
/// it decrypts ECH and returns an [`EchProxyResult`] indicating the outcome.
///
/// The input is the raw handshake message (`type(1) || length(3) || body`),
/// without any transport framing. For TLS-over-TCP, strip the 5-byte TLS
/// record header before calling [`process`] and re-wrap the result. For QUIC,
/// pass the CRYPTO frame payload directly.
///
/// [`process`]: EchProxy::process
/// [RFC 9849 Section 3.1]: https://datatracker.ietf.org/doc/html/rfc9849#section-3.1
pub struct EchProxy {
    index: Arc<EchKeyIndex>,
    ech: EchServerState,
    done_retry: bool,
}

impl EchProxy {
    /// Create a new ECH proxy with the given key index.
    pub fn new(index: Arc<EchKeyIndex>) -> Self {
        Self {
            index,
            ech: EchServerState::new(),
            done_retry: false,
        }
    }

    /// Process a ClientHello handshake message, decrypting ECH if present.
    ///
    /// The input `hs_msg` should be the raw handshake message bytes
    /// (`type(1) || length(3) || body`), without any transport framing.
    /// For TLS-over-TCP, strip the 5-byte TLS record header first.
    /// For QUIC, pass the CRYPTO frame payload directly.
    ///
    /// Returns an [`EchProxyResult`] indicating whether ECH was decrypted,
    /// not offered, or rejected. On [`Decrypted`], the returned bytes are the
    /// inner ClientHello handshake message (with the `ech_is_inner` marker),
    /// ready to forward to the backend.
    ///
    /// Call once for the initial ClientHello, and optionally once more if a
    /// HelloRetryRequest occurs.
    ///
    /// [`Decrypted`]: EchProxyResult::Decrypted
    pub fn process(&mut self, hs_msg: &[u8]) -> Result<EchProxyResult, Error> {
        // Parse raw handshake message bytes into an Input.
        let mut reader = Reader::new(hs_msg);
        let parsed = HandshakeMessagePayload::read(&mut reader)
            .map_err(|_| -> Error { PeerMisbehaved::InvalidEchClientHelloInner.into() })?;

        let input = Input {
            message: Message {
                version: ProtocolVersion::TLSv1_0,
                payload: MessagePayload::Handshake {
                    parsed,
                    encoded: Payload::Borrowed(hs_msg),
                },
            },
            aligned_handshake: None,
        };

        // Inner marker should not appear in proxy mode.
        let outer_hello = require_handshake_msg!(
            input.message,
            HandshakeType::ClientHello,
            HandshakePayload::ClientHello
        )?;
        if matches!(
            outer_hello.encrypted_client_hello,
            Some(EncryptedClientHello::Inner)
        ) {
            return Err(PeerMisbehaved::InvalidEchClientHelloInner.into());
        }

        let had_ech = outer_hello
            .encrypted_client_hello
            .is_some();

        let is_retry = self.done_retry;
        self.done_retry = true;

        let inner_input = if !is_retry {
            self.ech
                .resolve(&self.index, &input, false)?
        } else {
            self.ech.resolve_retry(&input)?
        };

        if let Some(inner_input) = inner_input {
            let encoded = match &inner_input.message.payload {
                MessagePayload::Handshake { encoded, .. } => encoded.bytes().to_vec(),
                _ => unreachable!(),
            };
            return Ok(EchProxyResult::Decrypted(encoded));
        }

        let retry_configs = self.index.retry_configs();
        if had_ech && !retry_configs.is_empty() {
            let mut retry_bytes = Vec::new();
            let mut inner = Vec::new();
            for config in retry_configs {
                config.encode(&mut inner);
            }
            (inner.len() as u16).encode(&mut retry_bytes);
            retry_bytes.extend_from_slice(&inner);
            Ok(EchProxyResult::Rejected(retry_bytes))
        } else {
            Ok(EchProxyResult::NotOffered)
        }
    }
}

/// Result of processing a ClientHello for ECH split-mode proxying.
///
/// Returned by [`EchProxy::process`].
#[non_exhaustive]
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
    /// retry_configs that the backend may send in EncryptedExtensions.
    Rejected(Vec<u8>),
}
