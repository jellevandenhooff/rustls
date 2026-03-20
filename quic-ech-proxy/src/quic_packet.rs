//! QUIC Initial packet decryption and re-encryption.
//!
//! Adapted from pos3's support-server quic_sni.rs. Handles:
//! - Decrypting client Initial packets (DCID-derived keys per RFC 9001)
//! - Re-encrypting modified Initial packets (for ECH proxy forwarding)
//! - CRYPTO frame parsing and construction

use anyhow::{Result, bail};
use ring::aead::{self, Aad, Nonce};
use ring::hkdf;

/// QUIC v1 Initial salt (RFC 9001 Section 5.2).
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC v2 Initial salt (RFC 9369 Section 5.2).
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
    0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

const QUIC_V1: u32 = 0x00000001;
const QUIC_V2: u32 = 0x6b3343cf;

/// Maximum assembled CRYPTO data size (8 KB).
const MAX_CRYPTO_ASSEMBLER_SIZE: usize = 8192;

/// Minimum QUIC Initial packet size in a UDP datagram.
const MIN_INITIAL_SIZE: usize = 1200;

/// A CRYPTO frame segment extracted from a decrypted Initial packet.
#[derive(Debug, Clone)]
pub struct CryptoSegment {
    pub offset: usize,
    pub data: Vec<u8>,
}

/// Assembler for CRYPTO frame data that tracks which byte ranges are covered.
pub struct CryptoAssembler {
    data: Vec<u8>,
    covered: Vec<bool>,
}

impl CryptoAssembler {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            covered: Vec::new(),
        }
    }

    pub fn add_segments(&mut self, segments: &[CryptoSegment]) {
        for seg in segments {
            let end = seg.offset + seg.data.len();
            if end > MAX_CRYPTO_ASSEMBLER_SIZE {
                continue;
            }
            if end > self.data.len() {
                self.data.resize(end, 0);
                self.covered.resize(end, false);
            }
            self.data[seg.offset..end].copy_from_slice(&seg.data);
            for i in seg.offset..end {
                self.covered[i] = true;
            }
        }
    }

    pub fn contiguous_len(&self) -> usize {
        self.covered
            .iter()
            .position(|&c| !c)
            .unwrap_or(self.covered.len())
    }

    pub fn contiguous_data(&self) -> &[u8] {
        &self.data[..self.contiguous_len()]
    }
}

/// Parsed Initial packet header fields needed for re-encryption.
#[derive(Debug, Clone)]
pub struct InitialHeader {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub packet_number: u32,
    /// The salt to use for key derivation (v1 or v2).
    salt: [u8; 20],
}

/// Result of decrypting a QUIC Initial packet.
pub struct DecryptedInitial {
    pub header: InitialHeader,
    pub crypto_segments: Vec<CryptoSegment>,
}

/// Decrypt a QUIC Initial packet and return its header and CRYPTO frame segments.
///
/// Returns `Ok(Some(...))` for Initial packets with CRYPTO data,
/// `Ok(None)` for non-Initial packets, `Err(...)` on parse/decrypt errors.
pub fn decrypt_initial(packet: &[u8]) -> Result<Option<DecryptedInitial>> {
    if packet.len() < 6 {
        bail!("packet too short");
    }

    let first_byte = packet[0];
    if (first_byte & 0x80) == 0 {
        return Ok(None); // Short header
    }

    let version = u32::from_be_bytes(packet[1..5].try_into().unwrap());

    let salt = match version {
        QUIC_V1 => {
            if (first_byte & 0x30) != 0x00 {
                return Ok(None); // Not Initial
            }
            QUIC_V1_SALT
        }
        QUIC_V2 => {
            if (first_byte & 0x30) != 0x10 {
                return Ok(None); // Not Initial (v2 uses 0b01)
            }
            QUIC_V2_SALT
        }
        _ => return Ok(None),
    };

    // Parse long header fields
    let dcid_len = packet[5] as usize;
    if packet.len() < 6 + dcid_len + 1 {
        bail!("packet too short for DCID");
    }
    let dcid = packet[6..6 + dcid_len].to_vec();

    let scid_offset = 6 + dcid_len;
    let scid_len = packet[scid_offset] as usize;
    if packet.len() < scid_offset + 1 + scid_len {
        bail!("packet too short for SCID");
    }
    let scid = packet[scid_offset + 1..scid_offset + 1 + scid_len].to_vec();

    // Token
    let mut pos = scid_offset + 1 + scid_len;
    let (token_len, token_len_size) = read_varint(packet, pos)?;
    pos += token_len_size;
    let token = packet[pos..pos + token_len as usize].to_vec();
    pos += token_len as usize;

    // Payload Length
    if pos >= packet.len() {
        bail!("packet truncated before payload length");
    }
    let (payload_len, payload_len_size) = read_varint(packet, pos)?;
    pos += payload_len_size;

    let payload_len = payload_len as usize;
    if pos + payload_len > packet.len() {
        bail!("payload length exceeds packet size");
    }

    let header_len = pos;

    // Derive client Initial keys from DCID
    let (key, iv, hp_key) = derive_client_initial_keys(&dcid, &salt)?;

    // Header protection sample
    let sample_offset = pos + 4;
    if sample_offset + 16 > pos + payload_len {
        bail!("packet too short for header protection sample");
    }
    let sample = &packet[sample_offset..sample_offset + 16];
    let mask = compute_hp_mask(&hp_key, sample)?;

    // Unmask first byte
    let mut header = packet[..header_len].to_vec();
    header[0] ^= mask[0] & 0x0f;

    let pn_len = ((header[0] & 0x03) + 1) as usize;
    if pos + pn_len > pos + payload_len {
        bail!("packet number extends beyond payload");
    }

    // Build full header with unmasked packet number
    let mut full_header = header;
    full_header.extend_from_slice(&packet[pos..pos + pn_len]);
    for i in 0..pn_len {
        full_header[header_len + i] ^= mask[1 + i];
    }

    // Reconstruct packet number
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[4 - pn_len + i] = full_header[header_len + i];
    }
    let packet_number = u32::from_be_bytes(pn_bytes);

    // Build nonce
    let mut nonce_bytes = iv;
    let pn_be = (packet_number as u64).to_be_bytes();
    for i in 0..8 {
        nonce_bytes[12 - 8 + i] ^= pn_be[i];
    }
    let nonce =
        Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| anyhow::anyhow!("bad nonce"))?;

    // Decrypt payload
    let encrypted_start = pos + pn_len;
    let encrypted_len = payload_len - pn_len;
    let mut decrypted = packet[encrypted_start..encrypted_start + encrypted_len].to_vec();

    let aad = Aad::from(&full_header);
    let opening_key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &key)
            .map_err(|_| anyhow::anyhow!("invalid AES key"))?,
    );

    let plaintext = match opening_key.open_in_place(nonce, aad, &mut decrypted) {
        Ok(p) => p,
        Err(_) => bail!("AEAD decryption failed"),
    };

    let segments = parse_crypto_frames(plaintext)?;
    if segments.is_empty() {
        return Ok(None);
    }

    Ok(Some(DecryptedInitial {
        header: InitialHeader {
            version,
            dcid,
            scid,
            token,
            packet_number,
            salt,
        },
        crypto_segments: segments,
    }))
}

/// Build and encrypt a QUIC Initial packet with the given CRYPTO frame data.
///
/// Uses the same DCID/SCID/version as the original packet so that the
/// backend derives the same Initial keys and the client can decrypt responses.
pub fn encrypt_initial(header: &InitialHeader, crypto_data: &[u8]) -> Result<Vec<u8>> {
    let (key, iv, hp_key) = derive_client_initial_keys(&header.dcid, &header.salt)?;

    // Build the CRYPTO frame: type(0x06) + offset(varint) + length(varint) + data
    let mut frames = Vec::new();
    frames.push(0x06); // CRYPTO frame type
    write_varint(&mut frames, 0); // offset = 0
    write_varint(&mut frames, crypto_data.len() as u64);
    frames.extend_from_slice(crypto_data);

    // We'll use a 2-byte packet number encoding for simplicity
    let pn_len: usize = 2;
    let pn_bytes = &(header.packet_number as u16).to_be_bytes();

    // AEAD tag is 16 bytes
    let payload_len = pn_len + frames.len() + 16; // +16 for AEAD tag

    // Build the header
    let mut packet = Vec::with_capacity(MIN_INITIAL_SIZE);

    // First byte: long header (0x80) | fixed bit (0x40) | Initial type + pn_len
    let first_byte = match header.version {
        QUIC_V2 => 0xc0 | 0x10 | ((pn_len - 1) as u8), // v2 Initial = 0b01
        _ => 0xc0 | ((pn_len - 1) as u8),                // v1 Initial = 0b00
    };
    packet.push(first_byte);

    // Version
    packet.extend_from_slice(&header.version.to_be_bytes());

    // DCID
    packet.push(header.dcid.len() as u8);
    packet.extend_from_slice(&header.dcid);

    // SCID
    packet.push(header.scid.len() as u8);
    packet.extend_from_slice(&header.scid);

    // Token
    write_varint(&mut packet, header.token.len() as u64);
    packet.extend_from_slice(&header.token);

    // We need to figure out total padding to reach MIN_INITIAL_SIZE.
    // Calculate current header size + payload length varint + payload
    // The payload length varint encoding size depends on the value, which
    // depends on padding, which is circular. Solve by assuming 2-byte varint.
    let header_so_far = packet.len();
    // payload_len_varint_size = 2 bytes (can encode up to 16383)
    let min_payload_for_padding =
        MIN_INITIAL_SIZE.saturating_sub(header_so_far + 2 /* varint */);
    let actual_payload_len = payload_len.max(min_payload_for_padding);
    let padding_len = actual_payload_len - payload_len;

    // Payload Length (varint, 2-byte encoding)
    write_varint(&mut packet, actual_payload_len as u64);

    let header_len = packet.len();

    // Packet number (unencrypted for now)
    packet.extend_from_slice(&pn_bytes[..pn_len]);

    // Plaintext payload: CRYPTO frame + PADDING
    let mut plaintext = frames;
    plaintext.extend(core::iter::repeat(0u8).take(padding_len)); // PADDING frames

    // Encrypt
    let mut nonce_bytes = iv;
    let pn_be = (header.packet_number as u64).to_be_bytes();
    for i in 0..8 {
        nonce_bytes[12 - 8 + i] ^= pn_be[i];
    }
    let nonce =
        Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| anyhow::anyhow!("bad nonce"))?;

    let sealing_key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &key)
            .map_err(|_| anyhow::anyhow!("invalid AES key"))?,
    );

    let aad = Aad::from(&packet[..header_len + pn_len]);

    // Seal in place: ring appends the tag
    let mut ciphertext = plaintext;
    sealing_key
        .seal_in_place_append_tag(nonce, aad, &mut ciphertext)
        .map_err(|_| anyhow::anyhow!("AEAD seal failed"))?;

    packet.extend_from_slice(&ciphertext);

    // Apply header protection
    let sample_offset = header_len + pn_len + 4; // 4 bytes into ciphertext
    if sample_offset + 16 > packet.len() {
        bail!("packet too short for HP sample after encryption");
    }
    let sample: [u8; 16] = packet[sample_offset..sample_offset + 16]
        .try_into()
        .unwrap();
    let mask = compute_hp_mask(&hp_key, &sample)?;

    // Mask first byte
    packet[0] ^= mask[0] & 0x0f;
    // Mask packet number
    for i in 0..pn_len {
        packet[header_len + i] ^= mask[1 + i];
    }

    Ok(packet)
}

// --- Key derivation (RFC 9001 Section 5.2) ---

fn derive_client_initial_keys(
    dcid: &[u8],
    salt: &[u8],
) -> Result<([u8; 16], [u8; 12], [u8; 16])> {
    let initial_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let initial_secret = initial_salt.extract(dcid);

    let client_secret = hkdf_expand_label(&initial_secret, b"client in", 32)?;
    let client_secret_prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_secret);

    let key_bytes = hkdf_expand_label(&client_secret_prk, b"quic key", 16)?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&key_bytes[..16]);

    let iv_bytes = hkdf_expand_label(&client_secret_prk, b"quic iv", 12)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes[..12]);

    let hp_bytes = hkdf_expand_label(&client_secret_prk, b"quic hp", 16)?;
    let mut hp = [0u8; 16];
    hp.copy_from_slice(&hp_bytes[..16]);

    Ok((key, iv, hp))
}

fn hkdf_expand_label(prk: &hkdf::Prk, label: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0); // empty context

    let mut out = vec![0u8; length];
    prk.expand(&[&info], ArbitraryOutputLen(length))
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?
        .fill(&mut out)
        .map_err(|_| anyhow::anyhow!("HKDF fill failed"))?;

    Ok(out)
}

struct ArbitraryOutputLen(usize);

impl hkdf::KeyType for ArbitraryOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn compute_hp_mask(hp_key: &[u8; 16], sample: &[u8]) -> Result<[u8; 5]> {
    use aes::Aes128;
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};

    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = GenericArray::clone_from_slice(&sample[..16]);
    cipher.encrypt_block(&mut block);

    let mut mask = [0u8; 5];
    mask.copy_from_slice(&block[..5]);
    Ok(mask)
}

// --- QUIC frame parsing ---

fn parse_crypto_frames(plaintext: &[u8]) -> Result<Vec<CryptoSegment>> {
    let mut pos = 0;
    let mut segments = Vec::new();

    while pos < plaintext.len() {
        let (frame_type, ft_size) = read_varint(plaintext, pos)?;
        pos += ft_size;

        match frame_type {
            0x00 => continue, // PADDING
            0x01 => continue, // PING
            0x06 => {
                // CRYPTO frame
                let (offset, off_size) = read_varint(plaintext, pos)?;
                pos += off_size;
                let (length, len_size) = read_varint(plaintext, pos)?;
                pos += len_size;
                let length = length as usize;

                if pos + length > plaintext.len() {
                    bail!("CRYPTO frame data extends beyond plaintext");
                }

                segments.push(CryptoSegment {
                    offset: offset as usize,
                    data: plaintext[pos..pos + length].to_vec(),
                });
                pos += length;
            }
            0x02 | 0x03 => break, // ACK
            _ => break,
        }
    }

    Ok(segments)
}

// --- Varint encoding/decoding (RFC 9000 Section 16) ---

fn read_varint(data: &[u8], offset: usize) -> Result<(u64, usize)> {
    if offset >= data.len() {
        bail!("varint: offset beyond data");
    }
    let first = data[offset];
    let prefix = first >> 6;
    let length = 1usize << prefix;
    if offset + length > data.len() {
        bail!("varint: not enough data");
    }

    let mut value = (first & 0x3f) as u64;
    for i in 1..length {
        value = (value << 8) | data[offset + i] as u64;
    }

    Ok((value, length))
}

fn write_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 64 {
        buf.push(value as u8);
    } else if value < 16384 {
        buf.push(0x40 | (value >> 8) as u8);
        buf.push(value as u8);
    } else if value < 1_073_741_824 {
        buf.push(0x80 | (value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        buf.push(0xc0 | (value >> 56) as u8);
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    }
}

/// Check if a packet is a QUIC long header (Initial, Handshake, etc).
pub fn is_long_header(packet: &[u8]) -> bool {
    !packet.is_empty() && (packet[0] & 0x80) != 0
}

/// Extract the DCID from a QUIC long header packet.
pub fn parse_long_header_dcid(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 6 || (packet[0] & 0x80) == 0 {
        return None;
    }
    let dcid_len = packet[5] as usize;
    if packet.len() < 6 + dcid_len {
        return None;
    }
    Some(packet[6..6 + dcid_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for &val in &[0u64, 37, 15293, 494878333] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);
            let (decoded, _) = read_varint(&buf, 0).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn test_rfc9001_key_derivation() {
        // RFC 9001 Appendix A.1: DCID = 0x8394c8f03e515708
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let (key, iv, hp) = derive_client_initial_keys(&dcid, &QUIC_V1_SALT).unwrap();

        let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        assert_eq!(hex(&key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&hp), "9f50449e04a0e810283a1e9933adedd2");
    }
}
