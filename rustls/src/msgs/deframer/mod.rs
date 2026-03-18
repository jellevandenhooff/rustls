mod buffers;
pub(crate) use buffers::{Delocator, Locator, TlsInputBuffer, VecInput};

mod handshake;
pub(crate) use handshake::{HandshakeAlignedProof, HandshakeDeframer};

pub fn fuzz_deframer(data: &[u8]) {
    let mut buf = data.to_vec();
    let mut deframer = HandshakeDeframer::default();
    while let Some(result) = deframer.deframe(&mut buf) {
        if result.is_err() {
            break;
        }
    }

    assert!(deframer.processed() <= buf.len());
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::enums::ContentType;
    use crate::error::{Error, InvalidMessage};

    #[test]
    fn iterator_empty_before_header_received() {
        assert!(
            HandshakeDeframer::default()
                .deframe(&mut [])
                .is_none()
        );
        assert!(
            HandshakeDeframer::default()
                .deframe(&mut [0x16])
                .is_none()
        );
        assert!(
            HandshakeDeframer::default()
                .deframe(&mut [0x16, 0x03])
                .is_none()
        );
        assert!(
            HandshakeDeframer::default()
                .deframe(&mut [0x16, 0x03, 0x03])
                .is_none()
        );
        assert!(
            HandshakeDeframer::default()
                .deframe(&mut [0x16, 0x03, 0x03, 0x00])
                .is_none()
        );
        assert!(
            HandshakeDeframer::default()
                .deframe(&mut [0x16, 0x03, 0x03, 0x00, 0x01])
                .is_none()
        );
    }

    #[test]
    fn iterate_one_message() {
        let mut buffer = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        let mut deframer = HandshakeDeframer::default();

        let (message, bounds) = deframer
            .deframe(&mut buffer)
            .unwrap()
            .unwrap();

        assert_eq!(message.typ, ContentType::ApplicationData);
        assert_eq!(bounds.end, 6);
        assert!(deframer.deframe(&mut buffer).is_none());
    }

    #[test]
    fn iterate_two_messages() {
        let mut buffer = [
            0x16, 0x03, 0x03, 0x00, 0x01, 0x00, 0x17, 0x03, 0x03, 0x00, 0x01, 0x00,
        ];
        let mut deframer = HandshakeDeframer::default();

        let (message, bounds) = deframer
            .deframe(&mut buffer)
            .unwrap()
            .unwrap();

        assert_eq!(message.typ, ContentType::Handshake);
        assert_eq!(bounds.end, 6);

        let (message, bounds) = deframer
            .deframe(&mut buffer)
            .unwrap()
            .unwrap();

        assert_eq!(message.typ, ContentType::ApplicationData);
        assert_eq!(bounds.end, 12);
        assert!(deframer.deframe(&mut buffer).is_none());
    }

    #[test]
    fn iterator_invalid_protocol_version_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-version.bin").to_vec();
        let mut deframer = HandshakeDeframer::default();
        let result = deframer.deframe(&mut buffer).unwrap();
        assert_eq!(
            result.err(),
            Some(Error::InvalidMessage(
                InvalidMessage::UnknownProtocolVersion
            ))
        );
    }

    #[test]
    fn iterator_invalid_content_type_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-contenttype.bin").to_vec();
        let mut deframer = HandshakeDeframer::default();
        let result = deframer.deframe(&mut buffer).unwrap();
        assert_eq!(
            result.err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidContentType))
        );
    }

    #[test]
    fn iterator_excess_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-length.bin").to_vec();
        let mut deframer = HandshakeDeframer::default();
        let result = deframer.deframe(&mut buffer).unwrap();
        assert_eq!(
            result.err(),
            Some(Error::InvalidMessage(InvalidMessage::MessageTooLarge))
        );
    }

    #[test]
    fn iterator_zero_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-empty.bin").to_vec();
        let mut deframer = HandshakeDeframer::default();
        let result = deframer.deframe(&mut buffer).unwrap();
        assert_eq!(
            result.err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload))
        );
    }

    #[test]
    fn iterator_over_many_messages() {
        let client_hello = include_bytes!("../../testdata/deframer-test.1.bin");
        let mut buffer = Vec::with_capacity(3 * client_hello.len());
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        let mut deframer = HandshakeDeframer::default();
        let mut count = 0;
        let mut end = 0;

        while let Some(result) = deframer.deframe(&mut buffer) {
            let (message, bounds) = result.unwrap();
            assert_eq!(ContentType::Handshake, message.typ);
            count += 1;
            end = bounds.end;
        }

        assert_eq!(count, 3);
        assert_eq!(client_hello.len() * 3, end);
    }

    #[test]
    fn exercise_fuzz_deframer() {
        fuzz_deframer(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        for prefix in 0..7 {
            fuzz_deframer(&[0x16, 0x03, 0x03, 0x00, 0x01, 0xff][..prefix]);
        }
    }
}
