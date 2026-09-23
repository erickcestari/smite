//! BOLT 2 `splice_locked` message.

use bitcoin::Txid;

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `splice_locked` message (type 77).
///
/// Sent once a splice transaction reaches acceptable depth. The splice
/// completes when both peers have sent one for the same transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpliceLocked {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The splice transaction that reached acceptable depth.
    pub splice_txid: Txid,
}

impl SpliceLocked {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.splice_txid.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = WireFormat::read(&mut cursor)?;
        let splice_txid = WireFormat::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            splice_txid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, TXID_SIZE};
    use super::*;
    use bitcoin::hashes::Hash;

    fn sample_msg() -> SpliceLocked {
        SpliceLocked {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            splice_txid: Txid::from_byte_array([0xcd; TXID_SIZE]),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        assert_eq!(sample_msg().encode().len(), CHANNEL_ID_SIZE + TXID_SIZE);
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let decoded = SpliceLocked::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_splice_txid() {
        assert_eq!(
            SpliceLocked::decode(&[0x00; CHANNEL_ID_SIZE + 10]),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            SpliceLocked::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }
}
