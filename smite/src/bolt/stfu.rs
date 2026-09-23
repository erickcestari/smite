//! BOLT 2 `stfu` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `stfu` message (type 2).
///
/// Asks the peer to quiesce the channel, or answers such a request. Splicing
/// only starts once both sides have sent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stfu {
    /// The channel to quiesce.
    pub channel_id: ChannelId,
    /// 1 when the sender initiates quiescence, 0 when it replies to the peer's
    /// `stfu`.
    pub initiator: u8,
}

impl Stfu {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.initiator.write(&mut out);
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
        let initiator = WireFormat::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            initiator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn encode_fixed_field_size() {
        let msg = Stfu {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            initiator: 1,
        };
        assert_eq!(msg.encode().len(), CHANNEL_ID_SIZE + 1);
    }

    #[test]
    fn roundtrip() {
        let original = Stfu {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            initiator: 1,
        };
        let decoded = Stfu::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_initiator() {
        assert_eq!(
            Stfu::decode(&[0x00; CHANNEL_ID_SIZE]),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            Stfu::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }
}
