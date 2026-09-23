//! BOLT 2 `splice_ack` message.

use bitcoin::secp256k1::PublicKey;

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::{EmptyTlv, WireFormat};

/// TLV type for require confirmed inputs.
const TLV_REQUIRE_CONFIRMED_INPUTS: u64 = 2;

/// BOLT 2 `splice_ack` message (type 81).
///
/// Sent by the receiver of `splice_init` to accept the splice, after which the
/// initiator starts the interactive construction of the splice transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpliceAck {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// What the sender adds to (positive) or removes from (negative) its
    /// channel balance.
    pub funding_contribution_satoshis: i64,
    /// The sender's funding pubkey for the new funding output.
    pub funding_pubkey: PublicKey,
    /// Optional TLV extensions.
    pub tlvs: SpliceAckTlvs,
}

/// TLV extensions for the `splice_ack` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpliceAckTlvs {
    /// Whether the sender requires the receiver to only use confirmed inputs
    /// (TLV type 2, signalled by presence).
    pub require_confirmed_inputs: bool,
}

impl SpliceAck {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.funding_contribution_satoshis.write(&mut out);
        self.funding_pubkey.write(&mut out);

        let mut tlv_stream = TlvStream::new();
        if self.tlvs.require_confirmed_inputs {
            tlv_stream.add(TLV_REQUIRE_CONFIRMED_INPUTS, vec![]);
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field,
    /// `InvalidPublicKey` if `funding_pubkey` is invalid, or TLV errors if the
    /// TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = WireFormat::read(&mut cursor)?;
        let funding_contribution_satoshis = WireFormat::read(&mut cursor)?;
        let funding_pubkey = WireFormat::read(&mut cursor)?;

        let tlv_stream = TlvStream::decode_with_known(cursor, &[TLV_REQUIRE_CONFIRMED_INPUTS])?;
        let require_confirmed_inputs = tlv_stream
            .get_as::<EmptyTlv>(TLV_REQUIRE_CONFIRMED_INPUTS)?
            .is_some();

        Ok(Self {
            channel_id,
            funding_contribution_satoshis,
            funding_pubkey,
            tlvs: SpliceAckTlvs {
                require_confirmed_inputs,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, PUBLIC_KEY_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Size of the fixed fields: `channel_id`, `funding_contribution_satoshis`
    /// and `funding_pubkey`.
    const FIXED_SIZE: usize = CHANNEL_ID_SIZE + 8 + PUBLIC_KEY_SIZE;

    fn sample_msg() -> SpliceAck {
        let sk = SecretKey::from_slice(&[0x22; 32]).expect("valid secret");
        SpliceAck {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            funding_contribution_satoshis: 0,
            funding_pubkey: PublicKey::from_secret_key(&Secp256k1::new(), &sk),
            tlvs: SpliceAckTlvs::default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        assert_eq!(sample_msg().encode().len(), FIXED_SIZE);
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let decoded = SpliceAck::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_negative_contribution() {
        let mut msg = sample_msg();
        msg.funding_contribution_satoshis = -50_000;
        let decoded = SpliceAck::decode(&msg.encode()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_with_require_confirmed_inputs() {
        let mut msg = sample_msg();
        msg.tlvs.require_confirmed_inputs = true;
        let decoded = SpliceAck::decode(&msg.encode()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let mut encoded = sample_msg().encode();
        encoded.extend_from_slice(&[0x03, 0x02, 0xff, 0xff]);
        assert_eq!(SpliceAck::decode(&encoded).unwrap(), sample_msg());
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let mut encoded = sample_msg().encode();
        encoded.extend_from_slice(&[0x04, 0x01, 0x00]);
        assert!(matches!(
            SpliceAck::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(4))
        ));
    }

    #[test]
    fn decode_truncated_contribution() {
        let encoded = sample_msg().encode();
        assert_eq!(
            SpliceAck::decode(&encoded[..CHANNEL_ID_SIZE + 3]),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 3
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            SpliceAck::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }
}
