//! BOLT 2 oracle for the peer accepting a splice, or an RBF of one.
//!
//! The receiver of `splice_init` or `tx_init_rbf` must reject it in several
//! states, which [`splice_init_rejection`] and [`splice_rbf_rejection`] judge
//! when we send the proposal. [`SpliceAckOracle`] then reports the peer
//! accepting one anyway.

use super::Oracle;
use crate::bolt::ChannelId;
use crate::channel_tx::ChannelState;
use crate::violation::Violation;

/// What we knew about the channel when proposing a splice or an RBF of one.
pub struct SpliceProposal<'a> {
    /// The channel being spliced.
    pub channel: &'a ChannelState,
    /// What our proposal adds to our balance.
    pub local_contribution: i64,
    /// Whether we sent `stfu` since quiescence last ended.
    pub quiesced: bool,
}

/// Why BOLT 2 requires the peer to reject our `splice_init`, if it does.
///
/// `over_unlocked_splice` is whether an earlier splice of the channel was
/// signed by both peers but not locked by both. A splice still being
/// negotiated is not judged: the peer may have aborted it in a message we have
/// not read.
#[must_use]
pub fn splice_init_rejection(
    proposal: &SpliceProposal<'_>,
    over_unlocked_splice: bool,
) -> Option<String> {
    if !proposal.quiesced {
        return Some("splice_init on a channel that is not quiescent".into());
    }
    if over_unlocked_splice {
        return Some("splice_init while an earlier splice is not locked".into());
    }
    overdraw(
        proposal.local_contribution,
        proposal.channel.holder_balance_msat(),
    )
    .map(|excess| format!("splice_init takes out {excess} msat more than our balance"))
}

/// Why BOLT 2 requires the peer to reject our `tx_init_rbf` of a splice, if it
/// does.
#[must_use]
pub fn splice_rbf_rejection(
    proposal: &SpliceProposal<'_>,
    sent_splice_locked: bool,
) -> Option<String> {
    if !proposal.quiesced {
        return Some("tx_init_rbf of a splice on a channel that is not quiescent".into());
    }
    if sent_splice_locked {
        return Some("tx_init_rbf of a splice after we sent splice_locked".into());
    }
    overdraw(
        proposal.local_contribution,
        proposal.channel.holder_balance_msat(),
    )
    .map(|excess| format!("tx_init_rbf takes out {excess} msat more than our balance"))
}

/// How far `contribution` takes out more than `balance_msat`, if it does.
fn overdraw(contribution: i64, balance_msat: u64) -> Option<i128> {
    let excess = -i128::from(contribution) * 1000 - i128::from(balance_msat);
    (excess > 0).then_some(excess)
}

/// Context for [`SpliceAckOracle`].
pub struct SpliceAckContext<'a> {
    /// The channel the acknowledgement names.
    pub channel_id: ChannelId,
    /// The channel being spliced.
    pub channel: &'a ChannelState,
    /// Why the peer had to reject the proposal it acknowledges, if it had to.
    pub must_reject: Option<&'a str>,
    /// What the peer's acknowledgement adds to its balance.
    pub remote_contribution: i64,
}

/// Checks a `splice_ack`, or a `tx_ack_rbf` of a splice: it must answer a
/// proposal BOLT 2 lets the peer accept, and take out no more than the peer's
/// balance, which BOLT 2 has us fail the channel over.
pub struct SpliceAckOracle;

impl Oracle<SpliceAckContext<'_>> for SpliceAckOracle {
    fn evaluate(&self, context: &SpliceAckContext<'_>) -> Result<(), Violation> {
        if let Some(reason) = context.must_reject {
            return Err(Violation::InvalidSpliceAck(
                context.channel_id,
                format!("accepted {reason}"),
            ));
        }
        if let Some(excess) = overdraw(
            context.remote_contribution,
            context.channel.counterparty_balance_msat(),
        ) {
            return Err(Violation::InvalidSpliceAck(
                context.channel_id,
                format!("takes out {excess} msat more than the peer's balance"),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::Features;
    use crate::channel_tx::{
        ChannelConfig, ChannelPartyConfig, CommitmentPartyState, CommitmentState, HolderIdentity,
        Side,
    };
    use bitcoin::OutPoint;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    /// A channel where we, the opener, hold 700k sat and the peer 300k sat.
    fn channel() -> ChannelState {
        let sk = SecretKey::from_slice(&[1; 32]).expect("valid secret key");
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let party = ChannelPartyConfig {
            funding_pubkey: pk,
            payment_basepoint: pk,
            revocation_basepoint: pk,
            delayed_payment_basepoint: pk,
            dust_limit_satoshis: 546,
            to_self_delay: 144,
        };
        let balance = |balance_msat| CommitmentPartyState {
            per_commitment_point: pk,
            balance_msat,
        };
        ChannelState::new(
            ChannelConfig {
                funding_outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 0),
                funding_satoshis: 1_000_000,
                channel_type: Features::from_bits(&[Features::OPTION_ANCHORS]),
                opener: party.clone(),
                acceptor: party,
                minimum_depth: 6,
            },
            HolderIdentity {
                side: Side::Opener,
                funding_privkey: sk,
            },
            CommitmentState {
                commitment_number: 0,
                feerate_per_kw: 253,
                opener: balance(700_000_000),
                acceptor: balance(300_000_000),
            },
            true,
            false,
            false,
        )
    }

    fn proposal(channel: &ChannelState, local_contribution: i64) -> SpliceProposal<'_> {
        SpliceProposal {
            channel,
            local_contribution,
            quiesced: true,
        }
    }

    #[test]
    fn splice_init_on_a_quiescent_channel_within_our_balance_may_be_accepted() {
        let channel = channel();
        assert_eq!(
            splice_init_rejection(&proposal(&channel, -700_000), false),
            None
        );
        assert_eq!(
            splice_init_rejection(&proposal(&channel, 5_000_000), false),
            None
        );
    }

    #[test]
    fn splice_init_must_be_rejected_when_not_quiescent() {
        let channel = channel();
        let proposal = SpliceProposal {
            quiesced: false,
            ..proposal(&channel, 0)
        };
        assert!(splice_init_rejection(&proposal, false).is_some());
    }

    #[test]
    fn splice_init_must_be_rejected_over_an_unlocked_splice() {
        let channel = channel();
        assert!(splice_init_rejection(&proposal(&channel, 0), true).is_some());
    }

    #[test]
    fn splice_init_must_be_rejected_when_taking_out_more_than_our_balance() {
        let channel = channel();
        assert!(splice_init_rejection(&proposal(&channel, -700_001), false).is_some());
    }

    #[test]
    fn splice_rbf_must_be_rejected_after_our_splice_locked() {
        let channel = channel();
        assert_eq!(splice_rbf_rejection(&proposal(&channel, 0), false), None);
        assert!(splice_rbf_rejection(&proposal(&channel, 0), true).is_some());
    }

    fn ack(
        channel: &ChannelState,
        must_reject: Option<&str>,
        remote: i64,
    ) -> Result<(), Violation> {
        SpliceAckOracle.evaluate(&SpliceAckContext {
            channel_id: ChannelId::new([0xab; 32]),
            channel,
            must_reject,
            remote_contribution: remote,
        })
    }

    #[test]
    fn accepting_a_proposal_that_had_to_be_rejected_is_a_violation() {
        let channel = channel();
        assert!(ack(&channel, None, 0).is_ok());
        assert!(matches!(
            ack(&channel, Some("splice_init"), 0),
            Err(Violation::InvalidSpliceAck(..))
        ));
    }

    #[test]
    fn taking_out_more_than_the_peers_balance_is_a_violation() {
        let channel = channel();
        assert!(ack(&channel, None, -300_000).is_ok());
        assert!(matches!(
            ack(&channel, None, -300_001),
            Err(Violation::InvalidSpliceAck(..))
        ));
    }
}
