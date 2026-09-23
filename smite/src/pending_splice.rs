//! BOLT 2 splice negotiation state.
//!
//! A splice replaces a live channel's funding transaction through the same
//! interactive construction a v2 open uses, so it shares the open's attempt
//! chain. [`Negotiations`] routes a channel's interactive construction messages
//! to its splice once one starts.

use std::collections::HashMap;

use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};

use crate::bolt::{ChannelId, SpliceAck, SpliceInit};
use crate::channel_tx::build_funding_witness_script;
use crate::pending_channel::{
    FundingAttempt, FundingAttempts, FundingNegotiation, PendingChannelV2, V2Negotiations,
};

/// The channel funding output a splice spends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorFunding {
    /// Its outpoint.
    pub outpoint: OutPoint,
    /// Its value.
    pub satoshis: u64,
    /// The 2-of-2 script both peers' previous funding pubkeys lock it to.
    pub witness_script: ScriptBuf,
}

impl PriorFunding {
    /// The output it names.
    #[must_use]
    pub fn txout(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.satoshis),
            script_pubkey: self.witness_script.to_p2wsh(),
        }
    }
}

/// A splice of a live channel, from the `splice_init` we sent.
pub struct PendingSplice {
    /// The `splice_init` that started it.
    pub splice_init: SpliceInit,
    /// The peer's `splice_ack`, once it accepts.
    pub splice_ack: Option<SpliceAck>,
    /// The funding output the splice transaction spends.
    pub prior: PriorFunding,
    attempts: FundingAttempts,
}

impl PendingSplice {
    /// Starts a splice from the `splice_init` we sent, whose first attempt
    /// awaits the peer's `splice_ack` the way an RBF attempt awaits
    /// `tx_ack_rbf`.
    #[must_use]
    pub fn new(splice_init: SpliceInit, prior: PriorFunding) -> Self {
        let mut first = FundingAttempt::new(
            splice_init.locktime,
            splice_init.funding_feerate_perkw,
            splice_init.funding_contribution_satoshis,
        );
        first.ack_pending = true;
        Self {
            splice_init,
            splice_ack: None,
            prior,
            attempts: FundingAttempts::new(first),
        }
    }

    /// Records the peer's `splice_ack` and its contribution.
    ///
    /// Returns `false`, recording nothing, when our `splice_init` was already
    /// answered.
    pub fn record_ack(&mut self, splice_ack: &SpliceAck) -> bool {
        if self.splice_ack.is_some() {
            return false;
        }
        let first = self.attempts.first_mut();
        first.ack_pending = false;
        first.remote_contribution = splice_ack.funding_contribution_satoshis;
        self.splice_ack = Some(splice_ack.clone());
        true
    }
}

impl FundingNegotiation for PendingSplice {
    fn funding_attempts(&self) -> &FundingAttempts {
        &self.attempts
    }

    fn funding_attempts_mut(&mut self) -> &mut FundingAttempts {
        &mut self.attempts
    }

    fn prior_capacity(&self) -> u64 {
        self.prior.satoshis
    }

    /// Known once `splice_ack` reveals the peer's new funding pubkey.
    fn funding_script(&self) -> Option<ScriptBuf> {
        let ack = self.splice_ack.as_ref()?;
        Some(
            build_funding_witness_script(&self.splice_init.funding_pubkey, &ack.funding_pubkey)
                .to_p2wsh(),
        )
    }

    fn is_accepted(&self) -> bool {
        self.splice_ack.is_some()
    }

    fn record_ack_rbf(&mut self, remote_contribution: i64) -> bool {
        self.attempts.record_ack_rbf(remote_contribution)
    }
}

/// Every funding negotiation in flight: v2 opens, and splices of live
/// channels.
///
/// A splice keeps its channel's `channel_id`, so once one starts, a message
/// naming that id belongs to the splice rather than to the open that funded
/// the channel.
#[derive(Default)]
pub struct Negotiations {
    /// Channel establishment v2 negotiations.
    pub opens: V2Negotiations,
    /// The latest splice of each channel.
    pub splices: HashMap<ChannelId, PendingSplice>,
}

impl Negotiations {
    /// The negotiation building `channel_id`'s funding transaction: its
    /// splice, else its v2 open, by either of the open's ids.
    #[must_use]
    pub fn get(&self, channel_id: ChannelId) -> Option<&dyn FundingNegotiation> {
        match self.splices.get(&channel_id) {
            Some(splice) => Some(splice),
            None => self
                .opens
                .get(channel_id)
                .map(|open| open as &dyn FundingNegotiation),
        }
    }

    /// Mutable sibling of [`Self::get`].
    pub fn get_mut(&mut self, channel_id: ChannelId) -> Option<&mut dyn FundingNegotiation> {
        match self.splices.get_mut(&channel_id) {
            Some(splice) => Some(splice),
            None => self
                .opens
                .get_mut(channel_id)
                .map(|open| open as &mut dyn FundingNegotiation),
        }
    }

    /// Every attempt of every negotiation, in no particular order.
    pub fn all_attempts(&self) -> impl Iterator<Item = &FundingAttempt> {
        let opens = self
            .opens
            .iter()
            .flat_map(|open: &PendingChannelV2| open.funding_attempts().all());
        let splices = self
            .splices
            .values()
            .flat_map(|splice| splice.funding_attempts().all());
        opens.chain(splices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::{SpliceAckTlvs, SpliceInitTlvs};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn pubkey(byte: u8) -> PublicKey {
        let sk = SecretKey::from_slice(&[byte; 32]).expect("valid secret key");
        PublicKey::from_secret_key(&Secp256k1::new(), &sk)
    }

    fn splice(contribution: i64) -> PendingSplice {
        PendingSplice::new(
            SpliceInit {
                channel_id: ChannelId::new([0xab; 32]),
                funding_contribution_satoshis: contribution,
                funding_feerate_perkw: 1_000,
                locktime: 0,
                funding_pubkey: pubkey(1),
                tlvs: SpliceInitTlvs::default(),
            },
            PriorFunding {
                outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 0),
                satoshis: 1_000_000,
                witness_script: build_funding_witness_script(&pubkey(3), &pubkey(4)),
            },
        )
    }

    fn splice_ack(contribution: i64) -> SpliceAck {
        SpliceAck {
            channel_id: ChannelId::new([0xab; 32]),
            funding_contribution_satoshis: contribution,
            funding_pubkey: pubkey(2),
            tlvs: SpliceAckTlvs::default(),
        }
    }

    #[test]
    fn splice_awaits_the_peers_splice_ack() {
        let mut splice = splice(-100_000);
        assert!(splice.expects_reply());
        assert!(!splice.is_accepted());
        assert_eq!(splice.funding_script(), None);

        assert!(splice.record_ack(&splice_ack(20_000)));

        assert!(!splice.expects_reply());
        assert!(splice.is_accepted());
        assert_eq!(
            splice.funding_script(),
            Some(build_funding_witness_script(&pubkey(1), &pubkey(2)).to_p2wsh())
        );
        // The prior capacity with both contributions applied.
        assert_eq!(splice.total_funding_satoshis(), 920_000);
    }

    #[test]
    fn a_second_splice_ack_is_not_recorded() {
        let mut splice = splice(0);
        assert!(splice.record_ack(&splice_ack(20_000)));

        assert!(!splice.record_ack(&splice_ack(50_000)));

        assert_eq!(splice.attempt().remote_contribution, 20_000);
    }

    #[test]
    fn aborting_the_splice_owes_no_reply() {
        let mut splice = splice(0);

        splice.funding_attempts_mut().abort();

        assert!(!splice.expects_reply());
        assert!(splice.attempt().tx_exchange.aborted());
    }

    #[test]
    fn negotiations_route_a_spliced_channel_to_its_splice() {
        let mut negotiations = Negotiations::default();
        let channel_id = ChannelId::new([0xab; 32]);
        assert!(negotiations.get(channel_id).is_none());

        negotiations.splices.insert(channel_id, splice(0));

        assert_eq!(
            negotiations
                .get(channel_id)
                .map(FundingNegotiation::prior_capacity),
            Some(1_000_000)
        );
    }
}
