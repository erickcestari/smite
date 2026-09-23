//! BOLT 2 channel negotiation state.
//!
//! Remembers the `open_channel`/`accept_channel` parameters of each channel
//! being established, so later steps can build commitments from them.

use std::collections::HashMap;

use bitcoin::{ScriptBuf, Witness};

use crate::bolt::{
    AcceptChannel, AcceptChannel2, ChannelId, OpenChannel, OpenChannel2, TemporaryChannelId,
};
use crate::channel_tx::{Contributor, TxExchange, build_funding_witness_script};

/// Negotiation parameters for a channel being established.
///
/// Contains the initiating peer's `open_channel` message, the corresponding
/// `accept_channel` once received, and whether a `funding_created` has already
/// been built from this negotiation.
pub struct PendingChannel {
    pub open_channel: OpenChannel,
    pub accept_channel: Option<AcceptChannel>,
    pub funding_built: bool,
}

/// Negotiation parameters for a channel being established with the v2
/// (dual-funded) protocol.
///
/// Keyed by `temporary_channel_id` while the negotiation is in flight. Unlike
/// v1, the real `channel_id` does not depend on the funding transaction: it is
/// derived from both peers' revocation basepoints and so becomes known as soon
/// as `accept_channel2` arrives.
pub struct PendingChannelV2 {
    pub open_channel2: OpenChannel2,
    pub accept_channel2: Option<AcceptChannel2>,
    /// The v2 `channel_id`, known once `accept_channel2` reveals the peer's
    /// revocation basepoint.
    pub channel_id: Option<ChannelId>,
    /// The attempt `open_channel2` and `accept_channel2` started, then those
    /// started by RBF.
    attempts: FundingAttempts,
}

/// One attempt at building and signing the funding transaction.
pub struct FundingAttempt {
    /// The interactive transaction exchange and the transaction it builds.
    pub tx_exchange: TxExchange,
    /// Progress through the commitment and signature exchange that follows it.
    pub commitment_exchange: CommitmentExchange,
    /// Witnesses from the peer's `tx_signatures`
    pub peer_witnesses: Vec<Witness>,
    /// Feerate the funding transaction pays, in satoshis per kilo-weight.
    pub feerate_perkw: u32,
    /// What we add to our channel balance, negative when we take funds out.
    pub local_contribution: i64,
    /// What the peer adds to its channel balance; 0 until it says.
    pub remote_contribution: i64,
    /// Whether our `tx_init_rbf` still awaits the peer's `tx_ack_rbf`.
    pub ack_pending: bool,
}

impl FundingAttempt {
    /// Starts an attempt whose transaction has the given `nLockTime`.
    #[must_use]
    pub fn new(locktime: u32, feerate_perkw: u32, local_contribution: i64) -> Self {
        Self {
            tx_exchange: TxExchange::new(locktime),
            commitment_exchange: CommitmentExchange::default(),
            peer_witnesses: Vec::new(),
            feerate_perkw,
            local_contribution,
            remote_contribution: 0,
            ack_pending: false,
        }
    }

    /// Value of the funding output this attempt builds, per BOLT 2: the
    /// `prior_capacity` it replaces (0 for an open) with both contributions
    /// applied.
    #[must_use]
    pub fn funding_output_value(&self, prior_capacity: u64) -> u64 {
        clamp_sat(
            i128::from(prior_capacity)
                + i128::from(self.local_contribution)
                + i128::from(self.remote_contribution),
        )
    }

    /// What our inputs leave once they cover our part of the funding output,
    /// `prior_capacity` plus our contribution, and our `fee`: the value of our
    /// change output.
    ///
    /// For a splice our inputs include the previous funding output, worth
    /// `prior_capacity`, so a splice-out leaves the amount taken out.
    #[must_use]
    pub fn local_change_value(&self, prior_capacity: u64, fee: u64) -> u64 {
        let inputs = self
            .tx_exchange
            .shared_tx()
            .contributed_input_value(Contributor::Local);
        clamp_sat(
            i128::from(inputs)
                - i128::from(prior_capacity)
                - i128::from(self.local_contribution)
                - i128::from(fee),
        )
    }
}

/// Clamps a satoshi amount into `u64`: a mutated contribution yields a zero or
/// maximal output the peer rejects, rather than a wrapped one.
fn clamp_sat(sats: i128) -> u64 {
    u64::try_from(sats.max(0)).unwrap_or(u64::MAX)
}

/// The attempts at one funding transaction: the one its negotiation started,
/// then those RBF started.
pub struct FundingAttempts {
    /// The attempt the negotiation's opening messages started.
    first: FundingAttempt,
    /// Attempts started by RBF, oldest first.
    rbf: Vec<FundingAttempt>,
}

impl FundingAttempts {
    /// Starts with the negotiation's own attempt.
    #[must_use]
    pub fn new(first: FundingAttempt) -> Self {
        Self {
            first,
            rbf: Vec::new(),
        }
    }

    /// Mutable access to the attempt the negotiation's opening messages
    /// started, which a late reply to them still parameterizes.
    pub fn first_mut(&mut self) -> &mut FundingAttempt {
        &mut self.first
    }

    /// The latest attempt.
    #[must_use]
    pub fn latest(&self) -> &FundingAttempt {
        self.rbf.last().unwrap_or(&self.first)
    }

    /// Mutable sibling of [`Self::latest`].
    pub fn latest_mut(&mut self) -> &mut FundingAttempt {
        self.rbf.last_mut().unwrap_or(&mut self.first)
    }

    /// The attempt before the latest, which an RBF attempt must share an
    /// input with. `None` until RBF starts one.
    #[must_use]
    pub fn previous(&self) -> Option<&FundingAttempt> {
        match self.rbf.len() {
            0 => None,
            1 => Some(&self.first),
            n => self.rbf.get(n - 2),
        }
    }

    /// Every attempt, oldest first.
    pub fn all(&self) -> impl Iterator<Item = &FundingAttempt> {
        std::iter::once(&self.first).chain(&self.rbf)
    }

    /// Whether the latest attempt was started by RBF.
    #[must_use]
    pub fn in_rbf(&self) -> bool {
        !self.rbf.is_empty()
    }

    /// Whether the peer owes us a reply in the latest attempt: its
    /// `tx_ack_rbf`, then one per interactive transaction message.
    #[must_use]
    pub fn expects_reply(&self) -> bool {
        let attempt = self.latest();
        attempt.ack_pending || attempt.tx_exchange.expects_reply()
    }

    /// Records a sent `tx_init_rbf`, starting an attempt that awaits the
    /// peer's `tx_ack_rbf`.
    pub fn start_rbf(&mut self, locktime: u32, feerate_perkw: u32, local_contribution: i64) {
        let mut attempt = FundingAttempt::new(locktime, feerate_perkw, local_contribution);
        attempt.ack_pending = true;
        self.rbf.push(attempt);
    }

    /// Records the peer's `tx_ack_rbf` and its contribution.
    ///
    /// Returns `false`, recording nothing, when no `tx_init_rbf` awaits one.
    pub fn record_ack_rbf(&mut self, remote_contribution: i64) -> bool {
        let attempt = self.latest_mut();
        if !attempt.ack_pending {
            return false;
        }
        attempt.ack_pending = false;
        attempt.remote_contribution = remote_contribution;
        true
    }

    /// Records the peer's `tx_abort`.
    ///
    /// Aborting an RBF attempt abandons only that attempt, per BOLT 2: the
    /// transaction it would have replaced still funds the channel, so it is
    /// the latest attempt again. Aborting the first attempt ends the
    /// negotiation.
    pub fn abort(&mut self) {
        if self.rbf.pop().is_none() {
            self.first.tx_exchange.abort();
        }
    }
}

/// Progress through a two-way exchange of one message type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Exchange {
    /// Whether we have sent ours.
    pub sent: bool,
    /// Whether the peer's has arrived.
    pub received: bool,
}

/// How far the commitment and signature exchange has progressed.
///
/// BOLT 2 gates each half on the other: `tx_signatures` may only be sent once
/// both peers' `commitment_signed`s have been exchanged, and the peer owes us
/// its `tx_signatures` once it has received ours.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommitmentExchange {
    /// Progress through the `commitment_signed` exchange for this funding
    /// transaction. `received` means arrived *and* verified.
    pub commitment_signed: Exchange,
    /// Progress through the `tx_signatures` exchange.
    pub tx_signatures: Exchange,
}

impl PendingChannelV2 {
    /// Starts a negotiation from the `open_channel2` we sent, whose first
    /// attempt takes its `nLockTime`, feerate and contribution from it.
    #[must_use]
    pub fn new(open_channel2: OpenChannel2) -> Self {
        let first_attempt = FundingAttempt::new(
            open_channel2.locktime,
            open_channel2.funding_feerate_perkw,
            i64::try_from(open_channel2.funding_satoshis).unwrap_or(i64::MAX),
        );
        Self {
            open_channel2,
            accept_channel2: None,
            channel_id: None,
            attempts: FundingAttempts::new(first_attempt),
        }
    }

    /// The attempts at the funding transaction.
    #[must_use]
    pub fn funding_attempts(&self) -> &FundingAttempts {
        &self.attempts
    }

    /// Mutable sibling of [`Self::funding_attempts`].
    pub fn funding_attempts_mut(&mut self) -> &mut FundingAttempts {
        &mut self.attempts
    }

    /// The latest attempt at the funding transaction.
    #[must_use]
    pub fn attempt(&self) -> &FundingAttempt {
        self.attempts.latest()
    }

    /// Mutable sibling of [`Self::attempt`].
    pub fn attempt_mut(&mut self) -> &mut FundingAttempt {
        self.attempts.latest_mut()
    }

    /// Whether the peer owes us a reply in the latest attempt.
    #[must_use]
    pub fn expects_reply(&self) -> bool {
        self.attempts.expects_reply()
    }

    /// Records the peer's `tx_ack_rbf` and its contribution, read as nothing
    /// when negative: an open has no channel balance to take funds out of.
    ///
    /// Returns `false`, recording nothing, when no `tx_init_rbf` awaits one.
    pub fn record_ack_rbf(&mut self, remote_contribution: i64) -> bool {
        self.attempts.record_ack_rbf(remote_contribution.max(0))
    }

    /// The funding output's `scriptPubKey`, once `accept_channel2` has
    /// revealed the peer's funding pubkey.
    #[must_use]
    pub fn funding_script(&self) -> Option<ScriptBuf> {
        let accept = self.accept_channel2.as_ref()?;
        Some(
            build_funding_witness_script(
                &self.open_channel2.funding_pubkey,
                &accept.funding_pubkey,
            )
            .to_p2wsh(),
        )
    }

    /// Funding output value of the latest attempt: the sum of both peers'
    /// contributions, per BOLT 2.
    #[must_use]
    pub fn total_funding_satoshis(&self) -> u64 {
        self.attempt().funding_output_value(0)
    }
}

/// Every channel establishment v2 negotiation in flight, addressable by either
/// of the two ids a message can carry.
///
/// BOLT 2 changes the id mid-negotiation: `open_channel2` and `accept_channel2`
/// carry a `temporary_channel_id`, everything after carries the `channel_id`
/// derived from both peers' revocation basepoints. Negotiations are keyed by
/// the temporary id, which is stable for the whole negotiation, and a second
/// map redirects the derived id onto it. Owning both together is what keeps
/// that redirection from outliving the negotiation it was built for.
#[derive(Default)]
pub struct V2Negotiations {
    by_temporary_id: HashMap<TemporaryChannelId, PendingChannelV2>,
    temporary_ids: HashMap<ChannelId, TemporaryChannelId>,
}

impl V2Negotiations {
    /// The `temporary_channel_id` keying the negotiation `channel_id` names,
    /// whichever of the two ids it is.
    fn key(&self, channel_id: ChannelId) -> Option<TemporaryChannelId> {
        if self.by_temporary_id.contains_key(&channel_id) {
            Some(channel_id)
        } else {
            self.temporary_ids.get(&channel_id).copied()
        }
    }

    /// The negotiation `channel_id` names, by either id.
    ///
    /// Returns `None` when neither matches, which is what a mutated program
    /// that dropped its `open_channel2`, or pointed a message at an unrelated
    /// channel, looks like.
    #[must_use]
    pub fn get(&self, channel_id: ChannelId) -> Option<&PendingChannelV2> {
        self.by_temporary_id.get(&self.key(channel_id)?)
    }

    /// Mutable sibling of [`Self::get`].
    pub fn get_mut(&mut self, channel_id: ChannelId) -> Option<&mut PendingChannelV2> {
        let key = self.key(channel_id)?;
        self.by_temporary_id.get_mut(&key)
    }

    /// Every negotiation in flight, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &PendingChannelV2> {
        self.by_temporary_id.values()
    }

    /// Records a sent `open_channel2`, starting a negotiation keyed by its
    /// `temporary_channel_id`.
    ///
    /// A repeated `temporary_channel_id` starts a fresh negotiation, discarding
    /// the previous one: unlike v1 there is no `funding_created` marking the
    /// point of no return, and the id only has to stay unique until
    /// `accept_channel2` arrives. Any `channel_id` the discarded negotiation
    /// had derived is forgotten with it, so a message still naming the old one
    /// does not land on the new negotiation.
    pub fn record_open(&mut self, open_channel2: &OpenChannel2) {
        let temporary_channel_id = open_channel2.temporary_channel_id;
        self.temporary_ids
            .retain(|_, keyed_by| *keyed_by != temporary_channel_id);
        self.by_temporary_id.insert(
            temporary_channel_id,
            PendingChannelV2::new(open_channel2.clone()),
        );
    }

    /// Pairs a received `accept_channel2` with the recorded `open_channel2` of
    /// the same `temporary_channel_id`, and derives the v2 `channel_id` that
    /// every subsequent message carries.
    ///
    /// An `accept_channel2` for an unknown `temporary_channel_id` is ignored
    /// rather than fatal: a mutated program may have dropped the
    /// `open_channel2` that would have recorded it, and the message still
    /// decodes fine.
    pub fn record_accept(&mut self, accept_channel2: &AcceptChannel2) {
        let temporary_channel_id = accept_channel2.temporary_channel_id;
        let Some(pending) = self.by_temporary_id.get_mut(&temporary_channel_id) else {
            log::debug!(
                "accept_channel2 for unknown temporary_channel_id {temporary_channel_id}, ignoring",
            );
            return;
        };

        let channel_id = ChannelId::v2_from_revocation_basepoints(
            &pending.open_channel2.revocation_basepoint,
            &accept_channel2.revocation_basepoint,
        );
        pending.accept_channel2 = Some(accept_channel2.clone());
        pending.channel_id = Some(channel_id);
        pending.attempts.first_mut().remote_contribution =
            i64::try_from(accept_channel2.funding_satoshis).unwrap_or(i64::MAX);
        self.temporary_ids.insert(channel_id, temporary_channel_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_tx::{SharedInput, Step};
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, TxOut, Txid};

    /// An attempt contributing `local` and `remote`, whose local inputs are
    /// worth `input_value`.
    fn attempt(local: i64, remote: i64, input_value: u64) -> FundingAttempt {
        let mut attempt = FundingAttempt::new(0, 253, local);
        attempt.remote_contribution = remote;
        attempt.tx_exchange.send(Step::AddInput {
            serial_id: 2,
            input: SharedInput {
                outpoint: OutPoint::new(Txid::all_zeros(), 0),
                sequence: 0xffff_fffd,
                contributor: Contributor::Local,
                prevout: Some(TxOut {
                    value: Amount::from_sat(input_value),
                    script_pubkey: ScriptBuf::new(),
                }),
                shared: false,
            },
        });
        attempt
    }

    #[test]
    fn funding_output_value_applies_both_contributions_to_the_prior_capacity() {
        assert_eq!(attempt(200_000, 0, 0).funding_output_value(0), 200_000);
        assert_eq!(
            attempt(200_000, -50_000, 0).funding_output_value(1_000_000),
            1_150_000
        );
    }

    #[test]
    fn funding_output_value_clamps_rather_than_wrapping() {
        assert_eq!(attempt(-2_000_000, 0, 0).funding_output_value(1_000_000), 0);
        assert_eq!(
            attempt(i64::MAX, i64::MAX, 0).funding_output_value(u64::MAX),
            u64::MAX
        );
    }

    #[test]
    fn local_change_value_is_what_our_inputs_leave() {
        // An open: 300k of inputs fund 200k and a 1k fee.
        assert_eq!(
            attempt(200_000, 0, 300_000).local_change_value(0, 1_000),
            99_000
        );
        // A splice-out: the previous funding output is our only input, and
        // the 100k taken out of the channel comes back as change.
        assert_eq!(
            attempt(-100_000, 0, 1_000_000).local_change_value(1_000_000, 1_000),
            99_000
        );
        // Under-funded: nothing left rather than a wrapped amount.
        assert_eq!(attempt(200_000, 0, 100_000).local_change_value(0, 1_000), 0);
    }

    #[test]
    fn abort_of_an_rbf_attempt_restores_the_replaced_one() {
        let mut attempts = FundingAttempts::new(FundingAttempt::new(0, 253, 100_000));
        attempts.start_rbf(0, 300, 150_000);
        assert!(attempts.in_rbf());

        attempts.abort();

        assert!(!attempts.in_rbf());
        assert_eq!(attempts.latest().local_contribution, 100_000);
        assert!(!attempts.latest().tx_exchange.aborted());
    }

    #[test]
    fn abort_of_the_first_attempt_ends_the_negotiation() {
        let mut attempts = FundingAttempts::new(FundingAttempt::new(0, 253, 100_000));

        attempts.abort();

        assert!(attempts.latest().tx_exchange.aborted());
    }
}
