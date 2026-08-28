//! BOLT 2 channel negotiation state.
//!
//! Remembers the `open_channel`/`accept_channel` parameters of each channel
//! being established, so later steps can build commitments from them.

use std::collections::HashMap;

use crate::bolt::{
    AcceptChannel, AcceptChannel2, ChannelId, OpenChannel, OpenChannel2, TemporaryChannelId,
};

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
}

impl PendingChannelV2 {
    /// Starts a negotiation from the `open_channel2` we sent.
    #[must_use]
    pub fn new(open_channel2: OpenChannel2) -> Self {
        Self {
            open_channel2,
            accept_channel2: None,
            channel_id: None,
        }
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
        self.temporary_ids.insert(channel_id, temporary_channel_id);
    }
}
