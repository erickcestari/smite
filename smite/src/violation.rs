//! Target-misbehavior findings.
//!
//! Each [`Violation`] variant names a buggy target behavior (e.g., crashing,
//! hanging, breaking a protocol invariant). This is how the fuzzer reports bugs
//! in the target.
//!
//! Conditions that are *not* the target's fault should be ordinary errors and
//! never a `Violation` (e.g., transport failures, insufficient wallet funds,
//! mutator-produced invalid commitments, undecodable harness input).

use crate::bolt::ChannelId;

/// A detected misbehavior of the target under test.
#[derive(Debug, thiserror::Error)]
pub enum Violation {
    /// The target process died during or after processing the input.
    #[error("target crashed")]
    Crashed,

    /// The target stopped responding to the post-input ping-pong sync.
    #[error("target hung (ping timeout)")]
    Hung,

    /// The target closed the connection during the post-input ping-pong sync
    /// instead of responding.
    #[error("target unexpectedly disconnected")]
    UnexpectedDisconnect,

    /// The target referenced a channel for which no state was ever established.
    /// This covers:
    /// - a `funding_signed` or `channel_ready` for a `channel_id` we never
    ///   opened, or
    /// - an `accept_channel` for a `temporary_channel_id` we never sent
    ///   `open_channel` for.
    #[error("unknown channel: no tracked state for channel_id {0:?}")]
    UnknownChannel(ChannelId),

    /// The target sent a second `accept_channel` for a `temporary_channel_id`
    /// whose in-progress negotiation already has one, i.e. the id was reused
    /// before its negotiation reached `funding_created`.
    #[error(
        "temporary_channel_id reuse: previous negotiation for {0:?} has not yet reached funding_created"
    )]
    TempChannelIdReuse(ChannelId),

    /// The target sent `funding_signed` even though the opener cannot afford the
    /// commitment feerate.
    #[error("opener cannot afford commitment fee for channel_id {0:?}")]
    OpenerCannotAffordFee(ChannelId),

    /// The target's `funding_signed` signature failed to verify against the
    /// holder's initial commitment transaction.
    #[error("invalid counterparty signature for channel_id {0:?}")]
    InvalidCounterpartySignature(ChannelId),
}
