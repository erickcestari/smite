//! Oracle trait for protocol invariant checks.
//!
//! Oracles evaluate conditions beyond simple crashes.

mod accept_channel;
mod funding_signed;
mod splice_ack;

use super::violation::Violation;
pub use accept_channel::{AcceptChannelContext, AcceptChannelOracle};
pub use funding_signed::{FundingSignedContext, FundingSignedOracle};
pub use splice_ack::{
    SpliceAckContext, SpliceAckOracle, SpliceProposal, splice_init_rejection, splice_rbf_rejection,
};

/// `Oracle` evaluates a condition against some context
pub trait Oracle<C> {
    /// Evaluate the oracle against the given context
    ///
    /// # Errors
    ///
    /// Returns `Violation` if an oracle invariant is violated.
    fn evaluate(&self, context: &C) -> Result<(), Violation>;
}
