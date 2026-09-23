//! Interactive transaction construction steps shared by the generators that
//! build a funding transaction with it: the v2 open and splicing.

use rand::{Rng, RngExt};

use crate::Operation;
use crate::builder::ProgramBuilder;
use crate::operation::TxOutputRole;

/// `serial_id` of the funding output we contribute. BOLT 2 requires the
/// initiator to use even ids; picking these from a high range keeps them clear
/// of the ones assigned to inputs.
const FUNDING_OUTPUT_SERIAL_ID: u64 = 2000;

/// `serial_id` of our change output.
const CHANGE_OUTPUT_SERIAL_ID: u64 = 2002;

/// `serial_id` of an input we add only to remove it again.
const DECOY_INPUT_SERIAL_ID: u64 = 1000;

/// `serial_id` of an output we add only to remove it again.
const DECOY_OUTPUT_SERIAL_ID: u64 = 2004;

/// Blocks that must pass after an attempt is signed before Eclair accepts
/// `tx_init_rbf` replacing it (its `attempt-delta-blocks`).
pub(super) const RBF_DELAY_BLOCKS: u8 = 3;

/// `nSequence` for the inputs we contribute. BOLT 2 caps it at `0xfffffffd` so
/// every input signals replaceability, and recommends one shared value across
/// implementations to avoid fingerprinting.
const SEQUENCE: u32 = 0xffff_fffd;

/// The `index`th input we contribute from the wallet.
pub(super) fn wallet_input(index: u8) -> Operation {
    Operation::SendTxAddInput {
        serial_id: input_serial_id(index),
        utxo_index: index,
        sequence: SEQUENCE,
    }
}

/// The `index`th input we contribute by re-adding one of the attempt being
/// replaced.
pub(super) fn previous_input(index: u8) -> Operation {
    Operation::SendTxAddPreviousInput {
        serial_id: input_serial_id(index),
        input_index: index,
        sequence: SEQUENCE,
    }
}

/// Even ids, as BOLT 2 requires of the initiator.
fn input_serial_id(index: u8) -> u64 {
    2 * (u64::from(index) + 1)
}

/// The lowest feerate BOLT 2 lets `tx_init_rbf` propose after `previous`:
/// 25/24 of it, rounded down, and at least 25 sat/kw more.
pub(super) fn min_rbf_feerate(previous: u32) -> u32 {
    (previous.saturating_mul(25) / 24).max(previous.saturating_add(25))
}

/// Exchanges `commitment_signed` and `tx_signatures` over the transaction the
/// session on `channel_id` built, then broadcasts it. Returns the
/// `channel_id` the peer's `commitment_signed` carries.
pub(super) fn sign_and_broadcast(
    builder: &mut ProgramBuilder,
    channel_id: usize,
    funding_privkey: usize,
) -> usize {
    let funding_transaction = builder.append(Operation::BuildFundingTransactionV2, &[channel_id]);
    let sent_commitment_signed = builder.append(
        Operation::SendCommitmentSigned,
        &[funding_transaction, funding_privkey, channel_id],
    );
    let funded_channel_id =
        builder.append(Operation::RecvCommitmentSigned, &[sent_commitment_signed]);

    // We contribute every input, so BOLT 2 has the peer send its
    // tx_signatures first.
    builder.append(Operation::RecvTxSignatures, &[channel_id]);
    builder.append(
        Operation::SendTxSignatures,
        &[channel_id, funding_transaction],
    );
    builder.append(Operation::RecvTxSignatures, &[channel_id]);

    builder.append(Operation::BroadcastTransaction, &[funding_transaction]);
    funded_channel_id
}

/// The variables an interactive transaction construction session draws on.
#[derive(Clone, Copy)]
pub(super) struct SessionVars {
    pub channel_id: usize,
    pub funding_satoshis: usize,
    pub upfront_shutdown_script: usize,
}

/// Emits one interactive transaction construction session: `inputs`, the
/// funding and change outputs, then `tx_complete`.
///
/// Sometimes also adds a decoy input or output and removes it again, which is
/// the only way `tx_remove_input` and `tx_remove_output` reach the peer. Both
/// are gone before the change output, whose value is computed from the
/// transaction as it stands when it is sent.
pub(super) fn construct_transaction(
    builder: &mut ProgramBuilder,
    rng: &mut impl Rng,
    inputs: &[Operation],
    session: SessionVars,
) {
    let channel_id = session.channel_id;
    // `SendTxAddOutput` takes the value and script alongside the channel.
    let output_inputs = [
        channel_id,
        session.funding_satoshis,
        session.upfront_shutdown_script,
    ];
    for input in inputs {
        send_turn(builder, input.clone(), &[channel_id]);
    }

    if rng.random_range(0..4) == 0 {
        send_turn(
            builder,
            Operation::SendTxAddInput {
                serial_id: DECOY_INPUT_SERIAL_ID,
                utxo_index: u8::try_from(inputs.len()).unwrap_or(u8::MAX),
                sequence: SEQUENCE,
            },
            &[channel_id],
        );
        send_turn(
            builder,
            Operation::SendTxRemoveInput {
                serial_id: DECOY_INPUT_SERIAL_ID,
            },
            &[channel_id],
        );
    }

    // The opener must contribute the funding output, and pays its fees. The
    // value and script inputs are derived from the negotiation for both
    // roles here; they matter only once a mutator switches the role to
    // `Explicit`.
    send_turn(
        builder,
        Operation::SendTxAddOutput {
            serial_id: FUNDING_OUTPUT_SERIAL_ID,
            role: TxOutputRole::Funding,
        },
        &output_inputs,
    );

    if rng.random_range(0..4) == 0 {
        send_turn(
            builder,
            Operation::SendTxAddOutput {
                serial_id: DECOY_OUTPUT_SERIAL_ID,
                role: TxOutputRole::Change,
            },
            &output_inputs,
        );
        send_turn(
            builder,
            Operation::SendTxRemoveOutput {
                serial_id: DECOY_OUTPUT_SERIAL_ID,
            },
            &[channel_id],
        );
    }

    send_turn(
        builder,
        Operation::SendTxAddOutput {
            serial_id: CHANGE_OUTPUT_SERIAL_ID,
            role: TxOutputRole::Change,
        },
        &output_inputs,
    );

    // The exchange ends once both sides have sent `tx_complete` back to back.
    // If the peer already sent one, ours ends it and nothing more arrives. If
    // the peer contributed instead, it still has to answer ours with its own
    // `tx_complete`. The executor tells the two cases apart at runtime, so
    // this receive reads only when a reply is owed.
    send_turn(builder, Operation::SendTxComplete, &[channel_id]);
}

/// Appends a send followed by the receive of the peer's reply. The protocol is
/// turn-based, so every message we send earns one.
pub(super) fn send_turn(builder: &mut ProgramBuilder, operation: Operation, inputs: &[usize]) {
    let sent = builder.append(operation, inputs);
    builder.append(Operation::RecvInteractiveTx, &[sent]);
}
