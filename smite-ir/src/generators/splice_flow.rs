//! Generators for splicing a channel they open first.

use rand::{Rng, RngExt};

use super::Generator;
use super::dual_funding_flow::append_dual_funding_flow;
use super::funding_flow::append_funding_flow;
use super::interactive_tx::{
    RBF_DELAY_BLOCKS, SEQUENCE, SessionVars, construct_transaction, min_rbf_feerate,
    previous_input, send_turn, sign_and_broadcast, wallet_input,
};
use crate::builder::ProgramBuilder;
use crate::operation::ShutdownScriptVariant;
use crate::{Operation, VariableType};

/// `serial_id` of the shared input: even, as BOLT 2 requires of the
/// initiator, and clear of the ids wallet inputs take.
const SHARED_INPUT_SERIAL_ID: u64 = 0;

/// Most we take out of the channel, small enough that our balance still
/// covers the reserve and commitment fees of the smallest channel the open
/// flows fund.
const MAX_SPLICE_OUT: i64 = 50_000;

/// Generates a splice of a channel opened with the v1 flow.
///
/// Emits instructions to:
/// 1. Open a channel through `channel_ready`
/// 2. Quiesce it with `stfu`, then send `splice_init`, splicing funds in or
///    out, and receive `splice_ack`
/// 3. Contribute the shared input, wallet inputs when splicing in, the new
///    funding output and a change output through interactive transaction
///    construction, concluding with `tx_complete`
/// 4. Exchange `commitment_signed` and `tx_signatures`, and broadcast the
///    splice transaction
/// 5. Sometimes replace a splice-in through RBF, quiescing again first
/// 6. Confirm the splice transaction and exchange `splice_locked`
#[derive(Clone, Copy)]
pub struct SpliceFlowGenerator;

impl Generator for SpliceFlowGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let channel_id = append_funding_flow(builder, rng);
        append_splice(builder, rng, channel_id);
    }
}

/// [`SpliceFlowGenerator`] for a channel opened with the v2 (dual-funded)
/// flow.
#[derive(Clone, Copy)]
pub struct DualFundedSpliceFlowGenerator;

impl Generator for DualFundedSpliceFlowGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let channel_id = append_dual_funding_flow(builder, rng);
        append_splice(builder, rng, channel_id);
    }
}

/// Emits a splice of the live channel `channel_id`, through `splice_locked`.
fn append_splice(builder: &mut ProgramBuilder, rng: &mut impl Rng, channel_id: usize) {
    quiesce(builder, channel_id);

    let splice_in: bool = rng.random();
    let contribution = if splice_in {
        rng.random_range(10_000..=1_000_000)
    } else {
        -rng.random_range(1_000..=MAX_SPLICE_OUT)
    };
    let contribution_var = builder.append(Operation::LoadContribution(contribution), &[]);
    let mut feerate = rng.random_range(253..=2_000);
    let feerate_perkw = builder.append(Operation::LoadFeeratePerKw(feerate), &[]);
    let locktime = builder.append(Operation::LoadBlockHeight(0), &[]);
    // BOLT 2 recommends a fresh funding key for each splice.
    let funding_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
    let funding_pubkey = builder.append(Operation::DerivePoint, &[funding_privkey]);
    send_turn(
        builder,
        Operation::SendSpliceInit {
            require_confirmed_inputs: rng.random_range(0..8) == 0,
        },
        &[
            channel_id,
            contribution_var,
            feerate_perkw,
            locktime,
            funding_pubkey,
        ],
    );

    // The funding and change roles derive their value and script from the
    // splice; these only matter once a mutator switches a role to `Explicit`.
    let amount = builder.append(Operation::LoadAmount(contribution.unsigned_abs()), &[]);
    let session = SessionVars {
        channel_id,
        funding_satoshis: amount,
        upfront_shutdown_script: builder.append(
            Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
            &[],
        ),
    };
    let num_inputs = if splice_in {
        rng.random_range(1u8..=2)
    } else {
        0
    };
    let inputs: Vec<Operation> = std::iter::once(shared_input())
        .chain((0..num_inputs).map(wallet_input))
        .collect();
    construct_transaction(builder, rng, &inputs, session);
    let mut signed = sign_and_broadcast(builder, channel_id, funding_privkey);

    // `tx_init_rbf` carries an unsigned contribution, so only a splice-in
    // keeps its amount when replaced.
    if splice_in && rng.random_range(0..4) == 0 {
        feerate = min_rbf_feerate(feerate) + rng.random_range(0..=500);
        builder.append(Operation::MineEmptyBlocks(RBF_DELAY_BLOCKS), &[]);
        // Quiescence ended with the splice's tx_signatures.
        quiesce(builder, channel_id);
        let rbf_feerate = builder.append(Operation::LoadFeeratePerKw(feerate), &[]);
        send_turn(
            builder,
            Operation::SendTxInitRbf {
                require_confirmed_inputs: rng.random_range(0..8) == 0,
            },
            &[channel_id, locktime, rbf_feerate, amount],
        );
        // Every attempt spends the previous funding output, so they all
        // double-spend each other; re-adding our wallet inputs keeps the fee
        // strictly higher.
        let inputs: Vec<Operation> = std::iter::once(shared_input())
            .chain((0..num_inputs).map(previous_input))
            .collect();
        construct_transaction(builder, rng, &inputs, session);
        signed = sign_and_broadcast(builder, channel_id, funding_privkey);
    }

    builder.append(Operation::MineBlocks(rng.random_range(1..=16)), &[]);
    builder.append(
        Operation::SendSpliceLocked,
        &[channel_id, signed.funding_transaction],
    );
    builder.append(Operation::RecvSpliceLocked, &[channel_id]);
}

/// Quiesces `channel_id`, which splicing and its RBF require.
fn quiesce(builder: &mut ProgramBuilder, channel_id: usize) {
    let sent = builder.append(Operation::SendStfu { initiator: true }, &[channel_id]);
    builder.append(Operation::RecvStfu, &[sent]);
}

/// The `tx_add_input` spending the channel's current funding output.
fn shared_input() -> Operation {
    Operation::SendTxAddSharedInput {
        serial_id: SHARED_INPUT_SERIAL_ID,
        sequence: SEQUENCE,
    }
}
