//! Generator for the complete channel establishment v2 (dual-funded) flow.

use rand::seq::IndexedRandom;
use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::operation::{AcceptChannel2Field, ShutdownScriptVariant, TxOutputRole};
use crate::{Operation, VariableType};
use smite::bolt::ChannelTypeVariant;

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
const RBF_DELAY_BLOCKS: u8 = 3;

/// `nSequence` for the inputs we contribute. BOLT 2 caps it at `0xfffffffd` so
/// every input signals replaceability, and recommends one shared value across
/// implementations to avoid fingerprinting.
const SEQUENCE: u32 = 0xffff_fffd;

/// Channel types most likely to be accepted, so the flow reaches its later
/// steps often enough to cover them. `LoadChannelType` is mutable, so the
/// mutator still reaches the rest.
const LIKELY_CHANNEL_TYPES: &[ChannelTypeVariant] = &[
    ChannelTypeVariant::Anchors,
    ChannelTypeVariant::StaticRemoteKey,
];

/// Generates the complete channel establishment v2 flow.
///
/// Emits instructions to:
/// 1. Build and send `open_channel2`, then receive `accept_channel2`
/// 2. Contribute inputs, the funding output and a change output through
///    interactive transaction construction, concluding with `tx_complete`;
///    sometimes add a decoy input or output and remove it again
/// 3. Exchange `commitment_signed`, then `tx_signatures`, and broadcast the
///    funding transaction
/// 4. Sometimes replace it through RBF, once or twice, repeating steps 2 and 3
/// 5. Confirm the funding transaction and complete the `channel_ready`
///    exchange
#[derive(Clone, Copy)]
pub struct DualFundingFlowGenerator;

impl Generator for DualFundingFlowGenerator {
    // One linear protocol script, from open_channel2 through channel_ready.
    // Splitting it would scatter a sequence that reads best in wire order.
    #[allow(clippy::too_many_lines)]
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // Keys are generated fresh to ensure they're distinct.
        let funding_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
        let funding_pubkey = builder.append(Operation::DerivePoint, &[funding_privkey]);
        let revocation_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let delayed_payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let htlc_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let first_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);
        let second_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);

        // BOLT 2 derives the v2 temporary_channel_id from our revocation
        // basepoint with a zeroed one standing in for the peer.
        let temporary_channel_id = builder.append(
            Operation::DeriveTemporaryChannelIdV2,
            &[revocation_basepoint],
        );

        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
        let funding_satoshis = builder.append(
            Operation::LoadAmount(rng.random_range(100_000..=1_000_000)),
            &[],
        );
        let funding_feerate = rng.random_range(253..=2_000);
        let funding_feerate_perkw =
            builder.append(Operation::LoadFeeratePerKw(funding_feerate), &[]);
        let commitment_feerate_perkw = builder.append(
            Operation::LoadFeeratePerKw(rng.random_range(253..=5_000)),
            &[],
        );
        let dust_limit_satoshis = builder.append(Operation::LoadAmount(546), &[]);
        let max_htlc_value_in_flight_msat = builder.append(Operation::LoadAmount(100_000_000), &[]);
        let htlc_minimum_msat = builder.append(Operation::LoadAmount(1), &[]);
        let to_self_delay = builder.append(Operation::LoadU16(144), &[]);
        let max_accepted_htlcs = builder.append(Operation::LoadU16(483), &[]);
        let locktime = builder.append(Operation::LoadBlockHeight(0), &[]);
        let channel_flags = builder.append(Operation::LoadU8(u8::from(rng.random::<bool>())), &[]);
        let upfront_shutdown_script = builder.append(
            Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
            &[],
        );
        let channel_type_variant = if rng.random_range(0..4) == 0 {
            *ChannelTypeVariant::ALL
                .choose(rng)
                .expect("ChannelTypeVariant::ALL is non-empty")
        } else {
            *LIKELY_CHANNEL_TYPES
                .choose(rng)
                .expect("LIKELY_CHANNEL_TYPES is non-empty")
        };
        let channel_type = builder.append(Operation::LoadChannelType(channel_type_variant), &[]);

        // Build and send open_channel2.
        let open_channel2_msg = builder.append(
            Operation::BuildOpenChannel2 {
                require_confirmed_inputs: rng.random_range(0..8) == 0,
            },
            &[
                chain_hash,
                temporary_channel_id,
                funding_feerate_perkw,
                commitment_feerate_perkw,
                funding_satoshis,
                dust_limit_satoshis,
                max_htlc_value_in_flight_msat,
                htlc_minimum_msat,
                to_self_delay,
                max_accepted_htlcs,
                locktime,
                funding_pubkey,
                revocation_basepoint,
                payment_basepoint,
                delayed_payment_basepoint,
                htlc_basepoint,
                first_per_commitment_point,
                second_per_commitment_point,
                channel_flags,
                upfront_shutdown_script,
                channel_type,
            ],
        );
        let sent_open_channel2 = builder.append(Operation::SendOpenChannel2, &[open_channel2_msg]);

        // Receive accept_channel2, which reveals the peer's revocation
        // basepoint and so the channel_id every later message carries.
        let accept_channel2 = builder.append(Operation::RecvAcceptChannel2, &[sent_open_channel2]);
        let peer_revocation_basepoint = builder.append(
            Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
            &[accept_channel2],
        );
        let channel_id = builder.append(
            Operation::DeriveChannelIdV2,
            &[revocation_basepoint, peer_revocation_basepoint],
        );

        // Interactive transaction construction.
        let mut num_inputs = rng.random_range(1u8..=3);
        let inputs: Vec<Operation> = (0..num_inputs).map(wallet_input).collect();
        let session = SessionVars {
            channel_id,
            funding_satoshis,
            upfront_shutdown_script,
        };
        construct_transaction(builder, rng, &inputs, session);
        let funded_channel_id = sign_and_broadcast(builder, channel_id, funding_privkey);

        // Fee-bump the funding transaction before it confirms.
        if rng.random() {
            let mut feerate = funding_feerate;
            for _ in 0..rng.random_range(1..=2) {
                feerate = min_rbf_feerate(feerate) + rng.random_range(0..=500);
                // Empty, since a block confirming the funding transaction
                // would end RBF.
                builder.append(Operation::MineEmptyBlocks(RBF_DELAY_BLOCKS), &[]);
                let rbf_feerate = builder.append(Operation::LoadFeeratePerKw(feerate), &[]);
                send_turn(
                    builder,
                    Operation::SendTxInitRbf {
                        require_confirmed_inputs: rng.random_range(0..8) == 0,
                    },
                    &[channel_id, locktime, rbf_feerate, funding_satoshis],
                );

                // Re-adding every input of the attempt being replaced keeps
                // the first coin in every attempt, and at no less weight and
                // a higher feerate pays a strictly higher fee, as CLN and
                // BIP125 both require.
                let fresh_inputs = rng.random_range(0..=1);
                let inputs: Vec<Operation> = (0..num_inputs)
                    .map(previous_input)
                    .chain((num_inputs..num_inputs + fresh_inputs).map(wallet_input))
                    .collect();
                num_inputs += fresh_inputs;
                construct_transaction(builder, rng, &inputs, session);
                sign_and_broadcast(builder, channel_id, funding_privkey);
            }
        }

        builder.append(Operation::MineBlocks(rng.random_range(1..=16)), &[]);

        // Reuse the second_per_commitment_point already committed to in
        // open_channel2: implementations may cross-check the two, and feeding
        // an unrelated point would fail channel_ready for a reason that has
        // nothing to do with the flow under test.
        let short_channel_id = builder.generate_fresh(VariableType::ShortChannelId, rng);
        builder.append(
            Operation::SendChannelReady {
                include_alias: rng.random(),
            },
            &[
                funded_channel_id,
                second_per_commitment_point,
                short_channel_id,
            ],
        );
        builder.append(Operation::RecvChannelReady, &[]);
    }
}

/// The `index`th input we contribute from the wallet.
fn wallet_input(index: u8) -> Operation {
    Operation::SendTxAddInput {
        serial_id: input_serial_id(index),
        utxo_index: index,
        sequence: SEQUENCE,
    }
}

/// The `index`th input we contribute by re-adding one of the attempt being
/// replaced.
fn previous_input(index: u8) -> Operation {
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
fn min_rbf_feerate(previous: u32) -> u32 {
    (previous.saturating_mul(25) / 24).max(previous.saturating_add(25))
}

/// Exchanges `commitment_signed` and `tx_signatures` over the transaction the
/// session on `channel_id` built, then broadcasts it. Returns the
/// `channel_id` the peer's `commitment_signed` carries.
fn sign_and_broadcast(
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
struct SessionVars {
    channel_id: usize,
    funding_satoshis: usize,
    upfront_shutdown_script: usize,
}

/// Emits one interactive transaction construction session: `inputs`, the
/// funding and change outputs, then `tx_complete`.
///
/// Sometimes also adds a decoy input or output and removes it again, which is
/// the only way `tx_remove_input` and `tx_remove_output` reach the peer. Both
/// are gone before the change output, whose value is computed from the
/// transaction as it stands when it is sent.
fn construct_transaction(
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
fn send_turn(builder: &mut ProgramBuilder, operation: Operation, inputs: &[usize]) {
    let sent = builder.append(operation, inputs);
    builder.append(Operation::RecvInteractiveTx, &[sent]);
}
