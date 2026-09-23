//! Generator for the complete channel establishment v2 (dual-funded) flow.

use rand::seq::IndexedRandom;
use rand::{Rng, RngExt};

use super::Generator;
use super::interactive_tx::{
    RBF_DELAY_BLOCKS, SessionVars, construct_transaction, min_rbf_feerate, previous_input,
    send_turn, sign_and_broadcast, wallet_input,
};
use crate::builder::ProgramBuilder;
use crate::operation::{AcceptChannel2Field, ShutdownScriptVariant};
use crate::{Operation, VariableType};
use smite::bolt::ChannelTypeVariant;

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
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        append_dual_funding_flow(builder, rng);
    }
}

/// Emits [`DualFundingFlowGenerator`]'s flow, returning the `ChannelId`
/// variable of the channel it opens.
// One linear protocol script, from open_channel2 through channel_ready.
// Splitting it would scatter a sequence that reads best in wire order.
#[allow(clippy::too_many_lines)]
pub(super) fn append_dual_funding_flow(builder: &mut ProgramBuilder, rng: &mut impl Rng) -> usize {
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
    let funding_feerate_perkw = builder.append(Operation::LoadFeeratePerKw(funding_feerate), &[]);
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
    let funded_channel_id = sign_and_broadcast(builder, channel_id, funding_privkey).channel_id;

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
    funded_channel_id
}
