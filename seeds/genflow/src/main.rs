//! Emits a deterministic, hand-tuned funding-flow IR program that runs all the
//! way to `channel_ready`, for each channel type we care about.
//!
//! The random `FundingFlowGenerator` picks channel parameters uniformly, so it
//! almost never produces a program a real target will accept. Here every value
//! is chosen to be inside every target's acceptance window, leaving the channel
//! type as the only variable.

use smite_ir::builder::ProgramBuilder;
use smite_ir::operation::{AcceptChannelField, ChannelTypeVariant, ShutdownScriptVariant};
use smite_ir::{Operation, Program};

/// Distinct, valid secp256k1 scalars for the keys the flow needs.
fn privkey(tag: u8) -> [u8; 32] {
    let mut sk = [0u8; 32];
    sk[31] = tag;
    sk[0] = 0x01;
    sk
}

fn funding_flow(variant: ChannelTypeVariant, mine_blocks: u8) -> Program {
    let mut b = ProgramBuilder::new();

    // Keys. The funding privkey is kept so `funding_created` can sign with it.
    let funding_privkey = b.append(Operation::LoadPrivateKey(privkey(1)), &[]);
    let funding_pubkey = b.append(Operation::DerivePoint, &[funding_privkey]);
    let point = |b: &mut ProgramBuilder, tag: u8| {
        let sk = b.append(Operation::LoadPrivateKey(privkey(tag)), &[]);
        b.append(Operation::DerivePoint, &[sk])
    };
    let revocation_basepoint = point(&mut b, 2);
    let payment_basepoint = point(&mut b, 3);
    let delayed_payment_basepoint = point(&mut b, 4);
    let htlc_basepoint = point(&mut b, 5);
    let first_per_commitment_point = point(&mut b, 6);

    // Channel parameters, all well inside every target's acceptance window.
    let chain_hash = b.append(Operation::LoadChainHashFromContext, &[]);
    let temporary_channel_id = b.append(Operation::LoadChannelId([0x11; 32]), &[]);
    let funding_satoshis = b.append(Operation::LoadAmount(1_000_000), &[]);
    let push_msat = b.append(Operation::LoadAmount(0), &[]);
    // 354 is the anchor/taproot dust floor; it is also legal for legacy.
    let dust_limit_satoshis = b.append(Operation::LoadAmount(354), &[]);
    let max_htlc_value_in_flight_msat = b.append(Operation::LoadAmount(500_000_000), &[]);
    let channel_reserve_satoshis = b.append(Operation::LoadAmount(10_000), &[]);
    let htlc_minimum_msat = b.append(Operation::LoadAmount(1), &[]);
    let feerate_per_kw = b.append(Operation::LoadFeeratePerKw(2_500), &[]);
    let to_self_delay = b.append(Operation::LoadU16(144), &[]);
    let max_accepted_htlcs = b.append(Operation::LoadU16(30), &[]);
    let upfront_shutdown_script =
        b.append(Operation::LoadShutdownScript(ShutdownScriptVariant::Empty), &[]);
    let channel_type = b.append(Operation::LoadChannelType(variant), &[]);
    // Unannounced: taproot forbids the announce bit, and every other type
    // reaches `channel_ready` the same way without it.
    let channel_flags = b.append(Operation::LoadU8(0), &[]);

    let open_channel_msg = b.append(
        Operation::BuildOpenChannel,
        &[
            chain_hash,
            temporary_channel_id,
            funding_satoshis,
            push_msat,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            channel_reserve_satoshis,
            htlc_minimum_msat,
            feerate_per_kw,
            to_self_delay,
            max_accepted_htlcs,
            funding_pubkey,
            revocation_basepoint,
            payment_basepoint,
            delayed_payment_basepoint,
            htlc_basepoint,
            first_per_commitment_point,
            channel_flags,
            upfront_shutdown_script,
            channel_type,
        ],
    );
    let sent_open_channel = b.append(Operation::SendOpenChannel, &[open_channel_msg]);

    let accept_channel = b.append(Operation::RecvAcceptChannel, &[sent_open_channel]);
    let acceptor_funding_pubkey = b.append(
        Operation::ExtractAcceptChannel(AcceptChannelField::FundingPubkey),
        &[accept_channel],
    );

    let funding_transaction = b.append(
        Operation::CreateFundingTransaction,
        &[
            funding_pubkey,
            acceptor_funding_pubkey,
            funding_satoshis,
            feerate_per_kw,
            channel_type,
        ],
    );

    let sent_funding_created = b.append(
        Operation::SendFundingCreated,
        &[funding_transaction, funding_privkey, temporary_channel_id],
    );
    let channel_id = b.append(Operation::RecvFundingSigned, &[sent_funding_created]);

    b.append(Operation::BroadcastTransaction, &[funding_transaction]);
    b.append(Operation::MineBlocks(mine_blocks), &[]);

    let second_per_commitment_point = point(&mut b, 7);
    let short_channel_id = b.append(Operation::LoadShortChannelId(0), &[]);
    b.append(
        Operation::SendChannelReady {
            include_alias: false,
        },
        &[channel_id, second_per_commitment_point, short_channel_id],
    );
    b.append(Operation::RecvChannelReady, &[]);

    b.build()
}

fn main() {
    let cases = [
        ("taproot", ChannelTypeVariant::SimpleTaproot),
        ("anchors", ChannelTypeVariant::Anchors),
        ("static-remotekey", ChannelTypeVariant::StaticRemoteKey),
    ];

    let mine_blocks: u8 = std::env::args()
        .nth(1)
        .map_or(6, |a| a.parse().expect("mine_blocks"));

    for (name, variant) in cases {
        let program = funding_flow(variant, mine_blocks);
        let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
        let path = format!("{name}.bin");
        std::fs::write(&path, &bytes).expect("write program");
        println!("== {path} ({} bytes) ==\n{program}", bytes.len());
    }
}
