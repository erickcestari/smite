mod harness;
mod programs;

use std::str::FromStr;

use super::*;
use bitcoin::Amount;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use harness::*;
use programs::*;
use smite::bolt::{
    AcceptChannelTlvs, ChannelTypeVariant, GossipTimestampFilter, Init, Ping, TxAbort,
};
use smite::channel_tx::build_funding_witness_script;
use smite_ir::Instruction;
use smite_ir::builder::ProgramBuilder;
use smite_ir::operation::ShutdownScriptVariant;

// -- execute() tests --

// All fields of the sent `open_channel` must match what we expected.
#[test]
fn execute_load_build_send() {
    let oc = announced_open_channel();

    let mut fx = Fixture::new();
    fx.run(&send_open_channel_program(&oc));

    assert_eq!(fx.sent_len(), 1);
    assert_eq!(fx.sent::<OpenChannel>(0), oc.message);
}

#[test]
fn execute_build_channel_announcement() {
    let node_sk_1_bytes = [0x11; 32];
    let node_sk_2_bytes = [0x22; 32];
    let bitcoin_sk_1_bytes = [0x33; 32];
    let bitcoin_sk_2_bytes = [0x44; 32];
    let scid = ShortChannelId::new(539_268, 845, 1);
    let features_bytes = vec![0x01, 0x02];

    let mut b = ProgramBuilder::new();
    let features = b.append(Operation::LoadFeatures(features_bytes.clone()), &[]);
    let chain_hash = b.append(Operation::LoadChainHashFromContext, &[]);
    let short_channel_id = b.append(Operation::LoadShortChannelId(scid.as_u64()), &[]);
    let node_sk_1 = b.append(Operation::LoadPrivateKey(node_sk_1_bytes), &[]);
    let node_sk_2 = b.append(Operation::LoadPrivateKey(node_sk_2_bytes), &[]);
    let bitcoin_sk_1 = b.append(Operation::LoadPrivateKey(bitcoin_sk_1_bytes), &[]);
    let bitcoin_sk_2 = b.append(Operation::LoadPrivateKey(bitcoin_sk_2_bytes), &[]);
    let announcement = b.append(
        Operation::BuildChannelAnnouncement,
        &[
            features,
            chain_hash,
            short_channel_id,
            node_sk_1,
            node_sk_2,
            bitcoin_sk_1,
            bitcoin_sk_2,
        ],
    );
    b.append(Operation::SendMessage, &[announcement]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let ca: ChannelAnnouncement = fx.sent(0);

    let secp = Secp256k1::new();
    let pk = |b: &[u8; 32]| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(b).unwrap());
    assert_eq!(ca.features, features_bytes);
    assert_eq!(ca.chain_hash, sample_context().chain_hash);
    assert_eq!(ca.short_channel_id, scid);
    assert_eq!(ca.node_id_1, pk(&node_sk_1_bytes));
    assert_eq!(ca.node_id_2, pk(&node_sk_2_bytes));
    assert_eq!(ca.bitcoin_key_1, pk(&bitcoin_sk_1_bytes));
    assert_eq!(ca.bitcoin_key_2, pk(&bitcoin_sk_2_bytes));
    assert!(ca.extra.is_empty());
    assert!(ca.verify());
}

#[test]
fn execute_build_node_announcement() {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 0x42;
    let rgb_color = [0x11, 0x22, 0x33];
    let mut alias = [0u8; 32];
    alias[..5].copy_from_slice(b"smite");
    let addresses_bytes = vec![0xaa, 0xbb, 0xcc];

    let mut b = ProgramBuilder::new();
    let node_sk = b.append(Operation::LoadPrivateKey(sk_bytes), &[]);
    let features = b.append(Operation::LoadFeatures(vec![0x01, 0x02]), &[]);
    let timestamp = b.append(Operation::LoadTimestamp(1_700_000_000), &[]);
    let addresses = b.append(Operation::LoadBytes(addresses_bytes.clone()), &[]);
    let announcement = b.append(
        Operation::BuildNodeAnnouncement { rgb_color, alias },
        &[node_sk, features, timestamp, addresses],
    );
    b.append(Operation::SendMessage, &[announcement]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let na: NodeAnnouncement = fx.sent(0);

    let secp = Secp256k1::new();
    let expected_node_id =
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
    assert_eq!(na.node_id, expected_node_id);
    assert_eq!(na.features, vec![0x01, 0x02]);
    assert_eq!(na.timestamp, 1_700_000_000);
    assert_eq!(na.rgb_color, rgb_color);
    assert_eq!(na.alias, alias);
    assert_eq!(na.addresses, addresses_bytes);
    assert!(na.extra.is_empty());
    assert!(na.verify());
}

#[test]
fn execute_build_channel_update() {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 0x42;
    let scid = ShortChannelId::new(538_532, 845, 1);

    let mut b = ProgramBuilder::new();
    let node_sk = b.append(Operation::LoadPrivateKey(sk_bytes), &[]);
    let chain_hash = b.append(Operation::LoadChainHashFromContext, &[]);
    let short_channel_id = b.append(Operation::LoadShortChannelId(scid.as_u64()), &[]);
    let timestamp = b.append(Operation::LoadTimestamp(1_715_000_000), &[]);
    let message_flags = b.append(Operation::LoadU8(0x01), &[]); // must_be_one
    let channel_flags = b.append(Operation::LoadU8(0x00), &[]);
    let cltv_expiry_delta = b.append(Operation::LoadU16(144), &[]);
    let htlc_minimum_msat = b.append(Operation::LoadAmount(1_000), &[]);
    let fee_base_msat = b.append(Operation::LoadForwardingFee(1_000), &[]);
    let fee_proportional_millionths = b.append(Operation::LoadForwardingFee(100), &[]);
    let htlc_maximum_msat = b.append(Operation::LoadAmount(99_000_000), &[]);
    let update = b.append(
        Operation::BuildChannelUpdate,
        &[
            node_sk,
            chain_hash,
            short_channel_id,
            timestamp,
            message_flags,
            channel_flags,
            cltv_expiry_delta,
            htlc_minimum_msat,
            fee_base_msat,
            fee_proportional_millionths,
            htlc_maximum_msat,
        ],
    );
    b.append(Operation::SendMessage, &[update]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let cu: ChannelUpdate = fx.sent(0);

    assert_eq!(cu.chain_hash, sample_context().chain_hash);
    assert_eq!(cu.short_channel_id, scid);
    assert_eq!(cu.timestamp, 1_715_000_000);
    assert_eq!(cu.message_flags, 0x01);
    assert_eq!(cu.channel_flags, 0x00);
    assert_eq!(cu.cltv_expiry_delta, 144);
    assert_eq!(cu.htlc_minimum_msat, 1_000);
    assert_eq!(cu.fee_base_msat, 1_000);
    assert_eq!(cu.fee_proportional_millionths, 100);
    assert_eq!(cu.htlc_maximum_msat, 99_000_000);
    assert!(cu.extra.is_empty());

    let secp = Secp256k1::new();
    let expected_node_id =
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
    assert!(cu.verify(&expected_node_id));
}

#[test]
fn execute_build_announcement_signatures() {
    let node_sk_1_bytes = [0x11; 32];
    let node_sk_2_bytes = [0x22; 32];
    let bitcoin_sk_1_bytes = [0x33; 32];
    let bitcoin_sk_2_bytes = [0x44; 32];
    let channel_id_bytes = [0xbb; 32];
    let scid = ShortChannelId::new(539_268, 845, 1);
    let features_bytes = vec![0x01, 0x02];

    // We sign with our own keys and carry the target's as points, so the
    // target's keys are loaded only to derive them.
    let program = {
        let mut b = ProgramBuilder::new();
        let channel_id = b.append(Operation::LoadChannelId(channel_id_bytes), &[]);
        let features = b.append(Operation::LoadFeatures(features_bytes.clone()), &[]);
        let chain_hash = b.append(Operation::LoadChainHashFromContext, &[]);
        let short_channel_id = b.append(Operation::LoadShortChannelId(scid.as_u64()), &[]);
        let node_sk_1 = b.append(Operation::LoadPrivateKey(node_sk_1_bytes), &[]);
        let node_sk_2 = b.append(Operation::LoadPrivateKey(node_sk_2_bytes), &[]);
        let node_id_2 = b.append(Operation::DerivePoint, &[node_sk_2]);
        let bitcoin_sk_1 = b.append(Operation::LoadPrivateKey(bitcoin_sk_1_bytes), &[]);
        let bitcoin_sk_2 = b.append(Operation::LoadPrivateKey(bitcoin_sk_2_bytes), &[]);
        let bitcoin_key_2 = b.append(Operation::DerivePoint, &[bitcoin_sk_2]);
        let ann_sigs = b.append(
            Operation::BuildAnnouncementSignatures,
            &[
                channel_id,
                features,
                chain_hash,
                short_channel_id,
                node_sk_1,
                node_id_2,
                bitcoin_sk_1,
                bitcoin_key_2,
            ],
        );
        b.append(Operation::SendMessage, &[ann_sigs]);

        b.build()
    };

    let mut fx = Fixture::new();
    fx.run(&program);

    assert_eq!(fx.sent_len(), 1);
    let ann_sigs: AnnouncementSignatures = fx.sent(0);

    assert_eq!(ann_sigs.channel_id, ChannelId::new(channel_id_bytes));
    assert_eq!(ann_sigs.short_channel_id, scid);

    // Verify the signatures in announcement_signatures directly against
    // the channel_announcement body digest.
    let secp = Secp256k1::new();
    let node_sk_1 = SecretKey::from_slice(&node_sk_1_bytes).unwrap();
    let node_sk_2 = SecretKey::from_slice(&node_sk_2_bytes).unwrap();
    let bitcoin_sk_1 = SecretKey::from_slice(&bitcoin_sk_1_bytes).unwrap();
    let bitcoin_sk_2 = SecretKey::from_slice(&bitcoin_sk_2_bytes).unwrap();
    let node_id_ours = PublicKey::from_secret_key(&secp, &node_sk_1);
    let node_id_theirs = PublicKey::from_secret_key(&secp, &node_sk_2);
    let bitcoin_key_ours = PublicKey::from_secret_key(&secp, &bitcoin_sk_1);
    let bitcoin_key_theirs = PublicKey::from_secret_key(&secp, &bitcoin_sk_2);
    let (n1, n2, bk1, bk2) = if node_id_ours.serialize() <= node_id_theirs.serialize() {
        (
            node_id_ours,
            node_id_theirs,
            bitcoin_key_ours,
            bitcoin_key_theirs,
        )
    } else {
        (
            node_id_theirs,
            node_id_ours,
            bitcoin_key_theirs,
            bitcoin_key_ours,
        )
    };
    let placeholder = Signature::from_compact(&[0u8; 64]).unwrap();
    let ca = ChannelAnnouncement {
        node_signature_1: placeholder,
        node_signature_2: placeholder,
        bitcoin_signature_1: placeholder,
        bitcoin_signature_2: placeholder,
        features: features_bytes,
        chain_hash: sample_context().chain_hash,
        short_channel_id: scid,
        node_id_1: n1,
        node_id_2: n2,
        bitcoin_key_1: bk1,
        bitcoin_key_2: bk2,
        extra: Vec::new(),
    };
    let digest = ca.signing_digest();
    assert!(
        secp.verify_ecdsa(&digest, &ann_sigs.node_signature, &node_id_ours)
            .is_ok()
    );
    assert!(
        secp.verify_ecdsa(&digest, &ann_sigs.bitcoin_signature, &bitcoin_key_ours)
            .is_ok()
    );
}

#[test]
fn execute_build_open_channel_with_tlvs() {
    let mut oc = announced_open_channel();
    oc.message.tlvs = OpenChannelTlvs {
        upfront_shutdown_script: Some(vec![0x00, 0x14, 0xab]),
        channel_type: Some(vec![0x01, 0x02]),
    };

    let mut fx = Fixture::new();
    fx.run(&send_open_channel_program(&oc));

    assert_eq!(fx.sent::<OpenChannel>(0), oc.message);
}

// Every pubkey of the `open_channel` is derived from one private key, so the
// message arriving with the expected pubkeys means `DerivePoint` produced the
// correct Point variable.
#[test]
fn execute_derive_point() {
    let oc = SampleOpenChannel::new(PointSource::Secret([0x11; 32]));

    let mut fx = Fixture::new();
    fx.run(&send_open_channel_program(&oc));

    assert_eq!(fx.sent::<OpenChannel>(0), oc.message);
}

#[test]
fn execute_recv_and_extract_all_fields() {
    // Receive accept_channel (v0), then extract all 16 fields (v1..v16).
    let fields = [
        AcceptChannelField::TemporaryChannelId,
        AcceptChannelField::DustLimitSatoshis,
        AcceptChannelField::MaxHtlcValueInFlightMsat,
        AcceptChannelField::ChannelReserveSatoshis,
        AcceptChannelField::HtlcMinimumMsat,
        AcceptChannelField::MinimumDepth,
        AcceptChannelField::ToSelfDelay,
        AcceptChannelField::MaxAcceptedHtlcs,
        AcceptChannelField::FundingPubkey,
        AcceptChannelField::RevocationBasepoint,
        AcceptChannelField::PaymentBasepoint,
        AcceptChannelField::DelayedPaymentBasepoint,
        AcceptChannelField::HtlcBasepoint,
        AcceptChannelField::FirstPerCommitmentPoint,
        AcceptChannelField::UpfrontShutdownScript,
        AcceptChannelField::ChannelType,
    ];

    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel(&mut b, &announced_open_channel());
    for field in fields {
        b.append(
            Operation::ExtractAcceptChannel(field),
            &[negotiated.accept_channel],
        );
    }

    // TODO: Once we add IR support for building accept_channel messages,
    // rebuild a message from the extracted fields and verify it matches the
    // original.

    Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run(&b.build());
}

#[test]
fn execute_recv_unexpected_message() {
    let err = Fixture::new()
        .queue(&Message::Init(Init::empty()))
        .run_err(&negotiate_channel_program(&announced_open_channel()));
    assert!(matches!(
        err,
        ExecuteError::UnexpectedMessage {
            expected: MessageType::ACCEPT_CHANNEL,
            got: MessageType::INIT,
        }
    ));
}

#[test]
fn execute_recv_peer_error() {
    let peer_error = smite::bolt::Error::all_channels("Wrong channel id in channel_ready");

    let err = Fixture::new()
        .queue(&Message::Error(peer_error.clone()))
        .run_err(&negotiate_channel_program(&announced_open_channel()));
    assert!(matches!(err, ExecuteError::PeerError(e) if e == peer_error));
}

#[test]
#[allow(clippy::similar_names)] // ping and pong are the canonical names
fn execute_recv_auto_pong() {
    let ping = Ping {
        num_pong_bytes: 4,
        ignored: vec![0xaa],
    };

    let mut fx = Fixture::new()
        .queue(&Message::Ping(ping))
        .queue(&Message::AcceptChannel(sample_accept_channel()));
    fx.run(&negotiate_channel_program(&announced_open_channel()));

    // Verify exactly two messages were sent: `open_channel` and `pong`.
    assert_eq!(fx.sent_len(), 2);
    fx.sent::<OpenChannel>(0);
    let pong: Pong = fx.sent(1);
    assert_eq!(pong.ignored.len(), 4);
}

#[test]
fn execute_recv_skips_gossip() {
    let gossip = GossipTimestampFilter::new([0u8; 32], 0, 86400);

    let mut fx = Fixture::new()
        .queue(&Message::GossipTimestampFilter(gossip))
        .queue(&Message::AcceptChannel(sample_accept_channel()));
    fx.run(&negotiate_channel_program(&announced_open_channel()));

    let accept_channel = fx
        .negotiation(&TemporaryChannelId::new([0xbb; 32]))
        .accept_channel
        .as_ref()
        .expect("accept_channel recorded");
    assert_eq!(accept_channel.clone(), sample_accept_channel());
}

#[test]
fn execute_records_negotiation_for_open_and_accept() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    let mut fx = Fixture::new().queue(&Message::AcceptChannel(sample_accept_channel()));
    fx.run(&negotiate_channel_program(&announced_open_channel()));

    let pending = fx.negotiation(&temporary_channel_id);
    assert_eq!(
        pending.open_channel.temporary_channel_id,
        temporary_channel_id
    );
    let accept_channel = pending.accept_channel.as_ref().unwrap();
    assert_eq!(accept_channel.clone(), sample_accept_channel());
    assert!(!pending.funding_built);
}

#[test]
fn execute_recv_accept_channel_unknown_channel() {
    let unknown_id = TemporaryChannelId::new([0xcc; 32]);

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(AcceptChannel {
            temporary_channel_id: unknown_id,
            ..sample_accept_channel()
        }))
        .run_err(&negotiate_channel_program(&announced_open_channel()));

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, unknown_id);
    assert!(
        reason.contains(
            "unknown temporary_channel_id: no open_channel was sent for this negotiation"
        )
    );
}

#[test]
fn execute_recv_accept_channel_opener_cannot_afford_fee() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    // Set `push_msat` so the opener cannot afford the commitment fee
    // requiring the peer to reject the `open_channel` per BOLT 2.
    let mut oc = announced_open_channel();
    oc.message.push_msat = 99_900_000;

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run_err(&negotiate_channel_program(&oc));

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, temporary_channel_id);
    assert!(
        reason.contains(
            "invalid open_channel: opener balance 100 sat cannot cover the commitment fee"
        )
    );
}

#[test]
fn execute_recv_accept_channel_rejects_reuse_before_funding() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    // Send the same `open_channel` a second time and receive another
    // `accept_channel` for it.
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel(&mut b, &announced_open_channel());
    let resent = b.append(
        Operation::SendOpenChannel,
        &[negotiated.open_channel.vars.built],
    );
    b.append(Operation::RecvAcceptChannel, &[resent]);

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, temporary_channel_id);
    assert!(reason.contains(
        "temporary_channel_id reuse: previous negotiation has not reached funding_created"
    ));
}

#[test]
fn execute_records_only_first_open_channel_for_duplicate_id_before_funding() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    // First open_channel: funding_satoshis = 100_000.
    // Second open_channel: same temporary_channel_id, funding_satoshis = 200_000.
    let mut b = ProgramBuilder::new();
    let first = send_open_channel(&mut b, &announced_open_channel());

    // Override only funding_satoshis; reuse the first open_channel's other 19 inputs.
    let mut second = first.vars;
    second.funding_satoshis = b.append(Operation::LoadAmount(200_000), &[]);
    second.built = b.append(Operation::BuildOpenChannel, &second.build_inputs());
    b.append(Operation::SendOpenChannel, &[second.built]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    // Both open_channel messages went out on the wire, but only the first
    // negotiation is recorded for the shared id.
    assert_eq!(fx.sent_len(), 2);
    assert_eq!(fx.sent::<OpenChannel>(0).funding_satoshis, 100_000);
    assert_eq!(fx.sent::<OpenChannel>(1).funding_satoshis, 200_000);
    let pending = fx.negotiation(&temporary_channel_id);
    assert_eq!(pending.open_channel.funding_satoshis, 100_000);
}

#[test]
fn execute_records_open_channel_for_duplicate_id_after_funding() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    // Negotiated open_channel: funding_satoshis = 10_000_000.
    // Second open_channel: same temporary_channel_id, funding_satoshis = 100_000.
    let mut b = ProgramBuilder::new();
    send_funding_created(&mut b);
    send_open_channel(&mut b, &announced_open_channel());

    let mut fx = Fixture::new().with_negotiation(sample_funding_negotiation());
    fx.run(&b.build());

    let pending = fx.negotiation(&temporary_channel_id);
    assert_eq!(pending.open_channel.funding_satoshis, 100_000);
    assert!(pending.accept_channel.is_none());
    assert!(!pending.funding_built);
}

// -- Panic path tests --

#[test]
#[should_panic(expected = "expected 1 inputs, got 0")]
fn execute_wrong_input_count_panics() {
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![], // expects 1 input
        }],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "expected PrivateKey, got Amount")]
fn execute_type_mismatch_panics() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(42),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0], // v0 is Amount, not PrivateKey
            },
        ],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "out of bounds")]
fn execute_variable_out_of_bounds_panics() {
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::SendMessage,
            inputs: vec![99],
        }],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "out of bounds")]
fn execute_forward_variable_reference_panics() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![1],
            },
            Instruction {
                operation: Operation::LoadPrivateKey([0x11; 32]),
                inputs: vec![],
            },
        ],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "is void")]
fn execute_void_variable_reference_panics() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::MineBlocks(1),
                inputs: vec![],
            },
            // Try to use the void variable.
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![0],
            },
        ],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "valid private key")]
fn execute_invalid_private_key_panics() {
    let mut b = ProgramBuilder::new();
    let sk = b.append(Operation::LoadPrivateKey([0; 32]), &[]);
    b.append(Operation::DerivePoint, &[sk]);

    Fixture::new().run(&b.build());
}

#[test]
#[should_panic(expected = "expected OpenChannelMessage, got Amount")]
fn execute_send_open_channel_wrong_type_panics() {
    let instrs = vec![
        Instruction {
            operation: Operation::LoadAmount(42),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![0],
        },
    ];

    let program = Program {
        instructions: instrs,
    };

    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "is void")]
fn execute_affine_overuse_panics() {
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel(&mut b, &announced_open_channel());
    let mut program = b.build();

    // `ProgramBuilder` rejects the reuse itself, so we manually append the
    // second receive instruction.
    program.instructions.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![negotiated.open_channel.sent],
    });

    Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run(&program);
}

// MineBlocks should track calls to mine_blocks
#[test]
fn execute_mine_blocks_invokes_cli() {
    let mut b = ProgramBuilder::new();
    b.append(Operation::MineBlocks(6), &[]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    // Verify that mine_blocks was called with the correct number
    assert_eq!(fx.bitcoin().mine_blocks_calls, vec![6]);
    assert!(fx.bitcoin().mined_private_mempool.is_empty());
    assert_eq!(fx.rpc().chain_syncs, 1);
}

#[test]
#[should_panic(expected = "expected 0 inputs, got 1")]
fn execute_mine_blocks_wrong_input() {
    let instrs = vec![
        Instruction {
            operation: Operation::LoadAmount(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::MineBlocks(6),
            inputs: vec![0],
        },
    ];
    let program = Program {
        instructions: instrs,
    };
    Fixture::new().run(&program);
}

#[test]
fn execute_create_and_broadcast_tx() {
    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx(&mut b);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.bitcoin().broadcast_calls.len(), 1);
    let broadcast_tx = &fx.bitcoin().broadcast_calls[0];
    assert_eq!(broadcast_tx.compute_txid(), funding_outpoint().txid);
    assert_eq!(fx.rpc().chain_syncs, 0);
}

// LookupShortChannelId should combine the confirmed block position with
// the funding output's vout to produce the correct SCID, which we verify
// by feeding it into a channel_announcement and decoding the sent message.
#[test]
fn execute_lookup_short_channel_id_confirmed() {
    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx(&mut b);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    b.append(Operation::MineBlocks(6), &[]);
    let scid = b.append(Operation::LookupShortChannelId, &[funding.tx]);
    send_channel_announcement(&mut b, scid);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.bitcoin().mine_blocks_calls, vec![6]);
    // The executor must have queried the mock with the broadcast
    // transaction's txid.
    assert_eq!(fx.bitcoin().block_position_lookups.len(), 1);
    let broadcast_txid = fx.bitcoin().broadcast_calls[0].compute_txid();
    assert_eq!(fx.bitcoin().block_position_lookups[0], broadcast_txid);

    // The mock returns block_height=800_042, tx_index=7 for a confirmed
    // tx, and the funding output is always at vout 0.
    let ca: ChannelAnnouncement = fx.sent(0);
    assert_eq!(ca.short_channel_id, ShortChannelId::new(800_042, 7, 0));
}

// LookupShortChannelId should produce the sentinel SCID (0/0/0) when the
// funding transaction is unknown to the node (e.g. never broadcast or
// never confirmed), rather than panicking. We verify the sentinel value
// via the SCID carried in a channel_announcement.
#[test]
fn execute_lookup_short_channel_id_unconfirmed_returns_sentinel() {
    // No BroadcastTransaction and no MineBlocks: the mock reports zero
    // confirmations and get_transaction_block_position returns None.
    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx(&mut b);
    let scid = b.append(Operation::LookupShortChannelId, &[funding.tx]);
    send_channel_announcement(&mut b, scid);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    // The mock was queried but returned None (zero confirmations), so the
    // executor took the sentinel path without panicking.
    assert!(fx.bitcoin().mine_blocks_calls.is_empty());
    assert_eq!(fx.bitcoin().block_position_lookups.len(), 1);

    let ca: ChannelAnnouncement = fx.sent(0);
    assert_eq!(ca.short_channel_id, ShortChannelId::new(0, 0, 0));
}

#[test]
fn execute_broadcast_dedupes_rejected_tx_in_private_mempool() {
    // Fund with a dust amount so the built funding tx carries a below-dust
    // output, and broadcast it twice.
    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx_with(&mut b, 200, 15_000);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    b.append(Operation::MineBlocks(1), &[]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.bitcoin().broadcast_calls.len(), 2);
    assert_eq!(
        fx.bitcoin().broadcast_calls[0].compute_txid(),
        fx.bitcoin().broadcast_calls[1].compute_txid(),
    );

    let rejected_hex = bitcoin::consensus::encode::serialize_hex(&fx.bitcoin().broadcast_calls[0]);
    assert!(fx.private_mempool().is_empty());
    assert_eq!(fx.bitcoin().mined_private_mempool, vec![rejected_hex]);
}

#[test]
fn execute_create_funding_transaction_insufficient_funds() {
    // UTXO too small to cover the funding amount and fees.
    let small_utxo = Utxo {
        amount: Amount::from_sat(1_000),
        ..sample_utxo()
    };
    let mut b = ProgramBuilder::new();
    create_funding_tx(&mut b);

    let err = Fixture::new()
        .with_utxos(vec![small_utxo])
        .run_err(&b.build());
    let ExecuteError::InsufficientFunds(funds_err) = err else {
        panic!("expected InsufficientFunds, got {err:?}");
    };
    assert_eq!(funds_err.available, Amount::from_sat(1_000));
    assert_eq!(funds_err.required, Amount::from_sat(10_007_290));
}

#[test]
fn execute_send_funding_created_and_recv_funding_signed() {
    // The acceptor replies with funding_signed carrying its signature over
    // the opener's commitment.
    let mut fx = recv_funding_signed_fixture();
    fx.run(&send_funding_created_and_recv_funding_signed_program());

    assert_eq!(fx.sent_len(), 1);
    let fc: FundingCreated = fx.sent(0);

    assert_eq!(fc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(fc.funding_txid, funding_outpoint().txid);
    assert_eq!(fc.funding_output_index, 0);

    // Verify the signature sent by the opener on the acceptor side.
    let state = fx.channel_state(&funding_channel_id());
    let holder = HolderIdentity {
        side: Side::Acceptor,
        funding_privkey: acceptor_funding_sk(),
    };

    assert!(
        state
            .config
            .verify_counterparty_signature(&state.commitment, &holder, &fc.signature)
    );

    let pending = fx.negotiation(&TemporaryChannelId::new([0xbb; 32]));
    assert!(pending.funding_built);
    assert_eq!(fx.rpc().chain_syncs, 0);
}

#[test]
fn execute_send_funding_created_uses_wire_funding_pubkey() {
    // Swap out the SendFundingCreated privkey. This should not affect the
    // constructed channel config, which uses the negotiated pubkeys. It
    // should only change the signature sent to the target.
    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx(&mut b);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    let funding_created = send_funding_created_with(&mut b, funding, funding.acceptor_privkey);
    b.append(Operation::RecvFundingSigned, &[funding_created.sent]);

    // The acceptor's signature still verifies, because the config is built
    // from the wire pubkeys rather than from the swapped privkey.
    let mut fx = recv_funding_signed_fixture();
    fx.run(&b.build());

    let secp = Secp256k1::new();
    let opener_pk = PublicKey::from_secret_key(&secp, &opener_funding_sk());
    // The funding pubkey matches what was negotiated.
    let state = fx.channel_state(&funding_channel_id());
    assert_eq!(state.config.opener.funding_pubkey, opener_pk);
    // But the swapped privkey used for signing is the acceptor's, which
    // does not match what was negotiated.
    assert_eq!(state.holder.funding_privkey, acceptor_funding_sk());
    assert_ne!(
        state.config.opener.funding_pubkey,
        PublicKey::from_secret_key(&secp, &state.holder.funding_privkey)
    );
}

#[test]
fn execute_send_funding_created_after_funding_built_does_not_track_channel() {
    // A second UTXO so the program can build a second funding transaction.
    let second_utxo = Utxo {
        outpoint: OutPoint {
            vout: 1,
            ..sample_utxo().outpoint
        },
        ..sample_utxo()
    };

    let mut b = ProgramBuilder::new();
    let first = send_funding_created(&mut b);

    // The opener's pubkey is used on both sides of the funding script, creating
    // a different outpoint than the first funding transaction's.
    let funding = first.tx;
    let second_tx = b.append(
        Operation::CreateFundingTransaction,
        &[
            funding.opener_pubkey,
            funding.opener_pubkey,
            funding.funding_satoshis,
            funding.feerate_per_kw,
        ],
    );
    b.append(
        Operation::SendFundingCreated,
        &[
            second_tx,
            funding.opener_privkey,
            first.temporary_channel_id,
        ],
    );

    let mut fx = Fixture::new()
        .with_utxos(vec![sample_utxo(), second_utxo])
        .with_negotiation(sample_funding_negotiation());
    fx.run(&b.build());

    // The message still goes out, only the state tracking is suppressed.
    assert_eq!(fx.sent_len(), 2);
    assert_eq!(fx.channel_states().len(), 1);
    // The tracked channel id derives from the first funding transaction's
    // outpoint.
    assert!(fx.channel_states().contains_key(&funding_channel_id()));
}

#[test]
fn execute_send_funding_created_push_exceeds_funding() {
    // A negotiated push_msat larger than the funding amount surfaces the
    // commitment construction error.
    let mut negotiation = sample_funding_negotiation();
    negotiation.open_channel.push_msat = 20_000_000_000;
    let err = Fixture::new()
        .with_negotiation(negotiation)
        .run_err(&send_funding_created_and_recv_funding_signed_program());
    assert!(matches!(
        err,
        ExecuteError::Commitment(smite::channel_tx::CommitmentError::PushExceedsFunding)
    ));
}

#[test]
fn execute_send_funding_created_funding_msat_overflow() {
    // A negotiated funding_satoshis of u64::MAX overflows when converted to
    // millisatoshis.
    let mut negotiation = sample_funding_negotiation();
    negotiation.open_channel.funding_satoshis = u64::MAX;
    let err = Fixture::new()
        .with_negotiation(negotiation)
        .run_err(&send_funding_created_and_recv_funding_signed_program());
    assert!(matches!(
        err,
        ExecuteError::Commitment(smite::channel_tx::CommitmentError::FundingMsatOverflow)
    ));
}

#[test]
fn execute_send_funding_created_no_open_channel() {
    // No negotiation exists for this temporary_channel_id, so we get a
    // `funding_created` with an all-zero signature and no recorded channel
    // state.
    let mut fx = Fixture::new();
    fx.run(&send_funding_created_program());

    let fc: FundingCreated = fx.sent(0);
    assert_eq!(fc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(fc.funding_txid, funding_outpoint().txid);
    assert_eq!(fc.funding_output_index, 0);
    assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
    assert!(fx.channel_states().is_empty());
}

#[test]
fn execute_send_funding_created_no_accept_channel() {
    // The `accept_channel` has not been received yet, so we get a
    // `funding_created` with an all-zero signature and no recorded channel
    // state.
    let mut negotiation = sample_funding_negotiation();
    negotiation.accept_channel = None;

    let mut fx = Fixture::new().with_negotiation(negotiation);
    fx.run(&send_funding_created_program());

    let fc: FundingCreated = fx.sent(0);
    assert_eq!(fc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(fc.funding_txid, funding_outpoint().txid);
    assert_eq!(fc.funding_output_index, 0);
    assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
    assert!(fx.channel_states().is_empty());
}

#[test]
fn execute_recv_funding_signed_unknown_channel() {
    let channel_id = ChannelId::new([0xbb; 32]);

    let err = Fixture::new()
        .with_negotiation(sample_funding_negotiation())
        .queue(&funding_signed_reply(channel_id))
        .run_err(&send_funding_created_and_recv_funding_signed_program());
    assert!(matches!(
        err,
        ExecuteError::Violation(Violation::UnknownChannel(id)) if id == channel_id
    ));
}

#[test]
fn execute_recv_funding_signed_invalid_signature() {
    let channel_id = funding_channel_id();
    let err = Fixture::new()
        .with_negotiation(sample_funding_negotiation())
        .queue(&Message::FundingSigned(FundingSigned {
            channel_id,
            signature: Signature::from_compact(&[0u8; 64])
                .expect("zero bytes parse as a signature"),
        }))
        .run_err(&send_funding_created_and_recv_funding_signed_program());
    assert!(matches!(
        err,
        ExecuteError::Violation(Violation::InvalidCounterpartySignature(id)) if id == channel_id
    ));
}

#[test]
fn execute_send_channel_ready() {
    let channel_id = funding_channel_id();
    let alias = ShortChannelId::new(538_532, 845, 1);
    let mut b = ProgramBuilder::new();
    let funding_created = send_funding_created(&mut b);
    let funded_channel_id = b.append(Operation::RecvFundingSigned, &[funding_created.sent]);
    let alias_scid = b.append(Operation::LoadShortChannelId(alias.as_u64()), &[]);
    b.append(
        Operation::SendChannelReady {
            include_alias: false,
        },
        &[
            funded_channel_id,
            funding_created.tx.opener_pubkey,
            alias_scid,
        ],
    );
    b.append(
        Operation::SendChannelReady {
            include_alias: true,
        },
        &[
            funded_channel_id,
            funding_created.tx.acceptor_pubkey,
            alias_scid,
        ],
    );

    let mut fx = recv_funding_signed_fixture();
    fx.run(&b.build());

    // The instructions send 1 `funding_created` and 2 `channel_ready` messages.
    assert_eq!(fx.sent_len(), 3);

    // The first channel_ready was sent with include_alias = false, so it must
    // not carry the short_channel_id TLV.
    let cr1: ChannelReady = fx.sent(1);
    let expected_pcp1 =
        PublicKey::from_str("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb")
            .unwrap();
    assert_eq!(cr1.channel_id, channel_id);
    assert_eq!(cr1.second_per_commitment_point, expected_pcp1);
    assert!(cr1.tlvs.short_channel_id.is_none());

    // The second channel_ready was sent with include_alias = true, so it must
    // carry the alias SCID we loaded in its short_channel_id TLV.
    let cr2: ChannelReady = fx.sent(2);
    let expected_pcp2 =
        PublicKey::from_str("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1")
            .unwrap();
    assert_eq!(cr2.channel_id, channel_id);
    assert_eq!(cr2.second_per_commitment_point, expected_pcp2);
    assert_eq!(cr2.tlvs.short_channel_id, Some(alias));

    // The holder's next per-commitment point must hold the first
    // `channel_ready`'s point, not any subsequent one.
    let state = fx.channel_state(&channel_id);
    assert_eq!(
        *state.next_holder_per_commitment_point(),
        Some(expected_pcp1)
    );
}

#[test]
fn execute_send_shutdown() {
    let channel_id = ChannelId::new([0x7a; 32]);
    let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);

    let mut b = ProgramBuilder::new();
    let channel_id_var = b.append(Operation::LoadChannelId(channel_id.0), &[]);
    let scriptpubkey = b.append(Operation::LoadShutdownScript(script.clone()), &[]);
    b.append(Operation::SendShutdown, &[channel_id_var, scriptpubkey]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let sd: Shutdown = fx.sent(0);
    assert_eq!(sd.channel_id, channel_id);
    assert_eq!(sd.scriptpubkey, script.encode());
}

#[test]
fn execute_send_shutdown_empty_scriptpubkey() {
    let channel_id = ChannelId::new([0x7a; 32]);
    // The fuzzer should allow an empty scriptpubkey in the shutdown message
    // to exercise the target's behavior even though it's protocol-invalid.
    let mut b = ProgramBuilder::new();
    let channel_id_var = b.append(Operation::LoadChannelId(channel_id.0), &[]);
    let scriptpubkey = b.append(
        Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
        &[],
    );
    b.append(Operation::SendShutdown, &[channel_id_var, scriptpubkey]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let sd: Shutdown = fx.sent(0);
    assert_eq!(sd.channel_id, channel_id);
    assert!(sd.scriptpubkey.is_empty());
}

#[test]
fn execute_recv_channel_ready_invalid_funding_outpoint_is_noop() {
    // Corrupt the negotiated opener funding pubkey so the broadcast funding
    // transaction's output no longer pays the negotiated 2-of-2 script,
    // marking the funding outpoint invalid.
    let mut negotiation = sample_funding_negotiation();
    negotiation.open_channel.funding_pubkey = sample_pubkey(1);

    // The corrupted pubkey changes the funding script, so our precomputed
    // funding_signed signature will no longer verify correctly. That
    // exchange is not what this test is about, so we neither queue the
    // funding_signed nor receive it.
    let mut fx = Fixture::new()
        .with_negotiation(negotiation)
        .queue(&channel_ready_reply(sample_pubkey(1)));
    let mut b = ProgramBuilder::new();
    send_funding_created(&mut b);
    b.append(Operation::MineBlocks(8), &[]);
    b.append(Operation::RecvChannelReady, &[]);

    // With invalid funding outpoint the target does not owe us a
    // `channel_ready`, so `RecvChannelReady` must be a no-op.
    fx.run(&b.build());

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert_eq!(fx.queued_len(), 1);
}

#[test]
fn execute_recv_channel_ready_below_minimum_depth_is_noop() {
    let (mut fx, _) = recv_channel_ready_fixture();

    // Mine one block fewer than the `minimum_depth` negotiated in `accept_channel` by
    // `sample_funding_negotiation()`.
    // With fewer than the negotiated `minimum_depth` confirmations the target
    // does not yet owe us a `channel_ready`, so `RecvChannelReady` must be a
    // no-op.
    fx.run(&recv_channel_ready_program(5));
    assert!(fx.bitcoin().mined_private_mempool.is_empty());

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert_eq!(fx.queued_len(), 1);
}

#[test]
fn execute_recv_channel_ready_at_minimum_depth_records_point() {
    let (mut fx, target_pcp) = recv_channel_ready_fixture();

    // Mine exactly the `minimum_depth` negotiated in `accept_channel` by
    // `sample_funding_negotiation()`.
    // At the negotiated `minimum_depth` confirmations the target owes us a
    // `channel_ready`, which `RecvChannelReady` receives and records.
    fx.run(&recv_channel_ready_program(6));
    assert!(fx.bitcoin().mined_private_mempool.is_empty());

    // The `channel_ready` was consumed and the target's next per-commitment
    // point is now recorded.
    let state = fx.channel_state(&funding_channel_id());
    assert_eq!(
        *state.next_counterparty_per_commitment_point(),
        Some(target_pcp)
    );
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_channel_ready_funding_mined_prematurely_is_noop() {
    let (mut fx, _) = recv_channel_ready_fixture();

    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx(&mut b);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    // Mine past the negotiated `minimum_depth` *before* sending
    // `funding_created`.
    b.append(Operation::MineBlocks(8), &[]);
    let funding_created = send_funding_created_with(&mut b, funding, funding.opener_privkey);
    b.append(Operation::RecvFundingSigned, &[funding_created.sent]);
    b.append(Operation::RecvChannelReady, &[]);

    // The funding transaction confirmed before `funding_created`, so the
    // target may never observe the confirmation and `RecvChannelReady` must
    // be a no-op even though the confirmation count is sufficient.
    fx.run(&b.build());

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(state.was_funding_mined_prematurely);
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert_eq!(fx.queued_len(), 1);
}

// -- extract_field tests --

// TODO: Once we can actually construct and send accept_channel messages, it
// would be better to test field extraction through an IR program that
// receives an accept_channel, extracts all fields, constructs a new
// accept_channel from those fields, and sends the new accept_channel. Then
// we'll have a full roundtrip test instead of testing the extract_field
// helper function in isolation.

#[test]
fn extract_scalar_fields() {
    let ac = sample_accept_channel();
    assert_eq!(
        extract_field(&ac, AcceptChannelField::DustLimitSatoshis),
        Variable::Amount(546)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::MaxHtlcValueInFlightMsat),
        Variable::Amount(100_000_000)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::ChannelReserveSatoshis),
        Variable::Amount(10_000)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::HtlcMinimumMsat),
        Variable::Amount(1_000)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::MinimumDepth),
        Variable::BlockHeight(6)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::ToSelfDelay),
        Variable::U16(144)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::MaxAcceptedHtlcs),
        Variable::U16(483)
    );
}

#[test]
fn extract_channel_id() {
    let ac = sample_accept_channel();
    assert_eq!(
        extract_field(&ac, AcceptChannelField::TemporaryChannelId),
        Variable::ChannelId(TemporaryChannelId::new([0xbb; 32]))
    );
}

#[test]
fn extract_pubkeys() {
    let ac = sample_accept_channel();
    assert_eq!(
        extract_field(&ac, AcceptChannelField::FundingPubkey),
        Variable::Point(sample_pubkey(1))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::RevocationBasepoint),
        Variable::Point(sample_pubkey(2))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::PaymentBasepoint),
        Variable::Point(sample_pubkey(3))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::DelayedPaymentBasepoint),
        Variable::Point(sample_pubkey(4))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::HtlcBasepoint),
        Variable::Point(sample_pubkey(5))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::FirstPerCommitmentPoint),
        Variable::Point(sample_pubkey(6))
    );
}

#[test]
fn extract_tlvs_present() {
    let ac = sample_accept_channel();
    assert_eq!(
        extract_field(&ac, AcceptChannelField::UpfrontShutdownScript),
        Variable::Bytes(vec![0xde, 0xad])
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::ChannelType),
        Variable::Features(vec![0x40, 0x10, 0x00])
    );
}

#[test]
fn extract_tlvs_absent() {
    let ac = AcceptChannel {
        tlvs: AcceptChannelTlvs::default(),
        ..sample_accept_channel()
    };
    assert_eq!(
        extract_field(&ac, AcceptChannelField::UpfrontShutdownScript),
        Variable::Bytes(vec![])
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::ChannelType),
        Variable::Features(vec![])
    );
}

// -- Channel establishment v2 --

#[test]
fn execute_build_and_send_open_channel2() {
    let mut b = ProgramBuilder::new();
    let inputs = load_open_channel2_inputs(&mut b);
    send_open_channel2_with(&mut b, inputs, true);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let sent: OpenChannel2 = fx.sent(0);
    assert_eq!(sent.temporary_channel_id, sample_v2_temporary_channel_id());
    assert_eq!(sent.funding_feerate_perkw, 253);
    assert_eq!(sent.commitment_feerate_perkw, 2500);
    assert_eq!(sent.funding_satoshis, 200_000);
    assert_eq!(sent.locktime, 120);
    assert_eq!(sent.revocation_basepoint, sample_v2_revocation_basepoint());
    let secp = Secp256k1::new();
    assert_eq!(
        sent.second_per_commitment_point,
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x77; 32]).unwrap())
    );
    assert!(sent.tlvs.require_confirmed_inputs);
    assert_eq!(
        sent.tlvs.channel_type,
        Some(ChannelTypeVariant::Anchors.encode()),
    );
    // A zero-length upfront_shutdown_script is the BOLT 2 opt-out signal,
    // so the TLV is sent rather than omitted.
    assert_eq!(sent.tlvs.upfront_shutdown_script, Some(vec![]));

    // The negotiation is recorded so later steps can build from what we
    // actually put on the wire.
    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    assert_eq!(pending.open_channel2, sent);
    assert!(pending.accept_channel2.is_none());
    assert!(pending.channel_id.is_none());
}

#[test]
fn execute_build_open_channel2_omits_an_empty_channel_type() {
    let mut b = ProgramBuilder::new();
    let mut inputs = load_open_channel2_inputs(&mut b);
    // Replace the channel type with an empty feature vector.
    inputs.channel_type = b.append(Operation::LoadFeatures(vec![]), &[]);
    send_open_channel2_with(&mut b, inputs, false);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    // BOLT 2 requires open_channel2 to set channel_type, so omitting it
    // must stay reachable for fuzzing the receiver's rejection path.
    assert_eq!(fx.sent::<OpenChannel2>(0).tlvs.channel_type, None);
}

#[test]
fn execute_recv_accept_channel2_records_the_v2_channel_id() {
    let accept = sample_accept_channel2(sample_v2_temporary_channel_id());

    let mut fx = Fixture::new().queue(&Message::AcceptChannel2(accept.clone()));
    fx.run(&negotiate_channel2_program());

    let expected_channel_id = ChannelId::v2_from_revocation_basepoints(
        &sample_v2_revocation_basepoint(),
        &accept.revocation_basepoint,
    );
    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    assert_eq!(pending.accept_channel2.as_ref(), Some(&accept));
    assert_eq!(pending.channel_id, Some(expected_channel_id));
    // Later messages carry the v2 channel_id, and must reach the same
    // negotiation as its temporary_channel_id does.
    assert_eq!(
        fx.negotiation_v2(expected_channel_id).channel_id,
        Some(expected_channel_id),
    );
}

#[test]
fn execute_recv_accept_channel2_unknown_temporary_channel_id_is_ignored() {
    // An accept_channel2 answering a temporary_channel_id we never opened,
    // as a mutated program that dropped its open_channel2 would see.
    let accept = sample_accept_channel2(ChannelId::new([0x77; 32]));

    let mut fx = Fixture::new().queue(&Message::AcceptChannel2(accept));
    // Executes without reporting a violation.
    fx.run(&negotiate_channel2_program());

    // The unknown negotiation is not invented, and the one we did open is
    // left untouched: no accept_channel2 paired, so no channel_id derived
    // and nothing for a later message to reach it by.
    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    assert!(pending.accept_channel2.is_none());
    assert!(pending.channel_id.is_none());
}

#[test]
fn record_open_forgets_the_replaced_negotiations_channel_id() {
    let temporary_channel_id = sample_v2_temporary_channel_id();
    let mut negotiations = V2Negotiations::default();

    negotiations.record_open(&sample_open_channel2());
    negotiations.record_accept(&sample_accept_channel2(temporary_channel_id));
    assert!(negotiations.get(v2_channel_id()).is_some());

    // Reusing the temporary_channel_id starts a fresh negotiation, which
    // has derived no channel_id yet. A message still naming the replaced
    // negotiation's must not land on it.
    negotiations.record_open(&sample_open_channel2());

    assert!(negotiations.get(v2_channel_id()).is_none());
    assert!(negotiations.get(temporary_channel_id).is_some());
}

#[test]
fn execute_recv_accept_channel2_unexpected_message() {
    let mut fx = Fixture::new().queue(&Message::AcceptChannel(sample_accept_channel()));

    // A v1 accept_channel does not answer an open_channel2.
    let err = fx.run_err(&negotiate_channel2_program());

    assert!(
        matches!(
            err,
            ExecuteError::UnexpectedMessage {
                expected: MessageType::ACCEPT_CHANNEL2,
                ..
            }
        ),
        "unexpected error: {err}",
    );
}

#[test]
fn execute_extract_all_accept_channel2_fields() {
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel2(&mut b);
    for &field in AcceptChannel2Field::ALL {
        b.append(
            Operation::ExtractAcceptChannel2(field),
            &[negotiated.accept_channel2],
        );
    }
    let accept = sample_accept_channel2(sample_v2_temporary_channel_id());

    Fixture::new()
        .queue(&Message::AcceptChannel2(accept.clone()))
        .run(&b.build());

    // Every field extracts, and each one produces the type it declares.
    for &field in AcceptChannel2Field::ALL {
        let extracted = extract_field_v2(&accept, field);
        assert_eq!(
            extracted.var_type(),
            field.output_type(),
            "{field} produced the wrong variable type",
        );
    }
    assert_eq!(
        extract_field_v2(&accept, AcceptChannel2Field::FundingSatoshis),
        Variable::Amount(0),
    );
    assert_eq!(
        extract_field_v2(&accept, AcceptChannel2Field::SecondPerCommitmentPoint),
        Variable::Point(sample_pubkey(17)),
    );
    assert_eq!(
        extract_field_v2(&accept, AcceptChannel2Field::MinimumDepth),
        Variable::BlockHeight(6),
    );
}

#[test]
fn execute_derive_channel_id_v2_feeds_the_channel_id_on_the_wire() {
    // Runtime variables do not outlive execution, so observe
    // DeriveChannelIdV2 through the only field that carries a ChannelId
    // here: open_channel2's temporary_channel_id.
    let mut b = ProgramBuilder::new();
    let mut inputs = load_open_channel2_inputs(&mut b);
    let peer_revocation_basepoint = b.append(Operation::LoadTargetPubkeyFromContext, &[]);
    inputs.temporary_channel_id = b.append(
        Operation::DeriveChannelIdV2,
        &[inputs.revocation_basepoint, peer_revocation_basepoint],
    );
    send_open_channel2_with(&mut b, inputs, false);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    let sent: OpenChannel2 = fx.sent(0);
    assert_eq!(
        sent.temporary_channel_id,
        ChannelId::v2_from_revocation_basepoints(
            &sample_v2_revocation_basepoint(),
            &sample_context().target_pubkey,
        ),
    );
    // Both basepoints are mixed in, so this is not the temporary id.
    assert_ne!(sent.temporary_channel_id, sample_v2_temporary_channel_id());
}

#[test]
#[should_panic(expected = "expected OpenChannel2Message, got Amount")]
fn execute_send_open_channel2_wrong_type_panics() {
    let instructions = vec![
        Instruction {
            operation: Operation::LoadAmount(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendOpenChannel2,
            inputs: vec![0],
        },
    ];

    Fixture::new().run(&Program { instructions });
}

#[test]
#[should_panic(expected = "is void")]
fn execute_recv_accept_channel2_affine_overuse_panics() {
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel2(&mut b);
    let mut program = b.build();

    // `ProgramBuilder` rejects the reuse itself, so we manually append the
    // second receive instruction.
    program.instructions.push(Instruction {
        operation: Operation::RecvAcceptChannel2,
        inputs: vec![negotiated.open_channel2.sent],
    });
    let accept = sample_accept_channel2(sample_v2_temporary_channel_id());

    Fixture::new()
        .queue(&Message::AcceptChannel2(accept.clone()))
        .queue(&Message::AcceptChannel2(accept))
        .run(&program);
}

// -- Interactive transaction construction --

#[test]
fn execute_send_tx_add_input_proposes_a_wallet_utxo() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    send_tx_add_input(&mut b, channel_id, 2, 0);

    let mut fx = v2_fixture();
    fx.run(&b.build());

    let sent: TxAddInput = fx.last_sent();
    let prevtx = sample_prevtx();
    assert_eq!(sent.serial_id, 2);
    assert_eq!(sent.sequence, 0xffff_fffd);
    assert_eq!(sent.prevtx_vout, 0);
    assert_eq!(sent.prevtx, bitcoin::consensus::encode::serialize(&prevtx));

    // The input is recorded with the value we know from the wallet, so the
    // change output can be computed from it.
    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    let (serial_id, input) = pending
        .tx_exchange
        .shared_tx()
        .inputs()
        .next()
        .expect("input recorded");
    assert_eq!(serial_id, 2);
    assert_eq!(input.contributor, Contributor::Local);
    assert_eq!(input.outpoint.txid, prevtx.compute_txid());
    assert_eq!(input.value(), 100_000_000);
}

#[test]
fn execute_send_tx_add_input_locks_the_selected_utxo() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    send_tx_add_input(&mut b, channel_id, 2, 0);

    let mut fx = v2_fixture();
    fx.run(&b.build());

    // Locking is what stops a later selection proposing the same coin,
    // which the peer would reject as a duplicate input.
    assert_eq!(
        fx.bitcoin().locked_outpoints,
        vec![OutPoint {
            txid: sample_prevtx().compute_txid(),
            vout: 0,
        }],
    );
}

#[test]
fn execute_send_tx_add_input_with_an_empty_wallet_sends_an_empty_prevtx() {
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel2(&mut b);
    send_tx_add_input(
        &mut b,
        negotiated.open_channel2.inputs.temporary_channel_id,
        2,
        0,
    );

    // An empty wallet is not a harness error.
    let mut fx = Fixture::new()
        .with_utxos(vec![])
        .queue(&accept_channel2_reply());
    fx.run(&b.build());

    // Nothing to spend, so nothing to prove non-malleable. The message
    // still goes out for the peer to reject.
    assert!(fx.last_sent::<TxAddInput>().prevtx.is_empty());
}

#[test]
fn execute_send_tx_add_output_derives_the_funding_output() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    send_tx_add_output(&mut b, channel_id, 4, TxOutputRole::Funding);

    let mut fx = v2_fixture();
    fx.run(&b.build());

    let sent: TxAddOutput = fx.last_sent();
    // The acceptor contributes nothing, so the funding output is worth
    // exactly our open_channel2.funding_satoshis.
    assert_eq!(sent.sats, 200_000);
    let secp = Secp256k1::new();
    let funding_pubkey =
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
    let expected_script = build_funding_witness_script(
        &funding_pubkey,
        &sample_accept_channel2(sample_v2_temporary_channel_id()).funding_pubkey,
    )
    .to_p2wsh();
    assert_eq!(ScriptBuf::from(sent.script), expected_script);
}

#[test]
fn execute_send_tx_add_output_change_covers_the_funding_and_the_fee() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    send_tx_add_input(&mut b, channel_id, 2, 0);
    send_tx_add_output(&mut b, channel_id, 4, TxOutputRole::Funding);
    send_tx_add_output(&mut b, channel_id, 6, TxOutputRole::Change);

    let mut fx = v2_fixture();
    fx.run(&b.build());

    let sent: TxAddOutput = fx.last_sent();
    // One 1 BTC input, 200_000 sat to the funding output, and our share of
    // the fee at 253 sat/kw: weight 42 + 164 + 172 + 124 + 108 = 610,
    // giving ceil(610 * 253 / 1000) = 155 sat.
    assert_eq!(sent.sats, 100_000_000 - 200_000 - 155);
    assert_eq!(ScriptBuf::from(sent.script), sample_change_spk());
}

#[test]
fn execute_send_tx_add_output_explicit_uses_its_inputs() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    let sats = b.append(Operation::LoadAmount(200_000), &[]);
    let script = b.append(Operation::LoadBytes(vec![]), &[]);
    b.append(
        Operation::SendTxAddOutput {
            serial_id: 4,
            role: TxOutputRole::Explicit,
        },
        &[channel_id, sats, script],
    );

    let mut fx = v2_fixture();
    fx.run(&b.build());

    let sent: TxAddOutput = fx.last_sent();
    assert_eq!(sent.sats, 200_000);
    assert!(sent.script.is_empty());
}

#[test]
fn execute_send_tx_remove_input_keeps_the_peers_input() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    let sent = send_tx_add_input(&mut b, channel_id, 2, 0);
    // The peer contributes an input of its own.
    recv_interactive_tx(&mut b, sent);
    // BOLT 2 forbids removing an input the peer added. A peer that
    // receives one keeps its input, so we must keep it too or our
    // reconstruction of the shared transaction diverges from theirs.
    b.append(Operation::SendTxRemoveInput { serial_id: 3 }, &[channel_id]);
    b.append(Operation::SendTxRemoveInput { serial_id: 2 }, &[channel_id]);

    let mut fx = v2_fixture().queue(&tx_add_input_reply(v2_channel_id(), 3));
    fx.run(&b.build());

    // Ours is gone, the peer's survives.
    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    let remaining: Vec<u64> = pending
        .tx_exchange
        .shared_tx()
        .inputs()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(remaining, vec![3]);

    // Both removals still went on the wire; only our own changed local
    // state, so the peer gets to reject the illegal one.
    let removals = fx
        .sent_types()
        .iter()
        .filter(|ty| **ty == MessageType::TX_REMOVE_INPUT)
        .count();
    assert_eq!(removals, 2);
}

#[test]
fn execute_send_tx_remove_output_keeps_the_peers_output() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    let sent = send_tx_add_output(&mut b, channel_id, 4, TxOutputRole::Funding);
    // The peer contributes an output of its own.
    recv_interactive_tx(&mut b, sent);
    b.append(
        Operation::SendTxRemoveOutput { serial_id: 5 },
        &[channel_id],
    );
    b.append(
        Operation::SendTxRemoveOutput { serial_id: 4 },
        &[channel_id],
    );

    let mut fx = v2_fixture().queue(&tx_add_output_reply(v2_channel_id(), 5));
    fx.run(&b.build());

    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    let remaining: Vec<u64> = pending
        .tx_exchange
        .shared_tx()
        .outputs()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(remaining, vec![5]);
}

#[test]
fn execute_recv_interactive_tx_records_peer_contributions() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    let sent = send_tx_complete(&mut b, channel_id);
    recv_interactive_tx(&mut b, sent);

    // The non-initiator uses odd serial ids.
    let mut fx = v2_fixture().queue(&tx_add_input_reply(v2_channel_id(), 3));
    fx.run(&b.build());

    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    let (serial_id, input) = pending
        .tx_exchange
        .shared_tx()
        .inputs()
        .next()
        .expect("input recorded");
    assert_eq!(serial_id, 3);
    assert_eq!(input.contributor, Contributor::Remote);
    assert_eq!(input.value(), 100_000_000);
    // The peer answered with a contribution, not a tx_complete, so our
    // tx_complete did not conclude the exchange.
    assert!(!pending.tx_exchange.concluded());
}

#[test]
fn execute_recv_interactive_tx_remove_input_keeps_our_input() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    let sent = send_tx_add_input(&mut b, channel_id, 2, 0);
    recv_interactive_tx(&mut b, sent); // the peer adds an input
    let sent = send_tx_complete(&mut b, channel_id);
    recv_interactive_tx(&mut b, sent); // the peer removes ours, which BOLT 2 forbids
    let sent = send_tx_complete(&mut b, channel_id);
    recv_interactive_tx(&mut b, sent); // the peer removes its own

    let mut fx = v2_fixture()
        .queue(&tx_add_input_reply(v2_channel_id(), 3))
        .queue(&tx_remove_input_reply(v2_channel_id(), 2))
        .queue(&tx_remove_input_reply(v2_channel_id(), 3));
    fx.run(&b.build());

    // The peer's illegal removal left ours in place; its own is gone.
    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    let remaining: Vec<u64> = pending
        .tx_exchange
        .shared_tx()
        .inputs()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(remaining, vec![2]);
}

#[test]
fn execute_recv_interactive_tx_remove_output_keeps_our_output() {
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    let sent = send_tx_add_output(&mut b, channel_id, 4, TxOutputRole::Funding);
    recv_interactive_tx(&mut b, sent); // the peer adds an output
    let sent = send_tx_complete(&mut b, channel_id);
    recv_interactive_tx(&mut b, sent); // the peer removes ours, which BOLT 2 forbids
    let sent = send_tx_complete(&mut b, channel_id);
    recv_interactive_tx(&mut b, sent); // the peer removes its own

    let mut fx = v2_fixture()
        .queue(&tx_add_output_reply(v2_channel_id(), 5))
        .queue(&tx_remove_output_reply(v2_channel_id(), 4))
        .queue(&tx_remove_output_reply(v2_channel_id(), 5));
    fx.run(&b.build());

    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    let remaining: Vec<u64> = pending
        .tx_exchange
        .shared_tx()
        .outputs()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(remaining, vec![4]);
}

#[test]
fn execute_recv_interactive_tx_for_an_unknown_channel_is_ignored() {
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel2(&mut b);
    let sent = send_tx_complete(&mut b, negotiated.open_channel2.inputs.temporary_channel_id);
    recv_interactive_tx(&mut b, sent);

    // An unknown channel_id is not a harness error.
    let mut fx = v2_fixture().queue(&tx_complete_reply(ChannelId::new([0x99; 32])));
    fx.run(&b.build());

    // Only the peer can tell whether that message is consistent with its
    // own view, so nothing is invented on our side: the reply to our
    // tx_complete is still owed.
    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    assert!(!pending.tx_exchange.concluded());
    assert_eq!(pending.tx_exchange.outstanding_replies(), 1);
}

#[test]
fn execute_recv_interactive_tx_unexpected_message() {
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel2(&mut b);
    let sent = send_tx_complete(&mut b, negotiated.open_channel2.inputs.temporary_channel_id);
    recv_interactive_tx(&mut b, sent);

    // An accept_channel does not belong in an interactive tx exchange.
    let mut fx = v2_fixture().queue(&Message::AcceptChannel(sample_accept_channel()));
    let err = fx.run_err(&b.build());

    assert!(
        matches!(err, ExecuteError::UnexpectedMessage { .. }),
        "unexpected error: {err}",
    );
}

#[test]
#[should_panic(expected = "is void")]
fn execute_recv_interactive_tx_affine_overuse_panics() {
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel2(&mut b);
    let sent = send_tx_complete(&mut b, negotiated.open_channel2.inputs.temporary_channel_id);
    recv_interactive_tx(&mut b, sent);
    let mut program = b.build();

    // The turn-based protocol earns one receive per send. `ProgramBuilder`
    // rejects the reuse itself, so we manually append the second receive.
    program.instructions.push(Instruction {
        operation: Operation::RecvInteractiveTx,
        inputs: vec![sent],
    });

    // Enough for the first receive to succeed, so the second one fails on
    // the consumed token rather than on an empty queue.
    v2_fixture()
        .queue(&tx_complete_reply(sample_v2_temporary_channel_id()))
        .run(&program);
}

#[test]
fn execute_build_funding_transaction_v2_locates_the_funding_output() {
    let mut b = ProgramBuilder::new();
    v2_funding_flow(&mut b);

    let mut fx = v2_flow_fixture();
    fx.run(&b.build());

    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    let secp = Secp256k1::new();
    let funding_pubkey =
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
    let funding = pending.tx_exchange.shared_tx().build_funding(
        &build_funding_witness_script(
            &funding_pubkey,
            &sample_accept_channel2(sample_v2_temporary_channel_id()).funding_pubkey,
        )
        .to_p2wsh(),
        200_000,
    );
    // Serial 4 (funding) sorts before serial 6 (change).
    assert_eq!(funding.vout, 0);
    assert_eq!(funding.tx.input.len(), 1);
    assert_eq!(funding.tx.output.len(), 2);
    assert_eq!(funding.tx.output[0].value.to_sat(), 200_000);
    assert_eq!(funding.tx.lock_time.to_consensus_u32(), 120);
}

#[test]
fn execute_build_funding_transaction_v2_unknown_channel_is_empty() {
    let mut b = ProgramBuilder::new();
    let channel_id = b.append(Operation::LoadChannelId([0x99; 32]), &[]);
    let funding_tx = b.append(Operation::BuildFundingTransactionV2, &[channel_id]);
    // The empty sentinel must flow into its consumers without panicking.
    b.append(Operation::BroadcastTransaction, &[funding_tx]);

    // An unknown channel_id is not a harness error.
    Fixture::new().run(&b.build());
}

#[test]
fn execute_recv_interactive_tx_stops_once_the_exchange_concludes() {
    // The exchange from a real Eclair run: the peer, contributing nothing,
    // answers each of our messages with tx_complete. Our own tx_complete
    // then makes two consecutive ones, concluding the exchange, and the
    // peer moves straight on to commitment_signed.
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    // Each send is followed by the peer's reply, as the turn-based
    // protocol and the generator both require.
    let sent = send_tx_add_input(&mut b, channel_id, 2, 0);
    recv_interactive_tx(&mut b, sent);
    let sent = send_tx_add_output(&mut b, channel_id, 2000, TxOutputRole::Funding);
    recv_interactive_tx(&mut b, sent);
    let sent = send_tx_add_output(&mut b, channel_id, 2002, TxOutputRole::Change);
    recv_interactive_tx(&mut b, sent);
    let sent = send_tx_complete(&mut b, channel_id);
    recv_interactive_tx(&mut b, sent);

    // One tx_complete per message we send before our own tx_complete, then
    // what the peer sends next, which the concluded exchange must not eat.
    let mut fx = v2_flow_fixture().queue(&commitment_signed_reply(v2_channel_id()));
    fx.run(&b.build());

    assert_eq!(
        fx.negotiation_v2(sample_v2_temporary_channel_id())
            .tx_exchange
            .outstanding_replies(),
        0,
    );
    // The commitment_signed is still queued for whoever asks for it next.
    // Consuming it here would leave every later operation one message
    // behind, and the program would fail on a message it never expected.
    assert_eq!(fx.queued_types(), vec![MessageType::COMMITMENT_SIGNED]);
}

#[test]
fn execute_recv_interactive_tx_settles_a_backlog_left_by_a_dropped_receive() {
    // A mutated program: the first tx_add_input has no paired receive, so
    // every later receive is answering an earlier message. The peer still
    // replies to all five contributions and stays silent after the
    // tx_complete that concludes the exchange, leaving one reply owed.
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    // The receive after this first send is the one a mutator dropped.
    send_tx_add_input(&mut b, channel_id, 2, 0);
    let sent = send_tx_add_input(&mut b, channel_id, 4, 1);
    recv_interactive_tx(&mut b, sent);
    let sent = send_tx_add_output(&mut b, channel_id, 2000, TxOutputRole::Funding);
    recv_interactive_tx(&mut b, sent);
    let sent = send_tx_add_output(&mut b, channel_id, 2002, TxOutputRole::Change);
    recv_interactive_tx(&mut b, sent);
    let sent = send_tx_complete(&mut b, channel_id);
    // The receive after our tx_complete is the one that must settle the
    // backlog rather than skip: the exchange has concluded, but a reply to
    // an earlier message is still owed.
    recv_interactive_tx(&mut b, sent);

    // One reply per contribution; none for the concluding tx_complete.
    let mut fx = v2_fixture()
        .queue_repeated(&tx_complete_reply(v2_channel_id()), 4)
        .queue(&commitment_signed_reply(v2_channel_id()));
    fx.run(&b.build());

    // Every owed reply was read, so the commitment_signed is still there
    // for the operation that actually wants it.
    assert_eq!(
        fx.negotiation_v2(sample_v2_temporary_channel_id())
            .tx_exchange
            .outstanding_replies(),
        0,
    );
    assert_eq!(fx.queued_types(), vec![MessageType::COMMITMENT_SIGNED]);
}

#[test]
fn execute_recv_interactive_tx_drops_contributions_sent_after_the_conclusion() {
    // A mutated program from a real CLN run: three inputs go out, with the
    // last two replies left unread, then the funding output, a tx_complete
    // and a change output. From the peer's side its tx_complete answering
    // the funding output and our tx_complete are consecutive, so the
    // exchange concludes without the change output. Our transaction must
    // agree, or the peer's perfectly good commitment signature reads as
    // invalid.
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    let sent = send_tx_add_input(&mut b, channel_id, 2, 0);
    recv_interactive_tx(&mut b, sent);
    let sent = send_tx_add_input(&mut b, channel_id, 4, 1);
    recv_interactive_tx(&mut b, sent);
    let third_input = send_tx_add_input(&mut b, channel_id, 6, 2);
    send_tx_add_output(&mut b, channel_id, 2000, TxOutputRole::Funding);
    let complete = send_tx_complete(&mut b, channel_id);
    let change = send_tx_add_output(&mut b, channel_id, 2002, TxOutputRole::Change);
    recv_interactive_tx(&mut b, change);
    recv_interactive_tx(&mut b, complete);
    // The exchange has concluded, so this one has nothing to read.
    recv_interactive_tx(&mut b, third_input);

    // One tx_complete per message before our own tx_complete; the peer then
    // moves straight on to commitment_signed.
    let mut fx = v2_fixture()
        .queue_repeated(&tx_complete_reply(v2_channel_id()), 4)
        .queue(&commitment_signed_reply(v2_channel_id()));
    fx.run(&b.build());

    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    assert!(pending.tx_exchange.concluded());
    assert_eq!(pending.tx_exchange.outstanding_replies(), 0);
    let inputs: Vec<u64> = pending
        .tx_exchange
        .shared_tx()
        .inputs()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(inputs, vec![2, 4, 6]);
    let outputs: Vec<u64> = pending
        .tx_exchange
        .shared_tx()
        .outputs()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        outputs,
        vec![2000],
        "the late change output is not the peer's"
    );
    assert_eq!(fx.queued_types(), vec![MessageType::COMMITMENT_SIGNED]);
}

#[test]
fn execute_send_after_a_known_conclusion_is_not_recorded() {
    // The peer's tx_complete has been read, so ours concludes the exchange
    // on the spot and a later contribution is neither recorded nor waited on.
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    let sent = send_tx_add_output(&mut b, channel_id, 2000, TxOutputRole::Funding);
    recv_interactive_tx(&mut b, sent);
    let complete = send_tx_complete(&mut b, channel_id);
    let change = send_tx_add_output(&mut b, channel_id, 2002, TxOutputRole::Change);
    recv_interactive_tx(&mut b, change);
    recv_interactive_tx(&mut b, complete);

    let mut fx = v2_fixture().queue(&tx_complete_reply(v2_channel_id()));
    fx.run(&b.build());

    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    assert!(pending.tx_exchange.concluded());
    assert_eq!(pending.tx_exchange.outstanding_replies(), 0);
    let outputs: Vec<u64> = pending
        .tx_exchange
        .shared_tx()
        .outputs()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(outputs, vec![2000]);
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_interactive_tx_still_reads_mid_exchange() {
    // Three contributions go out and only one reply is read. The peer's
    // tx_complete answered our first send, not our latest, so the exchange
    // is not concluded and the receive must not be skipped.
    let mut b = ProgramBuilder::new();
    let channel_id = negotiate_v2_channel(&mut b);
    send_tx_add_input(&mut b, channel_id, 2, 0);
    send_tx_add_input(&mut b, channel_id, 4, 1);
    let sent = send_tx_add_input(&mut b, channel_id, 6, 2);
    recv_interactive_tx(&mut b, sent);

    let mut fx = v2_fixture().queue(&tx_complete_reply(v2_channel_id()));
    fx.run(&b.build());

    assert_eq!(fx.queued_len(), 0, "the reply was not read");
    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    // The peer still owes two replies and the next receive must not skip
    // either.
    assert!(!pending.tx_exchange.concluded());
    assert_eq!(pending.tx_exchange.outstanding_replies(), 2);
}

#[test]
fn execute_recv_interactive_tx_records_a_peer_abort() {
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel2(&mut b);
    let sent = send_tx_complete(&mut b, negotiated.open_channel2.inputs.temporary_channel_id);
    recv_interactive_tx(&mut b, sent);

    // An abort is normal protocol behaviour, not a harness error.
    let mut fx = v2_fixture().queue(&Message::TxAbort(TxAbort::new(
        sample_v2_temporary_channel_id(),
        "funding output not to spec",
    )));
    fx.run(&b.build());

    let pending = fx.negotiation_v2(sample_v2_temporary_channel_id());
    assert!(pending.tx_exchange.aborted());
    // An abort is not a tx_complete, so the negotiation has not concluded.
    assert!(!pending.tx_exchange.concluded());
}
