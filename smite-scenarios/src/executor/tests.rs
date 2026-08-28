mod harness;
mod programs;

use std::str::FromStr;

use super::*;
use bitcoin::Amount;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use harness::*;
use programs::*;
use smite::bolt::{AcceptChannelTlvs, GossipTimestampFilter, Init, Ping};
use smite::pending_channel::PendingChannelV2;
use smite_ir::Instruction;
use smite_ir::operation::{ChannelTypeVariant, ShutdownScriptVariant};

/// Decodes a sent message expected to be a `channel_announcement`.
fn decode_sent_channel_announcement(bytes: &[u8]) -> ChannelAnnouncement {
    match Message::decode(bytes).expect("valid message") {
        Message::ChannelAnnouncement(ca) => ca,
        other => panic!("expected channel_announcement(256), got {other}"),
    }
}

fn decode_open_channel(bytes: &[u8]) -> OpenChannel {
    match Message::decode(bytes).expect("valid message") {
        Message::OpenChannel(oc) => oc,
        other => panic!("expected open_channel(32), got {other}"),
    }
}

fn decode_open_channel2(bytes: &[u8]) -> OpenChannel2 {
    match Message::decode(bytes).expect("valid open_channel2") {
        Message::OpenChannel2(oc) => oc,
        other => panic!("expected open_channel2, got {other}"),
    }
}
// -- execute() tests --

#[test]
fn execute_load_build_send() {
    let pk = sample_pubkey(1);
    let mut instrs = open_channel_instructions();
    instrs.push(Instruction {
        operation: Operation::BuildOpenChannel,
        inputs: (0..20).collect(),
    });
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![20],
    });

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    assert_eq!(executor.conn.sent.len(), 1);
    let oc = decode_open_channel(&executor.conn.sent[0]);
    assert_eq!(oc.chain_hash, [0xcc; 32]);
    assert_eq!(oc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(oc.funding_satoshis, 100_000);
    assert_eq!(oc.push_msat, 0);
    assert_eq!(oc.dust_limit_satoshis, 546);
    assert_eq!(oc.max_htlc_value_in_flight_msat, 100_000_000);
    assert_eq!(oc.channel_reserve_satoshis, 10_000);
    assert_eq!(oc.htlc_minimum_msat, 1_000);
    assert_eq!(oc.feerate_per_kw, 253);
    assert_eq!(oc.to_self_delay, 144);
    assert_eq!(oc.max_accepted_htlcs, 483);
    assert_eq!(oc.funding_pubkey, pk);
    assert_eq!(oc.revocation_basepoint, pk);
    assert_eq!(oc.payment_basepoint, pk);
    assert_eq!(oc.delayed_payment_basepoint, pk);
    assert_eq!(oc.htlc_basepoint, pk);
    assert_eq!(oc.first_per_commitment_point, pk);
    assert_eq!(oc.channel_flags, 1);
    assert_eq!(oc.tlvs.upfront_shutdown_script, Some(vec![]));
    assert_eq!(oc.tlvs.channel_type, Some(vec![0x40, 0x10, 0x00]));
}

#[test]
fn execute_build_channel_announcement() {
    let node_sk_1_bytes = [0x11; 32];
    let node_sk_2_bytes = [0x22; 32];
    let bitcoin_sk_1_bytes = [0x33; 32];
    let bitcoin_sk_2_bytes = [0x44; 32];
    let scid = ShortChannelId::new(539_268, 845, 1);
    let features = vec![0x01, 0x02];

    let instrs = vec![
        Instruction {
            operation: Operation::LoadFeatures(features.clone()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadShortChannelId(scid.as_u64()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(node_sk_1_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(node_sk_2_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(bitcoin_sk_1_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(bitcoin_sk_2_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildChannelAnnouncement,
            inputs: vec![0, 1, 2, 3, 4, 5, 6],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![7],
        },
    ];

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    assert_eq!(executor.conn.sent.len(), 1);
    let ca = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
        Message::ChannelAnnouncement(ca) => ca,
        other => panic!("expected channel_announcement(256), got {other}"),
    };

    let secp = Secp256k1::new();
    let pk = |b: &[u8; 32]| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(b).unwrap());
    assert_eq!(ca.features, features);
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
    let addresses = vec![0xaa, 0xbb, 0xcc];

    let instrs = vec![
        Instruction {
            operation: Operation::LoadPrivateKey(sk_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(vec![0x01, 0x02]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTimestamp(1_700_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadBytes(addresses.clone()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildNodeAnnouncement { rgb_color, alias },
            inputs: vec![0, 1, 2, 3],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![4],
        },
    ];

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    assert_eq!(executor.conn.sent.len(), 1);
    let na = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
        Message::NodeAnnouncement(na) => na,
        other => panic!("expected node_announcement(257), got {other}"),
    };

    let secp = Secp256k1::new();
    let expected_node_id =
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
    assert_eq!(na.node_id, expected_node_id);
    assert_eq!(na.features, vec![0x01, 0x02]);
    assert_eq!(na.timestamp, 1_700_000_000);
    assert_eq!(na.rgb_color, rgb_color);
    assert_eq!(na.alias, alias);
    assert_eq!(na.addresses, addresses);
    assert!(na.extra.is_empty());
    assert!(na.verify());
}

#[test]
fn execute_build_channel_update() {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 0x42;
    let scid = ShortChannelId::new(538_532, 845, 1);

    let instrs = vec![
        Instruction {
            operation: Operation::LoadPrivateKey(sk_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadShortChannelId(scid.as_u64()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTimestamp(1_715_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU8(0x01), // message_flags: must_be_one
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU8(0x00), // channel_flags
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(144), // cltv_expiry_delta
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1_000), // htlc_minimum_msat
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadForwardingFee(1_000), // fee_base_msat
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadForwardingFee(100), // fee_proportional_millionths
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(99_000_000), // htlc_maximum_msat
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildChannelUpdate,
            inputs: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![11],
        },
    ];

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    assert_eq!(executor.conn.sent.len(), 1);
    let cu = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
        Message::ChannelUpdate(cu) => cu,
        other => panic!("expected channel_update(258), got {other}"),
    };

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
#[allow(clippy::too_many_lines)]
fn execute_build_announcement_signatures() {
    let node_sk_1_bytes = [0x11; 32];
    let node_sk_2_bytes = [0x22; 32];
    let bitcoin_sk_1_bytes = [0x33; 32];
    let bitcoin_sk_2_bytes = [0x44; 32];
    let channel_id_bytes = [0xbb; 32];
    let scid = ShortChannelId::new(539_268, 845, 1);
    let features = vec![0x01, 0x02];

    // Instruction layout:
    //  v0 = LoadChannelId
    //  v1 = LoadFeatures
    //  v2 = LoadChainHashFromContext
    //  v3 = LoadShortChannelId
    //  v4 = LoadPrivateKey(node_sk_1)     -- our node signing key
    //  v5 = LoadPrivateKey(node_sk_2)     -- target's node key (derive pubkey from)
    //  v6 = DerivePoint(v5)               -- node_id_2 (target's node pubkey)
    //  v7 = LoadPrivateKey(bitcoin_sk_1)  -- our bitcoin signing key
    //  v8 = LoadPrivateKey(bitcoin_sk_2)  -- target's bitcoin key (derive pubkey from)
    //  v9 = DerivePoint(v8)               -- bitcoin_key_2 (target's bitcoin pubkey)
    // v10 = BuildAnnouncementSignatures(v0, v1, v2, v3, v4, v6, v7, v9)
    // v11 = SendMessage(v10)
    let instrs = vec![
        Instruction {
            operation: Operation::LoadChannelId(channel_id_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(features.clone()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadShortChannelId(scid.as_u64()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(node_sk_1_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(node_sk_2_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![5],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(bitcoin_sk_1_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(bitcoin_sk_2_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![8],
        },
        Instruction {
            operation: Operation::BuildAnnouncementSignatures,
            inputs: vec![0, 1, 2, 3, 4, 6, 7, 9],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![10],
        },
    ];

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    assert_eq!(executor.conn.sent.len(), 1);
    let ann_sigs = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
        Message::AnnouncementSignatures(s) => s,
        other => panic!("expected announcement_signatures(259), got {other}"),
    };

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
        features,
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
    let mut instrs = open_channel_instructions();
    instrs[18] = Instruction {
        operation: Operation::LoadBytes(vec![0x00, 0x14, 0xab]),
        inputs: vec![],
    };
    instrs[19] = Instruction {
        operation: Operation::LoadFeatures(vec![0x01, 0x02]),
        inputs: vec![],
    };
    instrs.push(Instruction {
        operation: Operation::BuildOpenChannel,
        inputs: (0..20).collect(),
    });
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![20],
    });

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    let oc = decode_open_channel(&executor.conn.sent[0]);
    assert_eq!(
        oc.tlvs.upfront_shutdown_script,
        Some(vec![0x00, 0x14, 0xab])
    );
    assert_eq!(oc.tlvs.channel_type, Some(vec![0x01, 0x02]));
}

#[test]
fn execute_derive_point() {
    let mut instrs = vec![
        Instruction {
            operation: Operation::LoadPrivateKey([0x11; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
    ];

    // Use the derived point in a BuildOpenChannel to verify it produced a
    // valid Point variable.
    let base = instrs.len();
    instrs.extend(open_channel_instructions());
    // Replace funding_pubkey (input 11) with the derived point (v1).
    let mut build_inputs: Vec<usize> = (base..base + 20).collect();
    build_inputs[11] = 1;
    instrs.push(Instruction {
        operation: Operation::BuildOpenChannel,
        inputs: build_inputs,
    });
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![base + 20],
    });

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    let oc = decode_open_channel(&executor.conn.sent[0]);
    let secp = Secp256k1::new();
    let expected = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
    assert_eq!(oc.funding_pubkey, expected);
}

#[test]
fn execute_recv_and_extract_all_fields() {
    let ac = sample_accept_channel();
    let ac_bytes = Message::AcceptChannel(ac).encode();

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

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let accept_channel_idx = instrs.len() - 1;
    for field in fields {
        instrs.push(Instruction {
            operation: Operation::ExtractAcceptChannel(field),
            inputs: vec![accept_channel_idx],
        });
    }

    // TODO: Once we add IR support for building accept_channel messages,
    // rebuild a message from the extracted fields and verify it matches the
    // original.

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(ac_bytes);
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();
}

#[test]
fn execute_recv_unexpected_message() {
    let init_bytes = Message::Init(Init::empty()).encode();

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(init_bytes);
    let err = executor
        .execute(&program, std::time::Instant::now())
        .unwrap_err();
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
    let error_bytes = Message::Error(peer_error.clone()).encode();

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(error_bytes);
    let err = executor
        .execute(&program, std::time::Instant::now())
        .unwrap_err();
    assert!(matches!(err, ExecuteError::PeerError(e) if e == peer_error));
}

#[test]
#[allow(clippy::similar_names)] // ping and pong are the canonical names
fn execute_recv_auto_pong() {
    let ping = Ping {
        num_pong_bytes: 4,
        ignored: vec![0xaa],
    };
    let ping_bytes = Message::Ping(ping).encode();
    let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });

    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(ping_bytes);
    executor.conn.queue_recv(ac_bytes);
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    // Verify exactly two messages were sent: `open_channel` and `pong`.
    assert_eq!(executor.conn.sent.len(), 2);

    // Verify the first message was `open_channel`.
    let oc = Message::decode(&executor.conn.sent[0]).unwrap();
    let Message::OpenChannel(_) = oc else {
        panic!("expected open_channel(32), got {oc}");
    };

    // Verify the second message was the pong.
    let pong = Message::decode(&executor.conn.sent[1]).unwrap();
    let Message::Pong(pong) = pong else {
        panic!("expected pong(19), got {pong}");
    };
    assert_eq!(pong.ignored.len(), 4);
}

#[test]
fn execute_recv_skips_gossip() {
    let gossip = GossipTimestampFilter::new([0u8; 32], 0, 86400);
    let gossip_bytes = Message::GossipTimestampFilter(gossip).encode();
    let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(gossip_bytes);
    executor.conn.queue_recv(ac_bytes);
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    let accept_channel = executor
        .negotiations
        .values()
        .next()
        .and_then(|pending| pending.accept_channel.as_ref())
        .expect("accept_channel recorded");
    assert_eq!(accept_channel.clone(), sample_accept_channel());
}

#[test]
fn execute_records_negotiation_for_open_and_accept() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);
    let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(ac_bytes);
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    let pending = executor.negotiations.get(&temporary_channel_id).unwrap();
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
    let ac_bytes = Message::AcceptChannel(AcceptChannel {
        temporary_channel_id: unknown_id,
        ..sample_accept_channel()
    })
    .encode();

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(ac_bytes);
    let err = executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap_err();

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
    let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

    // Set `push_msat` so the opener cannot afford the commitment fee
    // requiring the peer to reject the `open_channel` per BOLT 2.
    let mut instrs = send_open_channel_instructions();
    instrs[3] = Instruction {
        operation: Operation::LoadAmount(99_900_000),
        inputs: vec![],
    };
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });

    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(ac_bytes);
    let err = executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap_err();

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
    let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

    let mut instrs = send_open_channel_instructions();
    let built_open_channel = instrs.len() - 2;
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let resent_open_channel = instrs.len();
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![built_open_channel],
    });
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![resent_open_channel],
    });

    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(ac_bytes.clone());
    executor.conn.queue_recv(ac_bytes.clone());
    let err = executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap_err();

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
    let mut instrs = send_open_channel_instructions();

    // Override only funding_satoshis; reuse the first open_channel's other 19 inputs.
    let funding_satoshis = instrs.len();
    instrs.push(Instruction {
        operation: Operation::LoadAmount(200_000),
        inputs: vec![],
    });
    let mut build_inputs: Vec<usize> = (0..20).collect();
    build_inputs[2] = funding_satoshis;

    let built = instrs.len();
    instrs.push(Instruction {
        operation: Operation::BuildOpenChannel,
        inputs: build_inputs,
    });
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![built],
    });

    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    // Both open_channel messages went out on the wire, but only the first
    // negotiation is recorded for the shared id.
    assert_eq!(executor.conn.sent.len(), 2);
    assert_eq!(
        decode_open_channel(&executor.conn.sent[0]).funding_satoshis,
        100_000
    );
    assert_eq!(
        decode_open_channel(&executor.conn.sent[1]).funding_satoshis,
        200_000
    );
    let pending = executor.negotiations.get(&temporary_channel_id).unwrap();
    assert_eq!(pending.open_channel.funding_satoshis, 100_000);
}

#[test]
fn execute_records_open_channel_for_duplicate_id_after_funding() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };

    // Negotiated open_channel: funding_satoshis = 10_000_000.
    // Second open_channel: same temporary_channel_id, funding_satoshis = 100_000.
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.
    // The second program's input indices are shifted past the funding
    // flow's variables.
    let offset = instrs.len();
    for mut instr in send_open_channel_instructions() {
        for input in &mut instr.inputs {
            *input += offset;
        }
        instrs.push(instr);
    }

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor
        .negotiations
        .insert(temporary_channel_id, sample_funding_negotiation());
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    let pending = executor.negotiations.get(&temporary_channel_id).unwrap();
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
    let _ = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    )
    .execute(&program, std::time::Instant::now());
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
    let _ = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    )
    .execute(&program, std::time::Instant::now());
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
    let _ = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    )
    .execute(&program, std::time::Instant::now());
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
    let _ = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    )
    .execute(&program, std::time::Instant::now());
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
    let _ = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    )
    .execute(&program, std::time::Instant::now());
}

#[test]
#[should_panic(expected = "valid private key")]
fn execute_invalid_private_key_panics() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey([0; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ],
    };
    let _ = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    )
    .execute(&program, std::time::Instant::now());
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

    let _ = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    )
    .execute(&program, std::time::Instant::now());
}

#[test]
#[should_panic(expected = "is void")]
fn execute_affine_overuse_panics() {
    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.extend([
        Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        },
        Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        },
    ]);
    let program = Program {
        instructions: instrs,
    };
    let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor.conn.queue_recv(ac_bytes);
    let _ = executor.execute(&program, std::time::Instant::now());
}

// MineBlocks should track calls to mine_blocks
#[test]
fn execute_mine_blocks_invokes_cli() {
    let instrs = vec![Instruction {
        operation: Operation::MineBlocks(6),
        inputs: vec![],
    }];
    let program = Program {
        instructions: instrs,
    };
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    // Verify that mine_blocks was called with the correct number
    assert_eq!(executor.bitcoin_cli.mine_blocks_calls, vec![6]);
    assert!(executor.bitcoin_cli.mined_private_mempool.is_empty());
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
    let _ = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    )
    .execute(&program, std::time::Instant::now());
}

#[test]
fn execute_create_and_broadcast_tx() {
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };
    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor
        .execute(
            &Program {
                instructions: create_and_broadcast_tx_instructions(),
            },
            std::time::Instant::now(),
        )
        .expect("tx construction and broadcast should succeed");

    assert_eq!(executor.bitcoin_cli.broadcast_calls.len(), 1);
    let broadcast_tx = &executor.bitcoin_cli.broadcast_calls[0];
    assert_eq!(
        broadcast_tx.compute_txid().to_string(),
        "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
    );
}

// LookupShortChannelId should combine the confirmed block position with
// the funding output's vout to produce the correct SCID, which we verify
// by feeding it into a channel_announcement and decoding the sent message.
#[test]
fn execute_lookup_short_channel_id_confirmed() {
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };
    let mut instrs = create_and_broadcast_tx_instructions();
    instrs.push(Instruction {
        operation: Operation::MineBlocks(6),
        inputs: vec![],
    });
    instrs.push(Instruction {
        // Feed the FundingTransaction produced by
        // CreateFundingTransaction (instruction 6) into the lookup. The
        // resulting ShortChannelId is variable 9.
        operation: Operation::LookupShortChannelId,
        inputs: vec![6],
    });
    // Build and send a channel_announcement carrying the looked-up SCID.
    instrs.extend(channel_announcement_from_scid_instructions(instrs.len(), 9));

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .expect("lookup after confirmation should succeed");

    assert_eq!(executor.bitcoin_cli.mine_blocks_calls, vec![6]);
    // The executor must have queried the mock with the broadcast
    // transaction's txid.
    assert_eq!(executor.bitcoin_cli.block_position_lookups.len(), 1);
    let broadcast_txid = executor.bitcoin_cli.broadcast_calls[0].compute_txid();
    assert_eq!(
        executor.bitcoin_cli.block_position_lookups[0],
        broadcast_txid,
    );

    // The mock returns block_height=800_042, tx_index=7 for a confirmed
    // tx, and the funding output is always at vout 0.
    let ca = decode_sent_channel_announcement(&executor.conn.sent[0]);
    assert_eq!(ca.short_channel_id, ShortChannelId::new(800_042, 7, 0));
}

// LookupShortChannelId should produce the sentinel SCID (0/0/0) when the
// funding transaction is unknown to the node (e.g. never broadcast or
// never confirmed), rather than panicking. We verify the sentinel value
// via the SCID carried in a channel_announcement.
#[test]
fn execute_lookup_short_channel_id_unconfirmed_returns_sentinel() {
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };
    // No BroadcastTransaction and no MineBlocks: the mock reports zero
    // confirmations and get_transaction_block_position returns None.
    let mut instrs = vec![
        Instruction {
            operation: Operation::LoadPrivateKey([1u8; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([2u8; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![2],
        },
        Instruction {
            operation: Operation::LoadAmount(10_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeeratePerKw(15_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::CreateFundingTransaction,
            inputs: vec![1, 3, 4, 5],
        },
        // The looked-up SCID is variable 7.
        Instruction {
            operation: Operation::LookupShortChannelId,
            inputs: vec![6],
        },
    ];
    instrs.extend(channel_announcement_from_scid_instructions(instrs.len(), 7));

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .expect("lookup on unconfirmed tx should not fail");
    // The mock was queried but returned None (zero confirmations), so the
    // executor took the sentinel path without panicking.
    assert!(executor.bitcoin_cli.mine_blocks_calls.is_empty());
    assert_eq!(executor.bitcoin_cli.block_position_lookups.len(), 1);

    let ca = decode_sent_channel_announcement(&executor.conn.sent[0]);
    assert_eq!(ca.short_channel_id, ShortChannelId::new(0, 0, 0));
}

#[test]
fn execute_broadcast_dedupes_rejected_tx_in_private_mempool() {
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };

    // Fund with a dust amount so the built funding tx carries a below-dust
    // output.
    let mut instrs = create_and_broadcast_tx_instructions();
    instrs[4] = Instruction {
        operation: Operation::LoadAmount(200),
        inputs: vec![],
    };
    let funding_tx = instrs.len() - 2;
    instrs.push(Instruction {
        operation: Operation::BroadcastTransaction,
        inputs: vec![funding_tx],
    });
    instrs.push(Instruction {
        operation: Operation::MineBlocks(1),
        inputs: vec![],
    });

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    assert_eq!(executor.bitcoin_cli.broadcast_calls.len(), 2);
    assert_eq!(
        executor.bitcoin_cli.broadcast_calls[0].compute_txid(),
        executor.bitcoin_cli.broadcast_calls[1].compute_txid(),
    );

    let rejected_hex =
        bitcoin::consensus::encode::serialize_hex(&executor.bitcoin_cli.broadcast_calls[0]);
    assert!(executor.private_mempool.is_empty());
    assert_eq!(
        executor.bitcoin_cli.mined_private_mempool,
        vec![rejected_hex]
    );
}

#[test]
fn execute_create_funding_transaction_insufficient_funds() {
    // UTXO too small to cover the funding amount and fees.
    let small_utxo = Utxo {
        amount: Amount::from_sat(1_000),
        ..sample_utxo()
    };
    let mock_cli = MockBitcoinCli {
        utxos: vec![small_utxo],
        change_spk: sample_change_spk(),
        ..Default::default()
    };
    let err = Executor::new(MockConnection::new(), mock_cli, sample_context())
        .execute(
            &Program {
                instructions: create_and_broadcast_tx_instructions(),
            },
            std::time::Instant::now(),
        )
        .unwrap_err();
    let ExecuteError::InsufficientFunds(funds_err) = err else {
        panic!("expected InsufficientFunds, got {err:?}");
    };
    assert_eq!(funds_err.available, Amount::from_sat(1_000));
    assert_eq!(funds_err.required, Amount::from_sat(10_007_290));
}

#[test]
fn execute_send_funding_created_and_recv_funding_signed() {
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };

    // The acceptor replies with funding_signed carrying its signature over
    // the opener's commitment.
    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });

    // The expected signature here was computed using LDK as the source of
    // truth.
    let fs_bytes = Message::FundingSigned(FundingSigned {
        channel_id,
        signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
    })
    .encode();

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor.conn.queue_recv(fs_bytes);
    executor.negotiations.insert(
        TemporaryChannelId::new([0xbb; 32]),
        sample_funding_negotiation(),
    );
    executor
        .execute(
            &Program {
                instructions: send_funding_created_and_recv_funding_signed_instructions(),
            },
            std::time::Instant::now(),
        )
        .unwrap();

    assert_eq!(executor.conn.sent.len(), 1);
    let fc = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
        Message::FundingCreated(fc) => fc,
        other => panic!("expected funding_created(34), got {other}"),
    };

    assert_eq!(fc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(
        fc.funding_txid.to_string(),
        "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
    );
    assert_eq!(fc.funding_output_index, 0);

    // Verify the signature sent by the opener on the acceptor side.
    let state = executor.channel_states.get(&channel_id).unwrap();
    let holder = HolderIdentity {
        side: Side::Acceptor,
        funding_privkey: SecretKey::from_str(
            "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13",
        )
        .unwrap(),
    };

    assert!(
        state
            .config
            .verify_counterparty_signature(&state.commitment, &holder, &fc.signature)
    );

    let pending = executor
        .negotiations
        .get(&TemporaryChannelId::new([0xbb; 32]))
        .unwrap();
    assert!(pending.funding_built);
}

#[test]
fn execute_send_funding_created_uses_wire_funding_pubkey() {
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };

    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });

    // The same acceptor signature as the happy path (computed using LDK as
    // the source of truth): computed over the the commitment implied by the
    // negotiated funding pubkeys.
    let fs_bytes = Message::FundingSigned(FundingSigned {
        channel_id,
        signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
    })
    .encode();

    // Swap out the SendFundingCreated privkey. This should not affect the
    // constructed channel config, which uses the negotiated pubkeys. It
    // should only change the signature sent to the target.
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs[9].inputs[1] = 2;

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor.conn.queue_recv(fs_bytes);
    executor.negotiations.insert(
        TemporaryChannelId::new([0xbb; 32]),
        sample_funding_negotiation(),
    );
    // The acceptor's funding_signed still verifies, because the config is
    // built from the wire pubkeys rather than from the swapped privkey.
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    let secp = Secp256k1::new();
    let opener_pk = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_str("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749")
            .unwrap(),
    );
    // The funding pubkey matches what was negotiated.
    let state = executor.channel_states.get(&channel_id).unwrap();
    assert_eq!(state.config.opener.funding_pubkey, opener_pk);
    // But the swapped privkey used for signing is the acceptor's, which
    // does not match what was negotiated.
    assert_eq!(
        state.holder.funding_privkey,
        SecretKey::from_str("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13")
            .unwrap()
    );
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
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo(), second_utxo],
        change_spk: sample_change_spk(),
        ..Default::default()
    };

    // Channel id derived from the first funding transaction's outpoint.
    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });

    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.
    instrs.extend(vec![
        // Different funding spk, hence a different outpoint.
        Instruction {
            operation: Operation::CreateFundingTransaction,
            inputs: vec![1, 1, 4, 5],
        },
        Instruction {
            operation: Operation::SendFundingCreated,
            inputs: vec![10, 0, 8],
        },
    ]);

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor.negotiations.insert(
        TemporaryChannelId::new([0xbb; 32]),
        sample_funding_negotiation(),
    );
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    // The message still goes out, only the state tracking is suppressed.
    assert_eq!(executor.conn.sent.len(), 2);
    assert_eq!(executor.channel_states.len(), 1);
    assert!(executor.channel_states.contains_key(&channel_id));
}

#[test]
fn execute_send_funding_created_push_exceeds_funding() {
    // A negotiated push_msat larger than the funding amount surfaces the
    // commitment construction error.
    let mut negotiation = sample_funding_negotiation();
    negotiation.open_channel.push_msat = 20_000_000_000;
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };
    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor
        .negotiations
        .insert(TemporaryChannelId::new([0xbb; 32]), negotiation);
    let err = executor
        .execute(
            &Program {
                instructions: send_funding_created_and_recv_funding_signed_instructions(),
            },
            std::time::Instant::now(),
        )
        .unwrap_err();
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
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };
    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor
        .negotiations
        .insert(TemporaryChannelId::new([0xbb; 32]), negotiation);
    let err = executor
        .execute(
            &Program {
                instructions: send_funding_created_and_recv_funding_signed_instructions(),
            },
            std::time::Instant::now(),
        )
        .unwrap_err();
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
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    let fc = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
        Message::FundingCreated(fc) => fc,
        other => panic!("expected funding_created(34), got {other}"),
    };
    assert_eq!(fc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(
        fc.funding_txid.to_string(),
        "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
    );
    assert_eq!(fc.funding_output_index, 0);
    assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
    assert!(executor.channel_states.is_empty());
}

#[test]
fn execute_send_funding_created_no_accept_channel() {
    // The `accept_channel` has not been received yet, so we get a
    // `funding_created` with an all-zero signature and no recorded channel
    // state.
    let mut negotiation = sample_funding_negotiation();
    negotiation.accept_channel = None;
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor
        .negotiations
        .insert(TemporaryChannelId::new([0xbb; 32]), negotiation);
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    let fc = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
        Message::FundingCreated(fc) => fc,
        other => panic!("expected funding_created(34), got {other}"),
    };
    assert_eq!(fc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(
        fc.funding_txid.to_string(),
        "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
    );
    assert_eq!(fc.funding_output_index, 0);
    assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
    assert!(executor.channel_states.is_empty());
}

#[test]
fn execute_recv_funding_signed_unknown_channel() {
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };

    let channel_id = ChannelId::new([0xbb; 32]);

    // The expected signature here was computed using LDK as the source of
    // truth.
    let fs_bytes = Message::FundingSigned(FundingSigned {
        channel_id,
        signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
    })
    .encode();

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor.conn.queue_recv(fs_bytes);
    executor.negotiations.insert(
        TemporaryChannelId::new([0xbb; 32]),
        sample_funding_negotiation(),
    );
    let err = executor
        .execute(
            &Program {
                instructions: send_funding_created_and_recv_funding_signed_instructions(),
            },
            std::time::Instant::now(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ExecuteError::Violation(Violation::UnknownChannel(id)) if id == channel_id
    ));
}

#[test]
fn execute_recv_funding_signed_invalid_signature() {
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };

    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });
    let fs_bytes = Message::FundingSigned(FundingSigned {
        channel_id,
        signature: Signature::from_compact(&[0u8; 64]).expect("zero bytes parse as a signature"),
    })
    .encode();

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor.conn.queue_recv(fs_bytes);
    executor.negotiations.insert(
        TemporaryChannelId::new([0xbb; 32]),
        sample_funding_negotiation(),
    );
    let err = executor
        .execute(
            &Program {
                instructions: send_funding_created_and_recv_funding_signed_instructions(),
            },
            std::time::Instant::now(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ExecuteError::Violation(Violation::InvalidCounterpartySignature(id)) if id == channel_id
    ));
}

#[test]
fn execute_send_channel_ready() {
    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });
    let alias = ShortChannelId::new(538_532, 845, 1);
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };

    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.extend([
        Instruction {
            operation: Operation::LoadShortChannelId(alias.as_u64()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendChannelReady {
                include_alias: false,
            },
            inputs: vec![10, 1, 11],
        },
        Instruction {
            operation: Operation::SendChannelReady {
                include_alias: true,
            },
            inputs: vec![10, 3, 11],
        },
    ]);

    let program = Program {
        instructions: instrs,
    };

    // We also need to send this `funding_signed`, since the instructions reused
    // by this test expect one to be present in the executor's receive queue.
    // The expected signature here was computed using LDK as the source of
    // truth.
    let fs_bytes = Message::FundingSigned(FundingSigned {
        channel_id,
        signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
    })
    .encode();
    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor.conn.queue_recv(fs_bytes);
    executor.negotiations.insert(
        TemporaryChannelId::new([0xbb; 32]),
        sample_funding_negotiation(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    // The instructions send 1 `funding_created` and 2 `channel_ready` messages.
    assert_eq!(executor.conn.sent.len(), 3);

    // The first channel_ready was sent with include_alias = false, so it must
    // not carry the short_channel_id TLV.
    let cr1 = match Message::decode(&executor.conn.sent[1]).expect("valid message") {
        Message::ChannelReady(cr) => cr,
        other => panic!("expected channel_ready(36), got {other}"),
    };
    let expected_pcp1 =
        PublicKey::from_str("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb")
            .unwrap();
    assert_eq!(cr1.channel_id, channel_id);
    assert_eq!(cr1.second_per_commitment_point, expected_pcp1);
    assert!(cr1.tlvs.short_channel_id.is_none());

    // The second channel_ready was sent with include_alias = true, so it must
    // carry the alias SCID we loaded in its short_channel_id TLV.
    let cr2 = match Message::decode(&executor.conn.sent[2]).expect("valid message") {
        Message::ChannelReady(cr) => cr,
        other => panic!("expected channel_ready(36), got {other}"),
    };
    let expected_pcp2 =
        PublicKey::from_str("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1")
            .unwrap();
    assert_eq!(cr2.channel_id, channel_id);
    assert_eq!(cr2.second_per_commitment_point, expected_pcp2);
    assert_eq!(cr2.tlvs.short_channel_id, Some(alias));

    // The holder's next per-commitment point must hold the first
    // `channel_ready`'s point, not any subsequent one.
    let state = executor.channel_states.get_mut(&channel_id).unwrap();
    assert_eq!(
        *state.next_holder_per_commitment_point(),
        Some(expected_pcp1)
    );
}

#[test]
fn execute_send_shutdown() {
    let channel_id = ChannelId::new([0x7a; 32]);
    let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadChannelId(channel_id.0),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadShutdownScript(script.clone()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendShutdown,
                inputs: vec![0, 1],
            },
        ],
    };

    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    assert_eq!(executor.conn.sent.len(), 1);
    let sd = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
        Message::Shutdown(sd) => sd,
        other => panic!("expected shutdown(38), got {other}"),
    };
    assert_eq!(sd.channel_id, channel_id);
    assert_eq!(sd.scriptpubkey, script.encode());
}

#[test]
fn execute_send_shutdown_empty_scriptpubkey() {
    let channel_id = ChannelId::new([0x7a; 32]);
    // The fuzzer should allow an empty scriptpubkey in the shutdown message
    // to exercise the target's behavior even though it's protocol-invalid.
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadChannelId(channel_id.0),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendShutdown,
                inputs: vec![0, 1],
            },
        ],
    };

    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );
    executor
        .execute(&program, std::time::Instant::now())
        .unwrap();

    assert_eq!(executor.conn.sent.len(), 1);
    let sd = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
        Message::Shutdown(sd) => sd,
        other => panic!("expected shutdown(38), got {other}"),
    };
    assert_eq!(sd.channel_id, channel_id);
    assert!(sd.scriptpubkey.is_empty());
}

fn recv_channel_ready_executor() -> (
    Executor<MockConnection, MockBitcoinCli>,
    ChannelId,
    PublicKey,
) {
    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });
    let mock_cli = MockBitcoinCli {
        utxos: vec![sample_utxo()],
        change_spk: sample_change_spk(),
        ..Default::default()
    };

    // We also need to send this `funding_signed`, since the instructions reused
    // by this test expect one to be present in the executor's receive queue.
    // The expected signature here was computed using LDK as the source of
    // truth.
    let fs_bytes = Message::FundingSigned(FundingSigned {
        channel_id,
        signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
    })
    .encode();

    let target_pcp = sample_pubkey(1);
    let cr_bytes = Message::ChannelReady(ChannelReady {
        channel_id,
        second_per_commitment_point: target_pcp,
        tlvs: ChannelReadyTlvs::default(),
    })
    .encode();

    let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
    executor.conn.queue_recv(fs_bytes);
    executor.conn.queue_recv(cr_bytes);
    executor.negotiations.insert(
        TemporaryChannelId::new([0xbb; 32]),
        sample_funding_negotiation(),
    );

    (executor, channel_id, target_pcp)
}

#[test]
fn execute_recv_channel_ready_invalid_funding_outpoint_is_noop() {
    let (mut executor, channel_id, _) = recv_channel_ready_executor();

    // Corrupt the negotiated opener funding pubkey so the broadcast funding
    // transaction's output no longer pays the negotiated 2-of-2 script,
    // marking the funding outpoint invalid.
    executor
        .negotiations
        .get_mut(&TemporaryChannelId::new([0xbb; 32]))
        .unwrap()
        .open_channel
        .funding_pubkey = sample_pubkey(1);

    // The corrupted pubkey changes the funding script, so our precomputed
    // funding_signed signature will no longer verify correctly. That
    // exchange is not what this test is about, we just skip receiving the
    // funding_signed.
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop();
    executor.conn.recv_queue.pop_front();

    instrs.extend([
        Instruction {
            operation: Operation::MineBlocks(8),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::RecvChannelReady,
            inputs: vec![],
        },
    ]);

    // With invalid funding outpoint the target does not owe us a
    // `channel_ready`, so `RecvChannelReady` must be a no-op.
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = executor.channel_states.get_mut(&channel_id).unwrap();
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert_eq!(executor.conn.recv_queue.len(), 1);
}

#[test]
fn execute_recv_channel_ready_below_minimum_depth_is_noop() {
    let (mut executor, channel_id, _) = recv_channel_ready_executor();

    // Mine one block fewer than the `minimum_depth` negotiated in `accept_channel` by
    // `sample_funding_negotiation()`.
    let instrs = recv_channel_ready_instructions(5);

    // With fewer than the negotiated `minimum_depth` confirmations the target
    // does not yet owe us a `channel_ready`, so `RecvChannelReady` must be a
    // no-op.
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();
    assert!(executor.bitcoin_cli.mined_private_mempool.is_empty());

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = executor.channel_states.get_mut(&channel_id).unwrap();
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert_eq!(executor.conn.recv_queue.len(), 1);
}

#[test]
fn execute_recv_channel_ready_at_minimum_depth_records_point() {
    let (mut executor, channel_id, target_pcp) = recv_channel_ready_executor();

    // Mine exactly the `minimum_depth` negotiated in `accept_channel` by
    // `sample_funding_negotiation()`.
    let instrs = recv_channel_ready_instructions(6);

    // At the negotiated `minimum_depth` confirmations the target owes us a
    // `channel_ready`, which `RecvChannelReady` receives and records.
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();
    assert!(executor.bitcoin_cli.mined_private_mempool.is_empty());

    // The `channel_ready` was consumed and the target's next per-commitment
    // point is now recorded.
    let state = executor.channel_states.get_mut(&channel_id).unwrap();
    assert_eq!(
        *state.next_counterparty_per_commitment_point(),
        Some(target_pcp)
    );
    assert!(executor.conn.recv_queue.is_empty());
}

#[test]
fn execute_recv_channel_ready_funding_mined_prematurely_is_noop() {
    let (mut executor, channel_id, _) = recv_channel_ready_executor();

    let mut instrs = create_and_broadcast_tx_instructions();
    instrs.extend([
        Instruction {
            // Mine past the negotiated `minimum_depth` *before* sending
            // `funding_created`.
            operation: Operation::MineBlocks(8),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChannelId([0xbb; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendFundingCreated,
            inputs: vec![6, 0, 9],
        },
        Instruction {
            operation: Operation::RecvFundingSigned,
            inputs: vec![10],
        },
        Instruction {
            operation: Operation::RecvChannelReady,
            inputs: vec![],
        },
    ]);

    // The funding transaction confirmed before `funding_created`, so the
    // target may never observe the confirmation and `RecvChannelReady` must
    // be a no-op even though the confirmation count is sufficient.
    executor
        .execute(
            &Program {
                instructions: instrs,
            },
            std::time::Instant::now(),
        )
        .unwrap();

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = executor.channel_states.get_mut(&channel_id).unwrap();
    assert!(state.was_funding_mined_prematurely);
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert_eq!(executor.conn.recv_queue.len(), 1);
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
    let mut instructions = open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::BuildOpenChannel2 {
            require_confirmed_inputs: true,
        },
        inputs: OPEN_CHANNEL2_INPUTS.to_vec(),
    });
    instructions.push(Instruction {
        operation: Operation::SendOpenChannel2,
        inputs: vec![28],
    });
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");

    assert_eq!(executor.conn.sent.len(), 1);
    let sent = decode_open_channel2(&executor.conn.sent[0]);
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
    let pending = executor
        .negotiations_v2
        .get(sample_v2_temporary_channel_id())
        .expect("negotiation recorded");
    assert_eq!(pending.open_channel2, sent);
    assert!(pending.accept_channel2.is_none());
    assert!(pending.channel_id.is_none());
}

#[test]
fn execute_build_open_channel2_omits_an_empty_channel_type() {
    let mut instructions = open_channel2_instructions();
    // Replace the channel type with an empty feature vector.
    instructions[26] = Instruction {
        operation: Operation::LoadFeatures(vec![]),
        inputs: vec![],
    };
    instructions.push(Instruction {
        operation: Operation::BuildOpenChannel2 {
            require_confirmed_inputs: false,
        },
        inputs: OPEN_CHANNEL2_INPUTS.to_vec(),
    });
    instructions.push(Instruction {
        operation: Operation::SendOpenChannel2,
        inputs: vec![28],
    });
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");

    // BOLT 2 requires open_channel2 to set channel_type, so omitting it
    // must stay reachable for fuzzing the receiver's rejection path.
    assert_eq!(
        decode_open_channel2(&executor.conn.sent[0])
            .tlvs
            .channel_type,
        None
    );
}

#[test]
fn execute_recv_accept_channel2_records_the_v2_channel_id() {
    let (instructions, _) = send_open_channel2_instructions();
    let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
    let mut conn = MockConnection::new();
    conn.queue_recv(Message::AcceptChannel2(accept.clone()).encode());
    let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");

    let expected_channel_id = ChannelId::v2_from_revocation_basepoints(
        &sample_v2_revocation_basepoint(),
        &accept.revocation_basepoint,
    );
    let pending = executor
        .negotiations_v2
        .get(sample_v2_temporary_channel_id())
        .expect("negotiation recorded");
    assert_eq!(pending.accept_channel2.as_ref(), Some(&accept));
    assert_eq!(pending.channel_id, Some(expected_channel_id));
    // Later messages carry the v2 channel_id, and must reach the same
    // negotiation as its temporary_channel_id does.
    assert_eq!(
        executor
            .negotiations_v2
            .get(expected_channel_id)
            .and_then(|p| p.channel_id),
        Some(expected_channel_id),
    );
}

#[test]
fn execute_recv_accept_channel2_unknown_temporary_channel_id_is_ignored() {
    let (instructions, _) = send_open_channel2_instructions();
    // An accept_channel2 answering a temporary_channel_id we never opened,
    // as a mutated program that dropped its open_channel2 would see.
    let accept = sample_accept_channel2(ChannelId::new([0x77; 32]));
    let mut conn = MockConnection::new();
    conn.queue_recv(Message::AcceptChannel2(accept).encode());
    let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes without reporting a violation");

    // The unknown negotiation is not invented, and the one we did open is
    // left untouched: no accept_channel2 paired, so no channel_id derived
    // and nothing for a later message to reach it by.
    let pending = executor
        .negotiations_v2
        .get(sample_v2_temporary_channel_id())
        .expect("our own negotiation is still recorded");
    assert!(pending.accept_channel2.is_none());
    assert!(pending.channel_id.is_none());
}

#[test]
fn execute_recv_accept_channel2_unexpected_message() {
    let (instructions, _) = send_open_channel2_instructions();
    let mut conn = MockConnection::new();
    conn.queue_recv(Message::AcceptChannel(sample_accept_channel()).encode());
    let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

    let err = executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect_err("v1 accept_channel does not answer an open_channel2");

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
    let (mut instructions, accept_idx) = send_open_channel2_instructions();
    for &field in AcceptChannel2Field::ALL {
        instructions.push(Instruction {
            operation: Operation::ExtractAcceptChannel2(field),
            inputs: vec![accept_idx],
        });
    }
    let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
    let mut conn = MockConnection::new();
    conn.queue_recv(Message::AcceptChannel2(accept.clone()).encode());
    let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");

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
    let mut instructions = open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::LoadTargetPubkeyFromContext,
        inputs: vec![],
    }); // v28 the peer's revocation basepoint
    instructions.push(Instruction {
        operation: Operation::DeriveChannelIdV2,
        inputs: vec![13, 28],
    }); // v29
    let mut inputs = OPEN_CHANNEL2_INPUTS.to_vec();
    inputs[1] = 29;
    instructions.push(Instruction {
        operation: Operation::BuildOpenChannel2 {
            require_confirmed_inputs: false,
        },
        inputs,
    }); // v30
    instructions.push(Instruction {
        operation: Operation::SendOpenChannel2,
        inputs: vec![30],
    });
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");

    let sent = decode_open_channel2(&executor.conn.sent[0]);
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
    let mut executor = Executor::new(
        MockConnection::new(),
        MockBitcoinCli::default(),
        sample_context(),
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor.execute(&Program { instructions }, std::time::Instant::now())
    }));

    assert!(result.is_err(), "expected a panic on the type mismatch");
}

#[test]
fn execute_recv_accept_channel2_affine_overuse_panics() {
    let (mut instructions, _) = send_open_channel2_instructions();
    // Receive twice against a single SendOpenChannel2.
    instructions.push(Instruction {
        operation: Operation::RecvAcceptChannel2,
        inputs: vec![29],
    });
    let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
    let mut conn = MockConnection::new();
    conn.queue_recv(Message::AcceptChannel2(accept.clone()).encode());
    conn.queue_recv(Message::AcceptChannel2(accept).encode());
    let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor.execute(&Program { instructions }, std::time::Instant::now())
    }));

    assert!(
        result.is_err(),
        "expected a panic consuming SentOpenChannel2 twice"
    );
}

// -- Interactive transaction construction --

/// The `open_channel2` / `accept_channel2` exchange followed by
/// `instructions`, all against a wallet with one spendable output.
///
/// The `channel_id` for the interactive transaction messages is at index
/// 31, derived from both revocation basepoints.
fn run_v2_negotiation(extra: Vec<Instruction>) -> Executor<MockConnection, MockBitcoinCli> {
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        inputs: vec![30],
    }); // v31
    instructions.push(Instruction {
        operation: Operation::DeriveChannelIdV2,
        inputs: vec![13, 31],
    }); // v32 channel_id
    instructions.extend(extra);

    let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
    let mut conn = MockConnection::new();
    conn.queue_recv(Message::AcceptChannel2(accept).encode());
    let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());
    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");
    executor
}

/// Index of the `channel_id` variable produced by [`run_v2_negotiation`].
const V2_CHANNEL_ID_VAR: usize = 32;

fn decode_sent<T>(bytes: &[u8], f: impl Fn(Message) -> Option<T>) -> T {
    let msg = Message::decode(bytes).expect("valid message");
    let name = msg.to_string();
    f(msg).unwrap_or_else(|| panic!("unexpected message {name}"))
}

fn sole_negotiation(executor: &Executor<MockConnection, MockBitcoinCli>) -> &PendingChannelV2 {
    executor
        .negotiations_v2
        .get(sample_v2_temporary_channel_id())
        .expect("negotiation recorded")
}

#[test]
fn execute_send_tx_add_input_proposes_a_wallet_utxo() {
    let executor = run_v2_negotiation(vec![Instruction {
        operation: Operation::SendTxAddInput {
            serial_id: 2,
            utxo_index: 0,
            sequence: 0xffff_fffd,
        },
        inputs: vec![V2_CHANNEL_ID_VAR],
    }]);

    let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
        Message::TxAddInput(m) => Some(m),
        _ => None,
    });
    let prevtx = sample_prevtx();
    assert_eq!(sent.serial_id, 2);
    assert_eq!(sent.sequence, 0xffff_fffd);
    assert_eq!(sent.prevtx_vout, 0);
    assert_eq!(sent.prevtx, bitcoin::consensus::encode::serialize(&prevtx));

    // The input is recorded with the value we know from the wallet, so the
    // change output can be computed from it.
    let pending = sole_negotiation(&executor);
    let (serial_id, input) = pending.shared_tx.inputs().next().expect("input recorded");
    assert_eq!(serial_id, 2);
    assert_eq!(input.contributor, Contributor::Local);
    assert_eq!(input.outpoint.txid, prevtx.compute_txid());
    assert_eq!(input.value(), 100_000_000);
}

#[test]
fn execute_send_tx_add_input_locks_the_selected_utxo() {
    let executor = run_v2_negotiation(vec![Instruction {
        operation: Operation::SendTxAddInput {
            serial_id: 2,
            utxo_index: 0,
            sequence: 0xffff_fffd,
        },
        inputs: vec![V2_CHANNEL_ID_VAR],
    }]);

    // Locking is what stops a later selection proposing the same coin,
    // which the peer would reject as a duplicate input.
    assert_eq!(
        executor.bitcoin_cli.locked_outpoints,
        vec![OutPoint {
            txid: sample_prevtx().compute_txid(),
            vout: 0,
        }],
    );
}

#[test]
fn execute_send_tx_add_input_with_an_empty_wallet_sends_an_empty_prevtx() {
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::SendTxAddInput {
            serial_id: 2,
            utxo_index: 0,
            sequence: 0xffff_fffd,
        },
        inputs: vec![27],
    });
    let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
    let mut conn = MockConnection::new();
    conn.queue_recv(Message::AcceptChannel2(accept).encode());
    let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("an empty wallet is not a harness error");

    let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
        Message::TxAddInput(m) => Some(m),
        _ => None,
    });
    // Nothing to spend, so nothing to prove non-malleable. The message
    // still goes out for the peer to reject.
    assert!(sent.prevtx.is_empty());
}

#[test]
fn execute_send_tx_add_output_derives_the_funding_output() {
    let executor = run_v2_negotiation(vec![Instruction {
        operation: Operation::SendTxAddOutput {
            serial_id: 4,
            role: TxOutputRole::Funding,
        },
        inputs: vec![V2_CHANNEL_ID_VAR, 3, 25],
    }]);

    let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
        Message::TxAddOutput(m) => Some(m),
        _ => None,
    });
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
    let executor = run_v2_negotiation(vec![
        Instruction {
            operation: Operation::SendTxAddInput {
                serial_id: 2,
                utxo_index: 0,
                sequence: 0xffff_fffd,
            },
            inputs: vec![V2_CHANNEL_ID_VAR],
        },
        Instruction {
            operation: Operation::SendTxAddOutput {
                serial_id: 4,
                role: TxOutputRole::Funding,
            },
            inputs: vec![V2_CHANNEL_ID_VAR, 3, 25],
        },
        Instruction {
            operation: Operation::SendTxAddOutput {
                serial_id: 6,
                role: TxOutputRole::Change,
            },
            inputs: vec![V2_CHANNEL_ID_VAR, 3, 25],
        },
    ]);

    let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
        Message::TxAddOutput(m) => Some(m),
        _ => None,
    });
    // One 1 BTC input, 200_000 sat to the funding output, and our share of
    // the fee at 253 sat/kw: weight 42 + 164 + 172 + 124 + 108 = 610,
    // giving ceil(610 * 253 / 1000) = 155 sat.
    assert_eq!(sent.sats, 100_000_000 - 200_000 - 155);
    assert_eq!(ScriptBuf::from(sent.script), sample_change_spk());
}

#[test]
fn execute_send_tx_add_output_explicit_uses_its_inputs() {
    let executor = run_v2_negotiation(vec![Instruction {
        operation: Operation::SendTxAddOutput {
            serial_id: 4,
            role: TxOutputRole::Explicit,
        },
        // v3 is funding_satoshis (200_000), v25 the empty script.
        inputs: vec![V2_CHANNEL_ID_VAR, 3, 25],
    }]);

    let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
        Message::TxAddOutput(m) => Some(m),
        _ => None,
    });
    assert_eq!(sent.sats, 200_000);
    assert!(sent.script.is_empty());
}

#[test]
fn execute_send_tx_remove_input_keeps_the_peers_input() {
    let channel_id = ChannelId::v2_from_revocation_basepoints(
        &sample_v2_revocation_basepoint(),
        &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
    );
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        inputs: vec![30],
    }); // v31
    instructions.push(Instruction {
        operation: Operation::DeriveChannelIdV2,
        inputs: vec![13, 31],
    }); // v32
    instructions.push(Instruction {
        operation: Operation::SendTxAddInput {
            serial_id: 2,
            utxo_index: 0,
            sequence: 0xffff_fffd,
        },
        inputs: vec![32],
    }); // v33
    instructions.push(Instruction {
        operation: Operation::RecvInteractiveTx,
        inputs: vec![33],
    }); // the peer contributes an input of its own
    instructions.push(Instruction {
        // BOLT 2 forbids removing an input the peer added. A peer that
        // receives one keeps its input, so we must keep it too or our
        // reconstruction of the shared transaction diverges from theirs.
        operation: Operation::SendTxRemoveInput { serial_id: 3 },
        inputs: vec![32],
    }); // v35
    instructions.push(Instruction {
        operation: Operation::SendTxRemoveInput { serial_id: 2 },
        inputs: vec![32],
    }); // v36

    let mut conn = MockConnection::new();
    conn.queue_recv(
        Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id())).encode(),
    );
    conn.queue_recv(
        Message::TxAddInput(TxAddInput {
            channel_id,
            serial_id: 3,
            prevtx: bitcoin::consensus::encode::serialize(&sample_prevtx()),
            prevtx_vout: 0,
            sequence: 0xffff_fffd,
            tlvs: TxAddInputTlvs::default(),
        })
        .encode(),
    );
    let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");

    // Ours is gone, the peer's survives.
    let pending = sole_negotiation(&executor);
    let remaining: Vec<u64> = pending.shared_tx.inputs().map(|(id, _)| id).collect();
    assert_eq!(remaining, vec![3]);

    // Both removals still went on the wire; only our own changed local
    // state, so the peer gets to reject the illegal one.
    let removals = executor
        .conn
        .sent
        .iter()
        .filter(|bytes| {
            Message::decode(bytes).expect("valid").msg_type() == MessageType::TX_REMOVE_INPUT
        })
        .count();
    assert_eq!(removals, 2);
}

#[test]
fn execute_send_tx_remove_output_keeps_the_peers_output() {
    let channel_id = ChannelId::v2_from_revocation_basepoints(
        &sample_v2_revocation_basepoint(),
        &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
    );
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        inputs: vec![30],
    });
    instructions.push(Instruction {
        operation: Operation::DeriveChannelIdV2,
        inputs: vec![13, 31],
    });
    instructions.push(Instruction {
        operation: Operation::SendTxAddOutput {
            serial_id: 4,
            role: TxOutputRole::Funding,
        },
        inputs: vec![32, 3, 25],
    }); // v33
    instructions.push(Instruction {
        operation: Operation::RecvInteractiveTx,
        inputs: vec![33],
    });
    instructions.push(Instruction {
        operation: Operation::SendTxRemoveOutput { serial_id: 5 },
        inputs: vec![32],
    });
    instructions.push(Instruction {
        operation: Operation::SendTxRemoveOutput { serial_id: 4 },
        inputs: vec![32],
    });

    let mut conn = MockConnection::new();
    conn.queue_recv(
        Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id())).encode(),
    );
    conn.queue_recv(
        Message::TxAddOutput(TxAddOutput {
            channel_id,
            serial_id: 5,
            sats: 50_000,
            script: sample_change_spk().into_bytes(),
        })
        .encode(),
    );
    let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");

    let pending = sole_negotiation(&executor);
    let remaining: Vec<u64> = pending.shared_tx.outputs().map(|(id, _)| id).collect();
    assert_eq!(remaining, vec![5]);
}

#[test]
fn execute_recv_interactive_tx_records_peer_contributions() {
    let prevtx = sample_prevtx();
    let channel_id = ChannelId::v2_from_revocation_basepoints(
        &sample_v2_revocation_basepoint(),
        &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
    );
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        inputs: vec![30],
    }); // v31
    instructions.push(Instruction {
        operation: Operation::DeriveChannelIdV2,
        inputs: vec![13, 31],
    }); // v32
    instructions.push(Instruction {
        operation: Operation::SendTxComplete,
        inputs: vec![32],
    }); // v33
    instructions.push(Instruction {
        operation: Operation::RecvInteractiveTx,
        inputs: vec![33],
    });

    let mut conn = MockConnection::new();
    conn.queue_recv(
        Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id())).encode(),
    );
    conn.queue_recv(
        Message::TxAddInput(TxAddInput {
            channel_id,
            // The non-initiator uses odd serial ids.
            serial_id: 3,
            prevtx: bitcoin::consensus::encode::serialize(&prevtx),
            prevtx_vout: 0,
            sequence: 0xffff_fffd,
            tlvs: TxAddInputTlvs::default(),
        })
        .encode(),
    );
    let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");

    let pending = sole_negotiation(&executor);
    let (serial_id, input) = pending.shared_tx.inputs().next().expect("input recorded");
    assert_eq!(serial_id, 3);
    assert_eq!(input.contributor, Contributor::Remote);
    assert_eq!(input.value(), 100_000_000);
    // A contribution is not a tx_complete, so the negotiation has not
    // concluded even though we sent ours.
    assert!(pending.sent_tx_complete);
    assert!(!pending.peer_sent_tx_complete);
    assert!(!pending.tx_negotiation_complete());
}

#[test]
fn execute_recv_interactive_tx_completes_on_consecutive_tx_completes() {
    let channel_id = ChannelId::v2_from_revocation_basepoints(
        &sample_v2_revocation_basepoint(),
        &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
    );
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        inputs: vec![30],
    });
    instructions.push(Instruction {
        operation: Operation::DeriveChannelIdV2,
        inputs: vec![13, 31],
    });
    instructions.push(Instruction {
        operation: Operation::SendTxComplete,
        inputs: vec![32],
    });
    instructions.push(Instruction {
        operation: Operation::RecvInteractiveTx,
        inputs: vec![33],
    });

    let mut conn = MockConnection::new();
    conn.queue_recv(
        Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id())).encode(),
    );
    conn.queue_recv(Message::TxComplete(TxComplete { channel_id }).encode());
    let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("program executes");

    assert!(sole_negotiation(&executor).tx_negotiation_complete());
}

#[test]
fn execute_recv_interactive_tx_for_an_unknown_channel_is_ignored() {
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::SendTxComplete,
        inputs: vec![27],
    }); // v31
    instructions.push(Instruction {
        operation: Operation::RecvInteractiveTx,
        inputs: vec![31],
    });

    let mut conn = MockConnection::new();
    conn.queue_recv(
        Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id())).encode(),
    );
    conn.queue_recv(
        Message::TxComplete(TxComplete {
            channel_id: ChannelId::new([0x99; 32]),
        })
        .encode(),
    );
    let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

    executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect("an unknown channel_id is not a harness error");

    // Only the peer can tell whether that message is consistent with its
    // own view, so nothing is invented on our side.
    assert!(!sole_negotiation(&executor).peer_sent_tx_complete);
}

#[test]
fn execute_recv_interactive_tx_unexpected_message() {
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::SendTxComplete,
        inputs: vec![27],
    });
    instructions.push(Instruction {
        operation: Operation::RecvInteractiveTx,
        inputs: vec![31],
    });

    let mut conn = MockConnection::new();
    conn.queue_recv(
        Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id())).encode(),
    );
    conn.queue_recv(Message::AcceptChannel(sample_accept_channel()).encode());
    let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

    let err = executor
        .execute(&Program { instructions }, std::time::Instant::now())
        .expect_err("accept_channel does not belong in an interactive tx exchange");

    assert!(
        matches!(err, ExecuteError::UnexpectedMessage { .. }),
        "unexpected error: {err}",
    );
}

#[test]
fn execute_recv_interactive_tx_affine_overuse_panics() {
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::SendTxComplete,
        inputs: vec![27],
    });
    instructions.push(Instruction {
        operation: Operation::RecvInteractiveTx,
        inputs: vec![31],
    });
    instructions.push(Instruction {
        operation: Operation::RecvInteractiveTx,
        inputs: vec![31],
    });

    let mut conn = MockConnection::new();
    conn.queue_recv(
        Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id())).encode(),
    );
    // Enough for the first receive to succeed, so the second one fails on
    // the consumed token rather than on an empty queue.
    conn.queue_recv(
        Message::TxComplete(TxComplete {
            channel_id: sample_v2_temporary_channel_id(),
        })
        .encode(),
    );
    let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor.execute(&Program { instructions }, std::time::Instant::now())
    }));

    assert!(
        result.is_err(),
        "the turn-based protocol earns one receive per send",
    );
}
