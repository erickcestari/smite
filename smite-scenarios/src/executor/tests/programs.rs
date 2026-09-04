//! Program fragments used by executor tests.
//!
//! Each helper returns the instructions for one flow.

use crate::executor::*;
use smite_ir::Instruction;
use smite_ir::operation::ChannelTypeVariant;
use std::str::FromStr;

/// Builds the 20 `open_channel` input instructions in wire order.
pub fn open_channel_instructions() -> Vec<Instruction> {
    vec![
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChannelId([0xbb; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(100_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(0),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(546),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(100_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(10_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeeratePerKw(253),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(144),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(483),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU8(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadBytes(vec![]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(vec![0x40, 0x10, 0x00]),
            inputs: vec![],
        },
    ]
}

pub fn create_and_broadcast_tx_instructions() -> Vec<Instruction> {
    let opener_privkey =
        SecretKey::from_str("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749")
            .unwrap()
            .secret_bytes();
    let acceptor_privkey =
        SecretKey::from_str("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13")
            .unwrap()
            .secret_bytes();

    vec![
        Instruction {
            operation: Operation::LoadPrivateKey(opener_privkey),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(acceptor_privkey),
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
        Instruction {
            operation: Operation::BroadcastTransaction,
            inputs: vec![6],
        },
    ]
}

/// Builds instructions that construct and send a `channel_announcement`
/// referencing the `ShortChannelId` produced at variable index `scid_var`.
///
/// `base` is the variable index the first appended instruction will occupy
/// (i.e. the current program length), used to wire up the inputs to
/// `BuildChannelAnnouncement`.
pub fn channel_announcement_from_scid_instructions(
    base: usize,
    scid_var: usize,
) -> Vec<Instruction> {
    vec![
        Instruction {
            operation: Operation::LoadFeatures(vec![0x01, 0x02]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x11; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x22; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x33; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x44; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildChannelAnnouncement,
            // features, chain_hash, short_channel_id, node_sk_1, node_sk_2,
            // bitcoin_sk_1, bitcoin_sk_2.
            inputs: vec![
                base,
                base + 1,
                scid_var,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
            ],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![base + 6],
        },
    ]
}

pub fn send_open_channel_instructions() -> Vec<Instruction> {
    let mut instructions = open_channel_instructions();
    instructions.extend([
        Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: (0..20).collect(),
        },
        Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![20],
        },
    ]);
    instructions
}

pub fn send_funding_created_and_recv_funding_signed_instructions() -> Vec<Instruction> {
    let mut instrs = create_and_broadcast_tx_instructions();
    instrs.extend(vec![
        Instruction {
            operation: Operation::LoadChannelId([0xbb; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendFundingCreated,
            inputs: vec![6, 0, 8],
        },
        Instruction {
            operation: Operation::RecvFundingSigned,
            inputs: vec![9],
        },
    ]);
    instrs
}

pub fn recv_channel_ready_instructions(confirmations: u8) -> Vec<Instruction> {
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.extend([
        Instruction {
            operation: Operation::MineBlocks(confirmations),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::RecvChannelReady,
            inputs: vec![],
        },
    ]);
    instrs
}

// -- Channel establishment v2 --

/// Builds the `open_channel2` inputs, deriving the `temporary_channel_id`
/// from our revocation basepoint (the `[0x22; 32]` key) as BOLT 2 requires.
/// [`OPEN_CHANNEL2_INPUTS`] maps each wire field to its variable index.
#[allow(clippy::too_many_lines)]
pub fn open_channel2_instructions() -> Vec<Instruction> {
    vec![
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeeratePerKw(253),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeeratePerKw(2500),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(200_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(546),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(100_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(144),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(483),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadBlockHeight(120),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x11; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![10],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x22; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![12],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x33; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![14],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x44; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![16],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x55; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![18],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x66; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![20],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x77; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![22],
        },
        Instruction {
            operation: Operation::LoadU8(0),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadBytes(vec![]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChannelType(ChannelTypeVariant::Anchors),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DeriveTemporaryChannelIdV2,
            inputs: vec![13],
        },
    ]
}

/// Indices into [`open_channel2_instructions`], in `BuildOpenChannel2`
/// wire order.
pub const OPEN_CHANNEL2_INPUTS: [usize; 21] = [
    0,  // chain_hash
    27, // temporary_channel_id
    1,  // funding_feerate_perkw
    2,  // commitment_feerate_perkw
    3,  // funding_satoshis
    4,  // dust_limit_satoshis
    5,  // max_htlc_value_in_flight_msat
    6,  // htlc_minimum_msat
    7,  // to_self_delay
    8,  // max_accepted_htlcs
    9,  // locktime
    11, // funding_pubkey
    13, // revocation_basepoint
    15, // payment_basepoint
    17, // delayed_payment_basepoint
    19, // htlc_basepoint
    21, // first_per_commitment_point
    23, // second_per_commitment_point
    24, // channel_flags
    25, // upfront_shutdown_script
    26, // channel_type
];

/// Emits the full `open_channel2` / `accept_channel2` exchange. The
/// `AcceptChannel2` compound lands at the returned instruction index.
pub fn send_open_channel2_instructions() -> (Vec<Instruction>, usize) {
    let mut instructions = open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::BuildOpenChannel2 {
            require_confirmed_inputs: false,
        },
        inputs: OPEN_CHANNEL2_INPUTS.to_vec(),
    }); // v28
    instructions.push(Instruction {
        operation: Operation::SendOpenChannel2,
        inputs: vec![28],
    }); // v29
    instructions.push(Instruction {
        operation: Operation::RecvAcceptChannel2,
        inputs: vec![29],
    }); // v30
    (instructions, 30)
}

// -- Commitment and signature exchange --

/// Drives the full v2 flow through `tx_complete`, then appends `extra`.
///
/// Variable indices of interest: 32 is the v2 `channel_id`, 36 the funding
/// transaction, 10 our funding private key.
pub fn v2_flow_instructions(extra: Vec<Instruction>) -> Vec<Instruction> {
    let (mut instructions, _) = send_open_channel2_instructions();
    instructions.push(Instruction {
        operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        inputs: vec![30],
    }); // v31
    instructions.push(Instruction {
        operation: Operation::DeriveChannelIdV2,
        inputs: vec![13, 31],
    }); // v32 channel_id
    instructions.push(Instruction {
        operation: Operation::SendTxAddInput {
            serial_id: 2,
            utxo_index: 0,
            sequence: 0xffff_fffd,
        },
        inputs: vec![32],
    }); // v33
    instructions.push(Instruction {
        operation: Operation::SendTxAddOutput {
            serial_id: 4,
            role: TxOutputRole::Funding,
        },
        inputs: vec![32, 3, 25],
    }); // v34
    instructions.push(Instruction {
        operation: Operation::SendTxAddOutput {
            serial_id: 6,
            role: TxOutputRole::Change,
        },
        inputs: vec![32, 3, 25],
    }); // v35
    instructions.push(Instruction {
        operation: Operation::BuildFundingTransactionV2,
        inputs: vec![32],
    }); // v36 funding transaction
    instructions.extend(extra);
    instructions
}
