//! Scenario implementations and helpers.

mod encrypted_bytes;
mod init;
mod ir;
mod noise;
mod setup;

pub use encrypted_bytes::EncryptedBytesScenario;
pub use init::InitScenario;
pub use ir::IrScenario;
pub use noise::NoiseScenario;
pub use setup::{PostInitSetup, REGTEST_CHAIN_HASH, SnapshotSetup};
use smite::scenarios::ScenarioError;

use std::time::Duration;

use bitcoin::secp256k1::SecretKey;
use smite::bolt::{Init, Message, Ping};
use smite::noise::NoiseConnection;

use crate::targets::Target;

/// Static keys for Noise handshake. Using fixed keys ensures reproducibility
/// of fuzz failures across runs.
const STATIC_KEY: [u8; 32] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const EPHEMERAL_KEY: [u8; 32] = [
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
];

/// Perform a Noise handshake with a target and receive its `Init` message.
///
/// Returns the encrypted connection and the target's `Init`. The caller is
/// responsible for sending its own `Init` response (e.g., via `Init::echo`).
///
/// # Errors
///
/// Returns an error if connection, handshake, or init receive fails.
#[allow(clippy::missing_panics_doc)] // Static keys are known-valid constants
pub fn handshake_with_target<T: Target>(
    target: &T,
    timeout: Duration,
) -> Result<(NoiseConnection, Init), ScenarioError> {
    let local_static = SecretKey::from_slice(&STATIC_KEY).expect("valid static key");
    let local_ephemeral = SecretKey::from_slice(&EPHEMERAL_KEY).expect("valid ephemeral key");

    let mut conn = NoiseConnection::connect(
        target.addr(),
        *target.pubkey(),
        local_static,
        local_ephemeral,
        timeout,
    )?;

    // Receive and validate target's init message
    let init_bytes = conn.recv_message()?;
    let Message::Init(init) = Message::decode(&init_bytes)? else {
        return Err(ScenarioError::Protocol("expected init message".into()));
    };

    log::debug!("Handshake complete, received target init");

    Ok((conn, init))
}

/// Send ping and wait for pong (for synchronization).
///
/// This ensures the target has done initial processing of any previously sent
/// message before we check if it's still alive.
///
/// # Errors
///
/// Returns an error if the connection is closed or times out.
pub fn ping_pong(conn: &mut NoiseConnection) -> Result<(), ScenarioError> {
    conn.send_message(&Message::Ping(Ping::new(0)).encode())?;

    // Read messages until we get a pong
    loop {
        let msg_bytes = conn.recv_message()?;
        if matches!(Message::decode(&msg_bytes)?, Message::Pong(_)) {
            return Ok(());
        }
        // Ignore other messages (warnings, errors, etc.)
    }
}

/// Default number of pre-snapshot warmup iterations. Chosen to comfortably
/// exceed the JVM's C1 tiered-compilation invocation threshold so Eclair's hot
/// message-handling methods are JIT compiled into the snapshot rather than
/// interpreted on every restore.
const DEFAULT_WARMUP_ITERS: usize = 2000;

/// Number of pre-snapshot warmup iterations, overridable via the
/// `SMITE_WARMUP_ITERS` environment variable.
///
/// Exposed as a knob so a campaign can sweep for the knee where more warmup
/// stops improving `execs_per_sec` (visible in AFL++'s `fuzzer_stats`). Setting
/// it to `0` disables warmup entirely.
#[must_use]
pub fn warmup_iters() -> usize {
    std::env::var("SMITE_WARMUP_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WARMUP_ITERS)
}

/// Warm up the target's message decode + handler path before the Nyx snapshot.
///
/// A single message does not push the JVM past its JIT thresholds, so warming
/// with just one message leaves Eclair running the hot path interpreted on
/// every snapshot restore. This drives `iters` messages through the same
/// Noise-decrypt + framing + message-dispatch + response-encode path the fuzzer
/// exercises on every input, pushing method invocation counters past the C1
/// tiered-compilation threshold and forcing class loading, so the compiled hot
/// path is captured in the snapshot. Non-JVM targets (LND/LDK/CLN) pay only a
/// one-time startup cost.
///
/// Each iteration sends a `Ping` (varying the requested pong length and padding
/// so the length-handling code is warmed across sizes rather than a single
/// cached shape) and drains until the matching `Pong`, which also keeps the
/// connection synchronized.
///
/// # Errors
///
/// Returns an error if the connection closes or times out mid-warmup.
pub fn warmup(conn: &mut NoiseConnection, iters: usize) -> Result<(), ScenarioError> {
    if iters == 0 {
        return Ok(());
    }

    log::info!("Warming up target message handling ({iters} iterations)...");
    // Rotating counter used to vary message sizes. A wrapping `u16` avoids
    // casting from the `usize` loop index.
    let mut tick: u16 = 0;
    for _ in 0..iters {
        // Vary request/padding sizes to warm the length-handling paths. Kept
        // small to stay well under the BOLT 1 rule that ignores pings
        // requesting >= 65532 pong bytes (which would leave us waiting for a
        // pong that never arrives).
        let num_pong_bytes = tick % 16;
        let padding_len = tick % 32;
        tick = tick.wrapping_add(1);
        conn.send_message(
            &Message::Ping(Ping::with_padding(num_pong_bytes, padding_len)).encode(),
        )?;

        // Drain until the matching pong to keep the connection in sync.
        loop {
            let msg_bytes = conn.recv_message()?;
            if matches!(Message::decode(&msg_bytes)?, Message::Pong(_)) {
                break;
            }
        }
    }
    log::info!("Warmup complete");

    Ok(())
}
