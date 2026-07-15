//! Fuzz init scenario - fuzzes the BOLT 1 init message with valid encryption.

use std::time::Duration;

use smite::bolt;
use smite::bolt::{Init, Message};
use smite::noise::{MAX_MESSAGE_SIZE, NoiseConnection};
use smite::scenarios::{Scenario, ScenarioError, ScenarioResult};

use super::{handshake_with_target, ping_pong, warmup, warmup_iters};
use crate::targets::Target;

/// Timeout for connection and message operations.
const TIMEOUT: Duration = Duration::from_secs(5);

/// A scenario that fuzzes the BOLT 1 init message.
///
/// Completes the Noise handshake and receives the target's init message
/// pre-snapshot. Each iteration sends a properly encrypted init message
/// with fuzz payload, testing the target's init validation logic (feature
/// negotiation, TLV parsing, dependency graph checks).
///
/// After sending the fuzz init, if the target stays connected we do a
/// ping-pong on the same connection to ensure it has processed the data
/// before checking for crashes.
pub struct InitScenario<T: Target> {
    target: T,
    conn: NoiseConnection,
}

impl<T: Target> Scenario for InitScenario<T> {
    fn new(_args: &[String]) -> Result<Self, ScenarioError> {
        let config = T::Config::default();
        let target = T::start(config)?;

        // Establish a warmup connection and drive many iterations through the
        // target's message handling code paths before the Nyx snapshot. This
        // JIT compiles the hot path into the snapshot for JVM targets (Eclair)
        // instead of leaving it interpreted on every restore.
        let (mut warmup_conn, target_init) = handshake_with_target(&target, TIMEOUT)?;
        let echo = Message::Init(Init::echo(&target_init)).encode();
        warmup_conn.send_message(&echo)?;
        warmup(&mut warmup_conn, warmup_iters())?;
        drop(warmup_conn);

        // Establish the fuzz connection, complete the handshake, and receive
        // the target's init.
        let (conn, _) = handshake_with_target(&target, TIMEOUT)?;

        Ok(Self { target, conn })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        let start = std::time::Instant::now();
        log::debug!(
            "[{:?}] Fuzzing init message ({} bytes)",
            start.elapsed(),
            input.len()
        );

        // Send an init-typed message with fuzz payload.
        let msg = bolt::message_with_type(bolt::msg_type::INIT, input);
        let truncated = &msg[..msg.len().min(MAX_MESSAGE_SIZE)];
        self.conn
            .send_message(truncated)
            .expect("fuzz init send successful");

        // Synchronize to ensure the target has processed the fuzz data.
        if let Err(e) = ping_pong(&mut self.conn) {
            log::debug!("[{:?}] ping_pong: {e}", start.elapsed());
            if e.is_timeout() {
                return ScenarioResult::Fail("target hung (ping timeout)".into());
            }
            // Non-timeout error likely means the target closed the connection.
            // This is expected for invalid init messages, but it could also
            // mean the target crashed. Use check_alive below to distinguish.
        } else {
            log::debug!("[{:?}] Target responded with pong", start.elapsed());
        }

        if let Err(e) = self.target.check_alive() {
            log::debug!("[{:?}] check_alive: {e}", start.elapsed());
            return ScenarioResult::Fail("target crashed".into());
        }

        ScenarioResult::Ok
    }
}
