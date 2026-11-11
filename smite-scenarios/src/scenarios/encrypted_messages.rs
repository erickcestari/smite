//! Raw messages scenario - sends fuzz input as a sequence of Lightning messages.

use std::time::Duration;

use smite::bolt::{Init, Message};
use smite::noise::NoiseConnection;
use smite::scenarios::{Scenario, ScenarioError, ScenarioResult};
use smite::violation::Violation;

use super::{handshake_with_target, ping_pong};
use crate::targets::Target;

/// Bounds the work of one execution; inputs made of empty messages would
/// otherwise send hundreds of thousands of them.
const MAX_MESSAGES: usize = 32;

/// Splits fuzz input into messages, each prefixed by its big-endian `u16`
/// length. A final message shorter than its prefix takes the rest of the input.
fn split_messages(mut input: &[u8]) -> Vec<&[u8]> {
    let mut messages = Vec::new();
    while messages.len() < MAX_MESSAGES {
        let Some((prefix, rest)) = input.split_first_chunk::<2>() else {
            break;
        };
        let len = usize::from(u16::from_be_bytes(*prefix)).min(rest.len());
        let (msg, rest) = rest.split_at(len);
        messages.push(msg);
        input = rest;
    }
    messages
}

/// A scenario that sends raw fuzz input as several Lightning messages.
///
/// The multi-message counterpart of `EncryptedBytesScenario`: it knows nothing
/// about the protocol, but one input can drive the target through several
/// messages on the same connection.
pub struct EncryptedMessagesScenario<T: Target> {
    /// Declared before `target` so the peer connection closes first and doesn't
    /// stall the target's shutdown.
    conn: NoiseConnection,
    target: T,
}

impl<T: Target> Scenario for EncryptedMessagesScenario<T> {
    fn new(_args: &[String]) -> Result<Self, ScenarioError> {
        let config = T::Config::default();
        let target = T::start(config)?;
        let (mut conn, target_init) = handshake_with_target(&target, Duration::from_secs(5))?;
        let echo = Message::Init(Init::echo(&target_init)).encode();
        conn.send_message(&echo)?;

        // Warm up the target's message handling path before the Nyx snapshot
        // (class loading and JIT for JVM-based targets).
        ping_pong(&mut conn)?;

        Ok(Self { conn, target })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        let start = std::time::Instant::now();

        let messages = split_messages(input);
        for (i, msg) in messages.iter().enumerate() {
            // A failed send means the target closed the connection on an
            // earlier message, so the rest cannot be delivered.
            if let Err(e) = self.conn.send_message(msg) {
                log::debug!("[{:?}] send message {i}: {e}", start.elapsed());
                break;
            }
            log::debug!(
                "[{:?}] Sent message {i} ({} bytes)",
                start.elapsed(),
                msg.len()
            );
        }

        // Synchronize so that every message was received and initially
        // processed. Messages on one connection are handled in order, so a
        // single ping after the last one is enough.
        if let Err(e) = ping_pong(&mut self.conn) {
            log::debug!("[{:?}] ping_pong: {e}", start.elapsed());
            if e.is_timeout() {
                return ScenarioResult::Fail(Violation::Hung.to_string());
            }
            // Non-timeout error likely means the target closed the connection.
            // This is expected for invalid messages, but it could also mean the
            // target crashed. Use check_alive below to distinguish.
        } else {
            log::debug!("[{:?}] Target responded with pong", start.elapsed());
        }

        if let Err(e) = self.target.check_alive() {
            log::debug!("[{:?}] check_alive: {e}", start.elapsed());
            return ScenarioResult::Fail(Violation::Crashed.to_string());
        }

        ScenarioResult::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_MESSAGES, split_messages};

    #[test]
    fn splits_length_prefixed_messages() {
        let input = [0, 2, 0xaa, 0xbb, 0, 0, 0, 1, 0xcc];
        let expected: [&[u8]; 3] = [&[0xaa, 0xbb], &[], &[0xcc]];
        assert_eq!(split_messages(&input), expected);
    }

    #[test]
    fn short_last_message_takes_the_rest() {
        let input = [0xff, 0xff, 0xaa, 0xbb];
        let expected: [&[u8]; 1] = [&[0xaa, 0xbb]];
        assert_eq!(split_messages(&input), expected);
    }

    #[test]
    fn incomplete_prefix_is_dropped() {
        assert_eq!(split_messages(&[]), [] as [&[u8]; 0]);
        assert_eq!(split_messages(&[0]), [] as [&[u8]; 0]);
        let expected: [&[u8]; 1] = [&[0xaa]];
        assert_eq!(split_messages(&[0, 1, 0xaa, 0]), expected);
    }

    #[test]
    fn caps_message_count() {
        let input = vec![0; 2 * (MAX_MESSAGES + 5)];
        assert_eq!(split_messages(&input).len(), MAX_MESSAGES);
    }
}
