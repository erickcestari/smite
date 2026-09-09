//! Harness side of the `LD_PRELOAD`ed crash handler protocol.
//!
//! Targets are spawned with `smite-nyx-sys/src/nyx-crash-handler.c` (or
//! `jvm-crash-handler.c` for JVM targets) preloaded. In Nyx mode the handler
//! reports crashes straight to the hypervisor. In local mode it writes the
//! crash report to [`CRASH_LOG_PATH`] and then sends `SIGUSR1` to the harness
//! pid it finds in [`HARNESS_PID_ENV`], so the harness fails the test case
//! the moment the target dies instead of at its next liveness check.
//!
//! The names and paths below must match the C sources.

use std::path::Path;
use std::process::Command;

/// Env var naming the crash handler shared object to `LD_PRELOAD` into targets.
pub const CRASH_HANDLER_ENV: &str = "SMITE_CRASH_HANDLER";

/// Env var through which the harness tells the crash handler its pid.
pub const HARNESS_PID_ENV: &str = "SMITE_HARNESS_PID";

/// Where the crash handler writes the crash report in local mode.
pub const CRASH_LOG_PATH: &str = "/tmp/smite-crash.log";

/// Marker file created right before the first fuzz input is delivered, so
/// crash handlers can filter out expected subprocess exits that occur during
/// node startup.
pub const STARTUP_COMPLETE_MARKER: &str = "/tmp/smite-startup-complete";

/// Creates [`STARTUP_COMPLETE_MARKER`].
///
/// # Panics
///
/// Panics if the marker file cannot be created.
pub fn create_startup_complete_marker() {
    std::fs::File::create(STARTUP_COMPLETE_MARKER).expect("startup complete file created");
}

/// Preloads the crash handler named by [`CRASH_HANDLER_ENV`] into `cmd`, if
/// set, and tells it which pid to signal on a crash.
///
/// Call this only on the target daemon itself, not on helper CLIs, so the
/// handler does not interfere with processes that are expected to exit.
pub fn preload(cmd: &mut Command) {
    if let Ok(handler) = std::env::var(CRASH_HANDLER_ENV) {
        preload_handler(cmd, &handler);
    }
}

fn preload_handler(cmd: &mut Command, handler: &str) {
    cmd.env("LD_PRELOAD", handler)
        .env(HARNESS_PID_ENV, std::process::id().to_string());
}

/// Consumes the crash report left at [`CRASH_LOG_PATH`], if any.
///
/// Returns `Some` if the crash handler fired, with whatever report it wrote
/// (possibly empty). The file is removed so a later run does not see it again.
#[must_use]
pub fn take_crash_log() -> Option<String> {
    take_crash_log_at(Path::new(CRASH_LOG_PATH))
}

fn take_crash_log_at(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let report = std::fs::read_to_string(path).unwrap_or_default();
    let _ = std::fs::remove_file(path);
    Some(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn preload_sets_handler_and_harness_pid() {
        let mut cmd = Command::new("true");
        preload_handler(&mut cmd, "/crash-handler.so");

        let envs: Vec<_> = cmd.get_envs().collect();
        let pid = std::process::id().to_string();
        assert!(envs.contains(&(
            OsStr::new("LD_PRELOAD"),
            Some(OsStr::new("/crash-handler.so"))
        )));
        assert!(envs.contains(&(OsStr::new(HARNESS_PID_ENV), Some(OsStr::new(&pid)))));
    }

    #[test]
    fn take_crash_log_returns_report_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crash.log");

        assert_eq!(take_crash_log_at(&path), None);

        std::fs::write(&path, "abort\n").expect("write crash log");
        assert_eq!(take_crash_log_at(&path).as_deref(), Some("abort\n"));
        assert!(!path.exists(), "crash log must be consumed");
        assert_eq!(take_crash_log_at(&path), None);
    }
}
