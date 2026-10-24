use std::time::Duration;

use crate::Error;

const FIRST: Duration = Duration::from_secs(60);
const LAST: Duration = Duration::from_secs(3600);

/// Background retry schedule of lease.md §6: 1 min doubling to 1 h, or the server's `Retry-After`.
#[derive(Clone, Debug, Default)]
pub struct Backoff {
    failures: u32,
}

impl Backoff {
    pub fn new() -> Self {
        Self::default()
    }

    /// Delay before the next background attempt after `error`.
    pub fn next_delay(&mut self, error: &Error) -> Duration {
        let doubled = FIRST.saturating_mul(1 << self.failures.min(6)).min(LAST);
        self.failures = self.failures.saturating_add(1);
        error.retry_after().unwrap_or(doubled)
    }

    /// Call after a successful attempt.
    pub fn reset(&mut self) {
        self.failures = 0;
    }
}
