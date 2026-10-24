use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Wall clock and monotonic clock; replaceable in tests.
pub trait Clock: Send + Sync {
    /// System time, Unix seconds.
    fn unix_now(&self) -> i64;
    /// Monotonic time since an arbitrary origin fixed for the process.
    fn monotonic(&self) -> Duration;
}

/// The operating system clocks.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn unix_now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
    fn monotonic(&self) -> Duration {
        self.origin.elapsed()
    }
}
