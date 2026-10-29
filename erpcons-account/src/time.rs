//! RFC 3339 parsing and trusted time (lease.md §7).
use std::time::Duration;

pub(crate) const SKEW: i64 = 300;
const PERSIST_EVERY: Duration = Duration::from_secs(600);

/// RFC 3339 date-time to Unix seconds; fractional seconds are truncated.
pub(crate) fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = s.get(19..)?;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = frac.get(digits..)?;
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let ob = rest.as_bytes();
            let sign = match ob.first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            if ob.len() != 6 || ob[3] != b':' {
                return None;
            }
            let oh: i64 = rest.get(1..3)?.parse().ok()?;
            let om: i64 = rest.get(4..6)?.parse().ok()?;
            sign * (oh * 3600 + om * 60)
        }
    };
    Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - offset)
}

/// IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) to Unix seconds; other HTTP date forms are rejected.
pub(crate) fn parse_http_date(s: &str) -> Option<i64> {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let b = s.as_bytes();
    if b.len() != 29
        || !DAYS.contains(&s.get(0..3)?)
        || &s[3..5] != ", "
        || b[7] != b' '
        || b[11] != b' '
        || b[16] != b' '
        || b[19] != b':'
        || b[22] != b':'
        || &s[25..] != " GMT"
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    let name = s.get(8..11)?;
    let month = i64::try_from(MONTHS.iter().position(|m| *m == name)?).ok()? + 1;
    let (d, y) = (num(5..7)?, num(12..16)?);
    let (h, mi, se) = (num(17..19)?, num(20..22)?, num(23..25)?);
    if !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, month, d) * 86400 + h * 3600 + mi * 60 + se)
}

// Howard Hinnant's days-from-civil algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `trusted_floor` bookkeeping for one process (lease.md §7).
#[derive(Debug)]
pub(crate) struct TrustedTime {
    floor0: i64,
    mono0: Duration,
    floor: i64,
    persisted_at: Option<Duration>,
    rolled_back: bool,
}

impl TrustedTime {
    pub(crate) fn new(stored_floor: i64, mono: Duration) -> Self {
        Self {
            floor0: stored_floor,
            mono0: mono,
            floor: stored_floor,
            persisted_at: None,
            rolled_back: false,
        }
    }

    /// Start of the process: `floor0` = stored floor, `mono0` = now.
    pub(crate) fn start(&mut self, stored: i64, mono: Duration) {
        self.floor0 = stored;
        self.mono0 = mono;
        self.floor = self.floor.max(stored);
    }

    /// `effective_now`; advances the in-memory floor and flags a rollback.
    pub(crate) fn now(&mut self, system: i64, mono: Duration) -> i64 {
        let running = i64::try_from(mono.saturating_sub(self.mono0).as_secs()).unwrap_or(i64::MAX);
        let effective = system
            .max(self.floor0.saturating_add(running))
            .max(self.floor);
        if system < effective - SKEW && !self.rolled_back {
            self.rolled_back = true;
            log::warn!("clock_rolled_back: system time is behind the trusted floor");
        }
        self.floor = effective;
        effective
    }

    pub(crate) fn floor(&self) -> i64 {
        self.floor
    }

    pub(crate) fn rolled_back(&self) -> bool {
        self.rolled_back
    }

    /// Takes a floor written by another process; floors only grow this way.
    pub(crate) fn merge(&mut self, stored: i64) {
        self.floor = self.floor.max(stored);
    }

    /// Server correction from a lease `iat`, the only way the floor goes down. True if applied.
    pub(crate) fn correct(&mut self, iat: i64, mono: Duration) -> bool {
        if self.floor < iat || self.floor > iat + SKEW {
            self.floor = iat;
            self.floor0 = iat;
            self.mono0 = mono;
            true
        } else {
            false
        }
    }

    pub(crate) fn persist_due(&self, mono: Duration) -> bool {
        self.persisted_at
            .is_none_or(|at| mono.saturating_sub(at) >= PERSIST_EVERY)
    }

    pub(crate) fn mark_persisted(&mut self, mono: Duration) {
        self.persisted_at = Some(mono);
    }
}
