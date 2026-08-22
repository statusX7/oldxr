use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

const CONNECTION_ERRORS_PER_SECOND: u64 = 8;
const COUNT_BITS: u32 = 16;
const COUNT_MASK: u64 = (1 << COUNT_BITS) - 1;

static VMESS_ERRORS: ErrorBucket = ErrorBucket::new();
static SS_ERRORS: ErrorBucket = ErrorBucket::new();

pub enum ErrorScope {
    FastVmess,
    FastSs,
}

impl ErrorScope {
    fn label(&self) -> &'static str {
        match self {
            Self::FastVmess => "FastVMess",
            Self::FastSs => "FastSS",
        }
    }

    fn bucket(&self) -> &'static ErrorBucket {
        match self {
            Self::FastVmess => &VMESS_ERRORS,
            Self::FastSs => &SS_ERRORS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorDecision {
    Log,
    Notice,
    Suppress,
}

struct ErrorBucket {
    // The high bits hold wall-clock seconds and the low bits hold the count.
    // Keeping both values in one CAS avoids a rollover race between two
    // independent atomics during an error burst.
    state: AtomicU64,
}

impl ErrorBucket {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }

    fn record(&self, epoch: u64) -> ErrorDecision {
        let encoded_epoch = epoch << COUNT_BITS;
        loop {
            let previous = self.state.load(Ordering::Relaxed);
            let previous_epoch = previous >> COUNT_BITS;
            let previous_count = previous & COUNT_MASK;
            let count = if previous_epoch == epoch {
                previous_count
            } else {
                0
            };
            let next_count = count.saturating_add(1).min(COUNT_MASK);
            let next = encoded_epoch | next_count;
            if self
                .state
                .compare_exchange_weak(previous, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return match count {
                    count if count < CONNECTION_ERRORS_PER_SECOND => ErrorDecision::Log,
                    CONNECTION_ERRORS_PER_SECOND => ErrorDecision::Notice,
                    _ => ErrorDecision::Suppress,
                };
            }
        }
    }
}

/// Keeps an invalid-auth or reconnect burst from turning stderr/journald into
/// a second CPU denial of service. The first errors remain visible, followed
/// by one explicit suppression notice per wall-clock second.
pub fn connection_error(scope: ErrorScope, error: impl fmt::Display) {
    let epoch = SystemTime::UNIX_EPOCH
        .elapsed()
        .map_or(0, |elapsed| elapsed.as_secs());
    match scope.bucket().record(epoch) {
        ErrorDecision::Log => {
            eprintln!("{} connection failed: {error}", scope.label());
        }
        ErrorDecision::Notice => eprintln!(
            "{} connection errors are rate limited for this second",
            scope.label()
        ),
        ErrorDecision::Suppress => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_bucket_logs_then_notices_and_resets_next_second() {
        let bucket = ErrorBucket::new();
        for _ in 0..CONNECTION_ERRORS_PER_SECOND {
            assert_eq!(bucket.record(7), ErrorDecision::Log);
        }
        assert_eq!(bucket.record(7), ErrorDecision::Notice);
        assert_eq!(bucket.record(7), ErrorDecision::Suppress);
        assert_eq!(bucket.record(8), ErrorDecision::Log);
    }
}
