//! A circuit breaker for the AIRS call, and the rule for which failures are retried.
//!
//! After `threshold` consecutive failures the breaker opens, and for the cooldown the policy does not call AIRS at
//! all, so an outage does not add the full timeout to every request. An open breaker never allows traffic: the
//! request is then decided like any other scanner failure (`onApiError`). After the cooldown, calls are tried again;
//! a success closes the breaker and a failure opens it for another cooldown. Each gateway worker keeps its own.

use crate::airs::ScanError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Closed,
    Open { since_ms: u64 },
    HalfOpen,
}

#[derive(Debug, Clone)]
pub struct Breaker {
    threshold: u32,
    cooldown_ms: u64,
    failures: u32,
    state: State,
}

impl Breaker {
    /// `threshold` 0 turns the breaker off.
    pub fn new(threshold: u32, cooldown_ms: u64) -> Breaker {
        Breaker { threshold, cooldown_ms, failures: 0, state: State::Closed }
    }

    /// Whether a call may be made now. Time comes from the caller, in milliseconds.
    pub fn permits(&mut self, now_ms: u64) -> bool {
        match self.state {
            State::Closed | State::HalfOpen => true,
            State::Open { since_ms } if now_ms.saturating_sub(since_ms) >= self.cooldown_ms => {
                self.state = State::HalfOpen;
                true
            }
            State::Open { .. } => false,
        }
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        self.state = State::Closed;
    }

    pub fn record_failure(&mut self, now_ms: u64) {
        if self.threshold == 0 {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        if self.state == State::HalfOpen || self.failures >= self.threshold {
            self.state = State::Open { since_ms: now_ms };
        }
    }
}

/// Retried: a timeout, a transport error, 429 and 5xx. Never retried: anything AIRS answered on purpose (4xx), a reply
/// the policy could not read, an open breaker, or a verdict with a failed detection service.
pub fn retryable(error: &ScanError) -> bool {
    match error {
        ScanError::Timeout | ScanError::Transport(_) => true,
        ScanError::Status(code) => *code == 429 || (500..=599).contains(code),
        ScanError::Undecodable | ScanError::MissingAction | ScanError::BreakerOpen | ScanError::Incomplete(_) => false,
    }
}
