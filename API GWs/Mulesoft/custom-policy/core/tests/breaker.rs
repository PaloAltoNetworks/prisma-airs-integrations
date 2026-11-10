use prisma_airs_core::airs::ScanError;
use prisma_airs_core::breaker::{retryable, Breaker};

#[test]
fn breaker_opens_after_threshold() {
    let mut b = Breaker::new(2, 30_000);
    assert!(b.permits(0));
    b.record_failure(0);
    assert!(b.permits(1), "one failure is below the threshold");
    b.record_failure(1);
    assert!(!b.permits(2));
    assert!(!b.permits(29_999));
}

#[test]
fn breaker_half_open_after_cooldown() {
    let mut b = Breaker::new(2, 30_000);
    b.record_failure(0);
    b.record_failure(0);
    assert!(b.permits(30_000), "the cooldown is over: one trial call is allowed");
    b.record_failure(30_000);
    assert!(!b.permits(30_001), "a failed trial re-opens the breaker");
    assert!(b.permits(60_000));
    b.record_success();
    assert!(b.permits(60_001));
    b.record_failure(60_001);
    assert!(b.permits(60_002), "after a success the count starts again");
}

#[test]
fn success_resets_the_count() {
    let mut b = Breaker::new(2, 30_000);
    b.record_failure(0);
    b.record_success();
    b.record_failure(1);
    assert!(b.permits(2));
}

#[test]
fn breaker_threshold_zero_never_opens() {
    let mut b = Breaker::new(0, 30_000);
    for t in 0..100 {
        b.record_failure(t);
    }
    assert!(b.permits(100));
}

#[test]
fn retryable_table() {
    assert!(retryable(&ScanError::Timeout));
    assert!(retryable(&ScanError::Transport("reset".into())));
    assert!(retryable(&ScanError::Status(429)));
    assert!(retryable(&ScanError::Status(500)));
    assert!(retryable(&ScanError::Status(503)));
    assert!(retryable(&ScanError::Status(599)));
    assert!(!retryable(&ScanError::Status(400)));
    assert!(!retryable(&ScanError::Status(401)));
    assert!(!retryable(&ScanError::Status(403)));
    assert!(!retryable(&ScanError::Status(413)));
    assert!(!retryable(&ScanError::Undecodable));
    assert!(!retryable(&ScanError::MissingAction));
    assert!(!retryable(&ScanError::BreakerOpen));
    assert!(!retryable(&ScanError::Incomplete(vec!["dlp:error".into()])));
}
