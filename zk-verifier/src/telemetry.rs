//! Minimal, generic sub-step timing for the `/verify` pipeline.
//!
//! A single histogram, `zk_verify_step_duration_milliseconds`, labelled by
//! `step`, so a verify request's ~1–2s can be broken down (gate wait vs
//! deserialize vs proof verify vs expand vs sign vs storage) in
//! Prometheus/Grafana — without a new metric name per step. Use the RAII
//! [`StepTimer`] to time a scope, or [`record_step`] to record an
//! already-measured (e.g. accumulated) duration. Add a step by naming it,
//! nothing else to wire.

use std::time::{Duration, Instant};

use metrics::histogram;

/// Record a measured duration for `step` under
/// `zk_verify_step_duration_milliseconds{step="<step>"}`. Use directly when the
/// duration is accumulated (e.g. a per-ct loop split into sub-steps); otherwise
/// prefer the RAII [`StepTimer`].
pub(crate) fn record_step(step: &'static str, elapsed: Duration) {
    histogram!("zk_verify_step_duration_milliseconds", "step" => step)
        .record(elapsed.as_secs_f64() * 1000.0);
}

/// RAII timer that records the elapsed wall time of its scope via
/// [`record_step`] on drop — so it captures the scope even on early return
/// (`?`), error, or panic.
///
/// ```ignore
/// let value = {
///     let _t = StepTimer::start("deserialize");
///     deserialize(bytes)?
/// };
/// ```
pub(crate) struct StepTimer {
    step: &'static str,
    start: Instant,
}

impl StepTimer {
    pub(crate) fn start(step: &'static str) -> Self {
        Self { step, start: Instant::now() }
    }
}

impl Drop for StepTimer {
    fn drop(&mut self) {
        record_step(self.step, self.start.elapsed());
    }
}
