//! # aegis-meter — token-aware cost governor + agentic circuit breakers (LLM06)
//!
//! A `● Contain` control (architecture-considerations.md §3 LLM06). It bounds consumption
//! deterministically:
//!
//! * **Pre-flight token estimation** — reject a request *before* inference when it would exceed
//!   the per-request token or cost ceiling.
//! * **Hard spending caps** — a non-overridable per-session cost cap that *halts* (trips the
//!   breaker), not just alarms.
//! * **Agentic circuit breakers** — step / recursion / wall-clock ceilings and state-hashing
//!   loop detection, so two agents cannot hand control back and forth forever.
//! * **Rate windows** — tokens-per-minute / per-day sliding windows (the growing-context guard).
//!
//! Time is passed in explicitly (`now_ms`, Unix milliseconds) so the whole meter is
//! deterministic and unit-testable with no real clock.

use std::borrow::Cow;
use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

mod estimate;
pub use estimate::{estimate_tokens, CostModel, HeuristicEstimator, TokenEstimator};

/// The verdict of a meter check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Within budget — proceed.
    Proceed,
    /// Refused. The reason is a fixed, non-sensitive string safe to log and return.
    Reject(Cow<'static, str>),
}

impl Verdict {
    /// A static-string rejection.
    pub fn reject(reason: &'static str) -> Self {
        Verdict::Reject(Cow::Borrowed(reason))
    }
    /// Whether this verdict permits proceeding.
    #[must_use]
    pub fn is_proceed(&self) -> bool {
        matches!(self, Verdict::Proceed)
    }
}

/// The configured budget for one session/run. Loaded from a versioned artifact (`meter.toml`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    /// Max estimated tokens for a single request (pre-flight rejects above this).
    pub max_tokens_per_request: u64,
    /// Sliding-window token ceiling per minute.
    pub tokens_per_minute: u64,
    /// Sliding-window token ceiling per day.
    pub tokens_per_day: u64,
    /// Max estimated cost (USD) for a single request.
    pub max_cost_per_request_usd: f64,
    /// Non-overridable cumulative cost cap (USD). Reaching it trips the breaker and halts.
    pub hard_cost_cap_usd: f64,
    /// Max agent steps (tool calls / loop iterations) in the session.
    pub max_steps: u32,
    /// Max recursion / delegation depth.
    pub max_recursion_depth: u32,
    /// Max wall-clock duration for the session (ms).
    pub max_wall_clock_ms: u64,
    /// How many times the same state hash may recur before it is treated as a loop.
    pub loop_repeat_threshold: u32,
    /// **Inter-agent fan-out cap** (§11.1, ASI08 blast radius): the max total number of
    /// sub-agents/tasks this session may spawn. Bounds how far a single fault can propagate.
    /// `#[serde(default)]` so pre-existing `meter.toml` files (without this field) still parse.
    #[serde(default = "default_max_fanout")]
    pub max_fanout: u32,
}

fn default_max_fanout() -> u32 {
    16
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tokens_per_request: 100_000,
            tokens_per_minute: 500_000,
            tokens_per_day: 20_000_000,
            max_cost_per_request_usd: 5.0,
            hard_cost_cap_usd: 50.0,
            max_steps: 50,
            max_recursion_depth: 8,
            max_wall_clock_ms: 15 * 60 * 1000, // Lambda's 900s ceiling.
            loop_repeat_threshold: 3,
            max_fanout: default_max_fanout(),
        }
    }
}

/// A sliding-window sum of `(timestamp_ms, amount)` samples within a fixed window.
#[derive(Debug, Clone, Default)]
struct WindowCounter {
    window_ms: u64,
    samples: VecDeque<(u64, u64)>,
    sum: u64,
}

impl WindowCounter {
    fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            samples: VecDeque::new(),
            sum: 0,
        }
    }
    /// Drop samples older than the window relative to `now_ms`.
    fn evict(&mut self, now_ms: u64) {
        while let Some(&(ts, amt)) = self.samples.front() {
            if now_ms.saturating_sub(ts) >= self.window_ms {
                self.samples.pop_front();
                self.sum -= amt;
            } else {
                break;
            }
        }
    }
    /// Current windowed sum after eviction.
    fn current(&mut self, now_ms: u64) -> u64 {
        self.evict(now_ms);
        self.sum
    }
    fn add(&mut self, now_ms: u64, amount: u64) {
        self.evict(now_ms);
        self.samples.push_back((now_ms, amount));
        self.sum += amount;
    }
}

/// The stateful meter for one session. Monotonic in cost/steps; the breaker, once tripped,
/// stays tripped (a hard cap halts the run rather than degrading gracefully).
#[derive(Debug, Clone)]
pub struct Meter {
    limits: Limits,
    minute: WindowCounter,
    day: WindowCounter,
    total_cost_usd: f64,
    steps: u32,
    fanout: u32,
    started_ms: Option<u64>,
    recent_states: VecDeque<u64>,
    state_counts: std::collections::HashMap<u64, u32>,
    tripped: Option<Cow<'static, str>>,
}

/// A serializable snapshot of a [`Meter`]'s enforcement state.
///
/// Purpose: persist a session's budget/breaker state durably so it is **not reset by a cold
/// restart across a pause** (e.g. a Rule-of-Two HITL `waitForTaskToken` wait). Without this, a
/// resumed session that lands on a fresh process would regain a full budget and shed its
/// loop/step/cost history — a real bypass of the LLM06 caps.
///
/// The [`Limits`] are deliberately **not** part of the snapshot: they come from the versioned
/// `meter.toml` config and are supplied to [`Meter::from_snapshot`], so a budget-tightening
/// re-deploy is honoured on rehydrate rather than being pinned to a stale copy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeterSnapshot {
    /// Cumulative cost recorded so far (USD).
    pub total_cost_usd: f64,
    /// Steps taken so far.
    pub steps: u32,
    /// Cumulative fan-out (sub-agents/tasks spawned).
    pub fanout: u32,
    /// When the session's wall-clock started (unix ms), if a step has been taken.
    pub started_ms: Option<u64>,
    /// The breaker trip reason, if tripped. Stored as an owned string; the live meter holds it as
    /// `Cow<'static, str>` (all trip reasons are static, so the text round-trips exactly).
    pub tripped: Option<String>,
    /// Loop-detection recency ring (state hashes).
    pub recent_states: Vec<u64>,
    /// Loop-detection per-state-hash occurrence counts.
    pub state_counts: std::collections::HashMap<u64, u32>,
    /// Minute-window token samples `(timestamp_ms, tokens)`.
    pub minute_samples: Vec<(u64, u64)>,
    /// Day-window token samples `(timestamp_ms, tokens)`.
    pub day_samples: Vec<(u64, u64)>,
}

impl Meter {
    /// A fresh meter with the given limits.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            minute: WindowCounter::new(60_000),
            day: WindowCounter::new(24 * 60 * 60 * 1000),
            total_cost_usd: 0.0,
            steps: 0,
            fanout: 0,
            started_ms: None,
            recent_states: VecDeque::new(),
            state_counts: std::collections::HashMap::new(),
            tripped: None,
            limits,
        }
    }

    /// **Fan-out breaker** (§11.1, ASI08): record `children` newly-spawned sub-agents/tasks and
    /// trip when the session's cumulative fan-out exceeds `max_fanout`. Bounds blast radius so a
    /// single fault cannot spawn an unbounded tree of agents.
    pub fn observe_fanout(&mut self, children: u32) -> Verdict {
        if let Some(reason) = self.tripped.clone() {
            return Verdict::Reject(reason);
        }
        self.fanout = self.fanout.saturating_add(children);
        if self.fanout > self.limits.max_fanout {
            return self.trip("inter-agent fan-out cap exceeded");
        }
        Verdict::Proceed
    }

    /// Cumulative fan-out (sub-agents/tasks spawned) so far.
    #[must_use]
    pub fn fanout(&self) -> u32 {
        self.fanout
    }

    /// Whether the circuit breaker has tripped (the session is halted).
    #[must_use]
    pub fn is_tripped(&self) -> bool {
        self.tripped.is_some()
    }

    /// The reason the breaker tripped, if any.
    #[must_use]
    pub fn trip_reason(&self) -> Option<&str> {
        self.tripped.as_deref()
    }

    /// Cumulative cost recorded so far (USD).
    #[must_use]
    pub fn total_cost_usd(&self) -> f64 {
        self.total_cost_usd
    }

    /// Steps taken so far.
    #[must_use]
    pub fn steps(&self) -> u32 {
        self.steps
    }

    fn trip(&mut self, reason: &'static str) -> Verdict {
        if self.tripped.is_none() {
            self.tripped = Some(Cow::Borrowed(reason));
        }
        Verdict::reject(reason)
    }

    /// **Pre-flight**: decide whether a request of `est_tokens` and `est_cost` USD may run,
    /// *before* paying for inference. Rejects on a tripped breaker, an over-size request, a
    /// per-request cost ceiling, a rate-window ceiling, or the hard cost cap.
    pub fn preflight(&mut self, now_ms: u64, est_tokens: u64, est_cost_usd: f64) -> Verdict {
        if let Some(reason) = self.tripped.clone() {
            return Verdict::Reject(reason);
        }
        if est_tokens > self.limits.max_tokens_per_request {
            return Verdict::reject("request exceeds max tokens per request");
        }
        if est_cost_usd > self.limits.max_cost_per_request_usd {
            return Verdict::reject("request exceeds max cost per request");
        }
        if self.minute.current(now_ms) + est_tokens > self.limits.tokens_per_minute {
            return Verdict::reject("tokens-per-minute limit exceeded");
        }
        if self.day.current(now_ms) + est_tokens > self.limits.tokens_per_day {
            return Verdict::reject("tokens-per-day limit exceeded");
        }
        // Hard cap is a halt: reaching it with this request trips the breaker.
        if self.total_cost_usd + est_cost_usd > self.limits.hard_cost_cap_usd {
            return self.trip("hard spending cap reached");
        }
        Verdict::Proceed
    }

    /// **Record** actual usage after a model call. Accumulates tokens into the rate windows and
    /// cost into the session total; trips the breaker if the hard cap is reached.
    pub fn record(&mut self, now_ms: u64, tokens_used: u64, cost_usd: f64) {
        self.minute.add(now_ms, tokens_used);
        self.day.add(now_ms, tokens_used);
        self.total_cost_usd += cost_usd;
        if self.total_cost_usd >= self.limits.hard_cost_cap_usd {
            self.trip("hard spending cap reached");
        }
    }

    /// **Step breaker**: call once per agent step (tool call / loop iteration). Trips on the step
    /// ceiling or the wall-clock ceiling.
    pub fn step(&mut self, now_ms: u64) -> Verdict {
        if let Some(reason) = self.tripped.clone() {
            return Verdict::Reject(reason);
        }
        let start = *self.started_ms.get_or_insert(now_ms);
        self.steps += 1;
        if self.steps > self.limits.max_steps {
            return self.trip("step ceiling exceeded");
        }
        if now_ms.saturating_sub(start) > self.limits.max_wall_clock_ms {
            return self.trip("wall-clock ceiling exceeded");
        }
        Verdict::Proceed
    }

    /// **Recursion breaker**: reject when a delegation/recursion depth exceeds the ceiling.
    pub fn check_recursion(&mut self, depth: u32) -> Verdict {
        if let Some(reason) = self.tripped.clone() {
            return Verdict::Reject(reason);
        }
        if depth > self.limits.max_recursion_depth {
            return self.trip("recursion depth exceeded");
        }
        Verdict::Proceed
    }

    /// **Loop breaker**: observe a hash of the agent's current state. When the same state recurs
    /// more than `loop_repeat_threshold` times the breaker trips (a stuck / oscillating agent).
    pub fn observe_state(&mut self, state_hash: u64) -> Verdict {
        if let Some(reason) = self.tripped.clone() {
            return Verdict::Reject(reason);
        }
        let count = self.state_counts.entry(state_hash).or_insert(0);
        *count += 1;
        if *count > self.limits.loop_repeat_threshold {
            return self.trip("loop detected (repeated state)");
        }
        // Keep the recency ring bounded.
        self.recent_states.push_back(state_hash);
        if self.recent_states.len() > 256 {
            self.recent_states.pop_front();
        }
        Verdict::Proceed
    }

    /// Capture a serializable [`MeterSnapshot`] of the enforcement state, for durable persistence
    /// so budgets/breakers survive a pause (see [`MeterSnapshot`]). Does not include the limits.
    #[must_use]
    pub fn snapshot(&self) -> MeterSnapshot {
        MeterSnapshot {
            total_cost_usd: self.total_cost_usd,
            steps: self.steps,
            fanout: self.fanout,
            started_ms: self.started_ms,
            tripped: self.tripped.as_ref().map(|c| c.to_string()),
            recent_states: self.recent_states.iter().copied().collect(),
            state_counts: self.state_counts.clone(),
            minute_samples: self.minute.samples.iter().copied().collect(),
            day_samples: self.day.samples.iter().copied().collect(),
        }
    }

    /// Rebuild a meter from `limits` (current config) and a previously captured [`MeterSnapshot`].
    /// The window samples are restored verbatim (ordered oldest-first); stale samples are evicted
    /// lazily on the next windowed check, exactly as during normal operation.
    #[must_use]
    pub fn from_snapshot(limits: Limits, snap: MeterSnapshot) -> Self {
        let mut minute = WindowCounter::new(60_000);
        for (ts, amt) in snap.minute_samples {
            minute.samples.push_back((ts, amt));
            minute.sum += amt;
        }
        let mut day = WindowCounter::new(24 * 60 * 60 * 1000);
        for (ts, amt) in snap.day_samples {
            day.samples.push_back((ts, amt));
            day.sum += amt;
        }
        Self {
            limits,
            minute,
            day,
            total_cost_usd: snap.total_cost_usd,
            steps: snap.steps,
            fanout: snap.fanout,
            started_ms: snap.started_ms,
            recent_states: snap.recent_states.into_iter().collect(),
            state_counts: snap.state_counts,
            // All trip reasons are static strings; `Cow::Owned` preserves the exact text.
            tripped: snap.tripped.map(Cow::Owned),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_limits() -> Limits {
        Limits {
            max_tokens_per_request: 1_000,
            tokens_per_minute: 1_500,
            tokens_per_day: 5_000,
            max_cost_per_request_usd: 1.0,
            hard_cost_cap_usd: 2.0,
            max_steps: 3,
            max_recursion_depth: 2,
            max_wall_clock_ms: 10_000,
            loop_repeat_threshold: 2,
            max_fanout: 4,
        }
    }

    #[test]
    fn fanout_breaker_trips_when_cap_exceeded() {
        let mut m = Meter::new(small_limits()); // max_fanout = 4
        assert!(m.observe_fanout(3).is_proceed()); // total 3
        assert!(m.observe_fanout(1).is_proceed()); // total 4 (== cap, allowed)
        assert_eq!(m.fanout(), 4);
        // The 5th child exceeds the cap and trips the breaker.
        assert_eq!(
            m.observe_fanout(1),
            Verdict::reject("inter-agent fan-out cap exceeded")
        );
        assert!(m.is_tripped());
    }

    #[test]
    fn snapshot_round_trips_enforcement_state() {
        let mut m = Meter::new(small_limits()); // max_steps=3, loop_repeat_threshold=2
        m.step(0); // steps = 1
        m.record(0, 100, 0.5); // cost 0.5; minute/day windows hold 100
        m.observe_state(42); // count{42} = 1
        m.observe_state(42); // count{42} = 2
        let snap = m.snapshot();

        // The snapshot survives a JSON round-trip unchanged (the durable-store wire form).
        let json = serde_json::to_string(&snap).unwrap();
        let snap2: MeterSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, snap2);

        // A meter rebuilt from the snapshot continues from the same state, not a fresh budget.
        let mut r = Meter::from_snapshot(small_limits(), snap2);
        assert_eq!(r.steps(), 1);
        assert!((r.total_cost_usd() - 0.5).abs() < 1e-9);
        // Loop-counter continuity: 42 seen twice already; once more exceeds threshold=2 -> trip.
        assert_eq!(
            r.observe_state(42),
            Verdict::reject("loop detected (repeated state)")
        );
        assert!(r.is_tripped());
    }

    #[test]
    fn snapshot_preserves_a_tripped_breaker() {
        let mut m = Meter::new(small_limits());
        m.record(0, 0, 5.0); // exceeds the $2 hard cap -> tripped
        assert!(m.is_tripped());
        let r = Meter::from_snapshot(small_limits(), m.snapshot());
        assert!(r.is_tripped());
        assert_eq!(r.trip_reason(), Some("hard spending cap reached"));
    }

    #[test]
    fn preflight_rejects_oversize_request() {
        let mut m = Meter::new(small_limits());
        assert_eq!(
            m.preflight(0, 2_000, 0.1),
            Verdict::reject("request exceeds max tokens per request")
        );
        assert!(
            !m.is_tripped(),
            "a per-request reject does not trip the breaker"
        );
    }

    #[test]
    fn preflight_rejects_per_request_cost() {
        let mut m = Meter::new(small_limits());
        assert_eq!(
            m.preflight(0, 10, 5.0),
            Verdict::reject("request exceeds max cost per request")
        );
    }

    #[test]
    fn per_minute_window_limits_and_then_recovers() {
        let mut m = Meter::new(small_limits());
        m.record(0, 1_000, 0.1);
        m.record(1_000, 400, 0.1);
        // 1400 in-window; +200 would exceed the 1500/min ceiling.
        assert_eq!(
            m.preflight(2_000, 200, 0.1),
            Verdict::reject("tokens-per-minute limit exceeded")
        );
        // After the window slides past 60s, the early sample is evicted.
        assert!(m.preflight(61_001, 200, 0.1).is_proceed());
    }

    #[test]
    fn hard_cost_cap_trips_and_stays_tripped() {
        let mut m = Meter::new(small_limits());
        m.record(0, 10, 1.5);
        assert!(!m.is_tripped());
        // Preflight that would cross the $2.00 cap trips the breaker (a halt).
        assert_eq!(
            m.preflight(0, 10, 1.0),
            Verdict::reject("hard spending cap reached")
        );
        assert!(m.is_tripped());
        // Once tripped, every check is refused — even a trivially cheap one.
        assert_eq!(
            m.preflight(0, 1, 0.0),
            Verdict::reject("hard spending cap reached")
        );
        assert!(!m.step(0).is_proceed());
    }

    #[test]
    fn record_trips_when_cumulative_cost_reaches_cap() {
        let mut m = Meter::new(small_limits());
        m.record(0, 10, 1.0);
        m.record(0, 10, 1.0); // total 2.0 >= cap
        assert!(m.is_tripped());
        assert_eq!(m.trip_reason(), Some("hard spending cap reached"));
    }

    #[test]
    fn step_ceiling_trips() {
        let mut m = Meter::new(small_limits());
        assert!(m.step(0).is_proceed()); // 1
        assert!(m.step(0).is_proceed()); // 2
        assert!(m.step(0).is_proceed()); // 3
        assert_eq!(m.step(0), Verdict::reject("step ceiling exceeded")); // 4 > 3
        assert!(m.is_tripped());
    }

    #[test]
    fn wall_clock_ceiling_trips() {
        let mut m = Meter::new(small_limits());
        assert!(m.step(0).is_proceed()); // starts the clock at t=0
        assert_eq!(
            m.step(10_001),
            Verdict::reject("wall-clock ceiling exceeded")
        );
    }

    #[test]
    fn recursion_depth_trips() {
        let mut m = Meter::new(small_limits());
        assert!(m.check_recursion(2).is_proceed());
        assert_eq!(
            m.check_recursion(3),
            Verdict::reject("recursion depth exceeded")
        );
    }

    #[test]
    fn loop_detection_trips_on_repeated_state() {
        let mut m = Meter::new(small_limits());
        assert!(m.observe_state(42).is_proceed()); // 1
        assert!(m.observe_state(42).is_proceed()); // 2
        assert_eq!(
            m.observe_state(42),
            Verdict::reject("loop detected (repeated state)")
        ); // 3 > threshold 2
           // A different state on a fresh meter is fine.
        let mut m2 = Meter::new(small_limits());
        assert!(m2.observe_state(1).is_proceed());
        assert!(m2.observe_state(2).is_proceed());
    }

    #[test]
    fn defaults_are_sane() {
        let m = Meter::new(Limits::default());
        assert_eq!(m.steps(), 0);
        assert_eq!(m.total_cost_usd(), 0.0);
        assert!(!m.is_tripped());
    }
}
