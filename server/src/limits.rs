use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

struct RateLimiterState {
    buckets: HashMap<String, VecDeque<Instant>>,
    last_sweep: Instant,
}

#[derive(Clone, Default)]
pub struct RateLimiter {
    state: Arc<Mutex<RateLimiterState>>,
}

impl Default for RateLimiterState {
    fn default() -> Self {
        Self {
            buckets: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RateLimiterState::default())),
        }
    }

    pub async fn check(&self, key: impl Into<String>, max_requests: usize, window: Duration) -> bool {
        let now = Instant::now();
        let cutoff = now - window;
        let mut state = self.state.lock().await;
        if now.duration_since(state.last_sweep) >= window {
            state
                .buckets
                .retain(|_, bucket| bucket.back().is_some_and(|instant| *instant >= cutoff));
            state.last_sweep = now;
        }

        let bucket = state.buckets.entry(key.into()).or_default();

        while bucket.front().is_some_and(|instant| *instant < cutoff) {
            bucket.pop_front();
        }

        if bucket.len() >= max_requests {
            return false;
        }

        bucket.push_back(now);
        true
    }
}
