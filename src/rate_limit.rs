use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    cooldown: Duration,
    last_alert: HashMap<String, Instant>,
}

impl RateLimiter {
    pub fn new(cooldown_seconds: u64) -> Self {
        Self {
            cooldown: Duration::from_secs(cooldown_seconds),
            last_alert: HashMap::new(),
        }
    }

    pub fn should_alert(&mut self, matched_rule: &str) -> bool {
        let now = Instant::now();
        if let Some(&last_time) = self.last_alert.get(matched_rule) {
            if now.duration_since(last_time) < self.cooldown {
                return false;
            }
        }
        self.last_alert.insert(matched_rule.to_string(), now);
        true
    }
}
