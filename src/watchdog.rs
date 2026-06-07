use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use chrono::Local;
use log::{debug, info, warn};
use regex::Regex;

use crate::config::Config;
use crate::notify::notify;
use crate::rate_limit::RateLimiter;

pub struct DnsWatchdog {
    cfg: Config,
    limiter: RateLimiter,
    stats: HashMap<String, u64>,
    stop_flag: Arc<AtomicBool>,
}

impl DnsWatchdog {
    pub fn new(cfg: Config, stop_flag: Arc<AtomicBool>) -> Self {
        let cooldown = cfg.cooldown_seconds;
        Self {
            cfg,
            limiter: RateLimiter::new(cooldown),
            stats: HashMap::new(),
            stop_flag,
        }
    }

    pub fn run(&mut self) {
        info!("DNS Watchdog starting — watchlist has {} entries, cooldown={}s", self.cfg.watchlist.len(), self.cfg.cooldown_seconds);

        while !self.stop_flag.load(Ordering::SeqCst) {
            self.stream_loop();
            if !self.stop_flag.load(Ordering::SeqCst) {
                warn!("tcpdump process ended unexpectedly. Restarting in 5s...");
                std::thread::sleep(Duration::from_secs(5));
            }
        }
        
        info!("DNS Watchdog shutting down cleanly.");
    }

    fn stream_loop(&mut self) {
        let interface = "en0"; // Adjust this if necessary or make it configurable
        
        debug!("Launching tcpdump on interface {}", interface);
        let mut child = match Command::new("tcpdump")
            .args(["-l", "-n", "-i", interface, "udp", "port", "53"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to start tcpdump: {}", e);
                return;
            }
        };

        let stdout = child.stdout.take().expect("Failed to open stdout");
        let reader = BufReader::new(stdout);
        
        // Regex pattern: looks for A or AAAA records
        // Ex: 192.168.1.1.53 > 192.168.1.2.1234: 1234 A? example.com.
        let pattern = Regex::new(r"A\?\s+([a-zA-Z0-9.-]+)\.").unwrap();

        for line_res in reader.lines() {
            if self.stop_flag.load(Ordering::SeqCst) {
                let _ = child.kill();
                break;
            }

            if let Ok(line) = line_res {
                if let Some(caps) = pattern.captures(&line) {
                    if let Some(domain_match) = caps.get(1) {
                        let domain = domain_match.as_str().to_lowercase();
                        self.process_domain(&domain);
                    }
                }
            }
        }
        
        let _ = child.wait();
    }

    fn process_domain(&mut self, domain: &str) {
        if let Some(hit) = match_watchlist(domain, &self.cfg.watchlist) {
            let count = self.stats.entry(domain.to_string()).or_insert(0);
            *count += 1;
            
            info!("[HIT] {}  (matched: '{}', total_hits={})", domain, hit, count);
            
            if self.limiter.should_alert(&hit) {
                self.fire_alert(domain, &hit);
            } else {
                debug!("[RATE-LIMITED] {} (rule: '{}')", domain, hit);
            }
        } else if self.cfg.verbose_non_hits {
            debug!("[DNS] {}", domain);
        }
    }

    fn fire_alert(&mut self, domain: &str, matched_rule: &str) {
        let ts = Local::now().format("%H:%M:%S").to_string();
        warn!("[ALERT] {}  rule='{}'  time={}", domain, matched_rule, ts);
        
        let title = "⚠️ DNS Watchdog Hit";
        let subtitle = format!("Rule: {}", matched_rule);
        let body = format!("{}  [{}]", domain, ts);
        
        notify(title, &subtitle, &body, Some(&self.cfg.alert_sound));
    }
}

pub fn match_watchlist(domain: &str, watchlist: &[String]) -> Option<String> {
    for rule in watchlist {
        let r = rule.to_lowercase();
        if r.ends_with('.') {
            if domain.contains(&r) {
                return Some(rule.clone());
            }
        } else {
            if domain == r || domain.ends_with(&format!(".{}", r)) {
                return Some(rule.clone());
            }
        }
    }
    None
}
