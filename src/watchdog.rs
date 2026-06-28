use chrono::Local;
use log::{debug, error, info, warn};
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::config::{Config, Profile, expand_user_path};
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
        let total_rules: usize = self.cfg.profiles.iter().map(|p| p.watchlist.len()).sum();
        info!(
            "DNS Watchdog starting - {} profiles with {} rules total, cooldown={}s",
            self.cfg.profiles.len(),
            total_rules,
            self.cfg.cooldown_seconds
        );
        for profile in &self.cfg.profiles {
            log_profile_assets(profile);
        }

        while !self.stop_flag.load(Ordering::SeqCst) {
            if let Err(e) = self.stream_loop() {
                if self.stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                error!("Stream loop crashed: {} - restarting in 5s", e);
                std::thread::sleep(Duration::from_secs(5));
            }
        }

        info!("DNS Watchdog stopped cleanly.");
    }

    fn stream_loop(&mut self) -> Result<(), String> {
        let cmd = build_log_stream_cmd();
        debug!("Launching: {}", cmd.join(" "));

        let mut child = Command::new(&cmd[0])
            .args(&cmd[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to start tcpdump: {e}"))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "failed to open tcpdump stdout".to_string())?;
        let reader = BufReader::new(stdout);

        for line_res in reader.lines() {
            if self.stop_flag.load(Ordering::SeqCst) {
                let _ = child.kill();
                break;
            }

            match line_res {
                Ok(line) => self.process_line(line.trim_end()),
                Err(e) => {
                    let _ = child.kill();
                    return Err(format!("failed reading tcpdump output: {e}"));
                }
            }
        }

        let status = child
            .wait()
            .map_err(|e| format!("failed waiting for tcpdump: {e}"))?;
        if !self.stop_flag.load(Ordering::SeqCst) && !status.success() {
            return Err(format!("tcpdump exited with status {status}"));
        }

        Ok(())
    }

    fn process_line(&mut self, line: &str) {
        let Some(domain) = parse_domain(line) else {
            return;
        };

        if let Some((hit, profile)) = match_profiles(&domain, &self.cfg.profiles) {
            let count = self.stats.entry(domain.clone()).or_insert(0);
            *count += 1;

            info!("{}", line);
            info!(
                "[HIT] {}  (matched: '{}', profile: '{}', total_hits={})",
                domain, hit, profile.name, count
            );

            if self.limiter.should_alert(&hit) {
                self.fire_alert(&domain, &hit, &profile);
            } else {
                debug!("[RATE-LIMITED] {} (rule: '{}')", domain, hit);
            }
        } else if self.cfg.verbose_non_hits {
            debug!("[DNS] {}", domain);
        }
    }

    fn fire_alert(&self, domain: &str, matched_rule: &str, profile: &Profile) {
        let ts = Local::now().format("%H:%M:%S").to_string();
        warn!(
            "[ALERT] {}  rule='{}'  profile='{}'  time={}",
            domain, matched_rule, profile.name, ts
        );

        let title = format!("⚠️ DNS Watchdog: {}", profile.name);
        let subtitle = format!("Rule: {}", matched_rule);
        let body = format!("{}  [{}]", domain, ts);

        notify(
            &title,
            &subtitle,
            &body,
            &profile.alert_sound,
            profile.alert_sound_duration,
        );

        if !profile.redirect_url.is_empty() {
            let active_user = crate::notify::get_active_user();
            info!(
                "[REDIRECT] Opening {} for user {}",
                profile.redirect_url, active_user
            );
            let mut cmd = Command::new("sudo");
            cmd.args(["-u", &active_user, "open", &profile.redirect_url])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Err(e) = cmd.spawn() {
                error!("Failed to open redirect_url: {}", e);
            }
        }
    }
}

fn log_profile_assets(profile: &Profile) {
    if profile.watchlist_file.is_empty() {
        info!(
            "Profile '{}' has {} inline rules and no watchlist_file",
            profile.name,
            profile.watchlist.len()
        );
    } else {
        let path = expand_user_path(&profile.watchlist_file);
        let status = if path.is_file() { "found" } else { "missing" };
        info!(
            "Profile '{}' has {} rules; watchlist_file={} ({})",
            profile.name,
            profile.watchlist.len(),
            path.display(),
            status
        );
    }

    if !profile.alert_sound.is_empty() {
        let path = expand_user_path(&profile.alert_sound);
        if path.is_file() {
            info!(
                "Profile '{}' alert_sound file={}",
                profile.name,
                path.display()
            );
        } else {
            info!(
                "Profile '{}' alert_sound treated as macOS sound name='{}'",
                profile.name, profile.alert_sound
            );
        }
    }
}

pub fn build_log_stream_cmd() -> Vec<String> {
    vec![
        "tcpdump".to_string(),
        "-l".to_string(),
        "-n".to_string(),
        "port".to_string(),
        "53".to_string(),
    ]
}

pub fn parse_domain(line: &str) -> Option<String> {
    for regex in dns_patterns() {
        if let Some(caps) = regex.captures(line) {
            let domain = caps
                .get(1)
                .map(|m| m.as_str().trim_end_matches('.').to_lowercase())?;
            if domain == "local" || domain == "localhost" || domain.ends_with(".local") {
                return None;
            }
            return Some(domain);
        }
    }

    None
}

fn dns_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)(?:Query|Resolve|resolv)\w*\s+for\s+([a-zA-Z0-9._\-]+\.[a-zA-Z]{2,})",
            r"(?i)querying\s+([a-zA-Z0-9._\-]+\.[a-zA-Z]{2,})",
            r"(?i)(?:^|\s)[A-Z0-9]+\?\s+([a-zA-Z0-9._\-]+\.[a-zA-Z]{2,})\.",
            r#"[\s"']([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)["'\s]"#,
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("DNS parser regex should compile"))
        .collect()
    })
}

pub fn match_profiles(domain: &str, profiles: &[Profile]) -> Option<(String, Profile)> {
    let dl = domain.to_lowercase();
    for profile in profiles {
        for entry in &profile.watchlist {
            let el = entry.to_lowercase();
            if el.ends_with('.') {
                if dl.contains(&el) {
                    return Some((entry.clone(), profile.clone()));
                }
            } else if dl == el || dl.ends_with(&format!(".{}", el)) {
                return Some((entry.clone(), profile.clone()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_dns_lines() {
        assert_eq!(
            parse_domain("mDNSResponder QueryRecord for Example.COM type A"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_domain("dnscrypt-proxy querying tracker.example.org"),
            Some("tracker.example.org".to_string())
        );
        assert_eq!(
            parse_domain("10.0.0.1.53 > 10.0.0.2.55555: 1234 AAAA? sub.example.net."),
            Some("sub.example.net".to_string())
        );
        assert_eq!(
            parse_domain(r#"dns log "bare.example.io" token"#),
            Some("bare.example.io".to_string())
        );
    }

    #[test]
    fn ignores_local_domains() {
        assert_eq!(parse_domain("querying printer.local"), None);
        assert_eq!(parse_domain("querying localhost"), None);
    }

    #[test]
    fn matches_profiles_with_boundary_rules() {
        let profiles = vec![Profile {
            name: "Test".to_string(),
            watchlist: vec!["example.com".to_string(), "tracking.".to_string()],
            watchlist_file: String::new(),
            alert_sound: String::new(),
            alert_sound_duration: 0,
        }];

        assert_eq!(
            match_profiles("a.example.com", &profiles).map(|(rule, profile)| (rule, profile.name)),
            Some(("example.com".to_string(), "Test".to_string()))
        );
        assert!(match_profiles("badexample.com", &profiles).is_none());
        assert_eq!(
            match_profiles("cdn.tracking.vendor.net", &profiles).map(|(rule, _)| rule),
            Some("tracking.".to_string())
        );
    }
}
