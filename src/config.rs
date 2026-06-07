use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub watchlist: Vec<String>,
    #[serde(default)]
    pub watchlist_file: String,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
    #[serde(default = "default_alert_sound")]
    pub alert_sound: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub verbose_non_hits: bool,
}

fn default_cooldown() -> u64 { 60 }
fn default_alert_sound() -> String { "Basso".to_string() }
fn default_log_level() -> String { "INFO".to_string() }

impl Default for Config {
    fn default() -> Self {
        Self {
            watchlist: vec![
                "ads.google.com".to_string(),
                "doubleclick.net".to_string(),
                "facebook.com".to_string(),
                "tracking.".to_string(),
                "telemetry.".to_string(),
                "analytics.".to_string(),
            ],
            watchlist_file: "~/project/dns_watchdog/root_custom_blocklist.txt".to_string(),
            cooldown_seconds: 60,
            alert_sound: "~/project/dns_watchdog/qayamat.wav".to_string(),
            log_level: "INFO".to_string(),
            verbose_non_hits: false,
        }
    }
}

pub fn get_true_home() -> PathBuf {
    if let Ok(sudo_user) = env::var("SUDO_USER") {
        let mac_home = PathBuf::from(format!("/Users/{}", sudo_user));
        if mac_home.exists() {
            return mac_home;
        }
    }
    
    if let Some(home) = dirs::home_dir() {
        return home;
    }
    PathBuf::from("~")
}

pub fn expand_user_path(p: &str) -> PathBuf {
    if p.starts_with("~/") {
        let mut home = get_true_home();
        home.push(&p[2..]);
        home
    } else {
        if let Ok(expanded) = shellexpand::full(p) {
            PathBuf::from(expanded.to_string())
        } else {
            PathBuf::from(p)
        }
    }
}

pub fn load_config(config_path: &Path) -> Config {
    let mut cfg = if config_path.exists() {
        if let Ok(contents) = fs::read_to_string(config_path) {
            serde_json::from_str(&contents).unwrap_or_else(|_| Config::default())
        } else {
            Config::default()
        }
    } else {
        Config::default()
    };

    if !cfg.watchlist_file.is_empty() {
        let wl_path = expand_user_path(&cfg.watchlist_file);
        if wl_path.exists() {
            if let Ok(contents) = fs::read_to_string(&wl_path) {
                for line in contents.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        cfg.watchlist.push(trimmed.to_string());
                    }
                }
            }
        }
    }
    
    cfg.watchlist.sort();
    cfg.watchlist.dedup();
    cfg
}

pub fn save_default_config(config_path: &Path) {
    if let Some(parent) = config_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if !config_path.exists() {
        let default_cfg = Config::default();
        if let Ok(json) = serde_json::to_string_pretty(&default_cfg) {
            let _ = fs::write(config_path, json);
        }
    }
}
