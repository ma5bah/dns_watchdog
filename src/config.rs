use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    #[serde(default = "default_profile_name")]
    pub name: String,
    #[serde(default)]
    pub watchlist: Vec<String>,
    #[serde(default)]
    pub watchlist_file: String,
    #[serde(default)]
    pub alert_sound: String,
    #[serde(default)]
    pub alert_sound_duration: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub verbose_non_hits: bool,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    profiles: Option<Vec<Profile>>,
    cooldown_seconds: Option<u64>,
    log_level: Option<String>,
    verbose_non_hits: Option<bool>,
    watchlist: Option<Vec<String>>,
    watchlist_file: Option<String>,
    alert_sound: Option<String>,
    alert_sound_duration: Option<u64>,
}

fn default_profile_name() -> String {
    "Default Profile".to_string()
}

fn default_cooldown() -> u64 {
    60
}

fn default_log_level() -> String {
    "INFO".to_string()
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: default_profile_name(),
            watchlist: vec!["not-random-facebook.com".to_string()],
            watchlist_file:
                "~/project/clarity/Note/System_Configs/Blocklist/root_custom_blocklist.txt"
                    .to_string(),
            alert_sound: "~/project/clarity/Note/Religion/Audio/qayamat.wav".to_string(),
            alert_sound_duration: 0,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profiles: vec![Profile::default()],
            cooldown_seconds: default_cooldown(),
            log_level: default_log_level(),
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
    } else if let Ok(expanded) = shellexpand::full(p) {
        PathBuf::from(expanded.to_string())
    } else {
        PathBuf::from(p)
    }
}

pub fn load_config(config_path: &Path) -> Config {
    let mut cfg = Config::default();

    if config_path.exists() {
        match fs::read_to_string(config_path) {
            Ok(contents) => match serde_json::from_str::<Value>(&contents)
                .ok()
                .and_then(|value| serde_json::from_value::<RawConfig>(value).ok())
            {
                Some(raw) => merge_raw_config(&mut cfg, raw),
                None => eprintln!("[WARN] Could not parse config; using defaults."),
            },
            Err(e) => eprintln!("[WARN] Could not read config ({e}); using defaults."),
        }
    }

    normalize_profile_paths(&mut cfg, config_path);
    load_profile_watchlists(&mut cfg);
    cfg
}

fn merge_raw_config(cfg: &mut Config, raw: RawConfig) {
    if raw.watchlist.is_some() || raw.watchlist_file.is_some() {
        cfg.profiles = vec![Profile {
            name: "Legacy Profile".to_string(),
            watchlist: raw.watchlist.unwrap_or_default(),
            watchlist_file: raw.watchlist_file.unwrap_or_default(),
            alert_sound: raw.alert_sound.unwrap_or_default(),
            alert_sound_duration: raw.alert_sound_duration.unwrap_or_default(),
        }];
    } else if let Some(profiles) = raw.profiles {
        cfg.profiles = profiles;
    }

    if let Some(cooldown_seconds) = raw.cooldown_seconds {
        cfg.cooldown_seconds = cooldown_seconds;
    }
    if let Some(log_level) = raw.log_level {
        cfg.log_level = log_level;
    }
    if let Some(verbose_non_hits) = raw.verbose_non_hits {
        cfg.verbose_non_hits = verbose_non_hits;
    }
}

fn load_profile_watchlists(cfg: &mut Config) {
    for profile in &mut cfg.profiles {
        if !profile.watchlist_file.is_empty() {
            let wl_path = expand_user_path(&profile.watchlist_file);
            if wl_path.exists() {
                match fs::read_to_string(&wl_path) {
                    Ok(contents) => {
                        for line in contents.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                                profile.watchlist.push(trimmed.to_string());
                            }
                        }
                    }
                    Err(e) => eprintln!(
                        "[WARN] Could not read watchlist file for profile '{}' ({e}).",
                        profile.name
                    ),
                }
            }
        }

        dedup_preserve_order(&mut profile.watchlist);
    }
}

fn normalize_profile_paths(cfg: &mut Config, config_path: &Path) {
    for profile in &mut cfg.profiles {
        if !profile.watchlist_file.is_empty() {
            profile.watchlist_file =
                expand_user_path_for_config(&profile.watchlist_file, config_path)
                    .to_string_lossy()
                    .to_string();
        }
        if !profile.alert_sound.is_empty() {
            profile.alert_sound = expand_user_path_for_config(&profile.alert_sound, config_path)
                .to_string_lossy()
                .to_string();
        }
    }
}

fn expand_user_path_for_config(p: &str, config_path: &Path) -> PathBuf {
    if p.starts_with("~/") {
        if let Some(home) = home_from_config_path(config_path) {
            return home.join(&p[2..]);
        }
    }
    expand_user_path(p)
}

fn home_from_config_path(config_path: &Path) -> Option<PathBuf> {
    let config_dir = config_path.parent()?;
    if config_dir.file_name()? == ".dns_watchdog" {
        return config_dir.parent().map(Path::to_path_buf);
    }
    None
}

pub fn apply_watchlist_override(cfg: &mut Config, watchlist_file: &str) {
    if cfg.profiles.is_empty() {
        cfg.profiles.push(Profile {
            name: "CLI Override".to_string(),
            watchlist: Vec::new(),
            watchlist_file: watchlist_file.to_string(),
            alert_sound: String::new(),
            alert_sound_duration: 0,
        });
    } else {
        cfg.profiles[0].watchlist_file = watchlist_file.to_string();
    }

    let wl_path = expand_user_path(watchlist_file);
    if wl_path.exists() {
        match fs::read_to_string(&wl_path) {
            Ok(contents) => {
                for line in contents.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        cfg.profiles[0].watchlist.push(trimmed.to_string());
                    }
                }
                dedup_preserve_order(&mut cfg.profiles[0].watchlist);
            }
            Err(e) => eprintln!("[WARN] Could not read CLI watchlist file ({e})."),
        }
    }
}

fn dedup_preserve_order(items: &mut Vec<String>) {
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(item.clone()));
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
