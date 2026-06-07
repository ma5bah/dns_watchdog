use std::process::{Command, Stdio};
use log::{info, warn};

pub fn get_active_user() -> String {
    // In Rust, we'll try to replicate the python logic: `stat -f '%Su' /dev/console`
    let output = Command::new("stat")
        .args(["-f", "%Su", "/dev/console"])
        .output();
        
    match output {
        Ok(out) if out.status.success() => {
            let user = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if user != "root" && !user.is_empty() {
                return user;
            }
        }
        _ => {}
    }
    
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        return sudo_user;
    }
    if let Ok(user) = std::env::var("USER") {
        return user;
    }
    "root".to_string()
}

pub fn notify(
    title: &str,
    subtitle: &str,
    body: &str,
    sound_path: Option<&str>,
) {
    let active_user = get_active_user();
    
    let applescript = format!(
        "display notification \"{}\" with title \"{}\" subtitle \"{}\"",
        body.replace("\"", "\\\""),
        title.replace("\"", "\\\""),
        subtitle.replace("\"", "\\\"")
    );
    
    // Spawn notification
    let _ = Command::new("sudo")
        .args(["-u", &active_user, "osascript", "-e", &applescript])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
        
    // Handle sound
    if let Some(sound) = sound_path {
        if !sound.is_empty() {
            // Check if it's an existing file or a named system sound
            let path = crate::config::expand_user_path(sound);
            if path.exists() && path.is_file() {
                // Kill existing afplay
                let _ = Command::new("killall")
                    .arg("afplay")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                    
                let _ = Command::new("sudo")
                    .args(["-u", &active_user, "afplay", &path.to_string_lossy()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
            } else {
                // Assume it's a named system sound
                let applescript = format!(
                    "display notification \"{}\" with title \"{}\" subtitle \"{}\" sound name \"{}\"",
                    body.replace("\"", "\\\""),
                    title.replace("\"", "\\\""),
                    subtitle.replace("\"", "\\\""),
                    sound.replace("\"", "\\\"")
                );
                let _ = Command::new("sudo")
                    .args(["-u", &active_user, "osascript", "-e", &applescript])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
            }
        }
    }
}
