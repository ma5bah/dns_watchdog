use log::{debug, warn};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn get_active_user() -> String {
    let output = Command::new("stat")
        .args(["-f", "%Su", "/dev/console"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let user = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if user != "root" && !user.is_empty() {
                return user;
            }
        }
    }

    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        return sudo_user;
    }
    if let Ok(user) = std::env::var("USER") {
        return user;
    }
    "root".to_string()
}

pub fn notify(title: &str, subtitle: &str, body: &str, sound: &str, sound_duration: u64) {
    let active_user = get_active_user();
    let expanded_sound = crate::config::expand_user_path(sound);
    let sound_file = if !sound.is_empty() && expanded_sound.is_file() {
        Some(expanded_sound)
    } else {
        None
    };

    let sound_clause = if !sound.is_empty() && sound_file.is_none() {
        format!(" sound name \"{}\"", escape_applescript(sound))
    } else {
        String::new()
    };

    let applescript = format!(
        "display notification \"{}\" with title \"{}\" subtitle \"{}\"{}",
        escape_applescript(body),
        escape_applescript(title),
        escape_applescript(subtitle),
        sound_clause
    );

    let mut osascript = Command::new("sudo");
    osascript
        .args(["-u", &active_user, "osascript", "-e", &applescript])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    match output_with_timeout(&mut osascript, Duration::from_secs(5)) {
        Ok(out) if out.status.success() => debug!("Notification sent: {} - {}", title, body),
        Ok(out) => warn!(
            "osascript notification failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => warn!("osascript notification failed: {}", e),
    }

    if let Some(sound_path) = sound_file {
        let _ = Command::new("killall")
            .arg("afplay")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let mut cmd = Command::new("sudo");
        cmd.args(["-u", &active_user, "afplay"]);
        if sound_duration > 0 {
            cmd.args(["-t", &sound_duration.to_string()]);
        }
        cmd.arg(sound_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Err(e) = cmd.spawn() {
            warn!("afplay failed: {}", e);
        }
    }
}

fn escape_applescript(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let mut child = command.spawn()?;
    let started = Instant::now();

    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let output = child.wait_with_output();
            warn!("osascript timed out sending notification");
            return output;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
