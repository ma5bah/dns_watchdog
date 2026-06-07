mod config;
mod notify;
mod rate_limit;
mod watchdog;

use clap::{Parser, Subcommand};
use log::{error, info, LevelFilter};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use config::{expand_user_path, get_true_home, load_config, save_default_config};
use notify::notify;
use watchdog::DnsWatchdog;

#[derive(Parser)]
#[command(name = "dns-watchdog")]
#[command(about = "Real-time macOS domain activity monitor", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(short, long)]
    config: Option<String>,

    #[arg(short, long)]
    log: Option<String>,

    #[arg(short, long)]
    watchlist_file: Option<String>,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand, PartialEq)]
enum Commands {
    Run,
    Config,
    Init,
    Test,
    Stop,
    Install,
    Uninstall,
}

fn setup_logging(level_str: &str, log_path: &Path) {
    let level = match level_str.to_uppercase().as_str() {
        "DEBUG" => LevelFilter::Debug,
        "WARNING" => LevelFilter::Warn,
        "ERROR" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("Failed to open log file");

    let target = env_logger::Target::Pipe(Box::new(file));
    
    env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp_secs()
        .target(target)
        .init();
}

fn main() {
    let cli = Cli::parse();
    
    let default_config_path = {
        let mut p = get_true_home();
        p.push(".dns_watchdog");
        p.push("config.json");
        p
    };
    
    let config_path = cli.config.as_ref().map(|c| expand_user_path(c)).unwrap_or(default_config_path);
    
    let log_path = if let Some(l) = cli.log.as_ref() {
        expand_user_path(l)
    } else {
        let mut p = config_path.parent().unwrap().to_path_buf();
        p.push("watchdog.log");
        p
    };

    save_default_config(&config_path);
    
    let mut cfg = load_config(&config_path);
    if cli.verbose {
        cfg.log_level = "DEBUG".to_string();
    }
    if let Some(w) = cli.watchlist_file.as_ref() {
        cfg.watchlist_file = w.clone();
        let wl_path = expand_user_path(w);
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
        cfg.watchlist.sort();
        cfg.watchlist.dedup();
    }
    
    let cmd = cli.command.unwrap_or(Commands::Run);
    
    if cmd == Commands::Config {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&cfg).unwrap());
        let _ = writeln!(stdout, "\n# Active Config Path: {}", config_path.display());
        let _ = writeln!(stdout, "# Active Log Path:    {}", log_path.display());
        return;
    }
    if cmd == Commands::Init {
        println!("Config is at {}", config_path.display());
        return;
    }
    
    setup_logging(&cfg.log_level, &log_path);

    match cmd {
        Commands::Test => {
            info!("[TEST] Firing test notification …");
            notify(
                "✅ DNS Watchdog — Test",
                "Notifications are working",
                "If you see this, alerts are configured correctly.",
                Some(&cfg.alert_sound),
            );
            info!("[TEST] Done.");
        }
        Commands::Stop => {
            info!("[STOP] Stopping running instances of dns-watchdog and audio ...");
            let _ = Command::new("killall").arg("dns-watchdog").status();
            let _ = Command::new("killall").arg("afplay").status();
            info!("[STOP] Done.");
        }
        Commands::Install => {
            cmd_install(&config_path);
        }
        Commands::Uninstall => {
            cmd_uninstall();
        }
        Commands::Run => {
            if unsafe { libc::geteuid() } != 0 {
                eprintln!("FATAL: You must run this script with sudo to sniff network packets!");
                error!("FATAL: You must run this script with sudo to sniff network packets!");
                process::exit(1);
            }
            
            let stop_flag = Arc::new(AtomicBool::new(false));
            let r = stop_flag.clone();

            ctrlc::set_handler(move || {
                r.store(true, Ordering::SeqCst);
            }).expect("Error setting Ctrl-C handler");

            let mut watchdog = DnsWatchdog::new(cfg, stop_flag);
            watchdog.run();
        }
        _ => {}
    }
}

fn cmd_install(config_path: &Path) {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("FATAL: You must run 'install' with sudo.");
        process::exit(1);
    }
    
    let active_user = notify::get_active_user();
    if active_user == "root" {
        eprintln!("Could not detect SUDO_USER. Run this using 'sudo ./target/release/dns-watchdog install'");
        process::exit(1);
    }
    
    let home_dir = get_true_home();
    let exec_path = env::current_exe().expect("Failed to get current executable path");
    let plist_path = PathBuf::from("/Library/LaunchDaemons/com.user.dns-watchdog.plist");
    
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.user.dns-watchdog</string>

  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>run</string>
    <string>--config</string>
    <string>{}</string>
  </array>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>{}/.dns_watchdog/launchd.out</string>
  <key>StandardErrorPath</key>
  <string>{}/.dns_watchdog/launchd.err</string>
</dict>
</plist>"#,
        exec_path.display(),
        config_path.display(),
        home_dir.display(),
        home_dir.display()
    );

    fs::write(&plist_path, plist_content).expect("Failed to write plist file");
    
    let _ = Command::new("launchctl")
        .args(["unload", &plist_path.to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
        
    let status = Command::new("launchctl")
        .args(["load", "-w", &plist_path.to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    
    if status.is_ok() && status.unwrap().success() {
        println!("✅ DNS Watchdog installed and started as a background daemon!");
    } else {
        eprintln!("Failed to load LaunchDaemon.");
    }
}

fn cmd_uninstall() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("FATAL: You must run 'uninstall' with sudo.");
        process::exit(1);
    }
    
    let plist_path = PathBuf::from("/Library/LaunchDaemons/com.user.dns-watchdog.plist");
    if plist_path.exists() {
        let _ = Command::new("launchctl")
            .args(["unload", "-w", &plist_path.to_string_lossy()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_file(&plist_path);
        println!("✅ DNS Watchdog daemon uninstalled.");
    } else {
        println!("Daemon is not currently installed.");
    }
}
