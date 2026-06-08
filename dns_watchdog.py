#!/usr/bin/env python3
"""
dns_watchdog.py — Real-time macOS domain activity monitor
Intercepts mDNSResponder traffic, matches against a watchlist,
and fires native macOS notifications + audio chimes on hits.
"""

import subprocess
import threading
import time
import re
import json
import os
import sys
import signal
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────
def get_true_home() -> Path:
    """Attempt to find the actual user's home directory even if running as root."""
    # 1. Check SUDO_USER (works for manual sudo runs)
    real_user = os.environ.get("SUDO_USER")
    if real_user:
        return Path(os.path.expanduser(f"~{real_user}"))
        
    # 2. Check if we're a daemon with a known config path
    try:
        if CONFIG_PATH and CONFIG_PATH.is_absolute() and ".dns_watchdog" in str(CONFIG_PATH):
            return CONFIG_PATH.parent.parent
    except NameError:
        pass
        
    # 3. Default fallback
    return Path("~").expanduser()

def expand_user_path(p: str) -> Path:
    if str(p).startswith("~/"):
        return get_true_home() / str(p)[2:]
    return Path(p).expanduser()

# Updated in main() if --config is passed
CONFIG_PATH = get_true_home() / ".dns_watchdog" / "config.json"
LOG_PATH    = get_true_home() / ".dns_watchdog" / "watchdog.log"

def update_paths(config_file: str = None, log_file: str = None):
    global CONFIG_PATH, LOG_PATH
    if config_file:
        CONFIG_PATH = expand_user_path(config_file).resolve()
        # By default, put log file next to the config file unless overridden
        LOG_PATH = CONFIG_PATH.parent / "watchdog.log"
    if log_file:
        LOG_PATH = expand_user_path(log_file).resolve()

DEFAULT_CONFIG = {
    # Profiles allow you to map different domain lists to different notification sounds.
    "profiles": [
        {
            "name": "Default Profile",
            "watchlist": [
                "not-random-facebook.com",
            ],
            "watchlist_file": "~/project/clarity/Note/System_Configs/Blocklist/root_custom_blocklist.txt",
            "alert_sound": "~/project/clarity/Note/Religion/Audio/qayamat.wav",
        }
    ],
    # Seconds to suppress repeated alerts for the same domain.
    "cooldown_seconds": 60,
    # How verbose the log file should be: DEBUG | INFO | WARNING
    "log_level": "INFO",
    # If true, also print parsed DNS events that do NOT match the watchlist.
    "verbose_non_hits": False,
}

# ─────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────

def setup_logging(level_name: str) -> logging.Logger:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    level = getattr(logging, level_name.upper(), logging.INFO)
    logger = logging.getLogger("dns_watchdog")
    logger.setLevel(level)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(LOG_PATH)
    fh.setFormatter(fmt)
    fh.setLevel(level)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    ch.setLevel(level)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ─────────────────────────────────────────────
#  Config helpers
# ─────────────────────────────────────────────

def load_config() -> dict:
    merged = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                user_cfg = json.load(f)
            
            # Migrate legacy flat config to profiles if present
            if "watchlist" in user_cfg or "watchlist_file" in user_cfg:
                profile = {
                    "name": "Legacy Profile",
                    "watchlist": user_cfg.get("watchlist", []),
                    "watchlist_file": user_cfg.get("watchlist_file", ""),
                    "alert_sound": user_cfg.get("alert_sound", ""),
                    "alert_sound_duration": user_cfg.get("alert_sound_duration", 0)
                }
                user_cfg["profiles"] = [profile]
                user_cfg.pop("watchlist", None)
                user_cfg.pop("watchlist_file", None)
                user_cfg.pop("alert_sound", None)
                user_cfg.pop("alert_sound_duration", None)
                
            # Merge with defaults so new keys are always present.
            merged.update(user_cfg)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[WARN] Could not read config ({e}); using defaults.", file=sys.stderr)
            
    if "profiles" not in merged:
        merged["profiles"] = []

    # Process each profile
    for profile in merged["profiles"]:
        if "watchlist" not in profile:
            profile["watchlist"] = []
            
        wl_path_str = profile.get("watchlist_file")
        if wl_path_str:
            wl_path = expand_user_path(wl_path_str)
            if wl_path.exists():
                try:
                    with open(wl_path) as f:
                        for line in f:
                            line = line.strip()
                            # Ignore empty lines and comments
                            if line and not line.startswith("#"):
                                profile["watchlist"].append(line)
                except OSError as e:
                    print(f"[WARN] Could not read watchlist file for profile '{profile.get('name')}' ({e}).", file=sys.stderr)
                    
        # Remove any duplicate entries
        profile["watchlist"] = list(set(profile["watchlist"]))
        
    return merged


def save_default_config():
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"[INFO] Default config written to {CONFIG_PATH}")


# ─────────────────────────────────────────────
#  macOS notification + audio
# ─────────────────────────────────────────────

def notify(title: str, subtitle: str, body: str, sound: str, sound_duration: int, logger: logging.Logger):
    """Fire a native macOS notification via osascript."""
    sound_clause = ""
    sound_path = None

    if sound:
        expanded_sound = str(expand_user_path(sound))
        if os.path.exists(expanded_sound) and os.path.isfile(expanded_sound):
            sound_path = expanded_sound
        else:
            sound_clause = f'sound name "{sound}"'

    script = (
        f'display notification "{body}" '
        f'with title "{title}" '
        f'subtitle "{subtitle}" '
        f'{sound_clause}'
    )
    
    try:
        active_user = subprocess.check_output(["stat", "-f", "%Su", "/dev/console"]).decode().strip()
    except Exception:
        active_user = os.environ.get("USER", "root")

    try:
        cmd_osa = ["sudo", "-u", active_user, "osascript", "-e", script]
        subprocess.run(
            cmd_osa,
            check=True,
            capture_output=True,
            timeout=5,
        )
        logger.debug(f"Notification sent: {title} — {body}")
        
        # Play custom sound file if provided
        if sound_path:
            # Kill any currently playing sounds to prevent overlapping audio
            subprocess.run(
                ["killall", "afplay"], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
            
            cmd_af = ["sudo", "-u", active_user, "afplay"]
            if sound_duration > 0:
                cmd_af.extend(["-t", str(sound_duration)])
            cmd_af.append(sound_path)
            
            subprocess.Popen(
                cmd_af,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
    except subprocess.CalledProcessError as e:
        logger.warning(f"osascript notification failed: {e.stderr.decode().strip()}")
    except subprocess.TimeoutExpired:
        logger.warning("osascript timed out sending notification")
    except FileNotFoundError:
        logger.warning("osascript not found — are you running on macOS?")


# ─────────────────────────────────────────────
#  Rate limiter
# ─────────────────────────────────────────────

class RateLimiter:
    """Per-domain cooldown. Thread-safe."""

    def __init__(self, cooldown_seconds: float):
        self._cooldown = cooldown_seconds
        self._last_alert: dict[str, float] = {}
        self._lock = threading.Lock()

    def should_alert(self, domain: str) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last_alert.get(domain, 0.0)
            if now - last >= self._cooldown:
                self._last_alert[domain] = now
                return True
            return False

    def update_cooldown(self, seconds: float):
        with self._lock:
            self._cooldown = seconds


# ─────────────────────────────────────────────
#  DNS log parser
# ─────────────────────────────────────────────

# mDNSResponder log lines look like (macOS Ventura/Sonoma):
#   mDNSResponder ... for <domain> type ...
# We also handle log stream output that includes JSON-like fields.
# Patterns are tried in order; first match wins.
_DNS_PATTERNS = [
    # log stream --predicate 'subsystem == "com.apple.mDNSResponder"'
    re.compile(
        r"(?:Query|Resolve|resolv)\w*\s+for\s+([a-zA-Z0-9._\-]+\.[a-zA-Z]{2,})",
        re.IGNORECASE,
    ),
    # dnscrypt-proxy / general "querying" phrasing
    re.compile(
        r"querying\s+([a-zA-Z0-9._\-]+\.[a-zA-Z]{2,})",
        re.IGNORECASE,
    ),
    # tcpdump / dns line: A? example.com. or AAAA? example.com.
    re.compile(
        r"(?:^|\s)[A-Z0-9]+\?\s+([a-zA-Z0-9._\-]+\.[a-zA-Z]{2,})\.",
        re.IGNORECASE,
    ),
    # Fallback: bare domain-like token on a DNS log line
    re.compile(
        r"[\s\"']([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)[\"'\s]"
    ),
]


def parse_domain(line: str) -> str | None:
    """Return the first plausible domain found in *line*, or None."""
    for pat in _DNS_PATTERNS:
        m = pat.search(line)
        if m:
            domain = m.group(1).rstrip(".")
            # Exclude localhost / link-local noise
            if domain in ("local", "localhost") or domain.endswith(".local"):
                return None
            return domain.lower()
    return None


# ─────────────────────────────────────────────
#  Watchlist matcher
# ─────────────────────────────────────────────

def match_profiles(domain: str, profiles: list[dict]) -> tuple[str, dict] | None:
    """
    Return the (matched_rule, profile) for the given domain.
    If the rule ends with a dot (e.g. 'tracking.'), it does a substring match.
    Otherwise, it matches the exact domain or its subdomains (e.g. 'b.com' matches 'a.b.com' but not 'bob.com').
    """
    dl = domain.lower()
    for profile in profiles:
        for entry in profile.get("watchlist", []):
            el = entry.lower()
            if el.endswith("."):
                if el in dl:
                    return entry, profile
            else:
                if dl == el or dl.endswith("." + el):
                    return entry, profile
    return None


# ─────────────────────────────────────────────
#  Log stream subprocess
# ─────────────────────────────────────────────

def build_log_stream_cmd() -> list[str]:
    """
    Return the command that produces a live stream of DNS-related log lines.
    Using tcpdump requires the script to be run with sudo, but completely bypasses
    the macOS unified logging restrictions (no profiles needed).
    """
    return [
        "tcpdump", 
        "-l",            # Make stdout line-buffered
        "-n",            # Don't resolve hostnames (prevents infinite loops)
        "port", "53"     # Only listen for DNS traffic
    ]


# ─────────────────────────────────────────────
#  Core monitor
# ─────────────────────────────────────────────

class DnsWatchdog:
    def __init__(self, config: dict, logger: logging.Logger):
        self.cfg     = config
        self.logger  = logger
        self.limiter = RateLimiter(config["cooldown_seconds"])
        self._stop   = threading.Event()
        self._proc   = None
        self._stats  = defaultdict(int)   # domain → total hit count

    # ── public API ───────────────────────────

    def run(self):
        """Block until interrupted."""
        signal.signal(signal.SIGINT,  self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        total_rules = sum(len(p.get("watchlist", [])) for p in self.cfg.get("profiles", []))
        self.logger.info(f"DNS Watchdog starting — {len(self.cfg.get('profiles', []))} profiles with {total_rules} rules total, "
                         f"cooldown={self.cfg['cooldown_seconds']}s")

        while not self._stop.is_set():
            try:
                self._stream_loop()
            except Exception as e:
                if self._stop.is_set():
                    break
                self.logger.error(f"Stream loop crashed: {e} — restarting in 5s")
                time.sleep(5)

        self.logger.info("DNS Watchdog stopped cleanly.")

    def stop(self):
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()

    # ── internals ────────────────────────────

    def _handle_signal(self, signum, frame):
        self.logger.info(f"Signal {signum} received — shutting down.")
        self.stop()

    def _stream_loop(self):
        cmd = build_log_stream_cmd()
        self.logger.debug(f"Launching: {' '.join(cmd)}")

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        for raw_line in self._proc.stdout:
            if self._stop.is_set():
                break
            self._process_line(raw_line.rstrip())

        self._proc.wait()

    def _process_line(self, line: str):
        domain = parse_domain(line)
        if domain is None:
            return

        hit_info = match_profiles(domain, self.cfg.get("profiles", []))

        if hit_info:
            hit, profile = hit_info
            self._stats[domain] += 1
            self.logger.info(f"{line}")
            self.logger.info(f"[HIT] {domain}  (matched: '{hit}', profile: '{profile.get('name', 'unnamed')}', "
                             f"total_hits={self._stats[domain]})")
            if self.limiter.should_alert(hit):
                self._fire_alert(domain, hit, profile)
            else:
                self.logger.debug(f"[RATE-LIMITED] {domain} (rule: '{hit}')")
        elif self.cfg.get("verbose_non_hits"):
            self.logger.debug(f"[DNS] {domain}")

    def _fire_alert(self, domain: str, matched_rule: str, profile: dict):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logger.warning(f"[ALERT] {domain}  rule='{matched_rule}'  profile='{profile.get('name', 'unnamed')}'  time={ts}")
        notify(
            title          = f"⚠️ DNS Watchdog: {profile.get('name', 'Hit')}",
            subtitle       = f"Rule: {matched_rule}",
            body           = f"{domain}  [{ts}]",
            sound          = profile.get("alert_sound", ""),
            sound_duration = profile.get("alert_sound_duration", 0),
            logger         = self.logger,
        )


# ─────────────────────────────────────────────
#  CLI entry point
# ─────────────────────────────────────────────

def print_help():
    print("""
dns_watchdog.py — Real-time macOS domain activity monitor

USAGE
  python3 dns_watchdog.py [command]

COMMANDS
  (none)      Start monitoring (default)
  config      Print the active configuration
  init        Write default config to ~/.dns_watchdog/config.json and exit
  test        Fire a test notification and exit
  stop        Stop any running background instances and active sounds
  install     Install and run as a permanent background daemon (LaunchDaemon)
  uninstall   Remove the background daemon
  help        Show this message

CONFIGURATION
  Edit  ~/.dns_watchdog/config.json  to customise:
    profiles           — list of profiles, each containing:
                           name: name of the profile
                           watchlist: list of domain substrings to watch
                           watchlist_file: external text file containing domains
                           alert_sound: macOS system sound name or path to audio file
    cooldown_seconds   — alert suppression window per domain
    log_level          — DEBUG | INFO | WARNING
    verbose_non_hits   — log every DNS query, not just hits

LOGS
  Tail the live log with:
    tail -f ~/.dns_watchdog/watchdog.log

REQUIREMENTS
  • macOS 12+ (Monterey or later recommended)
  • Python 3.10+
  • Run as your normal user account (no root needed for log stream)
""")


def cmd_test(cfg: dict, logger: logging.Logger):
    logger.info("[TEST] Firing test notification …")
    
    sound = ""
    duration = 0
    if cfg.get("profiles"):
        sound = cfg["profiles"][0].get("alert_sound", "")
        duration = cfg["profiles"][0].get("alert_sound_duration", 0)
        
    notify(
        title          = "✅ DNS Watchdog — Test",
        subtitle       = "Notifications are working",
        body           = "If you see this, alerts are configured correctly.",
        sound          = sound,
        sound_duration = duration,
        logger         = logger,
    )
    logger.info("[TEST] Done.")


def cmd_stop(logger: logging.Logger):
    logger.info("[STOP] Stopping running instances of dns_watchdog and audio ...")
    my_pid = str(os.getpid())
    
    try:
        ps_out = subprocess.check_output(["pgrep", "-f", "dns_watchdog.py"], text=True)
        for pid in ps_out.strip().split('\n'):
            if pid and pid != my_pid:
                subprocess.run(["kill", "-15", pid])
                logger.info(f"Terminated process {pid}")
    except subprocess.CalledProcessError:
        logger.info("No running background instances found.")

    subprocess.run(["killall", "afplay"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logger.info("[STOP] Done.")


def cmd_install(logger: logging.Logger):
    if os.geteuid() != 0:
        logger.error("FATAL: You must run 'install' with sudo.")
        sys.exit(1)

    real_user = os.environ.get("SUDO_USER")
    if not real_user:
        logger.error("Could not detect SUDO_USER. Run this using 'sudo ./dns_watchdog.py install'")
        sys.exit(1)
        
    home_dir = Path(os.path.expanduser(f"~{real_user}"))
    script_path = Path(__file__).resolve()
    plist_path = Path("/Library/LaunchDaemons/com.user.dns-watchdog.plist")
    
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.user.dns-watchdog</string>

  <key>ProgramArguments</key>
  <array>
    <string>{sys.executable}</string>
    <string>{script_path}</string>
    <string>run</string>
    <string>--config</string>
    <string>{CONFIG_PATH}</string>
  </array>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>{home_dir}/.dns_watchdog/launchd.out</string>
  <key>StandardErrorPath</key>
  <string>{home_dir}/.dns_watchdog/launchd.err</string>
</dict>
</plist>"""

    with open(plist_path, "w") as f:
        f.write(plist_content)
        
    logger.info("Unloading old daemon if exists...")
    subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True)
    logger.info("Loading new daemon...")
    subprocess.run(["launchctl", "load", "-w", str(plist_path)], check=True)
    logger.info("✅ DNS Watchdog installed and started as a background daemon!")


def cmd_uninstall(logger: logging.Logger):
    if os.geteuid() != 0:
        logger.error("FATAL: You must run 'uninstall' with sudo.")
        sys.exit(1)
    
    plist_path = Path("/Library/LaunchDaemons/com.user.dns-watchdog.plist")
    if plist_path.exists():
        subprocess.run(["launchctl", "unload", "-w", str(plist_path)], capture_output=True)
        plist_path.unlink()
        logger.info("✅ DNS Watchdog daemon uninstalled.")
    else:
        logger.info("Daemon is not currently installed.")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Real-time macOS domain activity monitor. Intercepts DNS queries via tcpdump and fires native macOS notifications on watchlist hits.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "command", nargs="?", default="run",
        choices=["run", "config", "init", "test", "stop", "install", "uninstall"],
        help="Command to execute (default: run)"
    )
    parser.add_argument("-c", "--config", help="Path to custom config.json file")
    parser.add_argument("-l", "--log", help="Path to custom log file")
    parser.add_argument("-w", "--watchlist-file", help="Path to external text file containing domains")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging")
    
    args = parser.parse_args()
    
    # Update global paths before doing anything else
    update_paths(config_file=args.config, log_file=args.log)
        
    save_default_config()
    cfg = load_config()
    
    # Apply CLI overrides to config
    if args.verbose:
        cfg["log_level"] = "DEBUG"
    if args.watchlist_file:
        if not cfg.get("profiles"):
            cfg["profiles"] = [{"name": "CLI Override", "watchlist": [], "watchlist_file": args.watchlist_file, "alert_sound": ""}]
        else:
            cfg["profiles"][0]["watchlist_file"] = args.watchlist_file
            
        # Reload watchlist if file was overridden
        wl_path = expand_user_path(args.watchlist_file)
        if wl_path.exists():
            try:
                with open(wl_path) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            cfg["profiles"][0]["watchlist"].append(line)
                cfg["profiles"][0]["watchlist"] = list(set(cfg["profiles"][0]["watchlist"]))
            except OSError as e:
                print(f"[WARN] Could not read CLI watchlist file ({e}).", file=sys.stderr)

    logger = setup_logging(cfg["log_level"])
    cmd = args.command

    if cmd == "run":
        # Privilege check — tcpdump requires root
        if os.geteuid() != 0:
            logger.error("FATAL: You must run this script with sudo to sniff network packets!")
            sys.exit(1)
        watchdog = DnsWatchdog(cfg, logger)
        watchdog.run()

    elif cmd == "config":
        print(json.dumps(cfg, indent=2))
        print(f"\n# Active Config Path: {CONFIG_PATH}")
        print(f"# Active Log Path:    {LOG_PATH}")

    elif cmd == "init":
        print(f"Config is at {CONFIG_PATH}")
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print("Default config written.")

    elif cmd == "test":
        cmd_test(cfg, logger)

    elif cmd == "stop":
        cmd_stop(logger)

    elif cmd == "install":
        cmd_install(logger)
        
    elif cmd == "uninstall":
        cmd_uninstall(logger)


if __name__ == "__main__":
    main()
