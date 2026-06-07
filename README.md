# macOS DNS Alerter 📡

Real-time macOS domain activity monitor. Intercepts DNS queries natively via `tcpdump`, matches every queried domain against your watchlist, and fires a native macOS desktop notification + audio chime on a hit. Includes smart cooldowns to keep alert fatigue at zero.

---

## Features
- **Root-level Packet Sniffing:** Bypasses macOS's modern private data redaction by intercepting raw port 53 traffic natively.
- **Smart Cooldowns:** Rate limits alerts per-rule so a single webpage loading 50 trackers doesn't bombard your audio.
- **Native macOS Alerts:** Safely pipes notifications and sounds directly to the active GUI user, even when running as a headless root daemon.
- **Background Daemon:** Fully automated `launchd` integration so it runs 24/7 silently and survives reboots.
- **Zero-Overlap Audio:** Rapid-fire hits seamlessly restart the audio track from the beginning instead of stacking chaotically.

---

## Quick Start

```bash
# 1. Make executable
chmod +x dns_watchdog.py

# 2. Write the default config
python3 dns_watchdog.py init

# 3. Edit your watchlist text file or config.json
open ~/.dns_watchdog/config.json

# 4. Test notifications
sudo ./dns_watchdog.py test

# 5. Start monitoring in the current terminal
sudo ./dns_watchdog.py run

# ...OR install as a permanent background daemon (survives reboots)
sudo ./dns_watchdog.py install

# To remove the background daemon later:
sudo ./dns_watchdog.py uninstall
```

---

## Configuration

Edit `~/.dns_watchdog/config.json`:

```json
{
  "watchlist": [
    "facebook.com"
  ],
  "watchlist_file": "~/project/dns_watchdog/root_custom_blocklist.txt",
  "cooldown_seconds": 60,
  "alert_sound": "~/project/dns_watchdog/qayamat.wav",
  "log_level": "INFO",
  "verbose_non_hits": false
}
```

### Path Resolution
**Important:** All paths containing `~/` automatically resolve to your **actual logged-in user's** home directory, even when the script is run under `sudo` or the root `launchd`. You do not need to hardcode `/Users/yourname/`.

---

## CLI Options

The script is highly configurable via the command line, allowing you to override JSON settings on the fly.

```text
usage: dns_watchdog.py [-h] [-c CONFIG] [-l LOG] [-w WATCHLIST_FILE] [-v]
                       [{run,config,init,test,stop,install,uninstall}]

Commands:
  run         Start monitoring (default)
  config      Print the active configuration
  init        Write default config and exit
  test        Fire a test notification and exit
  stop        Stop any running background instances and active sounds
  install     Install and run as a permanent background daemon (LaunchDaemon)
  uninstall   Remove the background daemon

Options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to custom config.json file
  -l LOG, --log LOG     Path to custom log file
  -w WATCHLIST_FILE, --watchlist-file WATCHLIST_FILE
                        Path to external text file containing domains
  -v, --verbose         Enable DEBUG logging
```

---

## Live Logs

Monitor the script's activity while it runs in the background:
```bash
tail -f ~/.dns_watchdog/watchdog.log
```
