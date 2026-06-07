# DNS Watchdog 🐕

Real-time macOS domain activity monitor. Intercepts `mDNSResponder` / system
network log traffic, matches every queried domain against your watchlist, and
fires a native macOS desktop notification + audio chime on a hit — all with
per-domain cooldown to keep alert fatigue at zero.

---

## Requirements

| Requirement | Notes |
|---|---|
| macOS / Linux | Uses `tcpdump` under the hood |
| Python 3.10+ | uses `str \| None` union syntax |
| Admin Privileges | Requires `sudo` to run `tcpdump` and sniff network packets |

---

## Quick Start

```bash
# 1. Make executable
chmod +x dns_watchdog.py

# 2. Write the default config (auto-done on first run too)
python3 dns_watchdog.py init

# 3. Edit your watchlist
open ~/.dns_watchdog/config.json

# 4. Test notifications
sudo ./dns_watchdog.py test

# 5. Start monitoring in the current terminal...
sudo ./dns_watchdog.py

# ...OR install as a permanent background daemon (survives reboots & closing terminal)
sudo ./dns_watchdog.py install

# To remove the background daemon later:
sudo ./dns_watchdog.py uninstall
```

---

## Configuration  `~/.dns_watchdog/config.json`

```json
{
  "watchlist": [
    "ads.google.com",
    "doubleclick.net",
    "facebook.com",
    "tracking.",
    "telemetry.",
    "analytics."
  ],
  "cooldown_seconds": 60,
  "alert_sound": "Sosumi",
  "log_level": "INFO",
  "verbose_non_hits": false
}
```

| Key | Type | Description |
|---|---|---|
| `watchlist` | `[string]` | Substrings matched case-insensitively against every queried domain |
| `cooldown_seconds` | `int` | Suppress repeat alerts for the same domain for this many seconds |
| `alert_sound` | `string` | macOS system sound name (`"Basso"`, `"Ping"`, `"Sosumi"`, …) or `""` for silent |
| `log_level` | `string` | `"DEBUG"` / `"INFO"` / `"WARNING"` |
| `verbose_non_hits` | `bool` | If `true`, every parsed domain is logged (very noisy) |

---

## CLI Commands

```
python3 dns_watchdog.py          # start monitoring (default)
python3 dns_watchdog.py run      # same as above
python3 dns_watchdog.py init     # write default config and exit
python3 dns_watchdog.py config   # print active config
python3 dns_watchdog.py test     # fire a test notification and exit
python3 dns_watchdog.py help     # usage info
```

---

## Live Log

```bash
tail -f ~/.dns_watchdog/watchdog.log
```

Sample output:
```
2024-06-07 14:22:01 [INFO]  DNS Watchdog starting — watchlist has 6 entries, cooldown=60s
2024-06-07 14:22:05 [INFO]  [HIT] tracking.example.com  (matched: 'tracking.', total_hits=1)
2024-06-07 14:22:05 [WARNING] [ALERT] tracking.example.com  rule='tracking.'  time=14:22:05
2024-06-07 14:22:06 [INFO]  [HIT] tracking.example.com  (matched: 'tracking.', total_hits=2)
2024-06-07 14:22:06 [DEBUG] [RATE-LIMITED] tracking.example.com
```

---

## Run as a Background Agent (launchd)

Create `~/Library/LaunchAgents/com.user.dns-watchdog.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.user.dns-watchdog</string>

  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>/path/to/dns_watchdog.py</string>
  </array>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/Users/YOU/.dns_watchdog/launchd.out</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/.dns_watchdog/launchd.err</string>
</dict>
</plist>
```

Then load it:

```bash
launchctl load ~/Library/LaunchAgents/com.user.dns-watchdog.plist
```

`KeepAlive: true` makes launchd automatically restart the daemon after network
drops, sleep/wake cycles, or crashes — fulfilling the **System Resiliency**
requirement without any custom watchdog code.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  DnsWatchdog                    │
│                                                 │
│  _stream_loop()                                 │
│    └─ subprocess: log stream --predicate ...    │
│         │  raw syslog lines                     │
│         ▼                                       │
│  _process_line()                                │
│    └─ parse_domain()   ← regex cascade          │
│         │  domain string                        │
│         ▼                                       │
│  match_watchlist()     ← substring scan         │
│         │  hit / None                           │
│         ▼                                       │
│  RateLimiter.should_alert()                     │
│         │  bool                                 │
│         ▼                                       │
│  notify() → osascript → macOS Notification      │
│                       + system audio chime      │
└─────────────────────────────────────────────────┘
```

### Extending

| Goal | Where to change |
|---|---|
| Add a new watchlist source (e.g. CSV, remote blocklist) | `load_config()` or a new loader function |
| Add a new action (e.g. write to SQLite, send to webhook) | `DnsWatchdog._fire_alert()` |
| Add a new log source (tcpdump, dnscrypt-proxy) | `build_log_stream_cmd()` + new regex in `_DNS_PATTERNS` |
| Per-rule cooldowns | extend `RateLimiter` to key on `(domain, rule)` |

---

## Notes

- **No root required.** `log stream` runs as a normal user.
- **Sleep/wake resilience.** The stream process exits on sleep; the outer
  `while` loop in `DnsWatchdog.run()` restarts it automatically after a 5 s
  back-off.
- **Signal handling.** `SIGINT` (Ctrl-C) and `SIGTERM` trigger a clean shutdown
  that terminates the child subprocess before exiting.
