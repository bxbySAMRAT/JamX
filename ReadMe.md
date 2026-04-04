<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Scapy-2.5+-green?logo=wireshark&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Kali%20|%20Parrot%20|%20Debian-purple" />
  <img src="https://img.shields.io/badge/License-Educational-red" />
  <img src="https://img.shields.io/badge/Version-2.0-orange" />
</p>

<h1 align="center">JamX 🔴</h1>

```
     ██╗ █████╗ ███╗   ███╗██╗  ██╗
     ██║██╔══██╗████╗ ████║╚██╗██╔╝
     ██║███████║██╔████╔██║ ╚███╔╝
██   ██║██╔══██║██║╚██╔╝██║ ██╔██╗
╚█████╔╝██║  ██║██║ ╚═╝ ██║██╔╝ ██╗
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝

  ⚡ Multi-Target WiFi Deauth Tool ⚡
    Built by : bxbySAMRAT
  [ Auto Monitor Mode | Scapy-Powered ]
       FOR AUTHORIZED USE ONLY 🔴
```

<p align="center">
  <b>Continuous, Bidirectional WiFi Deauthentication & Disassociation Framework</b><br>
  <i>Plug & Play — One command to scan, attack, and restore.</i>
</p>

---

> ⚠️ **LEGAL DISCLAIMER**
>
> This tool is intended **strictly** for authorized penetration testing, security research, and educational purposes in lab environments. Unauthorized use against networks you do not own or have **explicit written permission** to test is **illegal** under the Computer Fraud and Abuse Act (CFAA), IT Act 2000 (India), and equivalent laws worldwide. The author assumes **zero liability** for misuse. **You are solely responsible for your actions.**

---

## 📌 What is JamX?

**JamX** is a Python-based 802.11 deauthentication and disassociation framework that automates the entire wireless disruption pipeline — from enabling monitor mode to restoring your NIC when you're done. Unlike basic deauth scripts that send a fixed number of frames and exit, JamX runs **continuously** until you press `Ctrl+C`, sending **bidirectional deauth + disassociation** frames with **randomized reason codes** and **spoofed client MACs** to make the attack significantly harder for both the access point and IDS/WIDS systems to mitigate.

### Why JamX Over Other Tools?

| Feature | Basic Deauth Scripts | `aireplay-ng` | **JamX v2** |
|---------|---------------------|---------------|-------------|
| Multi-target (all APs) | ❌ Manual per-AP | ❌ Single target | ✅ Auto-discovers all |
| Continuous attack | ❌ Fixed count | ✅ | ✅ Plug & play |
| Bidirectional frames | ❌ | ❌ AP→Client only | ✅ Both directions |
| Disassociation frames | ❌ | ❌ Deauth only | ✅ Deauth + Disassoc |
| Randomized reason codes | ❌ | ❌ Fixed reason | ✅ Evades IDS fingerprinting |
| Spoofed client MACs | ❌ | ❌ | ✅ Random per burst |
| Auto monitor mode | ❌ Manual setup | ❌ Manual setup | ✅ Auto + 3 fallbacks |
| Auto NIC restore | ❌ | ❌ | ✅ On Ctrl+C / exit |
| 5GHz support | ❌ | Partial | ✅ `--5ghz` flag |
| Live stats | ❌ | ❌ | ✅ Real-time frame counter |

---

## 🧬 How the Attack Works (In-Depth)

Understanding the 802.11 protocol is key to understanding what JamX does. Here's the full breakdown:

### Phase 1 — Auto Monitor Mode

Your wireless NIC normally operates in **managed mode** (connecting to APs like a regular client). To sniff and inject raw 802.11 frames, it must be switched to **monitor mode**. JamX handles this automatically with a 3-tier fallback system:

```
┌─────────────────────────────────────────────────────┐
│  1. airmon-ng check kill → airmon-ng start <iface>  │
│     ↓ (if that fails)                               │
│  2. Check if <iface>mon exists via iwconfig         │
│     ↓ (if that fails)                               │
│  3. iw <iface> set monitor none (manual fallback)   │
└─────────────────────────────────────────────────────┘
```

Interfering processes like `NetworkManager` and `wpa_supplicant` are killed first to prevent them from fighting for control of the NIC.

### Phase 2 — Channel Hopping & AP Discovery

WiFi access points operate on specific channels. To discover all nearby networks, JamX starts a **background channel hopper** that cycles through channels every 250ms while a Scapy sniffer captures `Dot11Beacon` frames:

```
Channel Hopper (background thread)
  ┌──→ CH 1 → CH 2 → CH 3 → ... → CH 13 ──┐
  └────────────────────────────────────────────┘
  With --5ghz:
  ┌──→ CH 1-13 → CH 36,40,44,48 → CH 52-64 → CH 100-144 → CH 149-165 ──┐
  └───────────────────────────────────────────────────────────────────────────┘

Beacon Sniffer (main thread)
  ┌───────────────────────────────────────────────────────┐
  │  For each Dot11Beacon received:                       │
  │    → Extract SSID (network name)                      │
  │    → Extract BSSID (AP MAC address)                   │
  │    → Extract Channel (from DS Parameter Set IE)       │
  │    → Store in ap_store{} if new                       │
  └───────────────────────────────────────────────────────┘
```

After the scan duration (default: 15 seconds), the channel hopper is **stopped independently** without affecting the attack phase — thanks to separate `scan_stop` and `run_stop` event flags.

### Phase 3 — Continuous Bidirectional Attack

For **every discovered AP**, a dedicated worker thread sends **4 frame types per burst** in an infinite loop:

```
┌──────────────────────────────────────────────────────────────────┐
│                    PER-BURST FRAME COMPOSITION                   │
├──────┬───────────────────────────────┬───────────────────────────┤
│  #   │  Direction                    │  Frame Type               │
├──────┼───────────────────────────────┼───────────────────────────┤
│  1   │  AP → ff:ff:ff:ff:ff:ff       │  Dot11Deauth (broadcast)  │
│  2   │  AP → ff:ff:ff:ff:ff:ff       │  Dot11Disas  (broadcast)  │
│  3   │  Spoofed Client → AP          │  Dot11Deauth (reverse)    │
│  4   │  Spoofed Client → AP          │  Dot11Disas  (reverse)    │
└──────┴───────────────────────────────┴───────────────────────────┘
```

#### Why 4 frame types?

- **Deauthentication** (subtype 12) — Tells the client "you are no longer authenticated", the client must re-authenticate from scratch
- **Disassociation** (subtype 10) — Tells the client "you are no longer associated", a less severe disconnection that's often overlooked by basic defenses
- **Bidirectional** — Frames 1-2 are spoofed from the AP to all clients. Frames 3-4 are spoofed from a fake client to the AP. This dual direction makes recovery significantly harder because the AP itself thinks a client is leaving

#### Why randomized reason codes?

Each burst picks a **random reason code** from `[1, 2, 3, 4, 7, 8]`:

| Code | Meaning (IEEE 802.11) |
|------|-----------------------|
| 1 | Unspecified reason |
| 2 | Previous authentication no longer valid |
| 3 | Deauthenticated because sending station is leaving |
| 4 | Disassociated due to inactivity |
| 7 | Class 3 frame received from nonassociated station |
| 8 | Disassociated because sending station is leaving BSS |

Simple IDS/WIDS systems fingerprint deauth attacks by looking for a **fixed reason code** repeated rapidly. Randomization defeats that signature.

#### Why randomized spoofed MACs?

Each burst generates a fresh `RandMAC()` for the spoofed client address. This means the AP sees disconnect requests from thousands of different "clients", making MAC-based filtering useless.

### Phase 4 — Live Stats

A background thread prints real-time attack statistics every 5 seconds:

```
[~] Live: 7 APs targeted | 14280 total frames sent
```

This gives you immediate visibility into attack progress without flooding the terminal.

### Phase 5 — Graceful Shutdown & NIC Restore

When you press `Ctrl+C`:

```
┌──────────────────────────────────────────────────┐
│  1. SIGINT handler sets run_stop event            │
│  2. All deauth workers exit their loops           │
│  3. Stats printer stops                           │
│  4. airmon-ng stop <mon_iface>                    │
│  5. NetworkManager restarted                      │
│  6. NIC restored to managed mode                  │
│  7. Final frame count printed                     │
└──────────────────────────────────────────────────┘
```

Your system is left in a **clean state** — regular WiFi connectivity is automatically restored.

---

## 🛠️ Requirements

### Operating System
- **Kali Linux** (recommended)
- Parrot OS
- Any Debian-based Linux distro
- Raspberry Pi OS (with compatible NIC)

### Hardware — Wireless NIC
You need a wireless adapter that supports **monitor mode** and **packet injection**:

| Adapter | Chipset | Band | Recommended |
|---------|---------|------|:-----------:|
| Alfa AWUS036ACH | RTL8812AU | 2.4GHz + 5GHz | ⭐ Best |
| Alfa AWUS036ACSM | RTL8812AU | 2.4GHz + 5GHz | ⭐ |
| Alfa AWUS036NHA | AR9271 | 2.4GHz | ✅ |
| TP-Link TL-WN722N **v1** | AR9271 | 2.4GHz | ✅ |
| Panda PAU09 | RT5572 | 2.4GHz + 5GHz | ✅ |

> ⚠️ The `--5ghz` flag requires a **dual-band** adapter (RTL8812AU or similar).

### System Dependencies

```bash
sudo apt update && sudo apt install -y aircrack-ng iw wireless-tools python3-scapy
```

| Package | Purpose |
|---------|---------|
| `aircrack-ng` | `airmon-ng` for monitor mode management |
| `iw` | Wireless interface configuration (fallback) |
| `wireless-tools` | `iwconfig` for channel control |
| `python3-scapy` | Packet crafting and injection engine |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/bxbySAMRAT/JamX.git

# Enter the directory
cd JamX

# Install dependencies (if not using apt)
pip install scapy
```

That's it. No config files, no setup scripts, no virtual environments needed.

---

## 🚀 Usage — CLI Reference

```bash
sudo python3 jamx.py -i <interface> [options]
```

> ⚡ **Must be run as root** (`sudo`). Raw socket injection requires elevated privileges.

### Arguments

| Flag | Long Flag | Default | Description |
|------|-----------|---------|-------------|
| `-i` | `--iface` | *(required)* | Wireless interface name (e.g., `wlan0`, `wlan1`) |
| `-s` | `--scan` | `15` | Duration of the AP discovery scan in seconds |
| `-t` | `--interval` | `0.05` | Delay between each 4-frame burst (seconds) |
| `-T` | `--threads` | `10` | Maximum concurrent attack worker threads |
| | `--5ghz` | `off` | Include 5GHz channels (36–165) in scan |

---

## 🎯 Quick Start Examples

### Plug & Play — Zero Configuration

The simplest way to run JamX. One command, full automation:

```bash
sudo python3 jamx.py -i wlan0
```

**What happens:**
1. Enables monitor mode on `wlan0`
2. Scans 2.4GHz channels (1–13) for 15 seconds
3. Launches continuous bidirectional deauth + disassoc on **all** discovered APs
4. Runs **forever** until you press `Ctrl+C`
5. Restores `wlan0` to managed mode

### Extended Scan with Aggressive Timing

```bash
sudo python3 jamx.py -i wlan0 -s 30 -t 0.02
```

- **30-second scan** — discovers more APs, especially those with low beacon rates
- **20ms burst interval** — higher frame rate for more aggressive disruption

### 5GHz Dual-Band Attack

```bash
sudo python3 jamx.py -i wlan0 --5ghz
```

- Scans **38 channels** (CH 1–13 + CH 36–165)
- Attacks APs on both 2.4GHz and 5GHz bands
- ⚠️ Requires a dual-band NIC (e.g., Alfa AWUS036ACH)

### Conservative / Low-Profile Attack

```bash
sudo python3 jamx.py -i wlan0 -s 20 -t 0.1 -T 5
```

- **100ms interval** — slower burst rate, lower signature
- **5 threads** — limits simultaneous channel switches

### Maximum Aggression (Lab Only)

```bash
sudo python3 jamx.py -i wlan0 -s 45 --5ghz -t 0.01 -T 20
```

- 45-second scan across all bands
- **10ms burst interval** — maximum frame rate
- 20 concurrent threads

---

## 📺 Example Output

```
     ██╗ █████╗ ███╗   ███╗██╗  ██╗
     ██║██╔══██╗████╗ ████║╚██╗██╔╝
     ██║███████║██╔████╔██║ ╚███╔╝
██   ██║██╔══██║██║╚██╔╝██║ ██╔██╗
╚█████╔╝██║  ██║██║ ╚═╝ ██║██╔╝ ██╗
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝

  ⚡ Multi-Target WiFi Deauth Tool ⚡
  Built by — bxbySAMRAT
  [ Auto Monitor Mode | Scapy-Powered ]
     FOR AUTHORIZED USE ONLY 🔴

[*] Channel band: 2.4GHz (13 channels)

[*] Killing interfering processes (NetworkManager, wpa_supplicant)...
[*] Enabling monitor mode on wlan0...
[+] Monitor mode enabled → interface: wlan0mon

[*] Scanning on wlan0mon for 15s...
  [+] Found: HomeNetwork_5G                BSSID: aa:bb:cc:dd:ee:01  CH:6
  [+] Found: OfficeWiFi                    BSSID: aa:bb:cc:dd:ee:02  CH:11
  [+] Found: <hidden>                      BSSID: aa:bb:cc:dd:ee:03  CH:1
  [+] Found: CafeHotspot                   BSSID: aa:bb:cc:dd:ee:04  CH:3

[*] Scan complete. 4 network(s) found.

[*] Launching continuous deauth on 4 network(s)...

    Press Ctrl+C to stop and restore NIC

  [>] Deauthing 'HomeNetwork_5G' (aa:bb:cc:dd:ee:01) CH6
  [>] Deauthing 'OfficeWiFi' (aa:bb:cc:dd:ee:02) CH11
  [>] Deauthing '<hidden>' (aa:bb:cc:dd:ee:03) CH1
  [>] Deauthing 'CafeHotspot' (aa:bb:cc:dd:ee:04) CH3

[~] Live: 4 APs targeted | 3200 total frames sent
[~] Live: 4 APs targeted | 7840 total frames sent
[~] Live: 4 APs targeted | 12480 total frames sent

^C
[!] Caught interrupt — shutting down...

[*] Attack stopped. 14280 total frames sent across 4 AP(s).

[*] Restoring wlan0 to managed mode...
[+] wlan0 restored to managed mode.
```

---

## 🗂️ Project Structure

```
JamX/
├── jamx.py            # Main tool — all attack logic in a single file
├── ReadMe.md          # This documentation
└── .gitignore         # Python bytecode exclusions
```

---

## ⚙️ Architecture & Code Map

```
jamx.py
├── ANSI Color Constants     ← Terminal color output
├── BANNER                   ← ASCII art with ANSI codes
├── Constants
│   ├── CHANNELS_2G          ← [1..13]
│   ├── CHANNELS_5G          ← [36..165] (25 channels)
│   └── DEAUTH_REASONS       ← [1, 2, 3, 4, 7, 8]
├── Shared State
│   ├── ap_store{}           ← {bssid: (ssid, channel)}
│   ├── scan_stop Event      ← Stops channel hopper only
│   ├── run_stop Event       ← Stops everything on Ctrl+C
│   └── total_frames         ← Atomic frame counter
├── enable_monitor_mode()    ← 3-tier monitor mode setup
├── disable_monitor_mode()   ← NIC restore + NetworkManager restart
├── channel_hopper()         ← Background thread, hops 250ms
├── beacon_handler()         ← Scapy callback for Dot11Beacon
├── scan_networks()          ← Timed sniff wrapper
├── build_attack_frames()    ← 4 frames per burst (deauth+disassoc×2)
├── deauth_worker()          ← Per-AP infinite loop worker
├── stats_printer()          ← Live stats every 5s
├── multi_deauth()           ← Worker orchestrator + semaphore
└── main()                   ← Entry point, argparse, signal handler
```

---

## 🔒 Evasion Techniques Built-In

JamX v2 incorporates several techniques to avoid detection by basic Wireless Intrusion Detection Systems (WIDS):

| Technique | How It Helps |
|-----------|-------------|
| **Randomized Reason Codes** | Prevents IDS from fingerprinting a repeated reason value |
| **Randomized Spoofed MACs** | Each burst appears to come from a different client — defeats MAC-based rate limiting |
| **Disassociation + Deauthentication** | Some IDS only monitor for deauth frames; disassoc frames fly under the radar |
| **Bidirectional Frames** | Attacking from both AP and client perspective doubles the disruption surface |
| **Per-AP Threading** | Frames are sent from multiple channel contexts simultaneously |

> ⚠️ Advanced WIDS systems (Cisco wIPS, Aruba RFProtect) can still detect deauth floods regardless of evasion. JamX is designed for **lab and authorized testing** environments.

---

## 📝 Changelog

### v2.0 — Current Release

**Bug Fixes:**
- 🐛 ANSI-colored banner now actually prints (was showing a plain `===` separator)
- 🐛 Split `stop_flag` into `scan_stop` + `run_stop` — channel hopper and deauth workers have independent lifecycles
- 🐛 Fixed `ord()` crash on empty/multi-byte channel info elements → uses `int.from_bytes()`
- 🐛 Replaced all `os.system()` calls with `subprocess.run()` — eliminates shell injection risk
- 🐛 Fixed root check error message (was referencing wrong filename)
- 🐛 Deauth now runs continuously instead of a fixed frame count

**New Features:**
- ✨ **Bidirectional Deauth + Disassoc** — 4 frame types per burst
- ✨ **Randomized Reason Codes** — picks from `[1, 2, 3, 4, 7, 8]` each burst
- ✨ **Randomized Spoofed Client MAC** — fresh `RandMAC()` per burst
- ✨ **Live Stats Printer** — real-time frame count every 5 seconds
- ✨ **5GHz Channel Support** — `--5ghz` flag adds channels 36–165
- ✨ **SIGINT Handler** — graceful Ctrl+C shutdown with NIC restore
- ✨ **Plug & Play** — no `-c` count flag, runs until you stop it

### v1.0 — Initial Release
- Multi-target deauth with auto monitor mode
- Channel hopping and beacon sniffing
- Basic `Dot11Deauth` broadcast frames

---

## 🤝 Contributing

Pull requests are welcome. If you'd like to contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## ⚖️ License & Legal

This tool is provided for **authorized security testing** and **educational purposes** only. The author is not responsible for any damage caused by the misuse of this software. Always obtain **explicit written permission** before testing any network. Use responsibly.

---

<p align="center">
  <b>Built with ❤️ by <a href="https://github.com/bxbySAMRAT">bxbySAMRAT</a></b><br>
  <i>Star ⭐ this repo if you found it useful!</i>
</p>
