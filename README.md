# Airgorah

A WiFi security auditing tool with a GTK4 GUI. Supports passive scanning, deauthentication attacks, WPA/WPA2/WPA3 handshake capture, PMKID capture, and offline cracking via aircrack-ng or hashcat.

Works on **Linux** and **macOS**.

---

## Features

- **Passive scan** — discovers APs and clients on 2.4 GHz and 5 GHz
- **Deauth attacks** — broadcast or targeted, with optional disassociation frames
- **Handshake capture** — detects WPA/WPA2 four-way handshakes automatically
- **PMKID capture** — clientless attack against WPA2 APs
- **Offline cracking** — wordlist or bruteforce via aircrack-ng; GPU cracking via hashcat (mode 22000 / 2500)
- **Export** — save captures as `.cap` (pcap), scan reports as `.json` or `.csv`
- **MAC spoofing** — random, default, or specific MAC before entering monitor mode
- **Vendor lookup** — identifies device manufacturers from OUI

---

## Requirements

### Linux

| Tool | Purpose | Required |
|------|---------|----------|
| `iw` | Interface / monitor mode management | Yes |
| `ip` | Interface state | Yes |
| `macchanger` | MAC address spoofing | Yes |
| `xterm` | Terminal for cracking jobs | Yes |
| `aircrack-ng` | Handshake cracking | Optional |
| `crunch` | Bruteforce wordlist generation | Optional |
| `hashcat` | GPU cracking | Optional |
| `pkexec` (polkit) | Privilege escalation | Recommended |

Install on Debian/Ubuntu:

```bash
sudo apt install iw macchanger xterm aircrack-ng crunch hashcat policykit-1
```

### macOS

| Tool | Purpose | Required |
|------|---------|----------|
| GTK4 | GUI framework | Yes |
| libpcap | Packet capture (RFMON mode) | Yes |
| `airport` | Channel switching | Bundled with macOS |
| `ifconfig` | Interface / MAC management | Bundled with macOS |
| `aircrack-ng` | Handshake cracking | Optional |
| `hashcat` | GPU cracking | Optional |

Install via Homebrew:

```bash
brew install gtk4 libpcap aircrack-ng hashcat
```

> **Note:** On macOS, airgorah uses libpcap's RFMON mode for capture and `osascript` for privilege escalation (a macOS password dialog appears on first use).

---

## Building

```bash
cargo build --release
```

The two produced binaries must stay in the same directory:

- `airgorah` — unprivileged GUI
- `airgorah-agent` — privileged agent (runs as root)

---

## Running

```bash
./target/release/airgorah
```

On first use airgorah will ask for your password to start the privileged agent. The agent is only launched when you commit to a privileged action (putting a card into monitor mode).

---

## Usage

1. **Select interface** — pick your wireless card from the dropdown
2. **Start scan** — toggle 2.4 GHz / 5 GHz, optionally filter channels (e.g. `1,6,11`), press ▶
3. **Select an AP** — click a row in the AP table to see its clients
4. **Deauth** — right-click an AP → Attack → choose broadcast or select specific clients
5. **Crack** — once a handshake or PMKID is captured, right-click → Decrypt
   - **Wordlist** — provide a wordlist file
   - **Bruteforce** — configure charset and length range
   - **Hashcat** — provide a `.cap` / `.22000` file and wordlist for GPU cracking
6. **Export** — use the Export button to save a `.cap` capture, or the Report button for `.json` / `.csv`

---

## Architecture

```
airgorah (GUI, unprivileged)
    │  IPC over Unix socket
    ▼
airgorah-agent (root)
    ├── interface management  (iw / airport)
    ├── native sniffer        (AF_PACKET on Linux, libpcap RFMON on macOS)
    ├── deauth injector       (raw 802.11 frames)
    └── PMKID solicitor       (raw association frames)
```

The GUI never runs as root. All privileged operations go through the agent, which validates every request before acting on it.

---

## Platform Notes

### macOS Limitations

- Frame injection (deauth / PMKID) requires a compatible adapter; the built-in Airport card does not support injection on recent macOS versions
- Monitor mode support varies by adapter and macOS version; an external USB adapter (e.g. Alfa AWUS036ACH) is recommended
- The "Kill network managers" setting is Linux-only and is hidden on macOS

### Linux Notes

- The app uses polkit (`pkexec`) for privilege escalation; install `policykit-1` or equivalent
- If polkit is unavailable, run the GUI as root: `sudo ./airgorah`

---

## License

MIT — see [LICENSE](LICENSE)
