# levicut — WiFi device manager for your own network

A NetCut-like CLI tool for Linux: see every device on your WiFi, cut or throttle
their internet, and protect your own connection from ARP spoofing.

```
  #  IP              MAC                STATE  OS / TYPE           VENDOR / HOST           DETAILS
  0  192.168.68.1    98:03:8E:16:72:88  ok     Router/AP?          TP-Link Systems Inc.    gateway
  1  192.168.68.127  e2:1d:da:ea:bb:2e  ok     iOS (iPhone?)       SSAs-iPhone-7.local
  2  192.168.68.123  f4:70:18:12:7d:ea  ok     Camera?             Hangzhou Ezviz Software Co., Ltd.
  3  192.168.68.138  e2:76:0a:61:eb:34  CUT    Phone? (random MAC)                         blocking active (st to verify)
```

## Features

| Feature | What it does |
|---|---|
| **Scan** | Multi-sweep ARP scan (auto-detects /22, /24, …) with vendor, hostname, and OS/type guess per device |
| **Cut** | Take a device offline via ARP spoofing, with clean restore on exit |
| **Limit** | Throttle a device to ~N% speed (duty-cycle chop, no MITM routing needed) |
| **Protect** | Watch for ARP spoof attacks against you/gateway and auto-repair |
| **Whitelist** | Mark your own devices safe so they can never be cut |
| **Your AP detection** | Shows the AP you connect through and refuses to block it |
| **Device memory** | Remembers silent devices for 15 min (`OLD`) instead of "losing" them |
| **UPnP discovery** | Find TVs/consoles/speakers by their advertised names |

## Requirements

- Linux with WiFi (uses `/proc/net/route`, `ip`, `iw`, `ping`)
- Python 3.10+
- Root access (`sudo` — raw sockets are required for ARP)
- Optional but recommended: `arp-scan` (vendor database), `nmap` (deep OS fingerprints)

## Installation

```bash
git clone https://github.com/<you>/levicut.git
cd levicut
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# optional: refresh the vendor database (new TP-Link/Ezviz blocks etc.)
sudo apt install arp-scan nmap
sudo get-oui
```

## Quick start

```bash
sudo ./venv/bin/python levicut.py
```

```
levicut> s          # scan the network
levicut> 5          # block device #5
levicut> st         # verify: packet counts prove the block is live
levicut> u5         # unblock it
levicut> q          # quit (restores everything)
```

## Interactive commands

| Command | Effect |
|---|---|
| `s` / `r` / `l` | Scan / rescan / list devices |
| `<n>` | Block device `#n` (also accepts IP or MAC) |
| `<n>!` | Force-block even if whitelisted (never self/gateway/AP) |
| `u<n>` | Unblock + unlimit |
| `a` | Restore everything |
| `limit <n> <pct>` | Throttle to ~pct% speed, e.g. `limit 3 20` |
| `unlimit <n>` | Remove throttle |
| `st` | Show live blocks/limits with spoof packet counts |
| `my` | Show your IP/MAC, your AP (BSSID/SSID/signal), whitelist |
| `wl` | List whitelisted devices |
| `wl add <n> [label]` | Never block this device, e.g. `wl add 2 'My phone'` |
| `wl del <n\|mac>` | Remove from whitelist |
| `os <n>` | Deep nmap fingerprint of one device (~15–60s) |
| `disc` | UPnP sweep: friendly names of TVs/consoles/speakers |
| `p` | Toggle anti-spoof protection |
| `f` | Toggle full isolation (spoof both sides) |
| `q` | Quit and restore all ARP tables |

## One-shot (scripting) mode

```bash
sudo ./venv/bin/python levicut.py --scan
sudo ./venv/bin/python levicut.py --scan --passes 3        # lossy WiFi
sudo ./venv/bin/python levicut.py --block 192.168.68.50 --time 300
sudo ./venv/bin/python levicut.py --limit 192.168.68.50 20 --time 300
sudo ./venv/bin/python levicut.py --unblock 192.168.68.50
sudo ./venv/bin/python levicut.py --protect                # guard until Ctrl+C
sudo ./venv/bin/python levicut.py --os-deep 5              # nmap device #5
sudo ./venv/bin/python levicut.py --disc                   # UPnP discovery
sudo ./venv/bin/python levicut.py --wl-add 192.168.68.50 'My phone'
sudo ./venv/bin/python levicut.py --wl-list
sudo ./venv/bin/python levicut.py --block 192.168.68.50 --force   # override whitelist
```

## Reading the table

`STATE` tells blocked vs normal at a glance:

| State | Meaning |
|---|---|
| `ok` | Normal, untouched |
| `CUT` | Blocking active (`st` shows live packet counts) |
| `LIM` | Throttled |
| `YOU` | This machine |
| `AP` | The AP you connect through (unblockable) |
| `SAFE` | Whitelisted |
| `OLD` | Silent lately (`DETAILS` shows since when) |

## How blocking works

Every 2 seconds levicut tells the victim *"the gateway is at my MAC"* (forged
ARP reply sent as a proper L2 frame). The victim's internet traffic comes to
you and dies (IP forwarding stays off). Unblocking sends the real gateway MAC
several times to repair the victim's ARP cache; quitting restores everyone.

Blocking never removes a device from scans — it stays on WiFi, still answers
ARP, and is listed as `CUT`. To confirm a block is working, use `st` (rising
spoof-packet counts) or check the victim device itself.

> Mesh WiFi note: satellites bridge client traffic at Layer 2, so "blocking" a
> mesh node only affects that node's own traffic, not the phones behind it.
> To cut a person, block the person's device IP — not the AP.

## OS / device-type detection

Each scan guesses the OS from 6 combined signals:

| Signal | Example |
|---|---|
| Names: mDNS (`Johns-iPhone.local`) → NetBIOS (`DESKTOP-X`) → reverse DNS | strongest hint |
| Ping TTL (128≈Windows, 64≈Linux/Android/Apple, 255≈embedded) | narrows family |
| Open ports (445/135≈Windows, 62078≈iPhone/Mac, 5555/8008≈Android, 554≈camera, 631≈printer, 548≈Mac) | strong when present |
| Vendor OUI (Samsung→Android?, Apple→iOS/macOS?, TP-Link→Router/AP?, Ezviz→Camera?) | fallback |
| Randomized MAC (`x2/x6/xA/xE` first octet = phone privacy MAC) | → `Phone?` |
| Same OUI as your router | flagged as mesh/AP |

Labels ending in `?` are guesses. `os <n>` gives a firmer nmap answer.

## Why do two scans show different devices?

Normal on WiFi: phones skip ARP replies in deep sleep, and a `/22` scan fires
~1000 requests at once so some replies get lost. levicut unions 2 sweeps per
scan (`--passes 3` on lossy networks) and remembers silent devices for
15 minutes (`known.json`), showing them as `OLD` instead of vanishing. `OLD`
entries can't be blocked (their IP may be reassigned) — rescan until they
answer.

## Safety rails

- You, your gateway, and your AP **can never be blocked or limited**.
- Whitelisted devices refuse blocks unless forced (`3!` / `--force`).
- Quitting (`q`, Ctrl+C) restores all ARP tables.

## Files

| File | Committed? | Purpose |
|---|---|---|
| `levicut.py` | ✅ | The tool (single file) |
| `requirements.txt` | ✅ | `scapy` |
| `whitelist.json` | ❌ local | Your safe devices (created on first `wl add`) |
| `known.json` | ❌ local | Recently seen devices for `OLD` entries |

## Legal / ethics

Use **only on networks you own or are explicitly authorized to manage**
(your home, parental controls, your lab). ARP spoofing other people's
networks without permission is illegal in most jurisdictions. The author
takes no responsibility for misuse.

## License

MIT — do what you want, don't blame me.
