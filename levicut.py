#!/usr/bin/env python3
"""
levicut.py - WiFi device manager for YOUR OWN network (Ubuntu/Linux).

Features:
  1. scan      - ARP scan + hostname + vendor + OS guess, correct /22, /24, etc.
  2. cut       - block device internet via ARP spoof (victim thinks gateway = you)
  3. limit     - throttle device via duty-cycle chop (e.g. allow 20% of time)
  4. protect   - detect ARP spoof attacks against you/gateway, auto-repair
  5. whitelist - mark your own devices safe so they can never be cut

Usage:
  Interactive:
    sudo ./venv/bin/python levicut.py [iface]
  One-shot:
    sudo ./venv/bin/python levicut.py --scan
    sudo ./venv/bin/python levicut.py --scan --iface wlp4s0
    sudo ./venv/bin/python levicut.py --block 192.168.68.100 --time 60
    sudo ./venv/bin/python levicut.py --unblock 192.168.68.100
    sudo ./venv/bin/python levicut.py --limit 192.168.68.100 20  (allow ~20%)
    sudo ./venv/bin/python levicut.py --protect  (run guard until Ctrl+C)
    sudo ./venv/bin/python levicut.py --os-deep 5  (nmap fingerprint of device #5)

Legal: use ONLY on networks you own or are explicitly authorized to manage.
Cutting neighbours / public WiFi without permission is illegal.
"""

import os
import sys
import re
import signal
import socket
import time
import threading
import argparse
import ipaddress
import json
import subprocess
from collections import defaultdict

from scapy.all import ARP, Ether, srp, sendp, sniff, get_if_addr, get_if_hwaddr, conf

BANNER = r"""
  _   _      _   __     __
 | \ | | ___| |_ \ \   / /_ _ _ __ ___
 |  \| |/ _ \ __|\ \ / / _` | '__/ _ \
 | |\  |  __/ |_  \ V / (_| | | |  __/
 |_| \_|\___|\__|  \_/ \__,_|_|  \___|
   WiFi device manager (scan/cut/limit/protect)
"""

SCAN_TIMEOUT = 3.0
SPOOF_INTERVAL = 2.0
LIMIT_WINDOW = 10.0  # seconds per duty-cycle window for --limit
SCAN_PASSES = 2      # ARP sweeps per scan (unioned: catches sleepy phones/lost packets)
STALE_MAX_AGE = 900  # remember silent devices this long (s); shown as STALE
CACHE_PRUNE_AGE = 7 * 86400  # forget devices unseen this long


def whitelist_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "whitelist.json")


def cache_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "known.json")
OUI_PATHS = [
    "/usr/share/arp-scan/ieee-oui.txt",
    "/usr/share/wireshark/manuf",
    "/usr/share/nmap/nmap-mac-prefixes",
]
_oui_cache = {}


# --------------------------------------------------------------------------- #
# Helpers: interface / gateway / vendor / hostname
# --------------------------------------------------------------------------- #
def detect_iface():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if len(p) >= 2 and p[1] == "00000000":
                    return p[0]
    except OSError:
        pass
    for iface in sorted(conf.ifaces):
        try:
            ip = get_if_addr(iface)
        except Exception:
            continue
        if ip and ip != "0.0.0.0" and not ip.startswith("127."):
            return iface
    sys.exit("[!] No suitable network interface found")


def detect_gateway():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if len(p) >= 3 and p[1] == "00000000":
                    return socket.inet_ntoa(bytes.fromhex(p[2])[::-1])
    except OSError:
        pass
    sys.exit("[!] Could not detect default gateway")


def detect_prefixlen(iface, ip):
    """Get e.g. 22 for 192.168.68.151/22 via `ip addr`. Fallback: /24."""
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show", iface],
            text=True, timeout=5,
        )
        m = re.search(rf"{re.escape(ip)}/(\d+)", out)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return 24


def my_ap_info(iface):
    """Which AP is THIS machine associated to? Reads `iw dev <iface> link`
    (BSSID/SSID/signal) with an nmcli fallback. Returns dict or None
    (e.g. on wired interfaces). This is how you know your own AP."""
    info = {}
    try:
        out = subprocess.check_output(["iw", "dev", iface, "link"],
                                      text=True, timeout=5)
        m = re.search(r"Connected to ([0-9a-fA-F:]{17})", out)
        if not m:
            return None  # "Not connected." (wired or down)
        info["bssid"] = m.group(1).lower()
        for pat, key in ((r"^\s*SSID: (.+)$", "ssid"),
                         (r"^\s*signal: (.+)$", "signal"),
                         (r"^\s*freq: (\d+)$", "freq")):
            mm = re.search(pat, out, re.MULTILINE)
            if mm:
                info[key] = mm.group(1).strip()
        return info
    except Exception:
        pass
    try:  # fallback: nmcli (NetworkManager; BSSID colons come escaped)
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "IN-USE,BSSID,SSID,SIGNAL", "dev", "wifi"],
            text=True, timeout=5)
        for line in out.splitlines():
            p = [f.replace("\\:", ":") for f in re.split(r"(?<!\\):", line)]
            if len(p) >= 3 and p[0] == "*" and re.match(
                    r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", p[1]):
                return {"bssid": p[1].lower(), "ssid": p[2],
                        "signal": (p[3] + "%") if len(p) > 3 and p[3] else ""}
    except Exception:
        pass
    return None


def load_oui():
    if _oui_cache:
        return _oui_cache
    for path in OUI_PATHS:
        if not os.path.exists(path):
            continue
        try:
            with open(path, errors="ignore") as f:
                for line in f:
                    # arp-scan format: "00AABB<TAB>Vendor..."
                    m = re.match(r"^([0-9A-Fa-f]{6})\s+(.+?)\s*$", line.strip())
                    if m:
                        _oui_cache[m.group(1).upper()] = m.group(2).strip()
            if _oui_cache:
                break
        except OSError:
            continue
    return _oui_cache


def vendor_of(mac):
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    hit = load_oui().get(prefix)
    return hit or VENDOR_FALLBACK.get(prefix)


def hostname_of(ip, timeout=1.0):
    """Reverse-DNS without hanging the scan (thread + timeout)."""
    result = [None]

    def _r():
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    t = threading.Thread(target=_r, daemon=True)
    t.start()
    t.join(timeout)
    return result[0]


# --------------------------------------------------------------------------- #
# OS / device-type guess (best-effort, combines 4 weak signals)
# Signals: ping TTL + TCP open ports + vendor OUI + hostname keywords.
# No single signal is conclusive (Android & Linux share TTL 64, Apple MACs
# cover iPhone+iPad+Mac), so results carry '?' when evidence is circumstantial.
# --------------------------------------------------------------------------- #
OS_PORTS = {  # port -> (tag, weight): what an open port tells us
    135: ("WIN-RPC", 2), 139: ("WIN-NBT", 2), 445: ("WIN-SMB", 3),
    554: ("RTSP-cam", 1), 631: ("IPP-print", 1), 548: ("AFP-Mac", 2),
    62078: ("iOS-lockdown", 3), 7000: ("AirPlay", 2), 7001: ("AirPlay", 2),
    5000: ("UPnP/SSDP", 1), 8008: ("Chromecast", 2), 8009: ("Chromecast", 2),
    5555: ("Android-ADB", 3), 22: ("SSH", 1), 80: ("HTTP", 0), 443: ("HTTPS", 0),
}

# vendor keyword -> likely OS family (checked against ieee-oui vendor string)
VENDOR_OS = [
    (("APPLE",), "Apple iOS/macOS?"),
    (("SAMSUNG", "XIAOMI", "ONEPLUS", "OPPO", "VIVO", "REALME", "HUAWEI",
      "MOTOROLA", "NOKIA", "GOOGLE", "TECNO", "INFINIX", "POCO", "REDMI"), "Android?"),
    (("MICROSOFT", "DELL", "LENOVO", "HEWLETT", "HP INC", "ASUS", "ACER",
      "MSI", "GIGABYTE", "INTEL CORPORATE"), "Windows?"),
    (("RASPBERRY", "ESPRESSIF", "TASMOTA", "SHELLY", "WYZE", "RING",
      "NEST", "SONOS", "AMAZON TECH", "IROBOT"), "IoT/Linux?"),
    (("HON HAI", "FOXCONN", "QUANTA", "COMPAL", "WISTRON", "PEGATRON",
      "INVENTEC"), "Windows?"),  # laptop ODMs — usually Windows laptops
    (("TP-LINK", "TP LINK", "TPLINK", "NETGEAR", "LINKSYS", "UBIQUITI",
      "D-LINK", "TENDA", "MERCUSYS", "MI ROUTER", "XIAOMI COMM"), "Router/AP?"),
    (("EZVIZ", "HIKVISION", "DAHUA", "ARLO", "EUFY", "REOLINK",
      "TP-LINK TAPO", "WYZE LABS"), "Camera?"),
    (("SONOS", "BOSE", "JBL", "HARMAN", "DENON", "YAMAHA"), "Speaker?"),
    (("LG ELECTRON", "SAMSUNG ELECTRON", "TCL", "HISENSE", "PHILIPS",
      "PANASONIC", "SONY"), "TV/Android-TV?"),
    (("NINTENDO", "SONY INTERACTIVE", "MICROSOFT XBOX"), "Console?"),
]

# Fallback for OUIs missing from a stale local ieee-oui.txt
# (refresh yours with: sudo get-oui)
VENDOR_FALLBACK = {
    "98038E": "TP-Link Systems Inc.",
    "F47018": "Hangzhou Ezviz Software Co., Ltd.",
}

HOST_OS = [  # hostname keyword -> OS (android-xyz, Johns-iPhone, DESKTOP-...)
    ("IPHONE", "iOS (iPhone?)"), ("IPAD", "iOS (iPad?)"),
    ("MACBOOK", "macOS?"), ("IMAC", "macOS?"), ("MAC-", "macOS?"),
    ("DESKTOP-", "Windows?"), ("WIN-", "Windows?"),
    ("ANDROID", "Android?"), ("PIXEL", "Android?"), ("GALAXY", "Android?"),
    ("ESP_", "IoT?"), ("TASMOTA", "IoT?"), ("PRINTER", "Printer?"),
    ("CAM", "Camera?"), ("DOORBELL", "Camera?"), ("TV", "TV?"),
    ("PLAYSTATION", "Console?"), ("XBOX", "Console?"),
    ("ECHO", "Speaker?"), ("GOOGLE-HOME", "Speaker?"), ("SONOS", "Speaker?"),
]


def is_random_mac(mac):
    """True if locally-administered UNICAST (1st octet & 0x03 == 0x02):
    modern Android/iOS WiFi privacy MACs. Strong phone/tablet signal."""
    try:
        return (int(mac.split(":")[0], 16) & 0x03) == 0x02
    except Exception:
        return False


def oui_of(mac):
    try:
        return mac.replace(":", "").replace("-", "").upper()[:6]
    except Exception:
        return ""


def ping_ttl(ip, timeout=1):
    """Return TTL from one ping, or None if host silent to ICMP."""
    try:
        out = subprocess.run(["ping", "-c1", "-W", str(timeout), ip],
                             capture_output=True, text=True, timeout=timeout + 2)
        m = re.search(r"ttl=(\d+)", out.stdout, re.IGNORECASE)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def tcp_open(ip, port, timeout=0.5):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def check_ports(ip, ports=None, timeout=0.5):
    """Parallel TCP connect; returns set of open ports."""
    ports = ports or list(OS_PORTS)
    open_p = set()
    lock = threading.Lock()

    def _p(pt):
        if tcp_open(ip, pt, timeout):
            with lock:
                open_p.add(pt)

    ts = [threading.Thread(target=_p, args=(pt,), daemon=True) for pt in ports]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout + 0.5)
    return open_p


def os_guess_fast(ip, mac, vendor=None, hostname="", nb_server=False):
    """Quick OS guess (~1s, parallel-safe). Returns short label like
    'Windows', 'Android?', 'Apple iOS/macOS?', 'Linux?', 'IoT?', 'Unknown'."""
    hn = (hostname or "").upper()
    for kw, label in HOST_OS:
        if kw in hn:
            return label
    if nb_server:
        # NetBIOS Server service (suffix 0x20): Windows file sharing (or Samba)
        return "Windows" if ping_ttl(ip) == 128 else "Windows?"
    ttl = ping_ttl(ip)
    open_p = check_ports(ip)
    tags = {OS_PORTS[p][0] for p in open_p if p in OS_PORTS}

    # strong port evidence first
    if "WIN-SMB" in tags or "WIN-RPC" in tags or "WIN-NBT" in tags:
        return "Windows"
    if "iOS-lockdown" in tags:
        return "iOS/macOS" if ttl == 64 else "Apple device"
    if "Android-ADB" in tags or "Chromecast" in tags:
        return "Android"
    if "AFP-Mac" in tags or "AirPlay" in tags:
        return "Apple (macOS/iOS?)"
    if "RTSP-cam" in tags:
        return "Camera?"
    if "IPP-print" in tags and not open_p & {135, 139, 445}:
        return "Printer?"

    v = (vendor or "").upper()
    for kws, label in VENDOR_OS:
        if any(k in v for k in kws):
            if ttl == 128 and "Android" in label:
                return "Windows?"  # TTL beats vendor (some VMs/NAT skew OUI)
            return label

    if is_random_mac(mac) and ttl == 64 and not open_p & {135, 139, 445}:
        return "Phone? (random MAC)"
    if is_random_mac(mac) and ttl is None:
        return "Phone/IoT? (random MAC)"

    # TTL fallback
    if ttl == 128:
        return "Windows?"
    if ttl == 64:
        if open_p & {22}:
            return "Linux?"
        return "Linux/Android/Mac?"
    if ttl is not None and ttl <= 64 and ttl >= 30 and not open_p:
        return "Linux/IoT?"
    if ttl == 255:
        return "Network gear?"
    return "Unknown"


def os_deep(ip, timeout=120):
    """nmap OS + service detection (root, slow ~15-60s). Returns summary str."""
    try:
        out = subprocess.run(
            ["nmap", "-O", "--osscan-guess", "-F", ip],
            capture_output=True, text=True, timeout=timeout)
        txt = out.stdout
        lines = []
        for pat in ("OS details:", "Aggressive OS guesses:",
                    "Device type:", "Running:", "OS CPE:"):
            m = re.search(rf"^{pat}(.+)$", txt, re.MULTILINE)
            if m:
                lines.append(f"{pat}{m.group(1).strip()}")
        ports = re.findall(r"^(\d+/tcp\s+\w+\s+\S+.*)$", txt, re.MULTILINE)[:8]
        res = "\n".join(lines) if lines else "(nmap could not fingerprint OS)"
        if ports:
            res += "\nOpen: " + "; ".join(p.strip() for p in ports)
        return res
    except subprocess.TimeoutExpired:
        return "(nmap timed out — host may filter probes)"
    except Exception as e:
        return f"(nmap failed: {e})"


def _dns_name(buf, off):
    """Decode a (possibly compressed) DNS name at offset; returns (name, end)."""
    labels, end, jumped = [], None, False
    for _ in range(20):  # loop guard
        ln = buf[off]
        if ln == 0:
            off += 1
            if not jumped:
                end = off
            break
        if ln & 0xC0:  # pointer
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            continue
        off += 1
        labels.append(buf[off:off + ln].decode("utf-8", "replace"))
        off += ln
        if not jumped:
            end = off
    return ".".join(labels), (end if end is not None else off)


def mdns_lookup(ip, timeout=1.5):
    """Ask the LAN (multicast DNS) who <ip> is. Often returns names like
    'Johns-iPhone.local' that plain reverse-DNS misses. Returns str or None."""
    import struct
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    qname = b"".join(bytes([len(p)]) + p.encode() for p in rev.split(".")) + b"\x00"
    pkt = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, ("224.0.0.251", 5353))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(1024)
            except socket.timeout:
                return None
            if len(data) < 12:
                continue
            qd = struct.unpack(">H", data[4:6])[0]
            off = 12
            for _ in range(qd):  # skip questions
                _, off = _dns_name(data, off)
                off += 4
            an = struct.unpack(">H", data[6:8])[0]
            for _ in range(an):
                _, off = _dns_name(data, off)
                rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                rdata = off + 10
                if rtype == 12 and rdata + rdlen <= len(data):  # PTR
                    name, _ = _dns_name(data, rdata)
                    if name:
                        return name.rstrip(".")
                off = rdata + rdlen
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass
    return None


# NetBIOS Node-Status request for name "*" (encodes the wildcard)
_NB_REQ = (b"\x00\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20"
           b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")


def netbios_status(ip, timeout=1.0):
    """NBSTAT query (UDP 137). Returns (computer_name, has_server_service).
    The Server-service flag (suffix 0x20) means Windows file sharing/Samba."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(_NB_REQ, (ip, 137))
        data, _ = s.recvfrom(1024)
        if len(data) < 57:
            return None, False
        n = data[56]
        if not 0 < n < 30 or len(data) < 57 + n * 18:
            return None, False
        name, server = None, False
        for i in range(n):
            e = data[57 + i * 18:57 + (i + 1) * 18]
            nm, suffix = e[:15].decode("ascii", "replace").strip(), e[15]
            if suffix == 0x20:
                server = True
            if suffix in (0x00, 0x03) and nm and nm != "__MSBROWSE__":
                name = name or nm
        return name, server
    except Exception:
        return None, False
    finally:
        try:
            s.close()
        except Exception:
            pass


def best_hostname(ip, timeout=1.0):
    """mDNS (.local names) -> NetBIOS (Windows names) -> reverse DNS.
    Runs the three in parallel; returns (hostname, nb_server_flag)."""
    res = {}

    def _m():
        res["mdns"] = mdns_lookup(ip)
    def _n():
        res["nb"] = netbios_status(ip)
    def _r():
        res["rdns"] = hostname_of(ip, timeout)

    ts = [threading.Thread(target=f, daemon=True) for f in (_m, _n, _r)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(3)
    nb_name, nb_server = res.get("nb") or (None, False)
    return res.get("mdns") or nb_name or res.get("rdns"), nb_server


def ssdp_discover(timeout=4):
    """UPnP/SSDP sweep: finds smart TVs, consoles, speakers, printers with
    their advertised names. Returns {ip: {'st': set, 'server': str, 'name': str}}."""
    msg = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           b"MAN: \"ns=01; ns=01\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        for _ in range(2):
            try:
                s.sendto(msg, ("239.255.255.250", 1900))
            except Exception:
                return found
            time.sleep(0.3)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, (ip, _) = s.recvfrom(4096)
            except socket.timeout:
                break
            try:
                txt = data.decode("utf-8", "replace")
            except Exception:
                continue
            if "200 OK" not in txt and "NOTIFY" not in txt:
                continue
            heads = {}
            for line in txt.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    heads[k.strip().upper()] = v.strip()
            e = found.setdefault(ip, {"st": set(), "server": "", "loc": ""})
            if heads.get("ST"):
                e["st"].add(heads["ST"])
            e["server"] = e["server"] or heads.get("SERVER", "")
            e["loc"] = e["loc"] or heads.get("LOCATION", "")
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    # fetch friendlyName from device XML (that's the "Living-Room TV" label)
    import urllib.request
    import xml.etree.ElementTree as ET

    def _name(e):
        if not e["loc"]:
            return
        try:
            with urllib.request.urlopen(e["loc"], timeout=2.5) as r:
                xml = r.read(20000)
            root = ET.fromstring(xml)
            for el in root.iter():
                if el.tag.endswith("friendlyName") and el.text:
                    e["name"] = el.text.strip()
                    return
        except Exception:
            pass

    ts = [threading.Thread(target=_name, args=(e,), daemon=True) for e in found.values()]
    for t in ts:
        t.start()
    for t in ts:
        t.join(4)
    return found


def print_ssdp(found):
    if not found:
        print("  (no UPnP/SSDP devices answered — TVs/consoles often stay quiet)")
        return
    print(f"\n  {'IP':<16}{'NAME':<30}ADVERTISED AS")
    print("  " + "-" * 78)
    for ip in sorted(found, key=lambda x: tuple(int(o) for o in x.split("."))):
        e = found[ip]
        name = e.get("name") or e.get("server") or "-"
        st = ", ".join(sorted(e["st"])[:2])
        print(f"  {ip:<16}{name[:29]:<30}{st[:40]}")


def set_ip_forward(enable: bool):
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1" if enable else "0")
    except OSError as e:
        print(f"[!] could not set ip_forward={int(enable)}: {e}")


# --------------------------------------------------------------------------- #
# Whitelist — never block/limit these (your own phone, laptop, TV...)
# Stored in whitelist.json next to this script: {MAC: {label, last_ip, added}}
# --------------------------------------------------------------------------- #
class Whitelist:
    def __init__(self, path=None):
        self.path = path or whitelist_path()
        self.entries = {}  # MAC-upper -> {label, last_ip, added}
        self.load()

    @staticmethod
    def norm_mac(mac):
        return mac.strip().upper().replace("-", ":")

    def load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
            # normalize keys
            self.entries = {self.norm_mac(k): v for k, v in data.items()}
        except (OSError, ValueError):
            self.entries = {}

    def save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self.entries, f, indent=2)
        except OSError as e:
            print(f"[!] could not save whitelist: {e}")

    def add(self, mac, label="", last_ip=""):
        mac = self.norm_mac(mac)
        self.entries[mac] = {
            "label": label or self.entries.get(mac, {}).get("label", ""),
            "last_ip": last_ip or self.entries.get(mac, {}).get("last_ip", ""),
            "added": self.entries.get(mac, {}).get("added", time.strftime("%Y-%m-%d %H:%M")),
        }
        self.save()
        return mac

    def remove(self, key):
        """key may be MAC, IP, or exact label. Returns removed MAC or None."""
        k = key.strip()
        ku = k.upper().replace("-", ":")
        if ku in self.entries:
            del self.entries[ku]
            self.save()
            return ku
        for mac, info in list(self.entries.items()):
            if info.get("last_ip") == k or info.get("label", "").lower() == k.lower():
                del self.entries[mac]
                self.save()
                return mac
        return None

    def is_whitelisted(self, mac):
        return self.norm_mac(mac) in self.entries if mac else False

    def label_of(self, mac):
        info = self.entries.get(self.norm_mac(mac), None) if mac else None
        return info.get("label", "") if info else ""

    def touch_ip(self, mac, ip):
        mac = self.norm_mac(mac)
        if mac in self.entries and ip:
            self.entries[mac]["last_ip"] = ip
            self.save()

    def list_lines(self):
        if not self.entries:
            return ["  (whitelist empty — add your own devices so you never cut them)"]
        return [f"  {mac:<19}{info.get('label',''):<24}last ip: {info.get('last_ip','-')}"
                for mac, info in sorted(self.entries.items())]


def is_protected_target(d, whitelist: Whitelist, net) -> str | None:
    """Return reason string if d must not be blocked/limited, else None."""
    if d.get("stale"):
        return (f"silent since {d['stale']} — rescan until it answers "
                "(its IP may be reassigned by now)")
    ap_bssid = ((getattr(net, "ap", None)) or {}).get("bssid", "")
    if ap_bssid and d["mac"].lower() == ap_bssid:
        return ("YOUR AP — you connect through here; cutting it cuts YOU. "
                "To control WiFi clients, block/limit the client IPs, not APs")
    if d.get("note") == "gateway" or d["ip"] == net.gateway_ip:
        return "gateway (blocking it kills everyone's internet, including yours)"
    if d.get("note", "").startswith("you") or \
            d["mac"].lower() == net.my_mac.lower() or d["ip"] == net.my_ip:
        return "this is YOU (the machine running levicut)"
    if whitelist and whitelist.is_whitelisted(d["mac"]):
        lbl = whitelist.label_of(d["mac"])
        return f"whitelisted{' (' + lbl + ')' if lbl else ''} — remove first (wl del)"
    return None


class Network:
    def __init__(self, iface=None):
        self.iface = iface or detect_iface()
        self.my_ip = get_if_addr(self.iface)
        self.my_mac = get_if_hwaddr(self.iface)
        self.gateway_ip = detect_gateway()
        prefix = detect_prefixlen(self.iface, self.my_ip)
        self.subnet = str(ipaddress.ip_network(f"{self.my_ip}/{prefix}", strict=False))
        self.prefix = prefix
        self.gateway_mac = self.resolve_mac(self.gateway_ip)
        if not self.gateway_mac:
            sys.exit(f"[!] Could not resolve gateway MAC for {self.gateway_ip}")
        self.ap = my_ap_info(self.iface)  # BSSID you're associated to (None if wired)

    def resolve_mac(self, ip, timeout=2):
        ans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout, iface=self.iface, verbose=0,
        )[0]
        for _, rcv in ans:
            return rcv[Ether].src
        return None

    def summary(self):
        s = (f"  interface : {self.iface}\n"
             f"  your ip   : {self.my_ip}  ({self.my_mac})\n"
             f"  gateway   : {self.gateway_ip}  ({self.gateway_mac})\n"
             f"  subnet    : {self.subnet}")
        if self.ap and self.ap.get("bssid"):
            extra = "".join(f" {k}={v}" for k, v in
                            (("ssid", self.ap.get("ssid")),
                             ("sig", self.ap.get("signal")),
                             ("freq", self.ap.get("freq"))) if v)
            s += f"\n  your AP   : {self.ap['bssid']}{extra}  <-- you connect through here"
        return s


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #
def arp_sweep(net, timeout=SCAN_TIMEOUT):
    """One ARP pass over the subnet; returns {mac: ip} for responders."""
    arp = ARP(pdst=net.subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    ans, _ = srp(ether / arp, timeout=timeout, iface=net.iface, verbose=0,
                 inter=0.002, retry=0)
    out = {}
    for _, rcv in ans:
        try:
            out[rcv[Ether].src] = rcv[ARP].psrc
        except Exception:
            continue
    return out


def merge_sweeps(sweeps):
    """Union of {mac: ip} dicts; first-seen IP wins (stable across passes)."""
    merged = {}
    for s in sweeps:
        for mac, ip in s.items():
            merged.setdefault(mac, ip)
    return merged


def age_str(epoch_now, then):
    s = max(0, int(epoch_now - then))
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    return f"{s // 3600}h ago"


class DeviceCache:
    """known.json: remembers every device ever seen ({MAC: info+last_seen}).
    Lets scans show STALE entries instead of devices 'vanishing' when a
    phone sleeps through one sweep or WiFi drops a reply."""

    def __init__(self, path=None):
        self.path = path or cache_path()
        self.known = {}
        self.load()

    def load(self):
        try:
            with open(self.path) as f:
                self.known = json.load(f)
        except (OSError, ValueError):
            self.known = {}

    def save(self):
        try:
            now = time.time()
            self.known = {m: i for m, i in self.known.items()
                          if now - i.get("last_seen", 0) < CACHE_PRUNE_AGE}
            with open(self.path, "w") as f:
                json.dump(self.known, f, indent=2)
        except OSError as e:
            print(f"[!] could not save device cache: {e}")

    def update(self, devices):
        now = time.time()
        for d in devices:
            if d.get("stale"):
                continue
            mac = Whitelist.norm_mac(d["mac"])
            self.known[mac] = {"ip": d["ip"], "vendor": d.get("vendor"),
                               "hostname": d.get("hostname"), "os": d.get("os"),
                               "last_seen": now}
        self.save()

    def stale(self, live_macs, max_age=STALE_MAX_AGE):
        now = time.time()
        live = {Whitelist.norm_mac(m) for m in live_macs}
        out = []
        for mac, info in self.known.items():
            if mac in live or now - info.get("last_seen", 0) > max_age:
                continue
            out.append({"ip": info.get("ip", "?"), "mac": mac,
                        "vendor": info.get("vendor"),
                        "hostname": info.get("hostname"), "os": info.get("os"),
                        "stale": age_str(now, info.get("last_seen", now))})
        out.sort(key=lambda d: tuple(int(o) for o in d["ip"].split("."))
                 if re.match(r"^(\d+\.){3}\d+$", d["ip"] or "") else (999,))
        return out


def scan(net: Network, cache=None, passes=SCAN_PASSES,
         resolve_names=True, detect_os=True):
    print(f"[*] Scanning {net.subnet} on {net.iface} ({passes}x sweep) ...")
    sweeps = []
    for p in range(passes):
        if p:
            print(f"[*] sweep {p + 1}/{passes} ...")
        sweeps.append(arp_sweep(net))
    seen = merge_sweeps(sweeps)
    print(f"[*] {len(seen)} responder(s) across {passes} sweep(s)")

    devices = [{"ip": ip, "mac": mac} for mac, ip in seen.items()]

    # ensure gateway + self are represented even if silent
    if not any(d["ip"] == net.gateway_ip for d in devices):
        devices.insert(0, {"ip": net.gateway_ip, "mac": net.gateway_mac,
                            "note": "gateway"})

    devices.sort(key=lambda d: tuple(int(o) for o in d["ip"].split(".")))

    # enrich (vendor + names + OS guess, one thread per host, all parallel)
    def _enrich(d):
        d["vendor"] = vendor_of(d["mac"])
        if resolve_names:
            d["hostname"], nb_server = best_hostname(d["ip"])
        else:
            d["hostname"], nb_server = None, False
        d["os"] = os_guess_fast(d["ip"], d["mac"], d["vendor"],
                                d["hostname"], nb_server) if detect_os else None

    threads = [threading.Thread(target=_enrich, args=(d,), daemon=True)
               for d in devices]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    # tag self/gateway notes (self = the machine running levicut)
    gw_oui = oui_of(net.gateway_mac)
    ap_bssid = (net.ap or {}).get("bssid", "")
    for d in devices:
        if d["ip"] == net.gateway_ip:
            d.setdefault("note", "gateway")
        if d["ip"] == net.my_ip or d["mac"].lower() == net.my_mac.lower():
            d["note"] = "you (this machine)"
        elif ap_bssid and d["mac"].lower() == ap_bssid:
            d["note"] = "YOUR AP (you connect here)"
        elif (d["ip"] != net.gateway_ip and gw_oui
                and oui_of(d["mac"]) == gw_oui and not is_random_mac(d["mac"])):
            d["hint"] = "same maker as router: mesh/AP?"
    # ensure self is represented even if silent (gateway handled above)
    if not any(x.get("note", "").startswith("you") for x in devices):
        devices.append({"ip": net.my_ip, "mac": net.my_mac,
                        "note": "you (this machine)",
                        "vendor": vendor_of(net.my_mac), "hostname": None,
                        "os": "YOU"})
    devices.sort(key=lambda d: tuple(int(o) for o in d["ip"].split(".")))
    live_macs = [d["mac"] for d in devices]
    stale = cache.stale(live_macs) if cache else []
    if stale:
        print(f"[*] +{len(stale)} known-but-silent (STALE, last seen <15m ago)")
    devices.extend(stale)
    if cache:
        cache.update(devices)
    return devices


def print_devices(devices, blocked=(), limited=(), whitelist=None):
    if not devices:
        print("  (no devices found)")
        return
    print(f"\n  {'#':<3}{'IP':<16}{'MAC':<19}{'STATE':<7}"
          f"{'OS / TYPE':<20}{'VENDOR / HOST':<24}DETAILS")
    print("  " + "-" * 112)
    for i, d in enumerate(devices):
        note = d.get("note", "")
        if d["ip"] in blocked:
            state = "CUT"
            details = "blocking active (st to verify)"
            if d.get("stale"):
                details += f"; silent {d['stale']}"
        elif d["ip"] in limited:
            state, details = "LIM", f"throttled ~{limited[d['ip']]}%"
        elif d.get("stale"):
            state, details = "OLD", f"silent {d['stale']}"
        elif note.startswith("you"):
            state, details = "YOU", "this machine"
        elif note.startswith("YOUR AP"):
            state, details = "AP", "you connect here"
        elif whitelist and whitelist.is_whitelisted(d["mac"]):
            state = "SAFE"
            details = whitelist.label_of(d["mac"]) or "whitelisted"
        else:
            state, details = "ok", ""
        if note == "gateway" and not details:
            details = "gateway"
        elif note and note not in ("gateway",) and not details:
            details = note.strip("()")
        if (whitelist and whitelist.is_whitelisted(d["mac"])
                and not note.startswith("you") and state != "SAFE"):
            details = (details + " " if details else "") + "[whitelisted]"
        if d.get("hint"):
            details = (details + " " if details else "") + f"[{d['hint']}]"
        extra = d.get("vendor") or d.get("hostname") or ""
        if d.get("hostname") and d.get("vendor"):
            extra = f"{d['vendor']} / {d['hostname']}"
        elif d.get("hostname"):
            extra = d["hostname"]
        oslbl = (d.get("os") or "-")[:19]
        print(f"  {i:<3}{d['ip']:<16}{d['mac']:<19}{state:<7}"
              f"{oslbl:<20}{extra[:23]:<24}{details}")


# --------------------------------------------------------------------------- #
# Blocker (cut) — no forwarding, victim traffic just dies.
# NOTE: all ARP packets are sent as L2 frames (Ether dst set) via sendp.
# Sending bare ARP via L3 send() triggers scapy warnings and can put the
# wrong destination on the wire.
# --------------------------------------------------------------------------- #
BROADCAST = "ff:ff:ff:ff:ff:ff"


def arp_reply(dst_mac, victim_ip, claimed_ip, claimed_mac):
    """'claimed_ip is-at claimed_mac' addressed to dst_mac (L2 + L3 correct)."""
    return (Ether(dst=dst_mac) /
            ARP(op="is-at", pdst=victim_ip, hwdst=dst_mac,
                psrc=claimed_ip, hwsrc=claimed_mac))


def send_arp(pkt, iface):
    sendp(pkt, iface=iface, verbose=0)


class Blocker:
    def __init__(self, net: Network, full=False):
        self.net = net
        self.full = full
        self._threads = {}
        self._stops = {}
        self._lock = threading.Lock()
        self.sent = {}    # ip -> forged packets sent (proof the block is live)
        self.since = {}   # ip -> epoch when blocking started

    def _loop(self, ip, mac, stop):
        net = self.net
        victim_pkt = arp_reply(mac, ip, net.gateway_ip, net.my_mac)
        gw_pkt = arp_reply(net.gateway_mac, net.gateway_ip, ip, net.my_mac)
        while not stop.is_set():
            send_arp(victim_pkt, net.iface)
            with self._lock:
                self.sent[ip] = self.sent.get(ip, 0) + 1
            if self.full:
                send_arp(gw_pkt, net.iface)
                with self._lock:
                    self.sent[ip] = self.sent.get(ip, 0) + 1
            stop.wait(SPOOF_INTERVAL)

    def block(self, ip, mac):
        with self._lock:
            if ip in self._threads:
                return False
            stop = threading.Event()
            t = threading.Thread(target=self._loop, args=(ip, mac, stop), daemon=True)
            self._stops[ip] = stop
            self._threads[ip] = t
            self.sent[ip] = 0
            self.since[ip] = time.time()
            t.start()
            return True

    def _restore(self, ip, mac):
        net = self.net
        pkt = arp_reply(mac, ip, net.gateway_ip, net.gateway_mac)
        gw_fix = arp_reply(net.gateway_mac, net.gateway_ip, ip, mac)
        for _ in range(5):
            send_arp(pkt, net.iface)
            if self.full:
                send_arp(gw_fix, net.iface)
            time.sleep(0.2)

    def unblock(self, ip, mac=None):
        with self._lock:
            stop = self._stops.pop(ip, None)
            t = self._threads.pop(ip, None)
        if stop is None:
            return False
        stop.set()
        if t:
            t.join(timeout=SPOOF_INTERVAL + 1)
        if mac:
            self._restore(ip, mac)
        with self._lock:
            self.sent.pop(ip, None)
            self.since.pop(ip, None)
        return True

    def unblock_all(self, known):
        for ip in list(self._threads.keys()):
            self.unblock(ip, known.get(ip))

    @property
    def active(self):
        return list(self._threads.keys())

    def status_lines(self, known):
        """Human-readable lines proving each block is live (packets + uptime)."""
        lines = []
        now = time.time()
        with self._lock:
            items = [(ip, self.sent.get(ip, 0), self.since.get(ip, now))
                     for ip in self._threads]
        for ip, n, t0 in items:
            mac = known.get(ip, "?")
            lines.append(f"  BLOCKED {ip:<16}{mac:<19}{n} spoof pkts, "
                         f"{int(now - t0)}s active")
        return lines


# --------------------------------------------------------------------------- #
# Limiter — duty-cycle chop: online pct% of each window, cut the rest.
# e.g. 20 -> ~20% of normal throughput. Simple, no MITM/tc needed.
# --------------------------------------------------------------------------- #
class Limiter:
    def __init__(self, net: Network):
        self.net = net
        self._threads = {}
        self._stops = {}
        self.pct = {}  # ip -> allowed percent
        self._lock = threading.Lock()
        self.sent = {}
        self.since = {}

    def _loop(self, ip, mac, stop):
        net = self.net
        cut_pkt = arp_reply(mac, ip, net.gateway_ip, net.my_mac)
        fix_pkt = arp_reply(mac, ip, net.gateway_ip, net.gateway_mac)
        while not stop.is_set():
            pct = self.pct.get(ip, 50)
            online = LIMIT_WINDOW * pct / 100.0
            offline = LIMIT_WINDOW - online
            # OFFLINE phase: hammer spoof
            end = time.time() + offline
            while time.time() < end and not stop.is_set():
                send_arp(cut_pkt, net.iface)
                with self._lock:
                    self.sent[ip] = self.sent.get(ip, 0) + 1
                stop.wait(SPOOF_INTERVAL)
            # ONLINE phase: repair once, then leave alone
            if stop.is_set():
                break
            for _ in range(2):
                send_arp(fix_pkt, net.iface)
            stop.wait(max(0, online))

    def limit(self, ip, mac, pct):
        pct = max(1, min(99, int(pct)))
        with self._lock:
            if ip in self._threads:
                self.pct[ip] = pct  # just update rate
                return "updated"
            stop = threading.Event()
            self.pct[ip] = pct
            self.sent[ip] = 0
            self.since[ip] = time.time()
            t = threading.Thread(target=self._loop, args=(ip, mac, stop), daemon=True)
            self._stops[ip] = stop
            self._threads[ip] = t
            t.start()
            return "started"

    def unlimit(self, ip, mac=None):
        with self._lock:
            stop = self._stops.pop(ip, None)
            t = self._threads.pop(ip, None)
            self.pct.pop(ip, None)
            self.sent.pop(ip, None)
            self.since.pop(ip, None)
        if stop is None:
            return False
        stop.set()
        if t:
            t.join(timeout=SPOOF_INTERVAL + 1)
        if mac:  # repair victim ARP
            pkt = arp_reply(mac, ip, self.net.gateway_ip, self.net.gateway_mac)
            for _ in range(3):
                send_arp(pkt, self.net.iface)
        return True

    def unlimit_all(self, known):
        for ip in list(self._threads.keys()):
            self.unlimit(ip, known.get(ip))

    @property
    def active(self):
        return dict(self.pct)

    def status_lines(self, known):
        lines = []
        now = time.time()
        with self._lock:
            items = [(ip, self.pct.get(ip), self.sent.get(ip, 0),
                      self.since.get(ip, now)) for ip in self._threads]
        for ip, pct, n, t0 in items:
            mac = known.get(ip, "?")
            lines.append(f"  LIMITED {ip:<16}{mac:<19}~{pct}% speed, "
                         f"{n} cut pkts, {int(now - t0)}s active")
        return lines


# --------------------------------------------------------------------------- #
# Protector — watch for ARP spoof aimed at us / gateway, auto-repair
# --------------------------------------------------------------------------- #
class Protector:
    def __init__(self, net: Network, autofix=True):
        self.net = net
        self.autofix = autofix
        self._stop = threading.Event()
        self._thread = None
        self.hits = 0

    def _handle(self, pkt):
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
            return
        psrc, hwsrc = pkt[ARP].psrc, pkt[ARP].hwsrc
        # Someone claims to be the gateway but with wrong MAC?
        if psrc == self.net.gateway_ip and hwsrc.lower() != self.net.gateway_mac.lower():
            self.hits += 1
            print(f"\n[!] SPOOF DETECTED: {psrc} claimed by {hwsrc} "
                  f"(real: {self.net.gateway_mac}) [{self.hits}]")
            if self.autofix:
                self.repair()
        # Someone claims to be US?
        elif psrc == self.net.my_ip and hwsrc.lower() != self.net.my_mac.lower():
            self.hits += 1
            print(f"\n[!] SPOOF DETECTED: someone claims YOUR ip {psrc} "
                  f"as {hwsrc} [{self.hits}]")

    def repair(self):
        net = self.net
        # fix OUR table: pin correct gateway MAC
        try:
            subprocess.run(
                ["ip", "neigh", "replace", net.gateway_ip, "lladdr",
                 net.gateway_mac, "dev", net.iface, "nud", "permanent"],
                check=False, capture_output=True, timeout=5,
            )
        except Exception:
            pass
        # broadcast the truth
        fix = arp_reply(BROADCAST, net.gateway_ip,
                        net.gateway_ip, net.gateway_mac)
        for _ in range(3):
            send_arp(fix, net.iface)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        print("[*] protection ON: watching for ARP spoof (gateway + self)")

    def _run(self):
        sniff(iface=self.net.iface, filter="arp",
              prn=self._handle, store=0,
              stop_filter=lambda _: self._stop.is_set())

    def stop(self):
        self._stop.set()
        print(f"[*] protection OFF ({self.hits} attacks seen)")


# --------------------------------------------------------------------------- #
# Lookup helpers (index or IP)
# --------------------------------------------------------------------------- #
def find_device(devices, key):
    key = key.strip()
    if key.isdigit():
        i = int(key)
        return devices[i] if 0 <= i < len(devices) else None
    for d in devices:
        if d["ip"] == key or d["mac"].lower() == key.lower():
            return d
    return None


# --------------------------------------------------------------------------- #
# One-shot CLI + interactive loop
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(description="Netcut-like WiFi manager (own network only)")
    p.add_argument("iface", nargs="?", help="interface (default: auto)")
    p.add_argument("--iface", dest="iface_opt", help="interface (alt spelling)")
    p.add_argument("--scan", action="store_true", help="scan and exit")
    p.add_argument("--block", metavar="IP", help="block IP, then exit (use --time)")
    p.add_argument("--unblock", metavar="IP")
    p.add_argument("--limit", nargs=2, metavar=("IP", "PCT"),
                   help="throttle IP to PCT%% (1-99)")
    p.add_argument("--unlimit", metavar="IP")
    p.add_argument("--protect", action="store_true", help="run ARP guard until Ctrl+C")
    p.add_argument("--time", type=int, default=0, help="seconds for one-shot block/limit (0=forever until Ctrl+C)")
    p.add_argument("--full", action="store_true", help="full isolation (spoof both sides)")
    p.add_argument("--no-names", action="store_true", help="skip reverse-DNS (faster scan)")
    p.add_argument("--no-os", action="store_true", help="skip OS/type guess (faster scan)")
    p.add_argument("--wl-list", action="store_true", help="show whitelist and exit")
    p.add_argument("--wl-add", nargs="+", metavar="IP|MAC [label]",
                   help="add device to whitelist (e.g. --wl-add 192.168.68.50 'My phone')")
    p.add_argument("--wl-del", metavar="IP|MAC|label", help="remove from whitelist")
    p.add_argument("--force", action="store_true",
                   help="allow blocking/limiting whitelisted devices (still never self/gateway)")
    p.add_argument("--os-deep", metavar="IP|#",
                   help="nmap OS fingerprint of one device (slow ~15-60s, needs open ports)")
    p.add_argument("--disc", action="store_true",
                   help="UPnP/SSDP discovery: find TVs, consoles, speakers with names")
    p.add_argument("--passes", type=int, default=SCAN_PASSES,
                   help="ARP sweeps per scan, unioned (default 2; raise on big/lossy WiFi)")
    return p.parse_args()


def shutdown(blocker, limiter, known, protector=None):
    print("\n[*] Restoring ARP tables ...")
    blocker.unblock_all(known)
    limiter.unlimit_all(known)
    if protector:
        protector.stop()
    print("[*] Done. Exiting.")


def main():
    args = parse_args()
    if os.geteuid() != 0:
        sys.exit("[!] Need root (raw sockets). Run with sudo:\n"
                 "    sudo ./venv/bin/python levicut.py")
    iface = args.iface_opt or args.iface
    net = Network(iface)
    print(BANNER)
    print(net.summary())
    print("\n[!] Use ONLY on networks you own / are authorized to manage.\n")

    set_ip_forward(False)  # pure cut mode: don't route victim traffic
    blocker = Blocker(net, full=args.full)
    limiter = Limiter(net)
    protector = Protector(net)
    wl = Whitelist()
    cache = DeviceCache()
    devices = []

    def rescan():
        devs = scan(net, cache=cache, passes=args.passes,
                    resolve_names=not args.no_names,
                    detect_os=not args.no_os)
        for d in devs:  # remember last-seen IP for whitelisted MACs
            if wl.is_whitelisted(d["mac"]):
                wl.touch_ip(d["mac"], d["ip"])
        return devs

    def known_map():
        return {d["ip"]: d["mac"] for d in devices}

    def guard(d, action="block"):
        """None if allowed, else refusal message. --force bypasses whitelist only."""
        reason = is_protected_target(d, wl, net)
        if reason is None:
            return None
        if "whitelisted" in reason and args.force and action in ("block", "limit"):
            return None
        return reason

    # ---- whitelist one-shots (no scan needed except --wl-add by IP) ----
    if args.wl_list:
        print("Whitelisted devices (never blocked/limited):")
        print("\n".join(wl.list_lines()))
        print(f"\nYou (always protected): {net.my_ip} ({net.my_mac})")
        return
    if args.wl_del:
        removed = wl.remove(args.wl_del)
        print(f"[+] removed {removed}" if removed else f"[-] not in whitelist: {args.wl_del}")
        return
    if args.wl_add:
        key = args.wl_add[0]
        label = " ".join(args.wl_add[1:]) if len(args.wl_add) > 1 else ""
        mac, ip = None, ""
        if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", key):
            mac = key
        else:  # IP or scan index -> need a scan to resolve MAC
            devices = rescan()
            d = find_device(devices, key)
            if not d:
                sys.exit(f"[!] {key} not found in scan; use a MAC directly")
            mac, ip = d["mac"], d["ip"]
            label = label or d.get("hostname") or d.get("vendor") or ""
        wl.add(mac, label, ip)
        print(f"[+] whitelisted {Whitelist.norm_mac(mac)}" + (f" ('{label}')" if label else ""))
        return

    # ---- one-shot modes ----
    if args.disc:
        print("[*] UPnP/SSDP discovery (~5s) ...")
        print_ssdp(ssdp_discover())
        return
    if args.os_deep:
        devices = rescan()
        d = find_device(devices, args.os_deep)
        if not d:
            sys.exit(f"[!] {args.os_deep} not found in scan")
        print(f"[*] nmap fingerprinting {d['ip']} ({d['mac']}) — may take ~1 min ...")
        print(f"  fast guess: {d.get('os')}")
        print(os_deep(d["ip"]))
        return
    if args.scan and not any([args.block, args.limit]):
        devices = rescan()
        print_devices(devices, whitelist=wl)
        print(f"\nYou (this machine): {net.my_ip} ({net.my_mac}) — always protected, "
              "gateway + whitelisted devices can't be blocked.")
        return
    if args.block:
        devices = rescan()
        d = find_device(devices, args.block)
        if not d:
            sys.exit(f"[!] {args.block} not found in scan")
        reason = guard(d, "block")
        if reason:
            sys.exit(f"[!] refusing to block {d['ip']}: {reason}")
        blocker.block(d["ip"], d["mac"])
        print(f"[+] blocking {d['ip']} ({d['mac']}). Ctrl+C to restore."
              + (f" ({args.time}s)" if args.time else ""))
        try:
            time.sleep(args.time if args.time else 10**9)
        except KeyboardInterrupt:
            pass
        finally:
            shutdown(blocker, limiter, known_map())
        return
    if args.limit:
        ip, pct = args.limit
        devices = rescan()
        d = find_device(devices, ip)
        if not d:
            sys.exit(f"[!] {ip} not found in scan")
        reason = guard(d, "limit")
        if reason:
            sys.exit(f"[!] refusing to limit {d['ip']}: {reason}")
        limiter.limit(d["ip"], d["mac"], pct)
        print(f"[+] limiting {d['ip']} to ~{pct}%. Ctrl+C to restore."
              + (f" ({args.time}s)" if args.time else ""))
        try:
            time.sleep(args.time if args.time else 10**9)
        except KeyboardInterrupt:
            pass
        finally:
            shutdown(blocker, limiter, known_map())
        return
    if args.unblock or args.unlimit:
        # stateless restore: push correct ARP entries (no thread to stop)
        devices = rescan()
        for key in ([args.unblock] if args.unblock else []) + ([args.unlimit] if args.unlimit else []):
            d = find_device(devices, key)
            if d:
                blocker._restore(d["ip"], d["mac"])
                print(f"[+] restore packets sent to {d['ip']}")
            else:
                print(f"[-] {key} not in scan; nothing sent")
        return
    if args.protect:
        protector.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            protector.stop()
        return

    # ---- interactive ----
    def on_signal(*_):
        shutdown(blocker, limiter, known_map(), protector)
        sys.exit(0)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    print("Commands: s)can  l)ist  <n> block  u<n> unblock  a)ll restore")
    print("          limit <n> <pct>  unlimit <n>  p)rotect on/off")
    print("          f)ull-isolation toggle  r)escan  st)atus  q)uit")
    print("          my (show your device+AP)  wl (list safe)  wl add <n> [label]  wl del <n|mac>")
    print("          os <n> (nmap deep-check one device, slow)  disc (find TVs/consoles/speakers)")
    print("Example : limit 3 20   -> device #3 gets ~20% speed")
    print("          wl add 2 'My phone' -> #2 can never be blocked\n")

    protecting = False
    while True:
        try:
            choice = input("levicut> ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "q"
        if not choice:
            continue
        low = choice.lower()

        if low == "q":
            on_signal()
        elif low in ("s", "r", "l", "list"):
            devices = rescan()
            print_devices(devices, set(blocker.active), limiter.active, wl)
        elif low in ("st", "status"):
            known = {d["ip"]: d["mac"] for d in devices} if devices else {}
            bl = blocker.status_lines(known)
            ll = limiter.status_lines(known)
            if not bl and not ll:
                print("  nothing blocked or limited right now.")
            else:
                print("Active actions (packet counts prove the spoof is live):")
                print("\n".join(bl + ll))
            print(f"  full-isolation: {'ON' if blocker.full else 'OFF'}")
        elif low in ("my", "iam", "me", "whoami"):
            print(f"\n  YOU (this machine running levicut):")
            print(f"    ip  : {net.my_ip}")
            print(f"    mac : {net.my_mac}")
            print(f"    iface: {net.iface}")
            if net.ap and net.ap.get("bssid"):
                print(f"    YOUR AP (you connect through here, can't be blocked):")
                print(f"      bssid : {net.ap['bssid']}")
                for k in ("ssid", "signal", "freq"):
                    if net.ap.get(k):
                        print(f"      {k:<6}: {net.ap[k]}")
                if devices:
                    apd = [d for d in devices
                           if d["mac"].lower() == net.ap["bssid"]]
                    if apd:
                        print(f"      scan entry: #{devices.index(apd[0])} "
                              f"({apd[0]['ip']}) — STATUS: YOUR AP")
            else:
                print("    AP    : unknown (wired, or install `iw` to detect WiFi AP)")
            if devices:
                mine = [d for d in devices
                        if d["ip"] == net.my_ip or d["mac"].lower() == net.my_mac.lower()]
                if mine:
                    print(f"    scan entry: #{devices.index(mine[0])} "
                          f"({mine[0]['ip']} / {mine[0]['mac']}) — STATUS: YOU, can't be blocked")
            print("  Whitelisted (your other devices, also safe):")
            print("\n".join(wl.list_lines()))
            print("\n  Tip: wl add <n> 'My phone'  to protect a device.\n")
        elif low in ("wl", "whitelist", "wl list"):
            print("Whitelisted devices (never blocked/limited):")
            print("\n".join(wl.list_lines()))
        elif low.startswith("wl add") or low.startswith("whitelist add"):
            parts = choice.split(None, 3)  # keep label case: wl add 2 My Phone
            if len(parts) < 3:
                print("[?] usage: wl add <n|ip|mac> [label]  (e.g. wl add 2 'My phone')")
                continue
            if not devices:
                # allow MAC directly without a scan
                if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", parts[2]):
                    mac = Whitelist.norm_mac(parts[2])
                    wl.add(mac, parts[3] if len(parts) > 3 else "")
                    print(f"[+] whitelisted {mac}")
                else:
                    print("[!] scan first (press s), or give a MAC directly")
                continue
            d = find_device(devices, parts[2])
            if not d:
                print("[!] bad target")
                continue
            label = parts[3] if len(parts) > 3 else (d.get("hostname") or d.get("vendor") or "")
            wl.add(d["mac"], label, d["ip"])
            print(f"[+] whitelisted {d['mac']} ({d['ip']})" + (f" as '{label}'" if label else ""))
            print_devices(devices, set(blocker.active), limiter.active, wl)
        elif low.startswith("wl del") or low.startswith("whitelist del") or \
                low.startswith("wl rm") or low.startswith("unwl"):
            parts = choice.split()
            key = parts[-1] if len(parts) > 1 and parts[-1] not in ("del", "rm") else None
            if not key:
                print("[?] usage: wl del <n|ip|mac|label>")
                continue
            d = find_device(devices, key) if devices else None
            removed = wl.remove(d["mac"] if d else key)
            print(f"[+] removed {removed}" if removed else f"[-] not in whitelist: {key}")
        elif low.startswith("os ") or low == "os":
            parts = choice.split()
            if len(parts) != 2 or not devices:
                print("[?] usage: os <n|ip>  (scan first; slow nmap fingerprint ~15-60s)")
                continue
            d = find_device(devices, parts[1])
            if not d:
                print("[!] bad target")
                continue
            print(f"[*] fast guess: {d.get('os')} — nmap deep-check, wait ...")
            print(os_deep(d["ip"]))
        elif low in ("disc", "discover", "upnp", "ssdp"):
            print("[*] UPnP/SSDP discovery (~5s) ...")
            print_ssdp(ssdp_discover())
        elif low == "a":
            n1, n2 = len(blocker.active), len(limiter.active)
            blocker.unblock_all(known_map())
            limiter.unlimit_all(known_map())
            print(f"[*] restored {n1 + n2} host(s).")
        elif low == "f":
            blocker.full = not blocker.full
            print(f"[*] full-isolation: {'ON' if blocker.full else 'OFF'}")
        elif low in ("p", "protect"):
            protecting = not protecting
            if protecting:
                protector.start()
            else:
                protector.stop()
        elif low.startswith("limit"):
            parts = low.split()
            if len(parts) != 3:
                print("[?] usage: limit <n|ip> <pct 1-99>  (e.g. limit 2 20)")
                continue
            if not devices:
                print("[!] scan first (press s)")
                continue
            d = find_device(devices, parts[1])
            try:
                pct = int(parts[2])
            except ValueError:
                print("[!] pct must be 1-99")
                continue
            if not d or not 1 <= pct <= 99:
                print("[!] bad target or pct (1-99)")
                continue
            if d["ip"] in blocker.active:
                print("[!] device is BLOCKED; unblock first (u<n>)")
                continue
            force = "!" in parts or "--force" in low
            reason = is_protected_target(d, wl, net)
            if reason and "whitelisted" in reason and force:
                reason = None  # '<n>!' overrides whitelist, never self/gateway
            if reason:
                print(f"[!] refusing to limit {d['ip']}: {reason}")
                continue
            r = limiter.limit(d["ip"], d["mac"], pct)
            print(f"[+] {r}: {d['ip']} -> ~{pct}% speed")
        elif low.startswith("unlimit") or (low.startswith("u") and low[1:].strip().isdigit()):
            # unlimit <key> OR u<n> (unblock + unlimit both)
            key = low.split()[1] if low.startswith("unlimit") else low[1:].strip()
            d = find_device(devices, key) if devices else None
            ip = d["ip"] if d else (key if "." in key else None)
            if not ip:
                print("[!] bad index; scan first")
                continue
            mac = d["mac"] if d else None
            b = blocker.unblock(ip, mac)
            l = limiter.unlimit(ip, mac)
            if not mac:  # unknown mac -> still try broadcast repair via scan resync
                blocker._restore(ip, mac) if False else None
            print(f"[+] {'restored' if (b or l) else 'not managed'}: {ip}")
        elif low.split()[0].isdigit() or low.rstrip("!").strip().isdigit():
            if not devices:
                print("[!] scan first (press s)")
                continue
            force = low.strip().endswith("!")
            d = find_device(devices, low.strip().rstrip("!"))
            if not d:
                print("[!] bad index")
                continue
            reason = is_protected_target(d, wl, net)
            if reason and "whitelisted" in reason and force:
                reason = None  # '<n>!' overrides whitelist, never self/gateway
            if reason:
                print(f"[!] refusing to block {d['ip']}: {reason}")
                continue
            if d["ip"] in limiter.active:
                print("[!] device is LIMITED; unlimit first")
                continue
            ok = blocker.block(d["ip"], d["mac"])
            print(f"[{'!' if ok else '-'}] {'blocking' if ok else 'already blocked'}: "
                  f"{d['ip']} ({d['mac']})")
        else:
            print("[?] s=scan <n>=block(!=force) u<n>=unblock limit <n> <pct> os <n> disc st=status wl add/del my p=protect q=quit")


if __name__ == "__main__":
    main()
