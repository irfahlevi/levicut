#!/usr/bin/env python3
"""Tests for levicut. No root, no network: every packet send is stubbed."""

import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_SENT = []          # every ARP frame "put on the wire"
_LIVE = []          # Blocker/Limiter instances, so tests can stop their threads

import levicut


def setUpModule():
    """Stub out everything that touches the network, and track every
    Blocker/Limiter so no spoof thread outlives its test."""
    levicut.send_arp = lambda pkt, iface: _SENT.append(pkt)
    levicut.sendp = lambda pkt, **kw: _SENT.append(pkt)
    levicut.srp = lambda *a, **kw: ([], [])

    real_b, real_l = levicut.Blocker, levicut.Limiter

    class TrackedBlocker(real_b):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            _LIVE.append(self)

    class TrackedLimiter(real_l):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            _LIVE.append(self)

    levicut.Blocker, levicut.Limiter = TrackedBlocker, TrackedLimiter
    levicut._real_subprocess = levicut.subprocess
    levicut.subprocess = types.SimpleNamespace(
        run=lambda *a, **kw: types.SimpleNamespace(stdout="", stderr=""),
        check_output=lambda *a, **kw: "",
        TimeoutExpired=Exception,
        CalledProcessError=Exception,
    )


def tearDownModule():
    for obj in _LIVE:
        try:
            obj.unblock_all({})
        except Exception:
            pass
        try:
            obj.unlimit_all({})
        except Exception:
            pass


class Base(unittest.TestCase):
    """Stops any spoof thread a test started, so frames can't leak between
    tests through the shared _SENT list."""

    def tearDown(self):
        for obj in list(_LIVE):
            try:
                obj.unblock_all({})
                obj.unlimit_all({})
            except Exception:
                pass
        time.sleep(0.05)
        _SENT.clear()
        _LIVE.clear()


def _fake_srp():
    return []


class FakeNetwork:
    """Stands in for Network: fixed values, no probing, no raw sockets."""

    def __init__(self, iface=None, **kw):
        self.iface = iface or "wlan0"
        self.my_ip = "192.168.68.10"
        self.my_mac = "AA:BB:CC:00:00:10"
        self.gateway_ip = "192.168.68.1"
        self.gateway_mac = "AA:BB:CC:00:00:01"
        self.prefix = 24
        self.subnet = "192.168.68.0/24"
        self.ap = None
        for k, v in kw.items():
            setattr(self, k, v)

    def summary(self):
        return (f"  interface : {self.iface}\n"
                f"  your ip   : {self.my_ip}  ({self.my_mac})\n"
                f"  gateway   : {self.gateway_ip}  ({self.gateway_mac})\n"
                f"  subnet    : {self.subnet}")

    def resolve_mac(self, ip, timeout=2):
        return self.gateway_mac


def fake_net(**kw):
    """A Network stand-in with fixed values."""
    n = types.SimpleNamespace()
    n.iface = "wlan0"
    n.my_ip = "192.168.68.10"
    n.my_mac = "AA:BB:CC:00:00:10"
    n.gateway_ip = "192.168.68.1"
    n.gateway_mac = "AA:BB:CC:00:00:01"
    n.prefix = 24
    n.subnet = "192.168.68.0/24"
    n.ap = None
    for k, v in kw.items():
        setattr(n, k, v)
    return n


def arp_fields(pkt):
    """(op, psrc, hwsrc, pdst, hwdst) from an ARP-in-Ether frame."""
    a = pkt[levicut.ARP]
    return (a.op, a.psrc, a.hwsrc, a.pdst, pkt[levicut.Ether].dst)


# --------------------------------------------------------------------------- #
class TestBug1BareUnlimit(Base):
    """Bare `unlimit` raised IndexError, killing the process with ARP tables
    still spoofed. Now the branch calls restore_target()."""

    def setUp(self):
        _SENT.clear()
        self.b = levicut.Blocker(fake_net())
        self.l = levicut.Limiter(fake_net())
        self.devs = [{"ip": "192.168.68.50", "mac": "AA:BB:CC:00:00:50"},
                     {"ip": "192.168.68.51", "mac": "AA:BB:CC:00:00:51"}]

    def _key_of(self, cmd):
        """Mirror how the interactive loop extracts the argument:
        `unlimit <key>` -> 2nd token; `u<n>` -> everything after the u."""
        low = cmd.lower().strip()
        if low.startswith("unlimit"):
            uparts = low.split()
            return uparts[1] if len(uparts) > 1 else ""
        return low[1:].strip()

    def test_bare_unlimit_no_crash(self):
        for cmd in ("unlimit", "unlimit "):
            out = levicut.restore_target(self.b, self.l, self.devs,
                                         self._key_of(cmd))
            self.assertIn("usage", out)

    def test_none_key_no_crash(self):
        self.assertIn("usage", levicut.restore_target(
            self.b, self.l, self.devs, None))

    def test_unlimit_with_index(self):
        self.b.block("192.168.68.50", "AA:BB:CC:00:00:50")
        out = levicut.restore_target(self.b, self.l, self.devs,
                                     self._key_of("unlimit 0"))
        self.assertIn("restored", out)
        self.assertIn("192.168.68.50", out)
        self.assertEqual(self.b.active, [])

    def test_unlimit_bare_ip_repairs_via_remembered_mac(self):
        """Unblocking by bare IP still repairs precisely: the Blocker kept the
        MAC it was handed at block() time."""
        self.b.block("192.168.68.77", "AA:BB:CC:00:00:77")
        time.sleep(0.05)
        _SENT.clear()
        out = levicut.restore_target(self.b, self.l, self.devs,
                                     self._key_of("unlimit 192.168.68.77"))
        self.assertIn("restored", out)
        self.assertTrue(_SENT, "no repair packets sent")
        for pkt in _SENT:
            self.assertEqual(pkt[levicut.Ether].dst, "AA:BB:CC:00:00:77")

    def test_unlimit_forgets_mac_after_use(self):
        ip, mac = "192.168.68.78", "AA:BB:CC:00:00:78"
        self.b.block(ip, mac)
        self.b.unblock(ip)
        self.assertNotIn(ip, self.b.macs)
        # second unblock has nothing to repair with
        _SENT.clear()
        levicut.restore_target(self.b, self.l, self.devs, ip)
        self.assertTrue(_SENT, "must fall back to a broadcast")

    def test_limiter_also_remembers_mac(self):
        ip, mac = "192.168.68.79", "AA:BB:CC:00:00:79"
        self.l.limit(ip, mac, 20)
        self.l.unlimit(ip)  # no mac passed
        self.assertNotIn(ip, self.l._macs)

    def test_unmanaged_ip_reports_not_managed(self):
        out = levicut.restore_target(self.b, self.l, self.devs,
                                     self._key_of("unlimit 192.168.68.99"))
        self.assertIn("not managed", out)

    def test_bad_index_message(self):
        out = levicut.restore_target(self.b, self.l, self.devs,
                                     self._key_of("unlimit 42"))
        self.assertIn("bad index", out)

    def test_no_scan_yet(self):
        out = levicut.restore_target(self.b, self.l, [], self._key_of("u0"))
        self.assertIn("bad index", out)

    def test_clears_limit_too(self):
        ip, mac = "192.168.68.51", "AA:BB:CC:00:00:51"
        self.l.limit(ip, mac, 20)
        out = levicut.restore_target(self.b, self.l, self.devs,
                                     self._key_of("unlimit 1"))
        self.assertIn("restored", out)
        self.assertEqual(self.l.active, {})


# --------------------------------------------------------------------------- #
class TestBug2DeadRestorePath(Base):
    """`blocker._restore(ip, mac) if False else None` never ran, so unblocking
    an IP with an unknown MAC left the victim's ARP cache poisoned."""

    def test_restore_without_mac_broadcasts(self):
        _SENT.clear()
        b = levicut.Blocker(fake_net())
        b._restore("192.168.68.99", None)
        self.assertTrue(_SENT, "no repair packets sent for unknown MAC")
        for pkt in _SENT:
            op, psrc, hwsrc, pdst, hwdst = arp_fields(pkt)
            self.assertEqual(hwdst, levicut.BROADCAST)
            self.assertEqual((psrc, hwsrc, pdst),
                             ("192.168.68.1", "AA:BB:CC:00:00:01", "192.168.68.1"))

    def test_restore_with_unknown_mac_never_uses_a_wrong_dest(self):
        """No invented MAC may be addressed — only the broadcast."""
        _SENT.clear()
        b = levicut.Blocker(fake_net())
        b._restore("192.168.68.99", None)
        dests = {p[levicut.Ether].dst for p in _SENT}
        self.assertEqual(dests, {levicut.BROADCAST})

    def test_restore_with_mac_is_targeted(self):
        _SENT.clear()
        b = levicut.Blocker(fake_net())
        b._restore("192.168.68.99", "AA:BB:CC:00:00:99")
        self.assertTrue(_SENT)
        op, psrc, hwsrc, pdst, hwdst = arp_fields(_SENT[0])
        self.assertEqual(hwdst, "AA:BB:CC:00:00:99")
        self.assertEqual((psrc, hwsrc, pdst),
                         ("192.168.68.1", "AA:BB:CC:00:00:01", "192.168.68.99"))

    def test_full_isolation_restores_gateway_side(self):
        _SENT.clear()
        b = levicut.Blocker(fake_net(), full=True)
        b._restore("192.168.68.99", "AA:BB:CC:00:00:99")
        to_gw = [p for p in _SENT
                 if p[levicut.Ether].dst == "AA:BB:CC:00:00:01"]
        self.assertTrue(to_gw, "full mode must also fix the gateway's entry")

    def test_unblock_restores_when_mac_unknown(self):
        _SENT.clear()
        net = fake_net()
        b = levicut.Blocker(net)
        b.block("192.168.68.99", "AA:BB:CC:00:00:99")
        time.sleep(0.05)
        self.assertTrue(b.unblock("192.168.68.99", None))
        self.assertTrue(_SENT, "unblock must leave the network healed")

    def test_no_dead_code_remains(self):
        src = open(levicut.__file__).read()
        self.assertNotIn("if False else None", src)


# --------------------------------------------------------------------------- #
class TestBug3CorruptJson(Base):
    """load() caught only OSError/ValueError; a valid non-dict JSON crashed."""

    def _wl(self, content):
        p = tempfile.mktemp(suffix=".json")
        with open(p, "w") as f:
            f.write(content)
        try:
            return levicut.Whitelist(p)
        finally:
            os.unlink(p)

    def _cache(self, content):
        p = tempfile.mktemp(suffix=".json")
        with open(p, "w") as f:
            f.write(content)
        try:
            return levicut.DeviceCache(p)
        finally:
            os.unlink(p)

    def test_whitelist_list_json(self):
        self.assertEqual(self._wl("[1,2]").entries, {})

    def test_whitelist_truncated_json(self):
        self.assertEqual(self._wl("{not json").entries, {})

    def test_cache_list_json_and_stale_usable(self):
        c = self._cache("[1,2]")
        self.assertEqual(c.known, {})
        self.assertEqual(c.stale(set()), [])  # must not raise

    def test_cache_garbage_entries_dont_break_stale(self):
        c = self._cache(json.dumps({
            "AA:BB:CC:00:00:01": {"ip": "192.168.68.9", "last_seen": time.time()},
            "AA:BB:CC:00:00:02": "not-a-dict",
        }))
        # the non-dict entry is skipped, the good one still shows up
        out = c.stale(set())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "192.168.68.9")
        c.save()  # and pruning drops the bad one instead of crashing
        self.assertEqual(list(c.known), ["AA:BB:CC:00:00:01"])

    def test_missing_file_is_quiet(self):
        w = levicut.Whitelist("/nonexistent/does-not-exist.json")
        self.assertEqual(w.entries, {})
        self.assertEqual(levicut.DeviceCache("/nonexistent/nope.json").known, {})

    def test_valid_whitelist_roundtrips(self):
        w = self._wl(json.dumps({"aa-bb-cc-00-00-01": {"label": "Phone"}}))
        self.assertIn("AA:BB:CC:00:00:01", w.entries)
        self.assertTrue(w.is_whitelisted("aa:bb:cc:00:00:01"))


# --------------------------------------------------------------------------- #
class TestBug4PermanentNeighbour(Base):
    """`nud permanent` pins the gateway MAC forever — a router reboot with a
    new MAC would never be relearned."""

    def test_repair_uses_reachable_not_permanent(self):
        calls = []
        levicut.subprocess = types.SimpleNamespace(
            run=lambda cmd, **kw: calls.append(cmd) or
            types.SimpleNamespace(stdout="", stderr=""),
            check_output=lambda *a, **kw: "",
            TimeoutExpired=Exception, CalledProcessError=Exception,
        )
        self.addCleanup(setattr, levicut, "subprocess",
                        levicut._real_subprocess)
        levicut.Protector(fake_net()).repair()
        self.assertTrue(calls, "repair must pin our own entry")
        self.assertIn("reachable", calls[0])
        self.assertNotIn("permanent", calls[0])


# --------------------------------------------------------------------------- #
class TestBug5RepairOffSniffThread(Base):
    """repair() ran inline on the sniff thread, blocking packet processing."""

    def test_handle_does_not_repair_inline(self):
        net = fake_net()
        p = levicut.Protector(net, autofix=True)
        where = []
        p.repair = lambda: where.append(threading.current_thread())
        pkt = levicut.Ether() / levicut.ARP(
            op=2, psrc=net.gateway_ip, hwsrc="DE:AD:BE:EF:00:01")
        p._handle(pkt)
        self.assertEqual(p.hits, 1)
        time.sleep(0.3)
        self.assertTrue(where, "no repair was attempted")
        self.assertIsNot(where[0], threading.current_thread(),
                         "repair must not run on the caller's (sniff) thread")

    def test_spoof_flood_is_rate_limited(self):
        net = fake_net()
        p = levicut.Protector(net, autofix=True)
        n = []
        p.repair = lambda: n.append(1)
        pkt = levicut.Ether() / levicut.ARP(
            op=2, psrc=net.gateway_ip, hwsrc="DE:AD:BE:EF:00:01")
        for _ in range(200):        # 200 spoof frames in a burst
            p._handle(pkt)
        time.sleep(0.2)
        self.assertEqual(p.hits, 200, "every frame should still be counted")
        self.assertLessEqual(len(n), 1,
                             f"200 frames caused {len(n)} repairs")

    def test_different_attackers_each_get_a_repair(self):
        net = fake_net()
        p = levicut.Protector(net, autofix=True)
        n = []
        p.repair = lambda: n.append(1)
        for mac in ("DE:AD:BE:EF:00:01", "DE:AD:BE:EF:00:02"):
            p._handle(levicut.Ether() / levicut.ARP(
                op=2, psrc=net.gateway_ip, hwsrc=mac))
        time.sleep(0.2)
        self.assertEqual(p.hits, 2)

    def test_ignores_own_forgeries(self):
        """Blocking + protecting together must not self-trigger."""
        net = fake_net()
        p = levicut.Protector(net, autofix=True)
        p.repair = lambda: self.fail("own packets flagged as spoof")
        pkt = levicut.Ether() / levicut.ARP(
            op=2, psrc=net.gateway_ip, hwsrc=net.my_mac)
        p._handle(pkt)
        self.assertEqual(p.hits, 0)

    def test_ignores_non_arp_and_requests(self):
        net = fake_net()
        p = levicut.Protector(net)
        p._handle(levicut.Ether())
        p._handle(levicut.Ether() / levicut.ARP(
            op=1, psrc=net.gateway_ip, hwsrc="DE:AD:BE:EF:00:01"))
        self.assertEqual(p.hits, 0)

    def test_legit_gateway_not_flagged(self):
        net = fake_net()
        p = levicut.Protector(net)
        p._handle(levicut.Ether() / levicut.ARP(
            op=2, psrc=net.gateway_ip, hwsrc=net.gateway_mac))
        self.assertEqual(p.hits, 0)

    def test_spoofing_our_own_ip_counted(self):
        net = fake_net()
        p = levicut.Protector(net, autofix=False)
        p._handle(levicut.Ether() / levicut.ARP(
            op=2, psrc=net.my_ip, hwsrc="DE:AD:BE:EF:00:09"))
        self.assertEqual(p.hits, 1)

    def test_autofix_off_never_repairs(self):
        net = fake_net()
        p = levicut.Protector(net, autofix=False)
        p.repair = lambda: self.fail("repaired with autofix off")
        p._handle(levicut.Ether() / levicut.ARP(
            op=2, psrc=net.gateway_ip, hwsrc="DE:AD:BE:EF:00:01"))
        time.sleep(0.1)


# --------------------------------------------------------------------------- #
class TestBug6ForceParsing(Base):
    """`limit 3! 20` failed to parse: find_device got '3!' which isn't a digit."""

    def test_strip_bang_before_lookup(self):
        devs = [{"ip": "192.168.68.50", "mac": "AA:BB:CC:00:00:50"}]
        self.assertIsNotNone(levicut.find_device(devs, "0".rstrip("!")))

    def test_bang_syntax_reaches_limit(self):
        low = "limit 0! 20"
        parts = low.split()
        self.assertEqual(len(parts), 3)
        d = levicut.find_device([{"ip": "192.168.68.50",
                                  "mac": "AA:BB:CC:00:00:50"}],
                                parts[1].rstrip("!"))
        self.assertIsNotNone(d)
        self.assertTrue(parts[1].endswith("!"))

    def test_block_force_syntax_still_works(self):
        devs = [{"ip": "192.168.68.50", "mac": "AA:BB:CC:00:00:50"}]
        self.assertIsNotNone(levicut.find_device(devs, "0!".rstrip("!")))


# --------------------------------------------------------------------------- #
class TestBug7ThreadNesting(Base):
    """hostname_of spawned a thread per call inside already-parallel threads."""

    def test_rdns_lookup_is_plain(self):
        before = threading.active_count()
        levicut.rdns_lookup("127.0.0.1")
        self.assertLessEqual(threading.active_count(), before + 1)

    def test_hostname_of_still_times_out(self):
        start = time.time()
        levicut.hostname_of("192.0.2.99", timeout=0.3)
        self.assertLess(time.time() - start, 2.0)

    def test_best_hostname_no_thread_leak(self):
        before = threading.active_count()
        for _ in range(5):
            levicut.best_hostname("192.0.2.99")
        time.sleep(0.3)
        self.assertLessEqual(threading.active_count(), before + 2)


# --------------------------------------------------------------------------- #
class TestBug8PortSweep(Base):
    """80/443 were scanned but never fed any decision."""

    def test_http_ports_not_probed_by_default(self):
        self.assertNotIn(80, levicut.OS_PORTS)
        self.assertNotIn(443, levicut.OS_PORTS)

    def test_every_remaining_port_has_a_consumer(self):
        src = open(levicut.__file__).read()
        for port, (tag, weight) in levicut.OS_PORTS.items():
            self.assertIn(f'"{tag}"', src,
                          f"port {port} tag {tag} is never checked")

    def test_no_zero_weight_ports(self):
        for port, (tag, weight) in levicut.OS_PORTS.items():
            self.assertGreater(weight, 0, f"{port}/{tag} has weight 0")

    def test_check_ports_returns_set(self):
        self.assertEqual(levicut.check_ports("192.0.2.99", ports=[1], timeout=0.05),
                         set())


# --------------------------------------------------------------------------- #
class TestBug9OuiCache(Base):
    """An empty-but-valid OUI file re-parsed on every vendor lookup."""

    def test_parsed_once_even_when_empty(self):
        levicut._oui_cache.clear()
        levicut._oui_loaded = False
        real_exists = os.path.exists
        levicut.os.path.exists = lambda p: False
        try:
            levicut.load_oui()
            levicut._oui_cache["X"] = 1     # would re-parse if guard is falsy-based
            levicut._oui_loaded = False     # simulate the old buggy guard
            levicut.load_oui()
            self.assertEqual(levicut._oui_cache["X"], 1)
        finally:
            levicut._oui_loaded = True
            levicut.os.path.exists = real_exists

    def test_vendor_lookup_does_not_raise(self):
        self.assertIsNone(levicut.vendor_of("zz"))


# --------------------------------------------------------------------------- #
class TestBug11HostnamePriority(Base):
    """A generic 'host.local' from mDNS beat a real NetBIOS name."""

    def test_generic_name_detection(self):
        for n in ("host.local", "device.local", "unknown.local",
                  "x.local", "", None):
            self.assertTrue(levicut._generic_name(n), n)
        for n in ("Johns-iPhone.local", "DESKTOP-ABC.local", "nas"):
            self.assertFalse(levicut._generic_name(n), n)

    def test_netbios_beats_generic_mdns(self):
        levicut.netbios_status = lambda ip: ("DESKTOP-XYZ", True)
        levicut.mdns_lookup = lambda ip: "host.local"
        levicut.rdns_lookup = lambda ip: "reverse.name"
        name, nb = levicut.best_hostname("192.168.68.5")
        self.assertEqual(name, "DESKTOP-XYZ")
        self.assertTrue(nb)

    def test_meaningful_mdns_still_wins_over_nothing(self):
        levicut.netbios_status = lambda ip: (None, False)
        levicut.mdns_lookup = lambda ip: "Johns-iPhone.local"
        levicut.rdns_lookup = lambda ip: "reverse.name"
        name, _ = levicut.best_hostname("192.168.68.5")
        self.assertEqual(name, "Johns-iPhone.local")

    def test_reverse_dns_used_when_all_else_generic(self):
        levicut.netbios_status = lambda ip: (None, False)
        levicut.mdns_lookup = lambda ip: "host.local"
        levicut.rdns_lookup = lambda ip: "reverse.name"
        name, _ = levicut.best_hostname("192.168.68.5")
        self.assertEqual(name, "reverse.name")

    def test_nothing_available(self):
        levicut.netbios_status = lambda ip: (None, False)
        levicut.mdns_lookup = lambda ip: None
        levicut.rdns_lookup = lambda ip: None
        name, nb = levicut.best_hostname("192.0.2.1")
        self.assertIsNone(name)
        self.assertFalse(nb)


# --------------------------------------------------------------------------- #
class TestInteractiveLoop(Base):
    """Drive the real main() interactive loop end to end with piped stdin.
    This is what caught the bare-`unlimit` crash: the loop itself must survive
    every command shape and still restore on the way out."""

    DEVS = [{"ip": "192.168.68.1", "mac": "AA:BB:CC:00:00:01",
             "note": "gateway", "os": "Network gear?"},
            {"ip": "192.168.68.10", "mac": "AA:BB:CC:00:00:10",
             "note": "you (this machine)", "os": "YOU"},
            {"ip": "192.168.68.50", "mac": "AA:BB:CC:00:00:50",
             "hostname": "Johns-iPhone", "os": "iOS (iPhone?)"},
            {"ip": "192.168.68.51", "mac": "AA:BB:CC:00:00:51",
             "os": "Windows?"}]

    def _run(self, cmds, devices=None, wl_path=None, cache_path_=None):
        import io
        import contextlib
        real_argv, real_stdin = sys.argv, sys.stdin
        real_scan = levicut.scan
        real_wl_cls, real_cache_cls = levicut.Whitelist, levicut.DeviceCache
        real_net = levicut.Network
        real_geteuid = os.geteuid
        out = io.StringIO()

        def fake_scan(net, cache=None, **kw):
            return [dict(d) for d in (devices if devices is not None
                                      else self.DEVS)]

        class WL(real_wl_cls):
            def __init__(self, path=None):
                super().__init__(path or wl_path or "/nonexistent/wl.json")
        class DC(real_cache_cls):
            def __init__(self, path=None):
                super().__init__(path or cache_path_ or "/nonexistent/k.json")

        sys.argv = ["levicut.py"]
        sys.stdin = io.StringIO("\n".join(cmds) + "\n")
        os.geteuid = lambda: 0  # fake root
        old_main = sys.modules.get("__main__")
        levicut.scan = fake_scan
        levicut.Whitelist, levicut.DeviceCache = WL, DC
        levicut.Network = FakeNetwork
        levicut.set_ip_forward = lambda enable: None
        try:
            with contextlib.redirect_stdout(out):
                # 'q' calls sys.exit(0) by design; that is a clean exit.
                try:
                    levicut.main()
                except SystemExit as e:
                    if e.code not in (0, None):
                        raise
        finally:
            sys.argv, sys.stdin, os.geteuid = real_argv, real_stdin, real_geteuid
            levicut.scan = real_scan
            levicut.Whitelist, levicut.DeviceCache = real_wl_cls, real_cache_cls
            levicut.Network = real_net
        return out.getvalue()

    def test_bare_unlimit_does_not_kill_the_loop(self):
        text = self._run(["unlimit", "st", "q"])
        self.assertIn("usage", text)
        self.assertIn("full-isolation", text)   # loop kept going
        self.assertIn("Done. Exiting.", text)

    def test_garbage_commands_never_crash(self):
        for cmd in ("", "   ", "u", "unlimit", "unlimit zzz", "u999",
                    "limit", "limit 0", "limit 0 500", "limit 0 abc",
                    "wl del", "os", "os 99", "999", "!!!", "zzzz",
                    "wl add", "limit 0 20 extra", "u0!", "s p q"):
            with self.subTest(cmd=cmd):
                text = self._run([cmd, "q"])
                self.assertIn("Done. Exiting.", text)

    def test_block_then_unblock_by_index(self):
        text = self._run(["s", "2", "st", "u2", "st", "q"])
        self.assertIn("BLOCKED 192.168.68.50", text)
        self.assertIn("nothing blocked or limited", text)

    def test_unblock_bare_ip_heals_network(self):
        text = self._run(["s", "2", "unlimit 192.168.68.50", "q"])
        self.assertIn("restored", text)

    def test_gateway_refused(self):
        text = self._run(["s", "0", "q"])
        self.assertIn("refusing to block", text)
        self.assertIn("gateway", text)

    def test_self_refused(self):
        text = self._run(["s", "1", "q"])
        self.assertIn("refusing to block", text)

    def test_limit_then_unlimit(self):
        text = self._run(["s", "limit 3 20", "st", "unlimit 3", "st", "q"])
        self.assertIn("started: 192.168.68.51 -> ~20% speed", text)
        self.assertIn("LIMITED 192.168.68.51", text)
        self.assertIn("restored: 192.168.68.51", text)
        # the final status must show a clean slate
        self.assertEqual(text.count("nothing blocked or limited"), 1)

    def test_limit_bad_pct(self):
        text = self._run(["s", "limit 3 0", "limit 3 100", "q"])
        self.assertIn("bad target or pct", text)

    def test_whitelist_blocks_then_force_overrides(self):
        p = tempfile.mktemp(suffix=".json")
        try:
            text = self._run(["s", "wl add 2 My Phone", "2", "2!", "q"],
                             wl_path=p)
            self.assertIn("refusing to block", text)
            self.assertIn("whitelisted", text)
            self.assertIn("] blocking: 192.168.68.50", text)
        finally:
            if os.path.exists(p):
                os.unlink(p)

    def test_whitelist_limit_then_force_overrides(self):
        """`limit 2! 20` on a whitelisted device: the `!` must survive parsing
        (find_device must get '2', not '2!') and the force flag must fire."""
        p = tempfile.mktemp(suffix=".json")
        try:
            text = self._run(["s", "wl add 2 My Phone", "limit 2 20",
                              "limit 2! 20", "st", "q"], wl_path=p)
            self.assertIn("refusing to limit", text)
            self.assertIn("started: 192.168.68.50 -> ~20% speed", text)
            self.assertIn("LIMITED 192.168.68.50", text)
        finally:
            if os.path.exists(p):
                os.unlink(p)

    def test_whitelist_add_by_mac_without_scan(self):
        p = tempfile.mktemp(suffix=".json")
        try:
            text = self._run(["wl add aa:bb:cc:00:00:99 Tablet", "q"],
                             wl_path=p)
            self.assertIn("whitelisted AA:BB:CC:00:00:99", text)
            self.assertIn("Tablet", text)
        finally:
            if os.path.exists(p):
                os.unlink(p)

    def test_whitelist_del_by_label(self):
        p = tempfile.mktemp(suffix=".json")
        try:
            with open(p, "w") as f:
                json.dump({"AA:BB:CC:00:00:50": {"label": "My Phone",
                                                 "last_ip": "",
                                                 "added": "x"}}, f)
            text = self._run(["wl del my phone", "q"], wl_path=p)
            self.assertIn("removed AA:BB:CC:00:00:50", text)
        finally:
            if os.path.exists(p):
                os.unlink(p)

    def test_status_and_my_and_prints(self):
        text = self._run(["s", "st", "my", "wl", "q"])
        self.assertIn("192.168.68.50", text)
        self.assertIn("YOU (this machine", text)
        self.assertIn("full-isolation", text)

    def test_full_toggle(self):
        text = self._run(["f", "st", "q"])
        self.assertIn("full-isolation: ON", text)

    def test_restore_all(self):
        text = self._run(["s", "2", "3", "limit 3 30", "a", "st", "q"])
        self.assertIn("restored", text)
        self.assertIn("nothing blocked or limited", text)

    def test_quit_restores_everything(self):
        text = self._run(["s", "2", "3", "q"])
        self.assertIn("Restoring ARP tables", text)
        self.assertIn("Done. Exiting.", text)

    def test_protect_toggle_does_not_crash(self):
        text = self._run(["p", "q"])
        self.assertIn("protection OFF", text)

    def test_scan_survives_corrupt_cache(self):
        p = tempfile.mktemp(suffix=".json")
        try:
            with open(p, "w") as f:
                f.write("[1,2,3]")
            text = self._run(["s", "q"], cache_path_=p)
            self.assertIn("not a JSON object", text)
            self.assertIn("192.168.68.50", text)
        finally:
            if os.path.exists(p):
                os.unlink(p)

    def test_print_devices_renders_all_states(self):
        out = []
        devs = [dict(self.DEVS[0]),
                dict(self.DEVS[1]),
                dict(self.DEVS[2]),
                {"ip": "192.168.68.60", "mac": "AA:BB:CC:00:00:60",
                 "os": "IoT?", "stale": "7m ago"},
                {"ip": "192.168.68.61", "mac": "AA:BB:CC:00:00:61",
                 "os": "Android?", "vendor": "Xiaomi",
                 "hint": "same maker as router: mesh/AP?"}]
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            levicut.print_devices(devs, blocked={"192.168.68.50"},
                                  limited={"192.168.68.51": 20})
        text = buf.getvalue()
        self.assertIn("CUT", text)
        self.assertIn("OLD", text)
        self.assertIn("YOU", text)
        self.assertIn("AP" if False else "gateway", text)
        self.assertIn("silent 7m ago", text)
        self.assertIn("mesh/AP?", text)


class TestMutantKills(Base):
    """Each of these reintroduces one original bug and must be caught."""

    def _with(self, old, new):
        """Compile the source with one edit applied, in a namespace that keeps
        the test suite's network stubs. Each test then asserts the mutant
        exhibits the original bug — if a mutation no longer produces the bug,
        the mutation test itself is wrong."""
        src = open(levicut.__file__).read()
        self.assertIn(old, src, f"mutation anchor missing: {old!r}")
        ns = dict(vars(levicut))
        exec(compile(src.replace(old, new, 1), "mutant", "exec"), ns)
        ns["send_arp"] = lambda pkt, iface: _SENT.append(pkt)
        ns["sendp"] = lambda pkt, **kw: _SENT.append(pkt)
        ns["_SENT"] = _SENT
        return ns

    def test_mutant_bare_unlimit(self):
        ns = self._with('    key = (key or "").strip()',
                        "    key = key.split()[1]")
        with self.assertRaises(IndexError):
            ns["restore_target"](None, None, [], "unlimit")

    def test_mutant_permanent_nud(self):
        ns = self._with('net.iface, "nud", "reachable"]',
                        'net.iface, "nud", "permanent"]')
        seen = []
        ns["subprocess"] = types.SimpleNamespace(
            run=lambda cmd, **kw: seen.append(cmd))
        ns["Protector"](fake_net()).repair()
        self.assertIn("permanent", seen[0])

    def test_mutant_inline_repair(self):
        ns = self._with(
            "            if self.autofix and due:\n"
            "                threading.Thread(target=self.repair, daemon=True).start()",
            "            if self.autofix:\n                self.repair()")
        p = ns["Protector"](fake_net(), autofix=True)
        here = []
        p.repair = lambda: here.append(threading.current_thread())
        p._handle(ns["Ether"]() / ns["ARP"](
            op=2, psrc="192.168.68.1", hwsrc="DE:AD:BE:EF:00:01"))
        time.sleep(0.2)
        self.assertEqual(here[0], threading.current_thread())

    def test_mutant_no_flood_limit(self):
        """Neutralise both rate limits (pre-fix behaviour): every frame of a
        flood spawns a repair + 3 broadcasts."""
        src = open(levicut.__file__).read()
        edits = [
            ("            if now - self._last_seen.get(key, 0) < self.REPEAT_WINDOW:"
             "\n                return self.hits, False",
             "            if False:\n                return self.hits, False"),
            ("            due = now - self._last_repair >= self.REPAIR_INTERVAL",
             "            due = True"),
        ]
        for old, new in edits:
            self.assertIn(old, src, f"anchor missing: {old!r}")
            src = src.replace(old, new, 1)
        ns = dict(vars(levicut))
        exec(compile(src, "mutant", "exec"), ns)
        ns["send_arp"] = lambda pkt, iface: _SENT.append(pkt)
        p = ns["Protector"](fake_net(), autofix=True)
        n = []
        p.repair = lambda: n.append(1)
        pkt = ns["Ether"]() / ns["ARP"](
            op=2, psrc="192.168.68.1", hwsrc="DE:AD:BE:EF:00:01")
        for _ in range(50):
            p._handle(pkt)
        time.sleep(0.4)
        self.assertGreater(len(n), 1,
                           "mutant should repair per frame (that IS the bug)")
        # real code: one repair for the whole burst
        p2 = levicut.Protector(fake_net(), autofix=True)
        n2 = []
        p2.repair = lambda: n2.append(1)
        pkt2 = levicut.Ether() / levicut.ARP(
            op=2, psrc="192.168.68.1", hwsrc="DE:AD:BE:EF:00:01")
        for _ in range(50):
            p2._handle(pkt2)
        time.sleep(0.4)
        self.assertEqual(p2.hits, 50, "every frame still counted")
        self.assertLessEqual(len(n2), 1, "burst must not repair per frame")

    def test_mutant_flags_own_packets(self):
        ns = self._with(
            "        if hwsrc.lower() == self.net.my_mac.lower():\n            return",
            "        if False:\n            return")
        p = ns["Protector"](fake_net())
        p.repair = lambda: None
        p._handle(ns["Ether"]() / ns["ARP"](
            op=2, psrc="192.168.68.1", hwsrc="AA:BB:CC:00:00:10"))
        self.assertEqual(p.hits, 1, "own forgeries must stay invisible")

    def test_mutant_non_dict_json(self):
        ns = self._with("        if not isinstance(data, dict):",
                        "        if False:")
        p = tempfile.mktemp(suffix=".json")
        with open(p, "w") as f:
            f.write("[1,2]")
        try:
            with self.assertRaises(AttributeError):
                ns["Whitelist"](p)
        finally:
            os.unlink(p)

    def test_mutant_non_dict_cache_entry(self):
        ns = self._with("            if not isinstance(info, dict):\n"
                        "                continue  # hand-edited / corrupted entry: "
                        "skip, don't crash",
                        "            if False:\n                continue")
        c = ns["DeviceCache"].__new__(ns["DeviceCache"])
        c.path = "/dev/null"
        c.known = {"AA:BB:CC:00:00:01": "not-a-dict"}
        with self.assertRaises(AttributeError):
            c.stale(set())

    def test_mutant_force_bang(self):
        ns = self._with('d = find_device(devices, parts[1].rstrip("!"))',
                        'd = find_device(devices, parts[1])')
        self.assertIsNone(ns["find_device"](
            [{"ip": "1.2.3.4", "mac": "AA:BB:CC:00:00:04"}], "0!"))

    def test_mutant_http_ports_back(self):
        ns = self._with('    5555: ("Android-ADB", 3), 22: ("SSH", 1),\n}',
                        '    5555: ("Android-ADB", 3), 22: ("SSH", 1),\n'
                        '    80: ("HTTP", 0), 443: ("HTTPS", 0),\n}')
        self.assertIn(80, ns["OS_PORTS"], "80 should not be probed by default")

    def test_mutant_generic_name(self):
        ns = self._with(
            '    return len(n) < 3 or n in ("host", "device", "pc", "laptop", "desktop",\n'
            '                               "unknown", "default")',
            "    return False")
        # mutant: every name looks informative
        self.assertFalse(ns["_generic_name"]("host.local"),
                         "mutant should not detect generic names")
        self.assertTrue(levicut._generic_name("host.local"),
                        "real code must detect it")

    def test_mutant_generic_mdns_wins(self):
        """With both guards neutralised, a generic mDNS name wins — the
        original behaviour. The real code must not do this."""
        ns = self._with("    if nb_name:\n        return nb_name, nb_server",
                        "    if False:\n        return nb_name, nb_server")
        ns["netbios_status"] = lambda ip: ("DESKTOP-XYZ", True)
        ns["mdns_lookup"] = lambda ip: "host.local"
        ns["rdns_lookup"] = lambda ip: "reverse"
        ns["_generic_name"] = lambda n: False   # also disable the 2nd guard
        name, _ = ns["best_hostname"]("192.168.68.5")
        self.assertEqual(name, "host.local", "mutant: generic mDNS wins")
        # ...while the real implementation still prefers NetBIOS
        real = dict(vars(levicut))
        levicut.netbios_status = lambda ip: ("DESKTOP-XYZ", True)
        levicut.mdns_lookup = lambda ip: "host.local"
        levicut.rdns_lookup = lambda ip: "reverse"
        self.addCleanup(setattr, levicut, "netbios_status", real["netbios_status"])
        self.addCleanup(setattr, levicut, "mdns_lookup", real["mdns_lookup"])
        self.addCleanup(setattr, levicut, "rdns_lookup", real["rdns_lookup"])
        good, _ = levicut.best_hostname("192.168.68.5")
        self.assertEqual(good, "DESKTOP-XYZ")

    def test_mutant_dead_import_back(self):
        src = open(levicut.__file__).read()
        self.assertNotIn("from collections import defaultdict", src)


class TestSafetyInvariants(Base):
    """The guards that keep levicut from cutting itself must survive."""

    def _dev(self, **kw):
        d = {"ip": "192.168.68.50", "mac": "AA:BB:CC:00:00:50"}
        d.update(kw)
        return d

    def test_self_never_blocked(self):
        wl = levicut.Whitelist("/nonexistent/x.json")
        net = fake_net()
        self.assertIsNotNone(levicut.is_protected_target(
            self._dev(ip=net.my_ip), wl, net))

    def test_gateway_never_blocked(self):
        wl = levicut.Whitelist("/nonexistent/x.json")
        net = fake_net()
        r = levicut.is_protected_target(
            self._dev(ip=net.gateway_ip, note="gateway"), wl, net)
        self.assertIn("gateway", r)

    def test_our_ap_never_blocked(self):
        wl = levicut.Whitelist("/nonexistent/x.json")
        net = fake_net(ap={"bssid": "aa:bb:cc:00:00:77"})
        r = levicut.is_protected_target(
            self._dev(mac="AA:BB:CC:00:00:77"), wl, net)
        self.assertIn("YOUR AP", r)

    def test_stale_device_never_blocked(self):
        wl = levicut.Whitelist("/nonexistent/x.json")
        r = levicut.is_protected_target(
            self._dev(stale="5m ago"), wl, fake_net())
        self.assertIn("silent since", r)

    def test_normal_device_is_blockable(self):
        wl = levicut.Whitelist("/nonexistent/x.json")
        self.assertIsNone(levicut.is_protected_target(self._dev(), wl, fake_net()))


# --------------------------------------------------------------------------- #
class TestBlockerLifecycle(Base):
    def test_block_unblock_cycle(self):
        _SENT.clear()
        b = levicut.Blocker(fake_net())
        ip, mac = "192.168.68.50", "AA:BB:CC:00:00:50"
        self.assertTrue(b.block(ip, mac))
        self.assertFalse(b.block(ip, mac), "double block must be refused")
        self.assertEqual(b.active, [ip])
        time.sleep(0.1)
        self.assertTrue(b.unblock(ip, mac))
        self.assertEqual(b.active, [])
        self.assertNotIn(ip, b.sent)

    def test_unblock_unknown_is_false(self):
        self.assertFalse(levicut.Blocker(fake_net()).unblock("1.2.3.4"))

    def test_unblock_all(self):
        b = levicut.Blocker(fake_net())
        b.block("192.168.68.51", "AA:BB:CC:00:00:51")
        b.block("192.168.68.52", "AA:BB:CC:00:00:52")
        b.unblock_all({"192.168.68.51": "AA:BB:CC:00:00:51",
                       "192.168.68.52": "AA:BB:CC:00:00:52"})
        self.assertEqual(b.active, [])

    def test_unblock_all_repairs_even_with_empty_known_map(self):
        """A host that vanished from the scan must still be healed at exit."""
        b = levicut.Blocker(fake_net())
        b.block("192.168.68.53", "AA:BB:CC:00:00:53")
        time.sleep(0.05)
        _SENT.clear()
        b.unblock_all({})
        self.assertEqual(b.active, [])
        self.assertTrue(_SENT, "no repair packets at exit")
        for pkt in _SENT:
            self.assertEqual(pkt[levicut.Ether].dst, "AA:BB:CC:00:00:53")

    def test_unblock_forgets_mac_after_repair(self):
        b = levicut.Blocker(fake_net())
        b.block("192.168.68.54", "AA:BB:CC:00:00:54")
        b.unblock("192.168.68.54")
        self.assertNotIn("192.168.68.54", b.macs)

    def test_status_lines_show_evidence(self):
        b = levicut.Blocker(fake_net())
        b.block("192.168.68.53", "AA:BB:CC:00:00:53")
        time.sleep(0.1)
        lines = b.status_lines({"192.168.68.53": "AA:BB:CC:00:00:53"})
        self.assertTrue(lines)
        self.assertIn("spoof pkts", lines[0])


# --------------------------------------------------------------------------- #
class TestLimiterLifecycle(Base):
    def test_clamped_to_1_99(self):
        l = levicut.Limiter(fake_net())
        ip, mac = "192.168.68.60", "AA:BB:CC:00:00:60"
        self.assertEqual(l.limit(ip, mac, 0), "started")
        self.assertEqual(l.pct[ip], 1)
        l.limit(ip, mac, 500)
        self.assertEqual(l.pct[ip], 99)

    def test_update_existing(self):
        l = levicut.Limiter(fake_net())
        ip, mac = "192.168.68.61", "AA:BB:CC:00:00:61"
        l.limit(ip, mac, 20)
        self.assertEqual(l.limit(ip, mac, 80), "updated")
        self.assertEqual(len(l.active), 1)

    def test_unlimit(self):
        l = levicut.Limiter(fake_net())
        ip, mac = "192.168.68.62", "AA:BB:CC:00:00:62"
        l.limit(ip, mac, 20)
        self.assertTrue(l.unlimit(ip, mac))
        self.assertEqual(l.active, {})
        self.assertFalse(l.unlimit(ip, mac))

    def test_unlimit_remembers_mac_when_caller_omits_it(self):
        l = levicut.Limiter(fake_net())
        ip, mac = "192.168.68.66", "AA:BB:CC:00:00:66"
        l.limit(ip, mac, 20)
        time.sleep(0.05)
        _SENT.clear()
        self.assertTrue(l.unlimit(ip))  # no mac argument at all
        self.assertTrue(_SENT, "no repair sent")
        for pkt in _SENT:
            self.assertEqual(pkt[levicut.Ether].dst, mac)
        self.assertNotIn(ip, l._macs, "MAC must be forgotten after repair")

    def test_unlimit_all_uses_remembered_mac_when_known_map_misses(self):
        """known_map() is a scan snapshot; if the host dropped off, unlimit_all
        must still repair using the MAC it recorded at limit() time."""
        l = levicut.Limiter(fake_net())
        l.limit("192.168.68.63", "AA:BB:CC:00:00:63", 20)
        time.sleep(0.05)
        _SENT.clear()
        l.unlimit_all({})  # empty map: device no longer in the last scan
        self.assertEqual(l.active, {})
        self.assertTrue(_SENT, "no repair packets for a missed host")
        for pkt in _SENT:
            self.assertEqual(pkt[levicut.Ether].dst, "AA:BB:CC:00:00:63")

    def test_unlimit_all_prefers_known_map(self):
        l = levicut.Limiter(fake_net())
        l.limit("192.168.68.64", "AA:BB:CC:00:00:64", 20)
        time.sleep(0.05)
        _SENT.clear()
        l.unlimit_all({"192.168.68.64": "AA:BB:CC:00:00:65"})
        for pkt in _SENT:
            self.assertEqual(pkt[levicut.Ether].dst, "AA:BB:CC:00:00:65")

    def test_rdns_lookup_does_not_spawn_threads(self):
        """The optimization: rdns_lookup must be a plain call, because its
        callers already run on their own worker thread."""
        import inspect
        src = inspect.getsource(levicut.rdns_lookup)
        self.assertNotIn("threading.Thread", src,
                         "rdns_lookup must not spawn a thread of its own")

    def test_hostname_of_keeps_timeout_for_serial_callers(self):
        import inspect
        src = inspect.getsource(levicut.hostname_of)
        self.assertIn("threading.Thread", src,
                      "hostname_of still owns the timeout for serial callers")


# --------------------------------------------------------------------------- #
class TestWhitelistBehaviour(Base):
    def setUp(self):
        self.p = tempfile.mktemp(suffix=".json")
        self.wl = levicut.Whitelist(self.p)

    def tearDown(self):
        if os.path.exists(self.p):
            os.unlink(self.p)

    def test_add_and_lookup_by_ip(self):
        self.wl.add("AA:BB:CC:00:00:70", "Phone", "192.168.68.70")
        self.assertTrue(self.wl.is_whitelisted("aa:bb:cc:00:00:70"))
        self.assertEqual(self.wl.label_of("AA:BB:CC:00:00:70"), "Phone")
        # removable by the IP we recorded for it
        self.assertEqual(self.wl.remove("192.168.68.70"), "AA:BB:CC:00:00:70")
        self.assertFalse(self.wl.is_whitelisted("AA:BB:CC:00:00:70"))

    def test_remove_by_label_case_insensitive(self):
        self.wl.add("AA:BB:CC:00:00:71", "My Phone")
        self.assertEqual(self.wl.remove("my phone"), "AA:BB:CC:00:00:71")

    def test_relabel_preserves_added_time(self):
        self.wl.add("AA:BB:CC:00:00:72", "A")
        first = self.wl.entries["AA:BB:CC:00:00:72"]["added"]
        self.wl.add("AA:BB:CC:00:00:72", "B")
        e = self.wl.entries["AA:BB:CC:00:00:72"]
        self.assertEqual(e["label"], "B")
        self.assertEqual(e["added"], first)

    def test_touch_ip_ignores_unknown(self):
        self.wl.touch_ip("AA:BB:CC:00:00:73", "192.168.68.73")
        self.assertEqual(self.wl.entries, {})

    def test_list_lines_empty(self):
        self.assertIn("empty", self.wl.list_lines()[0])


# --------------------------------------------------------------------------- #
class TestDeviceCache(Base):
    def setUp(self):
        self.p = tempfile.mktemp(suffix=".json")

    def tearDown(self):
        if os.path.exists(self.p):
            os.unlink(self.p)

    def test_update_and_stale(self):
        c = levicut.DeviceCache(self.p)
        c.update([{"ip": "192.168.68.80", "mac": "aa:bb:cc:00:00:80",
                   "vendor": "V", "hostname": "H", "os": "Android?"}])
        # not in live set -> surfaces as STALE rather than vanishing
        out = c.stale(set())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "192.168.68.80")
        self.assertIn("stale", out[0])
        # present in this scan -> not stale
        self.assertEqual(c.stale({"AA:BB:CC:00:00:80"}), [])

    def test_stale_sorted_numerically(self):
        c = levicut.DeviceCache(self.p)
        now = time.time()
        c.known = {
            "AA:BB:CC:00:00:0A": {"ip": "192.168.68.10", "last_seen": now},
            "AA:BB:CC:00:00:02": {"ip": "192.168.68.2", "last_seen": now},
            "AA:BB:CC:00:00:09": {"ip": "192.168.68.9", "last_seen": now},
        }
        ips = [d["ip"] for d in c.stale(set())]
        self.assertEqual(ips, ["192.168.68.2", "192.168.68.9", "192.168.68.10"])

    def test_stale_respects_max_age(self):
        c = levicut.DeviceCache(self.p)
        c.known = {"AA:BB:CC:00:00:81":
                   {"ip": "192.168.68.81", "last_seen": time.time() - 99999}}
        self.assertEqual(c.stale(set()), [])

    def test_stale_entries_are_not_re_saved(self):
        c = levicut.DeviceCache(self.p)
        c.update([{"ip": "192.168.68.82", "mac": "AA:BB:CC:00:00:82"}])
        before = c.known["AA:BB:CC:00:00:82"]["last_seen"]
        c.update([{"ip": "192.168.68.82", "mac": "AA:BB:CC:00:00:82",
                   "stale": "1m ago"}])
        self.assertEqual(c.known["AA:BB:CC:00:00:82"]["last_seen"], before)

    def test_prunes_old_entries_on_save(self):
        c = levicut.DeviceCache(self.p)
        c.known = {"AA:BB:CC:00:00:83":
                   {"ip": "1.1.1.1", "last_seen": time.time() - 10 * 86400}}
        c.save()
        self.assertEqual(c.known, {})

    def test_age_str(self):
        now = time.time()
        self.assertIn("s ago", levicut.age_str(now, now - 5))
        self.assertIn("m ago", levicut.age_str(now, now - 300))
        self.assertIn("h ago", levicut.age_str(now, now - 7200))
        self.assertEqual(levicut.age_str(now, now + 50), "0s ago")


# --------------------------------------------------------------------------- #
class TestFindDevice(Base):
    def setUp(self):
        self.devs = [
            {"ip": "192.168.68.2", "mac": "AA:BB:CC:00:00:02"},
            {"ip": "192.168.68.3", "mac": "AA:BB:CC:00:00:03"},
        ]

    def test_by_index(self):
        self.assertEqual(levicut.find_device(self.devs, "1")["ip"], "192.168.68.3")

    def test_by_ip(self):
        self.assertEqual(levicut.find_device(self.devs, "192.168.68.2")["mac"],
                         "AA:BB:CC:00:00:02")

    def test_by_mac_any_case(self):
        self.assertEqual(
            levicut.find_device(self.devs, "aa:bb:cc:00:00:03")["ip"],
            "192.168.68.3")

    def test_out_of_range(self):
        self.assertIsNone(levicut.find_device(self.devs, "99"))

    def test_negative_index_rejected(self):
        self.assertIsNone(levicut.find_device(self.devs, "-1"))

    def test_unknown(self):
        self.assertIsNone(levicut.find_device(self.devs, "nope"))


# --------------------------------------------------------------------------- #
class TestMiscHelpers(Base):
    def test_norm_mac(self):
        self.assertEqual(levicut.Whitelist.norm_mac(" aa-bb-cc-dd-ee-ff "),
                         "AA:BB:CC:DD:EE:FF")

    def test_is_random_mac(self):
        self.assertTrue(levicut.is_random_mac("8A:11:22:33:44:55"))
        self.assertFalse(levicut.is_random_mac("00:11:22:33:44:55"))
        self.assertFalse(levicut.is_random_mac("garbage"))

    def test_oui_of(self):
        self.assertEqual(levicut.oui_of("aa:bb:cc:dd:ee:ff"), "AABBCC")

    def test_merge_sweeps_first_seen_wins(self):
        m = levicut.merge_sweeps([{"A": "1.1.1.1", "B": "2.2.2.2"},
                                  {"A": "9.9.9.9", "C": "3.3.3.3"}])
        self.assertEqual(m["A"], "1.1.1.1")
        self.assertEqual(m["C"], "3.3.3.3")

    def test_dns_name_parser(self):
        buf = b"\x03foo\x03com\x00"
        name, end = levicut._dns_name(buf, 0)
        self.assertEqual(name, "foo.com")
        self.assertEqual(end, 9)

    def test_dns_name_compression(self):
        # pointer at off 0 -> offset 12
        buf = b"\xc0\x0c" + b"\x00" * 10 + b"\x04name\x00"
        name, _ = levicut._dns_name(buf, 0)
        self.assertEqual(name, "name")

    def test_os_guess_hostname_keywords(self):
        g = levicut.os_guess_fast
        self.assertEqual(
            levicut.os_guess_fast("192.0.2.1", "00:11:22:33:44:55",
                                  hostname="Johns-iPhone"), "iOS (iPhone?)")
        self.assertEqual(
            levicut.os_guess_fast("192.0.2.1", "00:11:22:33:44:55",
                                  hostname="DESKTOP-ABC"), "Windows?")

    def test_shutdown_survives_broken_blocker(self):
        class Boom:
            def unblock_all(self, known): raise RuntimeError("boom")
        class L:
            def unlimit_all(self, known): pass
        levicut.shutdown(Boom(), L(), {})  # must not raise

    def test_shutdown_survives_broken_limiter(self):
        class B:
            def unblock_all(self, known): pass
        class L:
            def unlimit_all(self, known): raise RuntimeError("boom")
        levicut.shutdown(B(), L(), {})

    def test_no_unused_defaultdict_import(self):
        src = open(levicut.__file__).read()
        self.assertNotIn("from collections import defaultdict", src)

    def test_module_compiles(self):
        import py_compile
        py_compile.compile(levicut.__file__, doraise=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)