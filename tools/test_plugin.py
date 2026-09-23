#!/usr/bin/env python3
"""
tools/test_plugin.py — the plugin's own unit checks, run by CI after
tools/verify.py. Loads plugin.py with importlib against a stub `jen`
package and fake Flask/flask_login modules so nothing here needs Jen, a
database, or a browser; every check exercises a PURE function of the
plugin with hand-built inputs.

Run: `python3 tools/test_plugin.py` (exit 1 on the first failing check).
"""

import importlib.util
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _stub_modules():
    """Enough of flask / flask_login for plugin.py to import."""
    flask = types.ModuleType("flask")

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            def deco(fn):
                return fn

            return deco

    flask.Blueprint = Blueprint
    for name in ("flash", "jsonify", "make_response", "redirect", "render_template", "url_for"):
        setattr(flask, name, lambda *a, **k: None)
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", all_subnets=True, role="admin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


def load_plugin():
    _stub_modules()
    spec = importlib.util.spec_from_file_location("watchdog_plugin", os.path.join(ROOT, "plugin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


failures = []


def check(cond, msg):
    if cond:
        print(f"ok    {msg}")
    else:
        failures.append(msg)
        print(f"FAIL  {msg}")


def main():
    p = load_plugin()

    # ── probe string parsing ─────────────────────────────────────────────────
    check(p.parse_probe("ping") == ("ping", None), "parse_probe: bare 'ping'")
    check(p.parse_probe("tcp:80") == ("tcp", [80]), "parse_probe: single port")
    check(p.parse_probe("tcp:80,443") == ("tcp", [80, 443]), "parse_probe: multiple ports")
    kind, err = p.parse_probe("tcp:0")
    check(kind is None and "Invalid port" in err, "parse_probe: port 0 refused")
    kind, err = p.parse_probe("tcp:99999")
    check(kind is None and "Invalid port" in err, "parse_probe: port over 65535 refused")
    kind, err = p.parse_probe("garbage")
    check(kind is None and "Unknown probe" in err, "parse_probe: garbage refused")
    kind, err = p.parse_probe("")
    check(kind is None, "parse_probe: empty string refused")

    # ── ping output parsing ──────────────────────────────────────────────────
    up_stdout = (
        "PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.\n"
        "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms\n\n"
        "--- 10.0.0.1 ping statistics ---\n"
        "1 packets transmitted, 1 received, 0% packet loss, time 0ms\n"
        "rtt min/avg/max/mdev = 0.045/0.045/0.045/0.000 ms\n"
    )
    ok, rtt = p.parse_ping(0, up_stdout)
    check(ok is True and rtt == 0.045, f"parse_ping: a reply parses ok=True, rtt=0.045 (got ok={ok}, rtt={rtt})")
    down_stdout = (
        "PING 10.0.0.99 (10.0.0.99) 56(84) bytes of data.\n\n"
        "--- 10.0.0.99 ping statistics ---\n"
        "1 packets transmitted, 0 received, 100% packet loss, time 0ms\n"
    )
    ok, rtt = p.parse_ping(1, down_stdout)
    check(ok is False and rtt is None, f"parse_ping: no reply parses ok=False, rtt=None (got ok={ok}, rtt={rtt})")

    # ── state machine ────────────────────────────────────────────────────────
    state, fails, transitioned = p.next_state("unknown", 0, 3, True)
    check((state, fails, transitioned) == ("up", 0, True), "next_state: unknown -> up on first success")
    state, fails, transitioned = p.next_state("unknown", 0, 3, False)
    check((state, fails, transitioned) == ("unknown", 1, False), "next_state: unknown stays unknown on 1st of 3 fails")
    state, fails, transitioned = p.next_state("unknown", 1, 3, False)
    check((state, fails, transitioned) == ("unknown", 2, False), "next_state: unknown stays unknown on 2nd of 3 fails")
    state, fails, transitioned = p.next_state("unknown", 2, 3, False)
    check((state, fails, transitioned) == ("down", 3, True), "next_state: 3rd of 3 fails flips to down")
    state, fails, transitioned = p.next_state("up", 0, 3, False)
    check((state, fails, transitioned) == ("up", 1, False), "next_state: a lone blip does not flip up early")
    state, fails, transitioned = p.next_state("up", 2, 1, False)
    check((state, fails, transitioned) == ("down", 3, True), "next_state: fails_to_down=1 flips on the first fail")
    state, fails, transitioned = p.next_state("down", 7, 3, False)
    check((state, fails, transitioned) == ("down", 8, False), "next_state: staying down never re-alerts")
    state, fails, transitioned = p.next_state("down", 9, 3, True)
    check((state, fails, transitioned) == ("up", 0, True), "next_state: down -> up on the first success")

    # ── due-target selection ─────────────────────────────────────────────────
    from datetime import datetime, timedelta

    now = datetime(2026, 9, 23, 12, 0, 0)
    targets = [
        {"id": 1, "interval_min": 5, "enabled": True},
        {"id": 2, "interval_min": 5, "enabled": True},
        {"id": 3, "interval_min": 5, "enabled": True},
        {"id": 4, "interval_min": 5, "enabled": False},
    ]
    last_checked = {
        1: now - timedelta(minutes=10),  # overdue
        2: now - timedelta(minutes=1),  # recent, not due
        # 3: never checked -> due
        4: now - timedelta(minutes=10),  # overdue but disabled -> excluded
    }
    due = set(p.due_targets(targets, last_checked, now))
    check(due == {1, 3}, f"due_targets: overdue + never-checked are due, recent + disabled are not (got {due})")

    # ── uptime maths ──────────────────────────────────────────────────────────
    check(p.uptime_pct([]) is None, "uptime_pct: no checks is None, not 0 or 100")
    check(p.uptime_pct([{"ok": True}] * 9 + [{"ok": False}]) == 90, "uptime_pct: 9/10 ok rounds to 90%")
    check(p.uptime_pct([{"ok": True}]) == 100, "uptime_pct: a single ok check is 100%")
    check(p.uptime_pct([{"ok": False}]) == 0, "uptime_pct: a single failed check is 0%")

    # ── subnet derivation (the Q55 rule) ─────────────────────────────────────
    subnet_map = {1: {"cidr": "10.0.0.0/24"}, 2: {"cidr": "192.168.1.0/24"}}
    check(p.derive_subnet_id("10.0.0.5", subnet_map) == 1, "derive_subnet_id: matches the containing CIDR")
    check(p.derive_subnet_id("192.168.1.200", subnet_map) == 2, "derive_subnet_id: matches the second subnet")
    check(p.derive_subnet_id("172.16.0.1", subnet_map) is None, "derive_subnet_id: no match is None, not an error")
    check(p.derive_subnet_id("not-an-ip", subnet_map) is None, "derive_subnet_id: garbage IP is None, not an error")

    # ── MAC normalisation ────────────────────────────────────────────────────
    check(p._normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff", "_normalize_mac: uppercase colon form")
    check(p._normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff", "_normalize_mac: bare hex form")
    check(p._normalize_mac("not-a-mac") == "", "_normalize_mac: garbage is refused, not raised")
    check(p._normalize_mac("") == "", "_normalize_mac: empty input is refused")

    # ── write gate — viewers can look at Watchdog but not change it ─────────
    p.current_user.role = "viewer"
    check(p._is_admin() is False, "a viewer is not admin")
    check(p._require_write() is False, "a viewer cannot write")
    # request is None in this harness; a route that reaches request.form/
    # request.args raises AttributeError, so returning None without raising
    # proves _require_write() stopped it first.
    for fn, args in (
        (p.add_target, ()),
        (p.toggle_target, (1,)),
        (p.delete_target, (1,)),
        (p.watch_from_row, ()),
    ):
        try:
            fn(*args)
            gated = True
        except Exception:
            gated = False
        check(gated, f"{fn.__name__} refuses a viewer before touching the request")
    p.current_user.role = "admin"
    check(p._is_admin() is True, "admin role restored for the rest of the run")

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
