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

        def add_url_rule(self, *a, **k):
            pass

    flask.Blueprint = Blueprint
    for name in ("flash", "jsonify", "make_response", "redirect", "render_template", "url_for"):
        setattr(flask, name, lambda *a, **k: None)
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", all_subnets=True, role="admin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


class _FakeApp:
    def register_blueprint(self, bp):
        pass


def _stub_jen_plugin_api(periodic_min_minutes=None):
    """A stub `jen`/`jen.plugin_api` sufficient for register(app) to run
    end to end. Returns the list every register_periodic() call is
    recorded into, as (plugin_id, name, fn, every_minutes) tuples.
    `periodic_min_minutes=None` omits PERIODIC_MIN_MINUTES entirely, so
    `from jen.plugin_api import PERIODIC_MIN_MINUTES` raises ImportError
    the same way it does against a real pre-5.60.1 Jen."""
    calls = []

    def register_periodic(plugin_id, name, fn, every_minutes):
        calls.append((plugin_id, name, fn, every_minutes))

    jen_pkg = types.ModuleType("jen")
    plugin_api = types.ModuleType("jen.plugin_api")
    plugin_api.register_periodic = register_periodic
    plugin_api.register_alert_type = lambda *a, **k: None
    plugin_api.register_row_action = lambda *a, **k: None
    plugin_api.register_search_provider = lambda *a, **k: None
    plugin_api.api_key_required = lambda write=False: lambda fn: fn
    if periodic_min_minutes is not None:
        plugin_api.PERIODIC_MIN_MINUTES = periodic_min_minutes
    jen_pkg.plugin_api = plugin_api
    sys.modules["jen"] = jen_pkg
    sys.modules["jen.plugin_api"] = plugin_api
    return calls


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

    # ── 1.0.2: the first result of a new target is not an alert ─────────────
    check(
        p.should_alert("unknown", "up", True) is False,
        "should_alert: a new target's first success is not 'answering again'",
    )
    check(p.should_alert("down", "up", True) is True, "should_alert: down -> up is a recovery worth an alert")
    check(p.should_alert("up", "down", True) is True, "should_alert: up -> down alerts")
    check(
        p.should_alert("unknown", "down", True) is True,
        "should_alert: a target that never answered and crossed its threshold alerts",
    )
    check(p.should_alert("up", "up", False) is False, "should_alert: no transition, no alert")

    # ── a fake database and fake request, to run the impure routes ───────────
    _stub_jen_plugin_api()

    class FakeDB:
        def __init__(self, selects=None):
            self.statements = []
            self.selects = list(selects or [])
            self.lastrowid = 5

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.statements.append((sql.split()[0].upper(), sql, params))

        def fetchone(self):
            return self.selects.pop(0) if self.selects else None

        def fetchall(self):
            return self.selects.pop(0) if self.selects else []

        def commit(self):
            pass

        def close(self):
            pass

        def kinds(self):
            return [s[0] for s in self.statements]

    only_one = lambda sid: sid == 1  # noqa: E731 - a subnet-restricted caller: subnet 1, and None is not theirs
    everything = lambda sid: True  # noqa: E731 - an unrestricted caller
    flashed = []
    p.flash = lambda msg, cat="message": flashed.append(msg)
    p.redirect = lambda where: "redirect"
    p.url_for = lambda *a, **k: "/"
    p.jsonify = lambda payload: payload
    p._require_write = lambda: True

    # ── 1.0.2: by-id routes judge the row's OWN subnet ──────────────────────
    for label, row_subnet in (("a target in subnet 2", 2), ("a target in no subnet", None)):
        fdb = FakeDB([{"id": 9, "subnet_id": row_subnet, "enabled": 1}])
        p._get_db = lambda fdb=fdb: fdb
        p._can = only_one
        check(
            p.toggle_target(9) == "redirect" and flashed[-1] == "Target not found.",
            f"toggle: {label} reads as not found to a caller scoped to subnet 1",
        )
        check(fdb.kinds() == ["SELECT"], f"toggle: {label} — nothing was written")
        fdb = FakeDB([{"id": 9, "subnet_id": row_subnet, "enabled": 1}])
        p._get_db = lambda fdb=fdb: fdb
        check(
            p.delete_target(9) == "redirect" and fdb.kinds() == ["SELECT"],
            f"delete: {label} is not deleted by a caller scoped to subnet 1",
        )
        fdb = FakeDB([{"id": 9, "subnet_id": row_subnet, "enabled": 1}])
        p._get_db = lambda fdb=fdb: fdb
        result = p.target_history(9)
        check(result == ({"error": "not found"}, 404), f"history: {label} is a 404 to a caller scoped to subnet 1")

    fdb = FakeDB([{"id": 9, "subnet_id": 1, "enabled": 1}])
    p._get_db = lambda fdb=fdb: fdb
    check(
        p.toggle_target(9) == "redirect" and "UPDATE" in fdb.kinds(),
        "toggle: a target in the caller's own subnet is theirs to pause",
    )
    fdb = FakeDB([{"id": 9, "subnet_id": None, "enabled": 1}])
    p._get_db = lambda fdb=fdb: fdb
    p._can = everything
    check(
        p.delete_target(9) == "redirect" and "DELETE" in fdb.kinds(),
        "delete: an unrestricted caller may remove a target that has no subnet",
    )

    # ── 1.0.2: "Watch this host" derives the subnet from the ADDRESS ─────────
    p._subnet_map = lambda: {1: {"cidr": "10.1.0.0/24"}, 2: {"cidr": "10.2.0.0/24"}}
    p._can = only_one
    for label, ip in (("an address in subnet 2", "10.2.0.9"), ("an address in no subnet", "172.16.0.9")):
        fdb = FakeDB()
        p._get_db = lambda fdb=fdb: fdb
        p.request = types.SimpleNamespace(args={"ip": ip, "mac": "", "hostname": "h", "subnet_id": "1"})
        p.watch_from_row()
        check(fdb.statements == [], f"watch_from_row: {label} is refused even though the query string claims subnet 1")
    fdb = FakeDB()
    p._get_db = lambda fdb=fdb: fdb
    p.request = types.SimpleNamespace(args={"ip": "10.1.0.9", "mac": "", "hostname": "h", "subnet_id": "2"})
    p.watch_from_row()
    inserts = [s for s in fdb.statements if s[0] == "INSERT"]
    check(
        len(inserts) == 1 and inserts[0][2][2] == 1,
        "watch_from_row: stores the subnet the address is in (1), not the one the URL claimed (2)",
    )
    p.request = None

    # ── 1.0.2: the JSON API — a scoped key never gets a target with no subnet ─
    jen_api = sys.modules["jen.plugin_api"]

    def key_can(key, subnet_id, *, allow_unattributed=False):
        scope = key.get("subnet_ids")
        if scope is None:
            return True
        return subnet_id is not None and subnet_id in scope

    jen_api.api_key_can_access_subnet = key_can
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "k", "subnet_ids": [1]})
    rows = [
        {
            "id": 1,
            "ip": "10.1.0.5",
            "mac": "",
            "label": "mine",
            "subnet_id": 1,
            "probe": "ping",
            "enabled": 1,
            "state": "up",
            "uptime_pct": 100,
        },
        {
            "id": 2,
            "ip": "10.2.0.5",
            "mac": "",
            "label": "theirs",
            "subnet_id": 2,
            "probe": "ping",
            "enabled": 1,
            "state": "up",
            "uptime_pct": 100,
        },
        {
            "id": 3,
            "ip": "172.16.0.5",
            "mac": "",
            "label": "nowhere",
            "subnet_id": None,
            "probe": "ping",
            "enabled": 1,
            "state": "up",
            "uptime_pct": 100,
        },
    ]
    p._target_rows = lambda: rows
    listed = [t["label"] for t in p._api_list_targets()["targets"]]
    check(
        listed == ["mine"],
        f"api list: a scoped key sees its own subnet's targets only — not a subnet-less one (got {listed})",
    )
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "all", "subnet_ids": None})
    listed = [t["label"] for t in p._api_list_targets()["targets"]]
    check(listed == ["mine", "theirs", "nowhere"], "api list: an unrestricted key sees every target")
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "k", "subnet_ids": [1]})
    for label, ip in (("subnet 2", "10.2.0.7"), ("no subnet", "172.16.0.7")):
        fdb = FakeDB()
        p._get_db = lambda fdb=fdb: fdb
        p.request = types.SimpleNamespace(get_json=lambda silent=True, ip=ip: {"ip": ip, "label": "x"})
        result = p._api_add_target()
        check(result[1] == 403 and fdb.statements == [], f"api add: a scoped key cannot add a target in {label}")
    fdb = FakeDB()
    p._get_db = lambda fdb=fdb: fdb
    p.request = types.SimpleNamespace(get_json=lambda silent=True: {"ip": "10.1.0.7", "label": "x"})
    result = p._api_add_target()
    check(
        isinstance(result, dict) and result.get("ok") is True and "INSERT" in fdb.kinds(),
        "api add: a scoped key can add a target in its own subnet",
    )
    p.request = None

    # ── 1.0.2: the picker never offers a scoped admin another subnet's hosts ─
    kea_rows = [
        {"ip": "10.1.0.5", "hostname": "mine", "ident_hex": "AABBCCDDEE01", "ident_type": 0, "subnet_id": 1},
        {"ip": "10.2.0.5", "hostname": "theirs", "ident_hex": "AABBCCDDEE02", "ident_type": 0, "subnet_id": 2},
        {"ip": "10.9.0.5", "hostname": "global", "ident_hex": "AABBCCDDEE03", "ident_type": 0, "subnet_id": None},
    ]
    ipam_rows = [
        {"ip": "10.1.0.6", "mac": "", "label": "ipam-mine", "subnet_id": 1},
        {"ip": "10.2.0.6", "mac": "", "label": "ipam-theirs", "subnet_id": 2},
    ]
    for label, can, expected in (
        ("a scoped admin", only_one, {"mine", "ipam-mine"}),
        ("an unrestricted admin", everything, {"mine", "theirs", "global", "ipam-mine", "ipam-theirs"}),
    ):
        kdb, jdb = FakeDB([list(kea_rows)]), FakeDB([list(ipam_rows)])
        p._get_kea_db = lambda kdb=kdb: kdb
        p._get_db = lambda jdb=jdb: jdb
        p._can = can
        got = {c["label"] for c in p._candidate_hosts()}
        check(got == expected, f"_candidate_hosts: {label} is offered {sorted(expected)} (got {sorted(got)})")

    # ── 1.0.2: recording results — UTC timestamps, no alert on a first success ─
    alerts = []
    p._alert_transition = lambda target, state: alerts.append((target["id"], state))
    by_id = {7: {"id": 7, "fails_to_down": 3}}
    fdb = FakeDB([None])  # no wd_state row yet: a brand-new target
    p._get_db = lambda: fdb
    p._record_results(by_id, {7: (True, 4, "")})
    check(
        "UTC_TIMESTAMP()" in fdb.statements[0][1] and "checked_at" in fdb.statements[0][1],
        "_record_results: checked_at is written with UTC_TIMESTAMP(), like every other time in the table",
    )
    check(alerts == [], "_record_results: a new target's first success fires no 'answering again' alert")
    fdb = FakeDB([{"state": "down", "consecutive_fails": 4}])
    p._get_db = lambda: fdb
    p._record_results(by_id, {7: (True, 4, "")})
    check(alerts == [(7, "up")], "_record_results: a down target that answers still alerts")
    alerts.clear()
    fdb = FakeDB([{"state": "up", "consecutive_fails": 2}])
    p._get_db = lambda: fdb
    p._record_results(by_id, {7: (False, None, "no reply")})
    check(alerts == [(7, "down")], "_record_results: crossing the failure threshold still alerts")

    # ── 1.0.3: a database failure never reaches the page or the API ──────────
    def db_down(*a, **k):
        raise RuntimeError("Access denied for user 'jen'@'10.9.9.9' marker-q96")

    flashed.clear()
    p._can = everything
    p._get_db = db_down
    p.request = types.SimpleNamespace(
        form={"ip": "10.1.0.9", "label": "x", "probe": "ping", "interval_min": "5", "fails_to_down": "3"}, args={}
    )
    p.add_target()
    check(
        flashed and all("marker-q96" not in m and "10.9.9.9" not in m for m in flashed) and "Jen's log" in flashed[-1],
        f"add_target: a database failure shows a generic message and no exception text (got {flashed})",
    )
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "k", "subnet_ids": None})
    p.request = types.SimpleNamespace(get_json=lambda silent=True: {"ip": "10.1.0.7", "label": "x"})
    result = p._api_add_target()
    check(
        isinstance(result, tuple) and result[1] == 500 and "marker-q96" not in str(result[0]),
        f"_api_add_target: a database failure returns a generic 500, not the exception text (got {result})",
    )

    # ── register(): the periodic tick is registered at Jen's real floor ─────
    # (the actual v1.0.1 bug: register_periodic(..., 1) is below Jen's
    # PERIODIC_MIN_MINUTES=5 and raises, so the plugin never loads at all —
    # this calls the real register(app) end to end, not just inspects source)
    calls_with_export = _stub_jen_plugin_api(periodic_min_minutes=7)
    p.register(_FakeApp())
    tick_calls = [c for c in calls_with_export if c[1] == "probe-tick"]
    check(
        len(tick_calls) == 1 and tick_calls[0][3] == 7,
        f"register(): uses the exported PERIODIC_MIN_MINUTES when Jen offers it (got {tick_calls})",
    )

    calls_without_export = _stub_jen_plugin_api(periodic_min_minutes=None)
    p.register(_FakeApp())
    tick_calls2 = [c for c in calls_without_export if c[1] == "probe-tick"]
    check(
        len(tick_calls2) == 1 and tick_calls2[0][3] == 5,
        f"register(): falls back to 5 when PERIODIC_MIN_MINUTES isn't exported yet (got {tick_calls2})",
    )
    check(
        all(c[3] >= 5 for c in calls_with_export + calls_without_export),
        "register_periodic is never called below 5 — Jen's own PERIODIC_MIN_MINUTES floor",
    )

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
