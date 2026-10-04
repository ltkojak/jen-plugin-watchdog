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
    plugin_api.register_investigation_provider = lambda *a, **k: INVESTIGATION_CALLS.append((a, k))
    plugin_api.api_key_required = lambda write=False: lambda fn: fn

    def normalize_mac(raw):
        import re as _re

        if not isinstance(raw, str) or not raw.strip():
            return None
        cleaned = _re.sub(r"[^0-9a-fA-F]", "", raw).lower()
        if len(cleaned) != 12:
            return None
        mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
        return mac if _re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac) else None

    def like_pattern(text):
        return "%" + str(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"

    def in_placeholders(values):
        n = len(list(values))
        return ",".join(["%s"] * n) if n else "NULL"

    def search_scope(accessible_ids, all_subnets, column):
        if all_subnets:
            return "1=1", []
        ids = sorted({int(i) for i in (accessible_ids or [])})
        if not ids:
            return None
        return f"{column} IN ({in_placeholders(ids)})", ids

    def json_object_body():
        import sys as _sys

        req = getattr(_sys.modules.get("flask"), "request", None)
        try:
            body = req.get_json(silent=True) if req is not None else None
        except Exception:
            body = None
        if isinstance(body, dict):
            return body, None
        return None, ({"error": "expected a JSON object"}, 400)

    def str_field(body, name, max_len=None):
        value = body.get(name) if isinstance(body, dict) else None
        if not isinstance(value, str):
            return ""
        value = value.strip()
        return value[:max_len] if max_len is not None else value

    def api_key_can_access_subnet(key, subnet_id, *, allow_unattributed=False):
        if not key:
            return False
        scope = key.get("subnet_access")
        if scope is None:
            return True
        if subnet_id is None:
            return allow_unattributed
        return subnet_id in scope

    plugin_api.normalize_mac = normalize_mac
    plugin_api.like_pattern = like_pattern
    plugin_api.in_placeholders = in_placeholders
    plugin_api.search_scope = search_scope
    plugin_api.json_object_body = json_object_body
    plugin_api.str_field = str_field
    plugin_api.api_key_can_access_subnet = api_key_can_access_subnet
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
INVESTIGATION_CALLS = []  # every register_investigation_provider() call


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

    _stub_jen_plugin_api()

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
        sys.modules["flask"].request = types.SimpleNamespace(
            get_json=lambda silent=True, ip=ip: {"ip": ip, "label": "x"}
        )
        result = p._api_add_target()
        check(result[1] == 403 and fdb.statements == [], f"api add: a scoped key cannot add a target in {label}")
    fdb = FakeDB()
    p._get_db = lambda fdb=fdb: fdb
    sys.modules["flask"].request = types.SimpleNamespace(get_json=lambda silent=True: {"ip": "10.1.0.7", "label": "x"})
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
    sys.modules["flask"].request = types.SimpleNamespace(get_json=lambda silent=True: {"ip": "10.1.0.7", "label": "x"})
    result = p._api_add_target()
    check(
        isinstance(result, tuple) and result[1] == 500 and "marker-q96" not in str(result[0]),
        f"_api_add_target: a database failure returns a generic 500, not the exception text (got {result})",
    )

    # ── 1.0.4: _load_target no longer 500s on a DB failure ───────────────────
    p._get_db = db_down
    row, why = p._load_target(1)
    check(
        row is None and "marker-q96" not in why and why,
        f"_load_target: a database failure is a generic refusal, not an uncaught exception (got {row}, {why!r})",
    )

    # ── 1.0.4: add_target and the API refuse a second target for one IP ──────
    p._can = everything
    p._subnet_map = lambda: {1: {"cidr": "10.1.0.0/24"}}
    flashed.clear()
    fdb = FakeDB(selects=[{"id": 1}])  # the duplicate-IP SELECT finds a row
    p._get_db = lambda: fdb
    p.request = types.SimpleNamespace(
        form={"ip": "10.1.0.9", "label": "x", "probe": "ping", "interval_min": "5", "fails_to_down": "3"}, args={}
    )
    p.add_target()
    check(
        fdb.kinds() == ["SELECT"] and any("already" in m for m in flashed),
        f"add_target: a duplicate IP is refused before any INSERT (got {fdb.kinds()}, {flashed})",
    )
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "k", "subnet_ids": None})
    sys.modules["flask"].request = types.SimpleNamespace(get_json=lambda silent=True: {"ip": "10.1.0.9", "label": "x"})
    fdb = FakeDB(selects=[{"id": 1}])
    p._get_db = lambda: fdb
    result = p._api_add_target()
    check(
        isinstance(result, tuple) and result[1] == 409 and fdb.kinds() == ["SELECT"],
        f"_api_add_target: a duplicate IP is a 409, not a silent second target (got {result}, {fdb.kinds()})",
    )
    sys.modules["flask"].request = types.SimpleNamespace(
        get_json=lambda silent=True: {"ip": "10.1.0.9", "label": "x", "mac": 5}
    )
    result = p._api_add_target()
    check(isinstance(result, tuple) and result[1] == 400, f"_api_add_target: a non-string mac is a 400 (got {result})")

    # ── 1.0.4: _target_rows reads every target's uptime in ONE query ─────────
    # a fresh module: the "results page" test earlier permanently replaced p._target_rows with a
    # canned lambda, and the real one is what this checks.
    fresh = load_plugin()
    fdb = FakeDB(
        selects=[
            [{"id": 1, "label": "a"}, {"id": 2, "label": "b"}],  # the targets query
            [{"target_id": 1, "ok": 1}, {"target_id": 1, "ok": 0}, {"target_id": 2, "ok": 1}],  # ALL checks, one query
        ]
    )
    fresh._get_db = lambda: fdb
    rows = fresh._target_rows()
    check(
        fdb.kinds() == ["SELECT", "SELECT"],
        f"_target_rows: one query for the targets and ONE for every target's checks, not one per target (got {fdb.kinds()})",
    )
    by_id = {r["id"]: r for r in rows}
    check(
        by_id[1]["uptime_pct"] == 50 and by_id[2]["uptime_pct"] == 100,
        f"_target_rows: each target's own checks feed its own uptime (got {by_id[1]['uptime_pct']}, {by_id[2]['uptime_pct']})",
    )

    # ── 1.0.4: an alert is sent only after the recording connection is closed ─
    order = []
    p._alert_transition = lambda target, new_state: order.append("alert")

    class _ClosingDB(FakeDB):
        def close(self):
            order.append("close")

    fdb = _ClosingDB(selects=[{"state": "up", "consecutive_fails": 0}])
    p._get_db = lambda: fdb
    p._record_results({1: {"id": 1, "ip": "10.1.0.1", "fails_to_down": 1}}, {1: (False, None, "timeout")})
    check(
        order == ["close", "alert"],
        f"_record_results: the alert is sent after the connection closes, not inside the loop (got {order})",
    )

    # ── 1.0.4: the search provider scopes in SQL, before its own LIMIT ────────
    fdb = FakeDB(selects=[[]])
    p._get_db = lambda: fdb
    p._watchdog_search("printer", {1}, False)
    kind, sql, params = fdb.statements[0]
    check(
        "t.subnet_id IN (%s)" in sql and params[0] == 1,
        f"search: the caller's own subnet scope is in the SQL, not applied afterward (got {sql!r}, {params})",
    )
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p._watchdog_search("printer", set(), False)
    check(fdb.statements == [], "search: a caller who may see nothing runs no query at all")

    # ── 1.0.5: _tick() itself, end to end — the seam the real bug lived in ───
    # (the actual v1.0.0-1.0.4 bug: the SELECT that feeds due_targets() never
    # selected `enabled`, so every real row it fetched had no `enabled` key at
    # all and due_targets()'s own "if not t.get('enabled'): continue" skipped
    # every target unconditionally, forever — a hand-built dict carrying
    # `enabled` explicitly, the way due_targets() itself was already tested,
    # could never have caught it. This calls _tick() itself, never due_targets
    # or _record_results in isolation.)
    probed = []

    def _fake_probe(t):
        probed.append(t["id"])
        return (True, 4, "")

    p._probe_target = _fake_probe
    p._alert_transition = lambda target, new_state: (_ for _ in ()).throw(
        AssertionError("a brand-new target's first success must not alert")
    )

    target_row = {
        "id": 1,
        "ip": "10.1.0.5",
        "probe": "ping",
        "interval_min": 5,
        "fails_to_down": 3,
        "label": "tick-target",
        "subnet_id": 1,
        "mac": "",
        "enabled": 1,
    }
    fdb = FakeDB(selects=[[target_row], [], None])
    p._get_db = lambda: fdb
    p._tick()
    check(probed == [1], f"_tick: the enabled, due target actually reaches the probe pool (got {probed})")
    kinds_and_sql = [(k, sql) for k, sql, _params in fdb.statements]
    check(
        any(k == "INSERT" and "wd_checks" in sql for k, sql in kinds_and_sql),
        f"_tick: an enabled target gets a wd_checks row (got {fdb.kinds()})",
    )
    check(
        any(k == "INSERT" and "wd_state" in sql for k, sql in kinds_and_sql),
        f"_tick: a brand-new target also gets its first wd_state row (got {fdb.kinds()})",
    )

    # The real SQL's own WHERE enabled=1 means a disabled target is never even
    # fetched — this is what that looks like from _tick()'s side: an empty
    # targets result, same as an install with nothing enabled at all.
    probed.clear()
    fdb = FakeDB(selects=[[], []])
    p._get_db = lambda: fdb
    p._tick()
    check(probed == [], "_tick: no targets fetched means no probe ever runs")
    check(
        all(k == "SELECT" for k in fdb.kinds()),
        f"_tick: nothing is written when the enabled=1 query returns nothing (got {fdb.kinds()})",
    )

    # ── register(): the periodic tick is registered at Jen's real floor ─────
    # (the actual v1.0.1 bug: register_periodic(..., 1) is below Jen's
    # PERIODIC_MIN_MINUTES=5 and raises, so the plugin never loads at all —
    # this calls the real register(app) end to end, not just inspects source)
    INVESTIGATION_CALLS.clear()
    calls_with_export = _stub_jen_plugin_api(periodic_min_minutes=7)
    p.register(_FakeApp())
    check(
        len(INVESTIGATION_CALLS) == 1
        and INVESTIGATION_CALLS[0][0] == ("watchdog",)
        and INVESTIGATION_CALLS[0][1]["fn"] is p._investigate,
        "register(): exactly one investigation provider, the plugin's own",
    )

    # ── 1.1.0: the investigation provider ────────────────────────────────────
    ns = types.SimpleNamespace
    check(
        p.subject_addresses(
            ns(
                ip="10.0.0.5",
                leases4=[{"ip": "10.0.0.5"}, {"ip": "10.0.0.6"}, {"ip": "nope"}],
                reservations=[{"ip": "10.0.0.7"}],
            )
        )
        == ["10.0.0.5", "10.0.0.6", "10.0.0.7"],
        "subject_addresses: the typed address, the leases and the reservations, validated and de-duplicated",
    )
    check(
        p.subject_addresses(ns(ip="", leases4=None, reservations=None)) == [],
        "subject_addresses: nothing known is an empty list",
    )
    check(p.investigation_card([]) is None, "investigation_card: a client with no target adds no card")
    import datetime as _dt

    when = _dt.datetime(2026, 10, 1, 8, 30)
    up = {
        "ip": "10.0.0.5", "label": "printer", "state": "up", "since": when, "last_ok_at": when, "last_fail_at": None,
        "consecutive_fails": 0, "last_error": None, "probe": "ping", "enabled": 1,
    }  # fmt: skip
    card = p.investigation_card([up])
    check(
        card["status"] == "ok" and card["summary"] == "printer is answering (up since 2026-10-01 08:30 UTC)",
        f"investigation_card: an up target is an ok card (got {card['summary']!r})",
    )
    down = dict(up, state="down", consecutive_fails=3, last_fail_at=when, last_error="no answer")
    card = p.investigation_card([up, down])
    check(
        card["status"] == "warn"
        and card["summary"].startswith("printer is down since 2026-10-01 08:30 UTC (3 failed checks in a row)"),
        f"investigation_card: a down target makes it a warn card and is listed first (got {card['summary']!r})",
    )
    check(
        {"label": "Last error", "value": "no answer"} in card["rows"],
        "investigation_card: a down target shows its last error",
    )
    paused = p.investigation_card([dict(down, enabled=0)])
    check(
        paused["status"] == "ok" and "paused" in paused["summary"],
        "investigation_card: a paused target is not a warning, however its state reads",
    )
    check(
        "no result yet" in p.investigation_card([dict(up, state=None, since=None)])["summary"],
        "investigation_card: a target with no result yet says so",
    )
    check(
        len(
            [
                r
                for r in p.investigation_card([dict(up, ip=f"10.0.0.{i}", label=f"t{i}") for i in range(20)])["rows"]
                if r["label"] == "Probe"
            ]
        )
        == p._INVESTIGATION_MAX_TARGETS,
        "investigation_card: capped at five targets",
    )

    # the impure provider, end to end through the plugin's own query
    subject = ns(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.5", leases4=[{"ip": "10.0.0.5"}], reservations=[])
    fdb = FakeDB(selects=[[dict(up)]])
    p._get_db = lambda: fdb
    got = p._investigate(subject, {1}, False)
    kind, sql, params = fdb.statements[0]
    check(
        got is not None and got["href"] == "/network/watchdog" and "printer" in got["summary"],
        f"_investigate: the card for a seeded client, linking to the plugin's own page (got {got})",
    )
    check(
        "t.subnet_id IN (%s)" in sql
        and "t.mac=%s" in sql
        and "t.ip IN (%s)" in sql
        and params == (1, "aa:bb:cc:dd:ee:01", "10.0.0.5"),
        f"_investigate: the caller's scope, the MAC and the address are all in the one parameterised query (got {sql!r}, {params})",
    )
    fdb = FakeDB()
    p._get_db = lambda: fdb
    check(
        p._investigate(subject, set(), False) is None and fdb.statements == [],
        "_investigate: a caller who may see no subnet runs no query at all",
    )
    fdb = FakeDB(selects=[[]])
    p._get_db = lambda: fdb
    check(p._investigate(subject, None, True) is None, "_investigate: an unknown client gets None")
    check("1=1" in fdb.statements[0][1], "_investigate: an unrestricted caller's scope is 1=1")
    fdb = FakeDB()
    p._get_db = lambda: fdb
    check(
        p._investigate(ns(mac="", ip="", leases4=[], reservations=[]), None, True) is None and fdb.statements == [],
        "_investigate: a subject with no MAC and no address runs no query",
    )
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
