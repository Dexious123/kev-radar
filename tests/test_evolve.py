"""The living estate: one simulated day at a time, deterministic, and safe to re-run."""

import importlib.util
import json
from datetime import date, timedelta
from pathlib import Path

import pandas as pd
import pytest

from kev_radar import evolve
from kev_radar.feeds import load_json
from kev_radar.generate import generate_csv, generate_frame

ROOT = Path(__file__).resolve().parents[1]
START = date(2026, 10, 16)  # a Friday
SATURDAY = START + timedelta(days=1)
MONDAY = START + timedelta(days=3)


@pytest.fixture(scope="module")
def pool() -> list[dict]:
    return load_json("cve_pool.json")


@pytest.fixture(scope="module")
def estate(pool) -> pd.DataFrame:
    return evolve.read_estate(generate_csv(pool, as_of=START, host_count=60))


def _fresh_kev(pool: list[dict], added: date) -> dict:
    template = next(entry for entry in pool if entry.get("in_kev"))
    return dict(template, cve="CVE-2099-00001", date_added=added.isoformat(), family="any", vendor="Acme", product="Gateway")


def _refresh_module():
    spec = importlib.util.spec_from_file_location("refresh_snapshots", ROOT / "scripts" / "refresh_snapshots.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reading_and_writing_the_export_is_lossless(pool):
    text = generate_csv(pool, as_of=START, host_count=60)
    assert evolve.write_estate(evolve.read_estate(text)) == text


def test_hosts_are_rebuilt_from_the_export(pool):
    frame = generate_frame(pool, as_of=START, host_count=60)
    hosts = evolve.hosts_from_estate(frame.astype(str))
    assert len(hosts) == frame["asset.id"].nunique()
    for host in hosts:
        role = host.asset_name.split("-")[2]
        assert host.family == evolve.ROLE_FAMILY[role]
        assert host.exposed == host.ip.startswith("203.0.113.")


def test_a_day_is_deterministic(estate, pool):
    first, events_a = evolve.advance_one_day(estate, pool, MONDAY)
    second, events_b = evolve.advance_one_day(estate, pool, MONDAY)
    assert evolve.write_estate(first) == evolve.write_estate(second)
    assert events_a == events_b


def test_the_scanner_sees_every_open_finding_again(estate, pool):
    after, _ = evolve.advance_one_day(estate, pool, MONDAY)
    open_rows = after[after["state"].isin(evolve.OPEN_STATES)]
    assert set(open_rows["last_seen"]) == {f"{MONDAY.isoformat()}T15:04:00Z"}


def test_a_new_kev_entry_lands_and_is_not_closed_the_same_day(estate, pool):
    entry = _fresh_kev(pool, MONDAY - timedelta(days=1))
    after, events = evolve.advance_one_day(estate, pool + [entry], MONDAY)
    rows = after[after["definition.cve"] == entry["cve"]]
    assert len(events["new_kev"]) == 1 and events["new_kev"][0]["cve"] == entry["cve"]
    assert 2 <= len(rows) <= 4
    assert set(rows["state"]) == {"OPEN"}
    assert set(rows["first_observed"]) == {f"{MONDAY.isoformat()}T15:04:00Z"}
    assert any(json.loads(tags)["Internet Exposed"] == ["Yes"] for tags in rows["asset.tags"])
    again, events = evolve.advance_one_day(after, pool + [entry], MONDAY + timedelta(days=1))
    assert events["new_kev"] == []
    assert (again["definition.cve"] == entry["cve"]).sum() == len(rows)


def test_a_kev_entry_outside_the_window_does_not_land(estate, pool):
    entry = _fresh_kev(pool, MONDAY - timedelta(days=evolve.NEW_KEV_WINDOW_DAYS))
    after, events = evolve.advance_one_day(estate, pool + [entry], MONDAY)
    assert events["new_kev"] == [] and entry["cve"] not in set(after["definition.cve"])


def test_a_fix_closes_every_row_of_that_finding(estate, pool):
    after, events = evolve.advance_one_day(estate, pool, MONDAY)
    assert events["fixed"]
    stamp = f"{MONDAY.isoformat()}T15:04:00Z"
    for item in events["fixed"]:
        rows = after[(after["asset.host_name"] == item["host"]) & (after["definition.cve"] == item["cve"])]
        assert not rows.empty
        assert set(rows["state"]) == {"FIXED"} and set(rows["last_fixed"]) == {stamp}


def test_weekends_are_quiet(estate, pool):
    _, events = evolve.advance_one_day(estate, pool, SATURDAY)
    assert len(events["fixed"]) <= 1


def test_new_findings_get_plugin_ids_nobody_else_has(estate, pool):
    frame = estate
    for offset in range(1, 6):
        frame, _ = evolve.advance_one_day(frame, pool, START + timedelta(days=offset))
    ids = frame["definition.id"]
    assert ids.is_unique
    columns = frame.drop_duplicates(["asset.id", "definition.cve", "port"])
    assert len(columns) == len(frame)


def test_old_fixed_findings_leave_the_export(estate, pool):
    frame = estate.copy()
    old = f"{(MONDAY - timedelta(days=evolve.RETENTION_DAYS + 5)).isoformat()}T15:04:00Z"
    target = frame.index[frame["state"] == "FIXED"][0]
    frame.loc[target, "last_fixed"] = old
    after, _ = evolve.advance_one_day(frame, pool, MONDAY)
    assert old not in set(after["last_fixed"])
    assert len(after) < len(frame) + 20


def test_catching_up_runs_each_missed_day_once(estate, pool):
    after, log = evolve.advance_to(estate, pool, START, START + timedelta(days=4))
    assert [item["date"] for item in log] == [(START + timedelta(days=n)).isoformat() for n in range(1, 5)]
    stepped = estate
    for n in range(1, 5):
        stepped, _ = evolve.advance_one_day(stepped, pool, START + timedelta(days=n))
    assert evolve.write_estate(after) == evolve.write_estate(stepped)
    unchanged, nothing = evolve.advance_to(after, pool, START + timedelta(days=4), START + timedelta(days=4))
    assert nothing == [] and evolve.write_estate(unchanged) == evolve.write_estate(after)


def test_a_long_gap_only_replays_the_most_recent_days(estate, pool):
    _, log = evolve.advance_to(estate, pool, START, START + timedelta(days=90))
    assert len(log) == evolve.MAX_CATCH_UP_DAYS
    assert log[-1]["date"] == (START + timedelta(days=90)).isoformat()


def test_the_log_keeps_the_last_month(tmp_path):
    path = tmp_path / "estate_log.json"
    days = [{"date": (START + timedelta(days=n)).isoformat(), "fixed": []} for n in range(45)]
    evolve.save_log(path, START + timedelta(days=44), days)
    loaded = evolve.load_log(path)
    assert loaded["as_of"] == (START + timedelta(days=44)).isoformat()
    assert len(loaded["days"]) == evolve.LOG_DAYS and loaded["days"][-1] == days[-1]
    path.write_text("not json", encoding="utf-8")
    assert evolve.load_log(path) is None
    path.write_text(json.dumps({"as_of": "soon"}), encoding="utf-8")
    assert evolve.load_log(path) is None
    assert evolve.load_log(tmp_path / "missing.json") is None


def test_the_day_reads_as_one_plain_sentence():
    assert evolve.summarize_day({}) == "Nothing was fixed and the scanner found nothing new."
    events = {
        "fixed": [{"cve": "CVE-1"}] * 4,
        "new_kev": [{"cve": "CVE-2026-0001", "vendor": "Acme", "product": "Gateway", "hosts": ["a", "b", "c"]}],
        "discovered": [{"cve": "CVE-2"}],
        "reopened": [{"cve": "CVE-3"}],
    }
    assert evolve.summarize_day(events) == (
        "Owners closed 4 findings, new KEV entry CVE-2026-0001 (Acme Gateway) turned up on 3 hosts, "
        "the scanner found 1 other new issue, and 1 fixed finding came back."
    )
    assert evolve.summarize_day({"fixed": [{}], "discovered": [{}, {}]}) == (
        "Owners closed 1 finding and the scanner found 2 new issues."
    )
    two = {"new_kev": [{"cve": "A", "hosts": ["x"]}, {"cve": "B", "hosts": ["y", "z"]}]}
    assert evolve.summarize_day(two) == "2 new KEV entries turned up on 3 hosts."


def test_the_morning_job_builds_then_advances_then_rests(tmp_path, monkeypatch, pool):
    refresh = _refresh_module()
    demo, log_path, meta = tmp_path / "findings.csv", tmp_path / "estate_log.json", tmp_path / "metadata.json"
    meta.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(refresh, "DEMO_CSV", demo)
    monkeypatch.setattr(refresh, "ESTATE_LOG", log_path)
    monkeypatch.setattr(refresh, "snapshot_path", lambda name: tmp_path / name)

    refresh._advance_estate(pool, START)
    built = demo.read_bytes()
    assert b"\r\n" not in built
    assert evolve.load_log(log_path) == {"seed": evolve.DEMO_SEED, "as_of": START.isoformat(), "days": []}

    refresh._advance_estate(pool, MONDAY)
    log = evolve.load_log(log_path)
    assert log["as_of"] == MONDAY.isoformat() and len(log["days"]) == 3
    assert json.loads(meta.read_text(encoding="utf-8"))["estate_as_of"] == MONDAY.isoformat()
    advanced = demo.read_bytes()
    assert advanced != built

    refresh._advance_estate(pool, MONDAY)
    assert demo.read_bytes() == advanced and len(evolve.load_log(log_path)["days"]) == 3


def test_the_pool_keeps_every_cve_the_estate_still_holds(tmp_path, monkeypatch, pool):
    refresh = _refresh_module()
    demo = tmp_path / "findings.csv"
    demo.write_text(generate_csv(pool, as_of=START, host_count=60), encoding="utf-8")
    monkeypatch.setattr(refresh, "DEMO_CSV", demo)
    estate_cves = set(evolve.read_estate(demo.read_text(encoding="utf-8"))["definition.cve"])
    kev_cve, earlier_cve, *rest = sorted(estate_cves)
    kev_entry = {"cveID": kev_cve, "vendorProject": "Acme", "product": "Gateway", "vulnerabilityName": "Acme Gateway flaw", "dateAdded": "2025-01-02"}
    earlier = [{"cve": earlier_cve, "name": "kept from yesterday", "in_kev": False, "cvss": 7.5}]

    carried = refresh._estate_carryover([], {kev_cve: kev_entry}, earlier)
    by_cve = {record["cve"]: record for record in carried}
    assert set(by_cve) == estate_cves
    assert by_cve[kev_cve]["in_kev"] is True and by_cve[kev_cve]["vendor"] == "Acme"
    assert by_cve[earlier_cve]["name"] == "kept from yesterday"
    assert all(by_cve[cve]["in_kev"] is False for cve in rest)
    assert refresh._estate_carryover([{"cve": cve} for cve in estate_cves], {}, []) == []
