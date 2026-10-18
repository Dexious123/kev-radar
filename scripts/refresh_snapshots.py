#!/usr/bin/env python3
"""Refresh the public KEV, EPSS, and Vulnrichment snapshots, then advance the demo estate.

No API key. Safe to re-run: the estate moves forward one simulated day per calendar day,
so a second run on the same day changes nothing. Pass --rotate to copy the current KEV
snapshot to kev_previous.json before downloading, which is what the daily workflow does.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kev_radar.evolve import (  # noqa: E402
    advance_to,
    load_log,
    read_estate,
    save_log,
    summarize_day,
    write_estate,
)
from kev_radar.feeds import (  # noqa: E402
    DEMO_CSV,
    EPSS_URL,
    ESTATE_LOG,
    SNAPSHOT_DIR,
    extract_enrichment,
    fetch_cve_record,
    fetch_epss,
    fetch_json,
    fetch_kev,
    load_json,
    parse_iso_date,
    snapshot_path,
    write_json,
)
from kev_radar.generate import DEMO_SEED, generate_csv  # noqa: E402
from kev_radar.kevdiff import ransomware_known  # noqa: E402
from kev_radar.taxonomy import family_for  # noqa: E402

OLD_RANSOM = 18
OLD_OTHER = 12
NON_KEV_TARGET = 30
RECENT_DAYS = 45
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _rotate() -> None:
    current = snapshot_path("kev.json")
    previous = snapshot_path("kev_previous.json")
    if current.exists():
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(current, previous)
        print(f"rotated {current.name} -> {previous.name}")


def _ensure_previous(catalog: dict, as_of: date) -> None:
    previous = snapshot_path("kev_previous.json")
    if previous.exists():
        return
    start = as_of - timedelta(days=6)
    kept = []
    for entry in catalog.get("vulnerabilities", []):
        added = parse_iso_date(entry.get("dateAdded"))
        if added is None or added < start:
            kept.append(entry)
    payload = dict(catalog)
    payload["vulnerabilities"] = kept
    payload["count"] = len(kept)
    write_json("kev_previous.json", payload)
    print(
        f"wrote initial previous snapshot with {len(kept)} entries "
        f"(dropped additions on or after {start.isoformat()})"
    )


def _kev_record(entry: dict) -> dict:
    return {
        "cve": str(entry["cveID"]).upper(),
        "vendor": entry.get("vendorProject") or "",
        "product": entry.get("product") or "",
        "name": entry.get("vulnerabilityName") or entry["cveID"],
        "family": family_for(
            entry.get("vendorProject") or "",
            entry.get("product") or "",
            entry.get("vulnerabilityName") or "",
        ),
        "in_kev": True,
        "ransomware": ransomware_known(entry),
        "date_added": entry.get("dateAdded"),
        "cvss": None,
        "cvss_vector": None,
        "epss": None,
    }


def _pool_from_kev(catalog: dict, as_of: date) -> list[dict]:
    """Recent KEV entries, plus a seeded slice of older ransomware and other KEVs."""
    week_start = as_of - timedelta(days=6)
    recent_start = as_of - timedelta(days=RECENT_DAYS)
    recent = []
    old_ransom = []
    old_other = []
    for entry in catalog.get("vulnerabilities", []):
        added = parse_iso_date(entry.get("dateAdded"))
        record = _kev_record(entry)
        if added is not None and recent_start <= added <= as_of:
            recent.append(record)
        elif record["ransomware"]:
            old_ransom.append(record)
        else:
            old_other.append(record)
    rng = random.Random(DEMO_SEED)
    rng.shuffle(old_ransom)
    rng.shuffle(old_other)
    chosen = recent + old_ransom[:OLD_RANSOM] + old_other[:OLD_OTHER]
    week = sum(1 for record in recent if parse_iso_date(record["date_added"]) and parse_iso_date(record["date_added"]) >= week_start)
    print(
        f"KEV pool: {week} added this week, {len(recent)} in the last {RECENT_DAYS} days, "
        f"{min(OLD_RANSOM, len(old_ransom))} older ransomware, {min(OLD_OTHER, len(old_other))} older other"
    )
    return chosen


def _estate_carryover(pool: list[dict], kev_by_id: dict[str, dict], previous: list) -> list[dict]:
    """Pool records for CVEs the estate still holds but today's pool slice left out.

    The pool is re-picked every morning while the estate keeps its findings, so without
    this an older finding would lose its CVSS, EPSS, Vulnrichment, and MSRC coverage.
    """
    if not DEMO_CSV.exists():
        return []
    estate = read_estate(DEMO_CSV.read_text(encoding="utf-8"))
    in_pool = {entry["cve"] for entry in pool}
    earlier = {str(entry.get("cve", "")).upper(): entry for entry in previous if isinstance(entry, dict)}
    carried = []
    for row in estate.drop_duplicates("definition.cve").to_dict("records"):
        cve = str(row["definition.cve"]).upper()
        if not cve or cve in in_pool:
            continue
        if cve in kev_by_id:
            record = _kev_record(kev_by_id[cve])
        elif cve in earlier:
            record = dict(earlier[cve])
        else:
            name = row["definition.name"] or cve
            record = {
                "cve": cve,
                "vendor": "",
                "product": "",
                "name": name,
                "family": family_for(name),
                "in_kev": False,
                "ransomware": False,
                "date_added": None,
                "cvss": float(row["definition.cvss3.base_score"]) if row["definition.cvss3.base_score"] else None,
                "cvss_vector": row["definition.cvss3.base_vector"] or None,
                "epss": None,
            }
        carried.append(record)
    return carried


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def _advance_estate(pool: list[dict], as_of: date, *, rebuild: bool = False) -> None:
    """Move the synthetic estate forward to ``as_of``, or build it if there is none yet."""
    log = None if rebuild else load_log(ESTATE_LOG)
    if log is None or not DEMO_CSV.exists():
        _write_text(DEMO_CSV, generate_csv(pool, as_of=as_of, seed=DEMO_SEED))
        save_log(ESTATE_LOG, as_of, [])
        print(f"built a new synthetic estate as of {as_of.isoformat()}")
        days: list[dict] = []
    else:
        since = date.fromisoformat(log["as_of"])
        if since >= as_of:
            print(f"estate is already at {since.isoformat()}; nothing to advance")
            return
        frame = read_estate(DEMO_CSV.read_text(encoding="utf-8"))
        frame, days = advance_to(frame, pool, since, as_of, seed=int(log.get("seed") or DEMO_SEED))
        _write_text(DEMO_CSV, write_estate(frame))
        save_log(ESTATE_LOG, as_of, list(log.get("days") or []) + days)
        for events in days:
            print(f"  {events['date']}: {summarize_day(events)}")
        print(f"advanced the estate {len(days)} day(s) to {as_of.isoformat()}: {len(frame)} rows")
    meta_path = snapshot_path("metadata.json")
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["estate_as_of"] = as_of.isoformat()
        meta_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")


def _non_kev_candidates(kev_ids: set[str]) -> list[str]:
    """Recent published CVEs from NVD that are not already in KEV."""
    windows = [
        ("2026-08-18T00:00:00.000", "2026-08-25T00:00:00.000"),
        ("2026-09-02T00:00:00.000", "2026-09-09T00:00:00.000"),
        ("2026-07-06T00:00:00.000", "2026-07-13T00:00:00.000"),
    ]
    found: list[str] = []
    for start, end in windows:
        try:
            payload = fetch_json(
                NVD_URL,
                params={"resultsPerPage": 50, "pubStartDate": start, "pubEndDate": end},
                timeout=45,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"NVD {start[:10]} failed: {exc}")
            time.sleep(6)
            continue
        for item in payload.get("vulnerabilities") or []:
            cve = str((item.get("cve") or {}).get("id") or "").upper()
            if cve and cve not in kev_ids and cve not in found:
                found.append(cve)
        print(f"NVD {start[:10]}: {len(found)} non-KEV candidates")
        time.sleep(6)
    if len(found) >= 40:
        return found
    for offset in (1500, 8000):
        try:
            payload = fetch_json(EPSS_URL, params={"limit": 100, "offset": offset})
        except Exception as exc:  # noqa: BLE001
            print(f"EPSS page offset {offset} failed: {exc}")
            continue
        for row in payload.get("data") or []:
            cve = str(row.get("cve") or "").upper()
            if cve and cve not in kev_ids and cve not in found:
                found.append(cve)
        time.sleep(0.3)
    return found


def _identity(record: dict, cve: str) -> tuple[str, str, str, str]:
    cna = (record.get("containers") or {}).get("cna") or {}
    title = cna.get("title") or cve
    affected = cna.get("affected") or []
    vendor = product = ""
    if affected and isinstance(affected[0], dict):
        vendor = affected[0].get("vendor") or ""
        product = affected[0].get("product") or ""
    summary = ""
    for item in cna.get("descriptions") or []:
        if isinstance(item, dict) and item.get("lang") == "en":
            summary = item.get("value") or ""
            break
    return vendor, product, title, summary


def _enrich(cves: list[str]) -> dict[str, dict]:
    results: dict[str, dict] = {}

    def one(cve: str) -> tuple[str, dict | None]:
        try:
            record = fetch_cve_record(cve)
        except Exception as exc:  # noqa: BLE001
            print(f"  {cve} record failed: {exc}")
            return cve, None
        return cve, {"record": record, "enrichment": extract_enrichment(record)}

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(one, cve) for cve in cves]
        done = 0
        for future in as_completed(futures):
            cve, payload = future.result()
            done += 1
            if payload is not None:
                results[cve] = payload
            if done % 25 == 0:
                print(f"  enriched {done}/{len(cves)}")
    return results


def _fetch_epss_map(cves: list[str]) -> tuple[dict[str, dict], str | None]:
    scores: dict[str, dict] = {}
    score_date = None
    unique = sorted(set(cves))
    for index, chunk in enumerate(_chunks(unique, 100), start=1):
        try:
            rows = fetch_epss(chunk)
        except Exception as exc:  # noqa: BLE001
            print(f"EPSS chunk {index} failed: {exc}")
            time.sleep(1)
            continue
        for row in rows:
            cve = str(row.get("cve") or "").upper()
            if not cve:
                continue
            scores[cve] = {
                "epss": float(row["epss"]) if row.get("epss") is not None else None,
                "percentile": float(row["percentile"]) if row.get("percentile") is not None else None,
            }
            score_date = row.get("date") or score_date
        print(f"EPSS chunk {index}: {len(scores)} scores")
        time.sleep(0.25)
    return scores, score_date


def refresh(rotate: bool, *, rebuild: bool = False) -> None:
    as_of = date.today()
    previous_pool = load_json("cve_pool.json") if snapshot_path("cve_pool.json").exists() else []
    if rotate:
        _rotate()
    print("downloading KEV catalog")
    catalog = fetch_kev()
    write_json("kev.json", catalog)
    print(f"KEV {catalog.get('catalogVersion')} count={catalog.get('count')}")
    _ensure_previous(catalog, as_of)

    kev_by_id = {str(entry["cveID"]).upper(): entry for entry in catalog.get("vulnerabilities", [])}
    kev_ids = set(kev_by_id)
    pool = _pool_from_kev(catalog, as_of)
    carried = [] if rebuild else _estate_carryover(pool, kev_by_id, previous_pool if isinstance(previous_pool, list) else [])
    print(f"carrying {len(carried)} CVEs the estate still holds")
    print("looking for non-KEV CVEs in EPSS pages")
    candidates = _non_kev_candidates(kev_ids)
    print(f"{len(candidates)} non-KEV candidates")

    to_enrich = list(dict.fromkeys([entry["cve"] for entry in pool + carried] + candidates[:80]))
    print(f"fetching CVE records for {len(to_enrich)} ids")
    enriched = _enrich(to_enrich)

    valid: list[dict] = []
    for cve in candidates:
        payload = enriched.get(cve)
        if not payload:
            continue
        fields = payload["enrichment"]
        if not fields.get("automatable") or not fields.get("technical_impact"):
            continue
        vendor, product, title, summary = _identity(payload["record"], cve)
        valid.append(
            {
                "cve": cve,
                "vendor": vendor,
                "product": product,
                "name": title,
                "family": family_for(vendor, product, title, summary),
                "in_kev": False,
                "ransomware": False,
                "date_added": None,
                "cvss": fields.get("cvss"),
                "cvss_vector": fields.get("cvss_vector"),
                "epss": None,
                "_shape": (
                    str(fields["automatable"]).lower(),
                    str(fields["technical_impact"]).lower(),
                ),
            }
        )
    by_shape: dict[tuple[str, str], list[dict]] = {}
    for record in valid:
        by_shape.setdefault(record["_shape"], []).append(record)
    non_kev = []
    while len(non_kev) < NON_KEV_TARGET and any(by_shape.values()):
        for shape in sorted(by_shape):
            bucket = by_shape[shape]
            if not bucket or len(non_kev) >= NON_KEV_TARGET:
                continue
            non_kev.append(bucket.pop())
    for record in non_kev:
        record.pop("_shape", None)
    print(f"non-KEV kept: {len(non_kev)} from {len(valid)} enriched, shapes={sorted(by_shape)}")
    pool.extend(non_kev)
    present = {entry["cve"] for entry in pool}
    pool.extend(entry for entry in carried if entry["cve"] not in present)

    print("fetching EPSS for the KEV catalog and the pool")
    epss_scores, epss_date = _fetch_epss_map(sorted(kev_ids | {entry["cve"] for entry in pool}))

    vulnrichment = {}
    for entry in pool:
        payload = enriched.get(entry["cve"])
        fields = payload["enrichment"] if payload else {}
        if entry.get("cvss") is None and fields.get("cvss") is not None:
            entry["cvss"] = fields.get("cvss")
            entry["cvss_vector"] = fields.get("cvss_vector")
        score = epss_scores.get(entry["cve"])
        if score and score.get("epss") is not None:
            entry["epss"] = score["epss"]
        if fields:
            vulnrichment[entry["cve"]] = {
                "automatable": fields.get("automatable"),
                "technical_impact": fields.get("technical_impact"),
                "exploitation": fields.get("exploitation"),
                "cvss": fields.get("cvss"),
                "cvss_vector": fields.get("cvss_vector"),
                "cvss_version": fields.get("cvss_version"),
                "ssvc_version": fields.get("ssvc_version"),
            }

    write_json("cve_pool.json", pool)
    write_json("epss.json", {"score_date": epss_date, "scores": epss_scores})
    write_json("vulnrichment.json", vulnrichment)
    metadata = {
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "as_of": as_of.isoformat(),
        "kev_catalog_version": catalog.get("catalogVersion"),
        "kev_count": catalog.get("count"),
        "kev_released": catalog.get("dateReleased"),
        "epss_date": epss_date,
        "epss_count": len(epss_scores),
        "vulnrichment_count": len(vulnrichment),
        "pool_count": len(pool),
        "previous_snapshot": (
            "The first previous snapshot is the catalog with entries added in "
            "the last 7 days removed, so the diff matches that window. "
            "The daily workflow copies the prior kev.json over it before each refresh."
        ),
        "sources": {
            "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "epss": EPSS_URL,
            "vulnrichment": "https://cveawg.mitre.org/api/cve/{cve}",
            "decision_table": "https://certcc.github.io/SSVC/howto/cisa_response/",
            "implementation_guidance": "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk",
        },
    }
    write_json("metadata.json", metadata)

    try:
        _refresh_msrc(pool)
    except Exception as exc:
        print(f"MSRC snapshot skipped: {exc}")

    _advance_estate(pool, as_of, rebuild=rebuild)


def _refresh_msrc(pool: list[dict]) -> None:
    from kev_radar.msrc import build_kb_snapshot, microsoft_cves

    cves = microsoft_cves(pool)
    print(f"MSRC lookup for {len(cves)} Microsoft CVEs")
    if not cves:
        return
    snapshot = build_kb_snapshot(cves)
    write_json("msrc_kb.json", snapshot)
    meta_path = snapshot_path("metadata.json")
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["msrc_fetched_at"] = snapshot["fetched_at"]
        meta["msrc_cve_count"] = snapshot["cve_count"]
        meta["msrc_patch_count"] = snapshot["patch_count"]
        sources = meta.setdefault("sources", {})
        sources["msrc"] = "https://api.msrc.microsoft.com/cvrf/v3.0/"
        meta_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print(f"wrote msrc_kb.json ({snapshot['patch_count']} KB articles)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Copy the current kev.json onto kev_previous.json before downloading.",
    )
    parser.add_argument(
        "--msrc-only",
        action="store_true",
        help="Refresh only the MSRC KB snapshot from the current CVE pool.",
    )
    parser.add_argument(
        "--estate-only",
        action="store_true",
        help="Advance the demo estate to today from the current CVE pool, without downloading anything.",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Throw the estate's history away and generate a fresh one as of today.",
    )
    args = parser.parse_args()
    if args.msrc_only or args.estate_only:
        pool = load_json("cve_pool.json")
        if not isinstance(pool, list):
            raise SystemExit("cve_pool.json is not a list")
        if args.msrc_only:
            _refresh_msrc(pool)
        else:
            _advance_estate(pool, date.today(), rebuild=args.rebuild)
        return
    refresh(rotate=args.rotate, rebuild=args.rebuild)


if __name__ == "__main__":
    main()
