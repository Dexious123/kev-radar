"""The bundled demo estate must load: it is the first thing every visitor sees."""

import csv
from pathlib import Path

from kev_radar.evolve import load_log
from kev_radar.parse import parse_findings

DEMO_CSV = Path(__file__).resolve().parents[1] / "data" / "demo" / "tenable_findings.csv"
ESTATE_LOG = DEMO_CSV.with_name("estate_log.json")


def test_every_row_has_the_header_column_count():
    # An unquoted comma written into a cell adds a column and shifts every field after it.
    with DEMO_CSV.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    widths = {len(row) for row in rows}
    assert widths == {len(rows[0])}


def test_the_demo_estate_parses_into_findings():
    result = parse_findings(str(DEMO_CSV))
    assert len(result.findings) > 1000
    assert result.warnings == []


def test_the_estate_log_and_the_csv_agree_on_the_lab_date():
    # The morning job advances the CSV and the log together; a mismatch would replay or skip days.
    log = load_log(ESTATE_LOG)
    assert log is not None
    with DEMO_CSV.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    latest = max(row["last_seen"][:10] for row in rows)
    assert latest == log["as_of"]
    assert all(row["first_observed"][:10] <= log["as_of"] for row in rows)
