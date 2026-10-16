"""Exposure heatmap and per-host drill-down."""

from datetime import date

import pandas as pd

from kev_radar.surface import exposure_heatmap, heatmap_matrix, host_findings, host_index

AS_OF = date(2026, 10, 16)


def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "host_name": "edge.lab.invalid",
                "owner": "Owen",
                "business_unit": "Edge Network",
                "exposed": True,
                "in_kev": True,
                "state": "open",
                "cve": "CVE-2024-0001",
                "epss": 0.9,
                "score": 80,
                "sla_status": "Overdue",
                "decision_path": "KEV=Yes → Exposed=Yes",
            },
            {
                "host_name": "edge.lab.invalid",
                "owner": "Owen",
                "business_unit": "Edge Network",
                "exposed": True,
                "in_kev": False,
                "state": "open",
                "cve": "CVE-2024-0002",
                "epss": 0.1,
                "score": 20,
                "sla_status": "On track",
                "decision_path": "KEV=No",
            },
            {
                "host_name": "pay.lab.invalid",
                "owner": "Priya",
                "business_unit": "Payments",
                "exposed": False,
                "in_kev": True,
                "state": "fixed",
                "cve": "CVE-2024-0003",
                "epss": 0.4,
                "score": 50,
                "sla_status": "Fixed on time",
                "decision_path": "fixed",
            },
        ]
    )


def test_heatmap_lanes_are_mutually_exclusive():
    summary = exposure_heatmap(_frame())
    edge = summary[summary["business_unit"] == "Edge Network"]
    assert set(edge["lane"]) == {"Exposed · KEV", "Exposed · not KEV"}
    kev = edge[edge["lane"] == "Exposed · KEV"].iloc[0]
    assert int(kev["findings"]) == 1
    assert float(kev["mean_epss"]) == 0.9
    units, lanes, z, text = heatmap_matrix(summary)
    assert "Edge Network" in units
    assert lanes[3] == "Exposed · KEV"
    assert "1" in text[units.index("Edge Network")]


def test_host_drilldown_lists_every_finding():
    index = host_index(_frame())
    assert index.iloc[0]["host_name"] == "edge.lab.invalid"
    assert int(index.iloc[0]["open_findings"]) == 2
    assert int(index.iloc[0]["overdue"]) == 1
    detail = host_findings(_frame(), "edge.lab.invalid")
    assert list(detail["cve"])[0] == "CVE-2024-0001"
    assert len(detail) == 2
    assert host_findings(_frame(), "missing.lab.invalid").empty
