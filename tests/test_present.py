"""Display helpers: host names, links into the fix queue, and the queue's column labels."""

import pandas as pd

from kev_radar.present import QUEUE_COLUMNS, QUEUE_LABELS, find_in_queue, queue_link, short_host


def test_only_the_lab_domain_is_trimmed():
    assert short_host("hl-pay-ws-010.lab.invalid") == "hl-pay-ws-010"
    assert short_host("db01.corp.example.com") == "db01.corp.example.com"
    assert short_host(None) == ""


def test_a_queue_link_encodes_host_and_cve():
    assert queue_link("a b&c.lab.invalid", "CVE-2026-0001") == "?page=Fix+queue&finding=a+b%26c.lab.invalid%7CCVE-2026-0001"


def test_a_requested_finding_is_found_by_host_and_cve():
    queue = pd.DataFrame({"host_name": ["a", "b", "b"], "cve": ["CVE-1", "CVE-1", "CVE-2"]})
    assert find_in_queue(queue, "b|cve-2") == 2
    assert find_in_queue(queue, "b|CVE-9") is None
    assert find_in_queue(queue, "no separator") is None
    assert find_in_queue(queue, None) is None
    assert find_in_queue(queue.iloc[0:0], "a|CVE-1") is None


def test_every_queue_column_has_a_readable_label():
    assert all(column in QUEUE_LABELS for column in QUEUE_COLUMNS)
    assert all("_" not in label for label in QUEUE_LABELS.values())
    assert QUEUE_COLUMNS.index("vuln_name") < QUEUE_COLUMNS.index("host_name")
