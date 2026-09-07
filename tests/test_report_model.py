"""The rich report model: everything the flat DataFrame throws away."""

import pytest

from xnp.report_model import (
    HIGH_RISK_PORTS,
    HIGH_RISK_SERVICES,
    MEDIUM_RISK_PORTS,
    MEDIUM_RISK_SERVICES,
    build_hosts,
    classify_port,
    host_to_dict,
    merge_hosts,
    scan_to_dict,
)
from xnp.xml_report import NmapXMLReport

pytestmark = pytest.mark.usefixtures("quiet_logs")


@pytest.fixture
def report(xml):
    def _report(name, validate=True):
        return NmapXMLReport(xml(name), validate=validate)
    return _report


# --- Risk classification ----------------------------------------------------

@pytest.mark.parametrize("port,service,expected", [
    (445, "microsoft-ds", "high"),
    (23, "telnet", "high"),
    (6379, "redis", "high"),
    (22, "ssh", "medium"),
    (80, "http", "medium"),
    (49152, "unknown", "low"),
    (62078, None, "low"),
])
def test_ports_are_classified_by_number_and_service(port, service, expected):
    assert classify_port(port, service, None)["risk"] == expected


def test_a_database_on_an_unusual_port_is_still_caught():
    """The port number is not in the table, but -sV named the service."""
    assert classify_port(31337, "mongodb", None)["risk"] == "high"


def test_every_classification_carries_its_reason():
    """A red dot the reader cannot interrogate is a red dot they will ignore."""
    result = classify_port(445, "microsoft-ds", None)
    assert result["reasons"]
    for reason in result["reasons"]:
        assert set(reason) == {"en", "es"}
        assert all(isinstance(text, str) and text for text in reason.values())


def test_reasons_are_translated_not_duplicated():
    """The prose that explains a finding is the part most worth reading."""
    reason = classify_port(445, "microsoft-ds", None)["reasons"][0]
    assert reason["en"] != reason["es"]
    assert "SMB" in reason["en"] and "SMB" in reason["es"]


@pytest.mark.parametrize("table", [HIGH_RISK_PORTS, HIGH_RISK_SERVICES,
                                   MEDIUM_RISK_PORTS, MEDIUM_RISK_SERVICES])
def test_every_risk_entry_carries_both_languages(table):
    """A half-translated table ships English prose into a Spanish report."""
    for key, entry in table.items():
        assert isinstance(entry, tuple) and len(entry) == 2, key
        assert all(isinstance(text, str) and text.strip() for text in entry), key


def test_tls_demotes_a_cleartext_http_service():
    plain = classify_port(443, "http", None)
    tunnelled = classify_port(443, "http", "ssl")
    assert plain["cleartext"] is True
    assert tunnelled["cleartext"] is False
    assert tunnelled["risk"] == "low"


def test_an_unknown_port_and_service_is_low_with_no_reasons():
    result = classify_port(41234, None, None)
    assert result == {"risk": "low", "reasons": [], "cleartext": False}


# --- Host mapping -----------------------------------------------------------

def test_a_host_carries_what_the_dataframe_cannot(report):
    host = host_to_dict(report("full_scan").hosts[0], source="full_scan.xml")

    assert host["ip"]
    assert host["source"] == "full_scan.xml"
    # These five are precisely the fields get_simple_df drops on the floor.
    assert host["os"]["matches"], "OS detection should survive"
    assert host["os"]["best"]
    assert host["distance"] is not None
    assert host["extraports"] or host["trace"]
    assert host["state"] == "up"


def test_the_best_os_match_wins_and_names_its_family(report):
    host = host_to_dict(report("full_scan").hosts[0])
    accuracies = [match["accuracy"] for match in host["os"]["matches"]]
    assert accuracies == sorted(accuracies, reverse=True)
    assert host["os"]["accuracy"] == accuracies[0]


def test_structured_nse_tables_survive(report):
    hosts = [host_to_dict(h) for h in report("with_scripts").hosts]
    scripts = [s for host in hosts for port in host["ports"] for s in port["scripts"]]
    assert scripts, "the fixture has NSE output"
    assert any(script["tables"] for script in scripts), "structured <table> output is kept"


def test_ipv6_only_hosts_get_an_address(report):
    host = host_to_dict(report("ipv6_host").hosts[0])
    assert host["ipv4"] is None
    assert host["ipv6"]
    assert host["ip"] == host["ipv6"]


def test_scan_metadata_reaches_the_report(report):
    scan = scan_to_dict(report("full_scan"), source="full_scan.xml")
    assert scan["file"] == "full_scan.xml"
    assert scan["args"], "the nmap command line is the single most useful metadatum"
    assert scan["version"]
    assert scan["scaninfo"]


# --- build_hosts ------------------------------------------------------------

def test_only_open_drops_the_other_states(report):
    every = build_hosts([report("single_host")])
    open_only = build_hosts([report("single_host")], only_open=True)

    states = {port["state"] for host in every for port in host["ports"]}
    assert states > {"open"}, "the fixture has more than open ports"
    assert {port["state"] for host in open_only for port in host["ports"]} == {"open"}


def test_hosts_are_sorted_numerically_by_address(report):
    hosts = build_hosts([report("multi_host")])
    ips = [host["ip"] for host in hosts if host["ip"]]
    assert ips == sorted(ips, key=lambda ip: [int(o) for o in ip.split(".")])


def test_ports_within_a_host_are_ordered(report):
    host = build_hosts([report("single_host")])[0]
    keys = [(port["protocol"], port["port"]) for port in host["ports"]]
    assert keys == sorted(keys)


def test_a_host_that_is_up_with_no_ports_is_kept(report):
    """A fully filtered host is a finding, not an absence."""
    hosts = build_hosts([report("host_down")])
    assert hosts, "the host still belongs in the report"


# --- Merging ----------------------------------------------------------------

def test_merging_keeps_the_richest_record_per_port(report):
    hosts = build_hosts([report("dup_a"), report("dup_b")],
                        sources=["dup_a.xml", "dup_b.xml"], merge=True)

    ips = [host["ip"] for host in hosts]
    assert len(ips) == len(set(ips)), "one record per address"

    for host in hosts:
        keys = [(port["protocol"], port["port"]) for port in host["ports"]]
        assert len(keys) == len(set(keys)), "one record per protocol/port"


def test_merging_prefers_the_scan_that_identified_the_service():
    poor = {"ip": "10.0.0.1", "hostname": None, "mac": None, "mac_vendor": None,
            "state": "up", "os": {"matches": []},
            "ports": [{"protocol": "tcp", "port": 80,
                       "service": {"product": None, "version": None, "extrainfo": None}}]}
    rich = {"ip": "10.0.0.1", "hostname": "web", "mac": None, "mac_vendor": None,
            "state": "up", "os": {"matches": []},
            "ports": [{"protocol": "tcp", "port": 80,
                       "service": {"product": "nginx", "version": "1.18", "extrainfo": None}}]}

    merged = merge_hosts([poor, rich])
    assert len(merged) == 1
    assert merged[0]["ports"][0]["service"]["product"] == "nginx"
    assert merged[0]["hostname"] == "web", "a hostname resolved anywhere applies"


def test_hosts_without_an_address_are_not_merged_together():
    anonymous = [{"ip": None, "hostname": None, "mac": None, "mac_vendor": None,
                  "state": "up", "os": {"matches": []}, "ports": []} for _ in range(2)]
    assert len(merge_hosts(anonymous)) == 2


def test_a_non_numeric_attribute_becomes_none():
    """nmap emits strings; anything unparseable must not crash the report."""
    from xnp.report_model import _int
    assert _int("2049") == 2049
    assert _int("not-a-number") is None
    assert _int(None) is None


def test_a_host_without_an_ipv4_address_sorts_last():
    hosts = [{"ip": "10.0.0.2"}, {"ip": "fe80::1"}, {"ip": "10.0.0.1"}, {"ip": None}]
    from xnp.report_model import _host_sort_key
    order = [host["ip"] for host in sorted(hosts, key=_host_sort_key)]
    assert order[:2] == ["10.0.0.1", "10.0.0.2"], "IPv4 sorts numerically and first"


def test_merging_adopts_os_detection_from_whichever_scan_ran_it():
    blind = {"ip": "10.0.0.1", "hostname": None, "mac": None, "mac_vendor": None,
             "state": "up", "os": {"matches": []}, "ports": []}
    fingerprinted = {"ip": "10.0.0.1", "hostname": None, "mac": None, "mac_vendor": None,
                     "state": "up", "os": {"matches": [{"name": "Linux", "accuracy": 98}]},
                     "ports": []}
    merged = merge_hosts([blind, fingerprinted])
    assert merged[0]["os"]["matches"][0]["name"] == "Linux"
