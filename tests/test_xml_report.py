"""Mapping of the nmap XML schema onto the NmapXMLReport object model.

These are characterisation tests: several of them pin behaviour that is known
to be wrong and is corrected in a later commit.  Each one says so explicitly.
"""

import pytest
from lxml import etree

from xnp.xml_report import NmapXMLReport

CANARY = "CANARIO-XXE-NO-DEBE-APARECER"


def test_hosts_addresses_and_hostnames(xml):
    report = NmapXMLReport(xml("single_host"))
    assert len(report.hosts) == 1
    host = report.hosts[0]
    assert host.status[0].state == "up"
    assert host.addresses[0].addr == "10.0.0.1"
    assert host.addresses[0].addrtype == "ipv4"
    assert host.hostnames[0].hostnames[0].name == "web.lab.local"


def test_ports_states_and_services(xml):
    host = NmapXMLReport(xml("single_host")).hosts[0]
    assert [p.portid for p in host.ports] == ["80", "22", "443"]
    http = host.ports[0]
    assert http.protocol == "tcp"
    assert http.state[0].state == "open"
    assert http.service[0].name == "http"
    assert http.service[0].product == "Apache httpd"
    assert http.service[0].version == "2.4.52"
    assert http.service[0].extrainfo == "(Ubuntu)"


def test_extraports_are_mapped(xml):
    host = NmapXMLReport(xml("single_host")).hosts[0]
    assert host.extraports[0].state == "closed"
    assert host.extraports[0].count == "997"
    assert host.extraports[0].extrareasons[0].reason == "resets"


def test_scripts_cpe_and_nested_tables(xml):
    port = NmapXMLReport(xml("with_scripts")).hosts[0].ports[0]
    assert [s.id for s in port.script] == ["http-title", "ssl-cert"]
    assert port.script[0].output == "Welcome"
    assert port.service[0].cpe == ["cpe:/a:igor_sysoev:nginx:1.24.0"]


def test_scaninfo_verbose_and_debugging(xml):
    report = NmapXMLReport(xml("single_host"))
    assert report.scaninfo[0].type == "syn"
    assert report.scaninfo[0].protocol == "tcp"
    assert report.verbose[0].level == "0"
    assert report.debugging[0].level == "0"


def test_report_without_hosts_is_valid_but_empty(xml):
    assert NmapXMLReport(xml("no_hosts")).hosts == []


def test_ipv6_address_is_mapped_in_the_object_model(xml):
    """The object model does see IPv6; it is the DataFrame layer that drops it."""
    address = NmapXMLReport(xml("ipv6_host")).hosts[0].addresses[0]
    assert address.addrtype == "ipv6"
    assert address.addr == "2001:db8::1"


def test_host_without_ports_is_mapped(xml):
    hosts = NmapXMLReport(xml("host_down")).hosts
    assert len(hosts) == 2
    assert hosts[0].status[0].state == "down"
    assert hosts[0].ports == []


# --- Bugs pinned here, fixed in the next commit -----------------------------

def test_CURRENT_nmaprun_metadata_is_always_empty(xml):
    """BUG: the root element *is* <nmaprun>, so findall('nmaprun') never matches.

    scanner / args / version are silently lost.
    """
    assert NmapXMLReport(xml("single_host")).nmaprun == []


def test_CURRENT_dtd_failure_leaves_the_object_half_built(xml):
    """BUG: when the DTD does not validate, __init__ assigns nothing at all.

    Callers then blow up with AttributeError instead of getting a clear error.
    """
    report = NmapXMLReport(xml("not_nmap"))
    with pytest.raises(AttributeError, match="has no attribute 'hosts'"):
        report.hosts


def test_CURRENT_masscan_output_is_rejected_by_the_dtd(xml):
    """The DTD pins scanner="nmap", so nmap-compatible output is rejected."""
    report = NmapXMLReport(xml("masscan"))
    with pytest.raises(AttributeError):
        report.hosts


def test_malformed_xml_raises_a_syntax_error(xml):
    with pytest.raises(etree.XMLSyntaxError):
        NmapXMLReport(xml("malformed"))


def test_external_entities_are_never_expanded(xml, fixtures_dir):
    """XXE guard: the canary from xxe_secret.txt must never reach the parser.

    lxml's default parser does not load the internal DTD subset, so the file is
    rejected outright.  The assertion is written so that it keeps holding if the
    parser is later hardened explicitly and the file parses with an empty entity.
    """
    assert (fixtures_dir / "xxe_secret.txt").read_text().strip() == CANARY
    try:
        report = NmapXMLReport(xml("xxe"))
    except etree.XMLSyntaxError as exc:
        assert CANARY not in str(exc)
        return
    assert CANARY not in etree.tostring(
        etree.parse(xml("xxe")).getroot(), encoding="unicode")
    assert report is not None
