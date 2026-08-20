"""Mapping of the nmap XML schema onto the NmapXMLReport object model.

These are characterisation tests: several of them pin behaviour that is known
to be wrong and is corrected in a later commit.  Each one says so explicitly.
"""

import pytest
from lxml import etree

from xnp.errors import InvalidNmapReport, NotAnNmapReport
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


def test_nmaprun_metadata_is_read_from_the_root_element(xml):
    """The root element *is* <nmaprun>, so its attributes live on the root."""
    nmaprun = NmapXMLReport(xml("single_host")).nmaprun
    assert nmaprun.scanner == "nmap"
    assert nmaprun.version == "7.93"
    assert nmaprun.xmloutputversion == "1.05"
    assert nmaprun.startstr == "Sat Jun 24 12:00:00 2023"
    assert "nmap -sV" in nmaprun.args


# --- Layer 2: the root element must be <nmaprun> ---------------------------

def test_a_non_nmap_xml_is_rejected_with_a_clear_error(xml):
    with pytest.raises(NotAnNmapReport) as excinfo:
        NmapXMLReport(xml("not_nmap"))
    assert "is not an nmap XML report" in str(excinfo.value)
    assert "<report>" in str(excinfo.value)
    assert excinfo.value.exit_code == 2


def test_the_root_check_runs_even_with_validation_disabled(xml):
    """--no-validate relaxes the DTD, never the "is this nmap at all" check."""
    with pytest.raises(NotAnNmapReport):
        NmapXMLReport(xml("not_nmap"), validate=False)


# --- Layer 3: DTD validation ------------------------------------------------

def test_masscan_output_is_rejected_by_the_dtd(xml):
    """The DTD pins scanner="nmap", so nmap-compatible output fails validation."""
    with pytest.raises(InvalidNmapReport) as excinfo:
        NmapXMLReport(xml("masscan"))
    message = str(excinfo.value)
    assert "does not validate against nmap.dtd" in message
    assert "--no-validate" in message
    assert "masscan" in message           # quotes the real DTD complaint
    assert excinfo.value.exit_code == 2


def test_no_validate_accepts_masscan_output(xml):
    report = NmapXMLReport(xml("masscan"), validate=False)
    assert len(report.hosts) == 1
    assert report.hosts[0].addresses[0].addr == "10.0.0.8"
    assert report.nmaprun.scanner == "masscan"


def test_a_valid_report_still_validates(xml):
    assert NmapXMLReport(xml("single_host"), validate=True).hosts


# --- Layer 1: the hardened parser -------------------------------------------

def test_malformed_xml_raises_a_syntax_error(xml):
    with pytest.raises(etree.XMLSyntaxError):
        NmapXMLReport(xml("malformed"))


def test_the_parser_never_resolves_external_entities(xml, fixtures_dir):
    """XXE guard: the canary in xxe_secret.txt must never reach the tree.

    lxml's defaults already refuse to expand the entity; pinning the parser
    flags explicitly means that stays true regardless of future defaults.
    """
    assert (fixtures_dir / "xxe_secret.txt").read_text().strip() == CANARY

    report = NmapXMLReport(xml("xxe"))
    assert report.hosts[0].ports[0].service[0].cpe == [None]

    tree = etree.parse(xml("xxe"), NmapXMLReport.PARSER)
    assert CANARY not in etree.tostring(tree.getroot(), encoding="unicode")


def test_the_parser_does_not_expand_nested_entities(tmp_path):
    """Billion-laughs guard: nested entities must not be expanded either."""
    bomb = tmp_path / "bomb.xml"
    bomb.write_text(
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE nmaprun [\n'
        '  <!ENTITY a "AAAAAAAAAA">\n'
        '  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
        '  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
        ']>\n'
        '<nmaprun scanner="nmap" version="7.93" xmloutputversion="1.05">\n'
        '<verbose level="0"/><debugging level="0"/>\n'
        '<host><status state="up" reason="x" reason_ttl="1"/>\n'
        '<address addr="10.0.0.1" addrtype="ipv4"/>\n'
        '<ports><port protocol="tcp" portid="80">\n'
        '<state state="open" reason="x" reason_ttl="1"/>\n'
        '<service name="http" method="table" conf="3"><cpe>&c;</cpe></service>\n'
        '</port></ports></host>\n'
        '<runstats><finished time="1" exit="success"/><hosts up="1" down="0" total="1"/>'
        '</runstats></nmaprun>\n')

    tree = etree.parse(str(bomb), NmapXMLReport.PARSER)
    assert "AAAAAAAAAA" not in etree.tostring(tree.getroot(), encoding="unicode")
