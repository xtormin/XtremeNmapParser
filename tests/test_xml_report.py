"""Mapping of the nmap XML schema onto the NmapXMLReport object model.

These are characterisation tests: several of them pin behaviour that is known
to be wrong and is corrected in a later commit.  Each one says so explicitly.
"""

import pytest
from lxml import etree

from xnp.errors import InvalidNmapReport, NotAnNmapReport, XnpError
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


# --- Optional host elements (OS detection, traceroute, timing) --------------

def test_os_detection_is_mapped(xml):
    host = NmapXMLReport(xml("full_scan")).hosts[0]
    os_info = host.os[0]
    assert os_info.portused[0].portid == "22"
    assert os_info.portused[0].proto == "tcp"
    assert os_info.osmatch[0].name == "Linux 5.0 - 5.14"
    assert os_info.osmatch[0].accuracy == "98"
    assert os_info.osfingerprint[0].fingerprint.startswith("SCAN(")


def test_osclass_and_its_cpe_are_mapped(xml):
    osclass = NmapXMLReport(xml("full_scan")).hosts[0].os[0].osmatch[0].osclass[0]
    assert osclass.vendor == "Linux"
    assert osclass.osfamily == "Linux"
    assert osclass.osgen == "5.X"
    assert osclass.cpe == ["cpe:/o:linux:linux_kernel:5"]


def test_traceroute_hops_are_mapped(xml):
    trace = NmapXMLReport(xml("full_scan")).hosts[0].trace[0]
    assert trace.proto == "tcp"
    assert trace.port == "22"
    assert [h.ttl for h in trace.hops] == ["1", "2"]
    assert trace.hops[0].host == "gw.lab.local"
    assert trace.hops[1].host is None


def test_distance_uptime_and_sequences_are_mapped(xml):
    host = NmapXMLReport(xml("full_scan")).hosts[0]
    assert host.distance[0].value == "1"
    assert host.uptime[0].seconds == "120847"
    assert host.tcpsequence[0].difficulty == "Good luck!"
    assert host.ipidsequence[0].class_ == "All zeros"
    assert host.tcptssequence[0].class_ == "1000HZ"


def test_a_mac_address_does_not_replace_the_ipv4_one(xml):
    addresses = {a.addrtype: a for a in NmapXMLReport(xml("full_scan")).hosts[0].addresses}
    assert addresses["mac"].vendor == "VMware"
    assert addresses["ipv4"].addr == "10.0.0.11"


def test_port_owner_is_mapped(xml):
    port = NmapXMLReport(xml("full_scan")).hosts[0].ports[0]
    assert port.owner[0].name == "root"


def test_tasks_and_hosthints_are_mapped(xml):
    report = NmapXMLReport(xml("full_scan"))
    assert report.task_begins[0].task == "Ping Scan"
    assert report.task_ends[0].extrainfo == "1 total hosts"
    progress = report.task_progresses[0]
    assert progress.percent == "42.50"
    assert progress.remaining == "12"          # used to be printed from `percent`
    assert report.hosthints[0].addresses[0].addr == "10.0.0.11"


def test_the_generated_str_names_the_class_and_its_fields(xml):
    report = NmapXMLReport(xml("full_scan"))
    rendered = str(report.hosts[0].trace[0].hops[0])
    assert rendered.startswith("Hop(")
    assert "ttl=1" in rendered and "host=gw.lab.local" in rendered


def test_task_progress_str_reports_remaining_not_percent(xml):
    """Regression: the hand written __str__ read self.percent for `remaining`."""
    rendered = str(NmapXMLReport(xml("full_scan")).task_progresses[0])
    assert "remaining=12" in rendered
    assert "percent=42.50" in rendered


def test_report_str_covers_the_top_level_sections(xml):
    rendered = str(NmapXMLReport(xml("full_scan")))
    assert "NmapXMLReport(" in rendered
    assert "NmapRun(" in rendered
    assert "ScanInfo(" in rendered


def test_skipped_targets_are_mapped(xml):
    target = NmapXMLReport(xml("full_scan")).target[0]
    assert target.specification == "10.0.0.250"
    assert target.status == "skipped"
    assert target.reason == "invalid"


def test_structured_script_output_is_parsed(xml):
    """<script><table><elem> was modelled but never actually built."""
    ssl_cert = NmapXMLReport(xml("with_scripts")).hosts[0].ports[0].script[1]
    assert ssl_cert.id == "ssl-cert"
    table = ssl_cert.tables[0]
    assert table.key == "subject"
    assert table.table_elements[0].key == "commonName"
    assert table.table_elements[0].content == "tls.lab.local"


def test_a_script_without_structured_output_has_no_tables(xml):
    assert NmapXMLReport(xml("with_scripts")).hosts[0].ports[0].script[0].tables == []


def test_an_unreadable_dtd_raises(monkeypatch, xml):
    monkeypatch.setattr(NmapXMLReport, "DTD_PATH", "/nonexistent/nmap.dtd")
    with pytest.raises(XnpError, match="Could not read the nmap DTD"):
        NmapXMLReport(xml("single_host"))


def test_many_dtd_errors_are_truncated(tmp_path):
    """Only the first few DTD complaints are quoted, with a count of the rest."""
    broken = tmp_path / "broken.xml"
    ports = "".join(
        f'<port protocol="bogus{i}" portid="{i}"><state state="open" reason="x" '
        f'reason_ttl="1"/></port>' for i in range(10))
    broken.write_text(
        '<?xml version="1.0"?><!DOCTYPE nmaprun>'
        '<nmaprun scanner="nmap" version="7.93" xmloutputversion="1.05">'
        '<verbose level="0"/><debugging level="0"/>'
        '<host><status state="up" reason="x" reason_ttl="1"/>'
        '<address addr="10.0.0.1" addrtype="ipv4"/>'
        f'<ports>{ports}</ports></host>'
        '<runstats><finished time="1" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>')

    with pytest.raises(InvalidNmapReport) as excinfo:
        NmapXMLReport(str(broken))
    message = str(excinfo.value)
    assert "and " in message and "more" in message
    assert message.count("ERROR:VALID") <= NmapXMLReport.MAX_REPORTED_DTD_ERRORS
