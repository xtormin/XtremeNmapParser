"""The self-contained HTML report."""

import json
import re

import pytest

from xnp import html_report
from xnp.output import df_output_filters, df_to_html
from xnp.parser import NmapParser
from xnp.xml_report import NmapXMLReport

pytestmark = pytest.mark.usefixtures("quiet_logs")

DEFAULT_COLUMNS = [
    'Hostname', 'IP', 'State', 'Port', 'Protocol', 'State Port',
    'Service Name', 'Product', 'Version', 'Extrainfo',
]


@pytest.fixture
def report(xml):
    def _report(name):
        return NmapXMLReport(xml(name))
    return _report


def embedded_payload(document):
    """Pull the JSON payload back out of a rendered report."""
    match = re.search(r'<script id="xnp-data" type="application/json">(.*?)</script>',
                      document, re.DOTALL)
    assert match, "the report must carry its data as embedded JSON"
    return json.loads(match.group(1))


# --- Rendering --------------------------------------------------------------

def test_the_report_is_a_single_self_contained_file(report):
    document = html_report.render(html_report.build_payload([report("full_scan")]))

    assert document.startswith("<!DOCTYPE html>")
    assert "{{" not in document, "every placeholder must be substituted"
    # No external reference of any kind: the report has to open offline.
    assert not re.search(r'<script[^>]+\ssrc=', document)
    assert not re.search(r'<link[^>]+\srel=["\']?stylesheet', document)
    assert "//cdn" not in document and "https://cdnjs" not in document


def test_chartjs_is_inlined(report):
    document = html_report.render(html_report.build_payload([report("single_host")]))
    assert "Chart.js v4.5.1" in document


def test_both_themes_ship_in_the_stylesheet(report):
    document = html_report.render(html_report.build_payload([report("single_host")]))
    assert ':root[data-theme="dark"]' in document
    assert "color-scheme: light" in document


def test_the_payload_round_trips_as_json(report):
    payload = html_report.build_payload([report("full_scan")], sources=["full_scan.xml"])
    parsed = embedded_payload(html_report.render(payload))

    assert parsed["hosts"], "hosts reach the browser"
    assert parsed["scans"][0]["args"], "so does the nmap command line"
    assert parsed["xnp_version"]


# --- Escaping: banners are attacker controlled ------------------------------

def test_a_hostile_banner_cannot_close_the_script_element(report):
    """A service banner is written by the target, not by us."""
    document = html_report.render(html_report.build_payload([report("hostile_banner")]))

    payload_block = re.search(
        r'<script id="xnp-data" type="application/json">(.*?)</script>',
        document, re.DOTALL).group(1)

    assert "</script" not in payload_block.lower()
    assert "<img" not in payload_block.lower()
    assert "\\u003c" in payload_block, "angle brackets are escaped, not stripped"


def test_the_hostile_payload_still_decodes_to_the_original_text(report):
    parsed = embedded_payload(
        html_report.render(html_report.build_payload([report("hostile_banner")])))

    products = [port["service"]["product"]
                for host in parsed["hosts"] for port in host["ports"]]
    assert any("alert(document.domain)" in (p or "") for p in products), \
        "escaping must not corrupt the evidence"


def test_a_hostile_scan_title_is_escaped_in_the_header(report):
    payload = html_report.build_payload([report("hostile_banner")],
                                        title='<img src=x onerror=alert(1)>')
    document = html_report.render(payload)
    assert "<img src=x" not in document
    assert "&lt;img src=x" in document


# --- Payload contents -------------------------------------------------------

def test_only_open_is_carried_into_the_payload(report):
    payload = html_report.build_payload([report("single_host")], only_open=True)
    assert payload["only_open"] is True
    assert {port["state"] for host in payload["hosts"] for port in host["ports"]} == {"open"}


def test_merging_several_reports_produces_one_host_list(report):
    payload = html_report.build_payload([report("dup_a"), report("dup_b")],
                                        sources=["dup_a.xml", "dup_b.xml"], merge=True)
    assert len(payload["scans"]) == 2
    ips = [host["ip"] for host in payload["hosts"]]
    assert len(ips) == len(set(ips))


# --- The DataFrame-only fallback -------------------------------------------

def test_the_writer_works_without_the_parsed_reports(xml, tmp_path):
    """``df_to_html(df, path)`` must honour the plain writer contract."""
    df = df_output_filters(NmapParser(xml("single_host")).parse_file(),
                           DEFAULT_COLUMNS, False)
    target = tmp_path / "fallback.html"
    df_to_html(df, str(target))

    parsed = embedded_payload(target.read_text(encoding="utf-8"))
    assert parsed["hosts"]
    assert parsed["scans"] == [], "no reports means no scan metadata, not a crash"
    assert any(port["port"] for host in parsed["hosts"] for port in host["ports"])


def test_the_fallback_still_classifies_risk(xml, tmp_path):
    df = df_output_filters(NmapParser(xml("single_host")).parse_file(),
                           DEFAULT_COLUMNS, False)
    target = tmp_path / "fallback.html"
    df_to_html(df, str(target))

    parsed = embedded_payload(target.read_text(encoding="utf-8"))
    risks = {port["risk"] for host in parsed["hosts"] for port in host["ports"]}
    assert risks <= {"high", "medium", "low"}
    assert risks != {"low"}, "the fixture has ssh and http on their usual ports"


def test_the_rich_context_beats_the_fallback(xml, tmp_path, report):
    """Same DataFrame, but with reports the report gains OS detection."""
    df = df_output_filters(NmapParser(xml("full_scan")).parse_file(),
                           DEFAULT_COLUMNS, False)

    poor = tmp_path / "poor.html"
    rich = tmp_path / "rich.html"
    df_to_html(df, str(poor))
    df_to_html(df, str(rich),
               context={"reports": [report("full_scan")], "sources": [xml("full_scan")]})

    assert not any(host["os"]["matches"]
                   for host in embedded_payload(poor.read_text(encoding="utf-8"))["hosts"])
    assert any(host["os"]["matches"]
               for host in embedded_payload(rich.read_text(encoding="utf-8"))["hosts"])


# --- Error and edge paths ---------------------------------------------------

def test_a_missing_report_asset_is_reported_clearly(report, monkeypatch):
    from pathlib import Path

    from xnp.errors import XnpError

    def boom(self, encoding=None):
        raise OSError("no such file")

    monkeypatch.setattr(Path, "read_text", boom)
    with pytest.raises(XnpError, match="Missing report asset"):
        html_report.render(html_report.build_payload([report("single_host")]))


def test_a_row_without_a_usable_port_is_skipped_by_the_fallback():
    import pandas as pd

    df = pd.DataFrame([
        {"Hostname": "a", "IP": "10.0.0.1", "State": "up", "Port": None,
         "Protocol": None, "State Port": None, "Service Name": None,
         "Product": None, "Version": None, "Extrainfo": None},
        {"Hostname": "a", "IP": "10.0.0.1", "State": "up", "Port": "not-a-port",
         "Protocol": "tcp", "State Port": "open", "Service Name": "http",
         "Product": None, "Version": None, "Extrainfo": None},
    ])
    payload = html_report.payload_from_dataframe(df)
    assert payload["hosts"][0]["ports"] == []


def test_the_title_travels_in_both_languages(report):
    """The header is rendered in the browser, so both titles must be present."""
    payload = html_report.build_payload([report("single_host")],
                                        title="Informe", title_en="Report")
    assert payload["title"] == "Informe"
    assert payload["title_en"] == "Report"

    parsed = embedded_payload(html_report.render(payload))
    assert parsed["title"] == "Informe"
    assert parsed["title_en"] == "Report"


def test_an_english_title_falls_back_to_the_spanish_one(report):
    payload = html_report.build_payload([report("single_host")], title="Solo uno")
    assert payload["title_en"] == "Solo uno"


def test_the_header_chips_are_built_in_the_browser(report):
    """They used to be baked in Spanish by Python; the report is bilingual now."""
    document = html_report.render(html_report.build_payload(
        [report("dup_a"), report("dup_b")], sources=["dup_a.xml", "dup_b.xml"], merge=True))

    body = document[document.index("<body>"):document.index('<script id="xnp-data"')]
    assert '<div class="meta" id="meta"></div>' in body, "filled in by the browser"
    assert "META_CHIPS" not in document


def test_both_languages_ship_in_the_report(report):
    document = html_report.render(html_report.build_payload([report("single_host")]))
    assert '"tab.summary": "Resumen"' in document
    assert '"tab.summary": "Summary"' in document
    assert 'id="lang-select"' in document


def test_the_markup_carries_no_untranslated_prose(report):
    """Anything the reader sees is keyed, so a language switch leaves nothing behind."""
    document = html_report.render(html_report.build_payload(
        [report("single_host")], title="TITULO", title_en="TITLE"))
    body = document[document.index("<body>"):document.index('<script id="xnp-data"')]

    visible = [text.strip() for text in re.findall(r">([^<>]+)<", body) if text.strip()]
    # What legitimately stays: the configured title, the version tag, the two
    # glyph-only buttons, and the language names -- "ES" and "EN" read the same
    # in either language, which is the point of writing them that way.
    allowed = {"TITULO", "xnp " + html_report.__version__, "\u2715", "&gt;", "ES", "EN"}
    assert set(visible) <= allowed, f"untranslated text left in the markup: {set(visible) - allowed}"


def test_the_fonts_are_inlined_not_fetched(report):
    """The type is most of the design; it has to survive an offline machine."""
    document = html_report.render(html_report.build_payload([report("single_host")]))
    assert document.count("@font-face") == len(html_report.FONT_FACES)
    assert "src:url(data:font/woff2;base64," in document
    assert "fonts.googleapis" not in document and "fonts.gstatic" not in document


def test_a_missing_font_is_reported_clearly(monkeypatch):
    from pathlib import Path

    from xnp.errors import XnpError

    def boom(self):
        raise OSError("no such file")

    monkeypatch.setattr(Path, "read_bytes", boom)
    with pytest.raises(XnpError, match="Missing report font"):
        html_report._font_faces()
