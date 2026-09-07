"""End to end runs through xnp.cli.main."""

import json
import re
import shutil

import pandas as pd
import pytest

pytestmark = pytest.mark.usefixtures("quiet_logs")


@pytest.fixture
def scans(tmp_path, fixtures_dir):
    """A working directory holding two scans of the same host, plus a nested one."""
    for name in ("dup_a", "dup_b"):
        shutil.copy(fixtures_dir / f"{name}.xml", tmp_path / f"{name}.xml")
    nested = tmp_path / "nested"
    nested.mkdir()
    shutil.copy(fixtures_dir / "single_host.xml", nested / "single_host.xml")
    return tmp_path


def test_single_file_writes_every_format_next_to_the_xml(run_cli, tmp_path, fixtures_dir):
    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)
    assert run_cli(["-f", str(scan)], cwd=tmp_path) == 0
    for extension in ("csv", "xlsx", "json", "html"):
        assert (tmp_path / f"scan.{extension}").is_file()


def test_single_file_with_open_and_all_columns(run_cli, tmp_path, fixtures_dir):
    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "csv", "--open", "-C", "all"], cwd=tmp_path) == 0
    result = pd.read_csv(tmp_path / "scan.csv", sep=";")
    assert "Scripts" in result.columns
    assert set(result["State Port"]) == {"open"}
    assert list(result["Port"]) == [22, 80]


def test_directory_mode_writes_one_output_per_scan(run_cli, scans):
    assert run_cli(["-d", str(scans) + "/", "-oF", "csv"], cwd=scans) == 0
    assert (scans / "dup_a.csv").is_file()
    assert (scans / "dup_b.csv").is_file()


def test_readme_example_merge_recursive_open_all(run_cli, scans):
    """The example the README advertises: -d nmap/ -M -R --open -C all."""
    assert run_cli(["-d", str(scans) + "/", "-M", "-R", "--open", "-C", "all",
                    "-oF", "csv"], cwd=scans) == 0
    merged = pd.read_csv(scans / "merged_nmap_scan_data.csv", sep=";")
    # dup_a + dup_b collapse to 2 ports, and the nested scan adds 10.0.0.1.
    assert set(merged["IP"]) == {"10.0.0.1", "10.0.0.10"}
    assert len(merged[merged["IP"] == "10.0.0.10"]) == 2
    assert merged[merged["Port"] == 80].iloc[0]["Product"] == "Apache httpd"


def test_merge_honours_an_explicit_output_name(run_cli, scans):
    assert run_cli(["-d", str(scans) + "/", "-M", "-oN", "informe", "-oF", "csv"],
                   cwd=scans) == 0
    assert (scans / "informe.csv").is_file()


def test_non_recursive_mode_ignores_nested_directories(run_cli, scans):
    assert run_cli(["-d", str(scans) + "/", "-oF", "csv"], cwd=scans) == 0
    assert not (scans / "nested" / "single_host.csv").exists()


def test_an_empty_directory_exits_with_the_no_input_code(run_cli, tmp_path):
    assert run_cli(["-d", str(tmp_path) + "/", "-oF", "csv"], cwd=tmp_path) == 3


def test_a_scan_without_data_produces_no_output(run_cli, tmp_path, fixtures_dir):
    scan = tmp_path / "empty.xml"
    shutil.copy(fixtures_dir / "no_hosts.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "csv"], cwd=tmp_path) == 0
    assert not (tmp_path / "empty.csv").exists()


def test_an_explicit_output_name_is_honoured_for_a_single_file(run_cli, tmp_path, fixtures_dir):
    """-oN used to be silently dropped whenever -f was used."""
    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)
    assert run_cli(["-f", str(scan), "-oN", "informe", "-oF", "csv"], cwd=tmp_path) == 0
    assert (tmp_path / "informe.csv").is_file()


def test_a_non_nmap_file_exits_cleanly(run_cli, tmp_path, fixtures_dir, capsys):
    """An unparseable input used to escape as an AttributeError traceback."""
    scan = tmp_path / "bad.xml"
    shutil.copy(fixtures_dir / "not_nmap.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "csv"], cwd=tmp_path) == 2
    assert not (tmp_path / "bad.csv").exists()


def test_masscan_output_needs_no_validate(run_cli, tmp_path, fixtures_dir):
    scan = tmp_path / "masscan.xml"
    shutil.copy(fixtures_dir / "masscan.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "csv"], cwd=tmp_path) == 2
    assert run_cli(["-f", str(scan), "-oF", "csv", "--no-validate"], cwd=tmp_path) == 0
    assert pd.read_csv(tmp_path / "masscan.csv", sep=";").iloc[0]["IP"] == "10.0.0.8"


def test_include_hostless_reports_a_down_host(run_cli, tmp_path, fixtures_dir):
    scan = tmp_path / "down.xml"
    shutil.copy(fixtures_dir / "host_down.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "csv"], cwd=tmp_path) == 0
    assert not (tmp_path / "down.csv").exists()

    assert run_cli(["-f", str(scan), "-oF", "csv", "--include-hostless"], cwd=tmp_path) == 0
    result = pd.read_csv(tmp_path / "down.csv", sep=";")
    assert list(result["IP"]) == ["10.0.0.4", "10.0.0.5"]
    assert result["Port"].isna().all()


def test_a_truncated_scan_reports_an_error(run_cli, tmp_path, fixtures_dir):
    scan = tmp_path / "cut.xml"
    shutil.copy(fixtures_dir / "malformed.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "csv"], cwd=tmp_path) == 2


def test_the_startup_version_check_is_skipped_in_tests(run_cli, tmp_path, fixtures_dir,
                                                       monkeypatch):
    """No XNP run may reach the network or the user's git checkout."""
    import xnp.update as update_module

    def forbidden(*args, **kwargs):
        raise AssertionError("the network must not be touched")

    monkeypatch.setattr(update_module.requests, "get", forbidden)
    monkeypatch.setattr(update_module.subprocess, "run", forbidden)
    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "csv"], cwd=tmp_path) == 0


def test_a_directory_that_disappears_mid_run_reports_cleanly(tmp_path):
    """parse_xml_files translates filesystem errors into a clean XnpError."""
    from xnp.cli import parse_xml_files
    from xnp.errors import XnpError

    with pytest.raises(XnpError, match="not found"):
        parse_xml_files(single_xml=None, folder_multiple_xml=str(tmp_path / "gone") + "/",
                        list_output_format=["csv"], file_output_name=None, merger=False,
                        recursive=False, df_columns=["IP", "Port"], only_open_ports=False)


def test_a_file_passed_where_a_directory_is_expected_reports_cleanly(tmp_path):
    from xnp.cli import parse_xml_files
    from xnp.errors import XnpError

    scan = tmp_path / "scan.xml"
    scan.write_text("<x/>")
    with pytest.raises(XnpError, match="is a directory"):
        parse_xml_files(single_xml=None, folder_multiple_xml=str(scan),
                        list_output_format=["csv"], file_output_name=None, merger=False,
                        recursive=False, df_columns=["IP", "Port"], only_open_ports=False)


def test_a_directory_with_a_dataless_scan_skips_only_that_file(run_cli, tmp_path,
                                                               fixtures_dir):
    shutil.copy(fixtures_dir / "single_host.xml", tmp_path / "good.xml")
    shutil.copy(fixtures_dir / "no_hosts.xml", tmp_path / "empty.xml")
    assert run_cli(["-d", str(tmp_path) + "/", "-oF", "csv"], cwd=tmp_path) == 0
    assert (tmp_path / "good.csv").is_file()
    assert not (tmp_path / "empty.csv").exists()


# --- HTML report end to end -------------------------------------------------

def _payload(path):
    """Read back the JSON the report embeds for the browser."""
    match = re.search(r'<script id="xnp-data" type="application/json">(.*?)</script>',
                      path.read_text(encoding="utf-8"), re.DOTALL)
    assert match
    return json.loads(match.group(1))


def test_the_html_report_carries_scan_metadata_and_os(run_cli, tmp_path, fixtures_dir):
    """The whole point of the format: more than the eleven flat columns."""
    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "full_scan.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "html"], cwd=tmp_path) == 0

    payload = _payload(tmp_path / "scan.html")
    assert payload["scans"][0]["args"], "the nmap command line"
    assert any(host["os"]["matches"] for host in payload["hosts"]), "OS detection"


def test_merged_html_report_is_written_once(run_cli, scans):
    assert run_cli(["-d", str(scans) + "/", "-M", "-R", "-oF", "html"], cwd=scans) == 0
    merged = scans / "merged_nmap_scan_data.html"
    assert merged.is_file()

    payload = _payload(merged)
    ips = [host["ip"] for host in payload["hosts"]]
    assert len(ips) == len(set(ips)), "merging deduplicates hosts in the report too"
    assert len(payload["scans"]) > 1, "every source scan is listed"


def test_open_only_reaches_the_html_report(run_cli, tmp_path, fixtures_dir):
    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "html", "--open"], cwd=tmp_path) == 0

    payload = _payload(tmp_path / "scan.html")
    assert payload["only_open"] is True
    assert {p["state"] for h in payload["hosts"] for p in h["ports"]} == {"open"}


def test_the_html_report_makes_no_network_requests(run_cli, tmp_path, fixtures_dir):
    """A deliverable that phones home is a deliverable that leaks the engagement."""
    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "full_scan.xml", scan)
    assert run_cli(["-f", str(scan), "-oF", "html"], cwd=tmp_path) == 0

    document = (tmp_path / "scan.html").read_text(encoding="utf-8")
    assert not re.search(r'<(?:script|iframe)[^>]+\ssrc=', document)
    assert not re.search(r'<(?:link|img)[^>]+\s(?:href|src)=["\']?https?:', document)


# --- One bad file must not cost you the good ones ---------------------------

def test_a_directory_run_skips_a_file_that_does_not_validate(run_cli, tmp_path,
                                                             fixtures_dir, caplog):
    """Pointing at a directory means "process what is here"."""
    for name in ("single_host", "multi_host"):
        shutil.copy(fixtures_dir / f"{name}.xml", tmp_path / f"{name}.xml")
    shutil.copy(fixtures_dir / "masscan.xml", tmp_path / "masscan.xml")

    assert run_cli(["-d", str(tmp_path) + "/", "-M", "-oF", "csv",
                    "-oN", str(tmp_path / "merged")], cwd=tmp_path) == 0

    merged = pd.read_csv(tmp_path / "merged.csv", sep=";")
    assert not merged.empty, "the valid scans still produced a report"
    assert "masscan" in caplog.text and "Skipping" in caplog.text


def test_the_skipped_files_are_named_at_the_end(run_cli, tmp_path, fixtures_dir, caplog):
    """A partial run is never a silent one."""
    shutil.copy(fixtures_dir / "single_host.xml", tmp_path / "good.xml")
    shutil.copy(fixtures_dir / "masscan.xml", tmp_path / "bad.xml")

    assert run_cli(["-d", str(tmp_path) + "/", "-oF", "csv"], cwd=tmp_path) == 0
    assert (tmp_path / "good.csv").is_file()
    assert not (tmp_path / "bad.csv").exists()
    assert "1 of 2 files were skipped" in caplog.text
    assert "bad.xml" in caplog.text


def test_a_directory_where_nothing_parses_is_still_an_error(run_cli, tmp_path,
                                                            fixtures_dir):
    """Skipping everything is a failed run, not a successful empty one."""
    shutil.copy(fixtures_dir / "masscan.xml", tmp_path / "one.xml")
    shutil.copy(fixtures_dir / "not_nmap.xml", tmp_path / "two.xml")

    assert run_cli(["-d", str(tmp_path) + "/", "-oF", "csv"], cwd=tmp_path) == 2
    assert not list(tmp_path.glob("*.csv"))


def test_merging_a_directory_where_nothing_parses_is_an_error(run_cli, tmp_path,
                                                              fixtures_dir):
    shutil.copy(fixtures_dir / "masscan.xml", tmp_path / "one.xml")
    assert run_cli(["-d", str(tmp_path) + "/", "-M", "-oF", "csv"], cwd=tmp_path) == 2


def test_a_named_file_that_does_not_validate_still_fails(run_cli, tmp_path, fixtures_dir):
    """With -f you named that file, so its failure is the run's failure."""
    shutil.copy(fixtures_dir / "masscan.xml", tmp_path / "scan.xml")
    assert run_cli(["-f", str(tmp_path / "scan.xml"), "-oF", "csv"], cwd=tmp_path) == 2
    assert not (tmp_path / "scan.csv").exists()
