"""End to end runs through xnp.cli.main."""

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
    for extension in ("csv", "xlsx", "json"):
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


# --- Bugs pinned here, fixed in the next commit -----------------------------

def test_CURRENT_output_name_is_ignored_for_a_single_file(run_cli, tmp_path, fixtures_dir):
    """BUG: -oN is silently dropped when -f is used."""
    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)
    assert run_cli(["-f", str(scan), "-oN", "informe", "-oF", "csv"], cwd=tmp_path) == 0
    assert (tmp_path / "scan.csv").is_file()
    assert not (tmp_path / "informe.csv").exists()


def test_CURRENT_a_non_nmap_file_crashes_with_a_traceback(run_cli, tmp_path, fixtures_dir):
    """BUG: an unparseable input escapes as AttributeError instead of exit 2."""
    scan = tmp_path / "bad.xml"
    shutil.copy(fixtures_dir / "not_nmap.xml", scan)
    with pytest.raises(AttributeError):
        run_cli(["-f", str(scan), "-oF", "csv"], cwd=tmp_path)
