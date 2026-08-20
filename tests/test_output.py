"""Output filtering and the CSV / XLSX / JSON writers."""

import json

import pandas as pd
import pytest

from xnp.output import (
    df_output_filters,
    df_to_csv,
    df_to_json,
    df_to_xlsx,
    get_output_name,
    write_dataframe,
)
from xnp.parser import NmapParser

pytestmark = pytest.mark.usefixtures("quiet_logs")

DEFAULT_COLUMNS = [
    'Hostname', 'IP', 'State', 'Port', 'Protocol', 'State Port',
    'Service Name', 'Product', 'Version', 'Extrainfo',
]


@pytest.fixture
def df(xml):
    return NmapParser(xml("single_host")).parse_file()


# --- Filtering --------------------------------------------------------------

def test_only_the_requested_columns_are_kept(df):
    assert list(df_output_filters(df, DEFAULT_COLUMNS, False).columns) == DEFAULT_COLUMNS
    assert "Scripts" not in df_output_filters(df, DEFAULT_COLUMNS, False).columns


def test_open_flag_drops_every_non_open_port(df):
    filtered = df_output_filters(df, DEFAULT_COLUMNS, True)
    assert set(filtered["State Port"]) == {"open"}
    assert 443 not in list(filtered["Port"])


def test_rows_are_sorted_by_ip_and_numeric_port(xml):
    source = NmapParser.parse_file_multiple([xml("single_host"), xml("multi_host")])
    result = df_output_filters(source, DEFAULT_COLUMNS, False)
    assert list(result["Port"]) == [22, 80, 443, 5432, 53, 443]
    assert list(result["IP"]) == ["10.0.0.1"] * 3 + ["10.0.0.20", "10.0.0.3", "10.0.0.3"]


def test_port_is_converted_to_int_for_sorting(df):
    assert df_output_filters(df, DEFAULT_COLUMNS, False)["Port"].dtype == "int64"


def test_filtering_does_not_mutate_the_input(df):
    before = list(df.columns)
    df_output_filters(df, DEFAULT_COLUMNS, True)
    assert list(df.columns) == before


# --- Output names -----------------------------------------------------------

def test_merged_output_falls_back_to_a_default_name():
    assert get_output_name(None, None, True) == "merged_nmap_scan_data"


def test_merged_output_honours_an_explicit_name():
    assert get_output_name(None, "informe", True) == "informe"


def test_single_file_output_is_derived_from_the_xml_name():
    assert get_output_name("nmap/scan.xml", None, None) == "nmap/scan"


# --- Writers ----------------------------------------------------------------

def test_csv_roundtrip(df, tmp_path):
    target = tmp_path / "out.csv"
    df_to_csv(df_output_filters(df, DEFAULT_COLUMNS, False), str(target))
    reread = pd.read_csv(target, sep=";")
    assert list(reread.columns) == DEFAULT_COLUMNS
    assert list(reread["Port"]) == [22, 80, 443]
    assert reread.iloc[0]["Extrainfo"] == "Ubuntu Linux; protocol 2.0"


def test_json_roundtrip(df, tmp_path):
    target = tmp_path / "out.json"
    df_to_json(df_output_filters(df, DEFAULT_COLUMNS, False), str(target))
    rows = [json.loads(line) for line in target.read_text().splitlines()]
    assert len(rows) == 3
    assert rows[0]["Service Name"] == "ssh"
    assert rows[0]["IP"] == "10.0.0.1"


def test_xlsx_is_written_and_readable(df, tmp_path):
    target = tmp_path / "out.xlsx"
    df_to_xlsx(df_output_filters(df, DEFAULT_COLUMNS, False), str(target))
    assert target.is_file() and target.stat().st_size > 0
    reread = pd.read_excel(target)
    assert list(reread.columns) == DEFAULT_COLUMNS
    assert len(reread) == 3


def test_write_dataframe_emits_every_requested_format(df, tmp_path):
    write_dataframe(df_output_filters(df, DEFAULT_COLUMNS, False),
                    ["csv", "json", "xlsx"], file_xml=str(tmp_path / "scan.xml"))
    for extension in ("csv", "json", "xlsx"):
        assert (tmp_path / f"scan.{extension}").is_file()


def test_write_dataframe_skips_an_empty_dataframe(tmp_path):
    write_dataframe(pd.DataFrame(), ["csv"], file_xml=str(tmp_path / "scan.xml"))
    assert not (tmp_path / "scan.csv").exists()


# --- Bugs pinned here, fixed in the next commit -----------------------------

def test_CURRENT_output_name_splits_on_the_first_xml_in_the_path():
    """BUG: split('.xml') cuts at the first match anywhere in the path."""
    assert get_output_name("/data/backup.xml.old/scan.xml", None, None) == "/data/backup"


def test_CURRENT_output_name_is_ignored_for_a_single_file():
    """BUG: `xnp -f scan.xml -oN informe` silently writes scan.csv."""
    assert get_output_name("scan.xml", "informe", None) == "scan"


def test_CURRENT_a_write_failure_is_only_logged(df, tmp_path):
    """BUG: writers swallow every exception, so the run still reports success."""
    unwritable = tmp_path / "missing_dir" / "out.csv"
    df_to_csv(df_output_filters(df, DEFAULT_COLUMNS, False), str(unwritable))
    assert not unwritable.exists()
