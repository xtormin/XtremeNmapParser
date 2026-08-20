"""Output filtering and the CSV / XLSX / JSON writers."""

import json

import pandas as pd
import pytest

from xnp.errors import XnpError
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


def test_port_is_converted_to_a_nullable_integer_for_sorting(df):
    """Int64 (nullable) so that port-less rows survive instead of raising."""
    assert df_output_filters(df, DEFAULT_COLUMNS, False)["Port"].dtype == "Int64"


def test_rows_without_a_port_survive_filtering(xml):
    source = NmapParser(xml("host_down"), include_hostless=True).parse_file()
    result = df_output_filters(source, DEFAULT_COLUMNS, False)
    assert len(result) == 2
    assert result["Port"].isna().all()


def test_an_empty_dataframe_passes_through_untouched():
    empty = pd.DataFrame()
    assert df_output_filters(empty, DEFAULT_COLUMNS, False) is empty


def test_none_passes_through_untouched():
    assert df_output_filters(None, DEFAULT_COLUMNS, False) is None


def test_unknown_columns_raise(df):
    with pytest.raises(XnpError, match="Unknown output columns"):
        df_output_filters(df, ["IP", "Nope"], False)


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


def test_output_name_only_strips_the_real_extension():
    """splitext, not split('.xml'): a .xml in a directory name must survive."""
    assert get_output_name("/data/backup.xml.old/scan.xml", None, None) == \
        "/data/backup.xml.old/scan"


def test_an_explicit_output_name_wins_over_the_xml_name():
    """`xnp -f scan.xml -oN informe` used to silently write scan.csv."""
    assert get_output_name("scan.xml", "informe", None) == "informe"


def test_get_output_name_without_any_input_is_none():
    assert get_output_name(None, None, None) is None


def test_a_write_failure_raises_instead_of_being_swallowed(df, tmp_path, monkeypatch):
    """A run that could not write its output must not report success."""
    filtered = df_output_filters(df, DEFAULT_COLUMNS, False)
    target = tmp_path / "out.csv"

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(pd.DataFrame, "to_csv", boom)
    with pytest.raises(XnpError, match="file not created"):
        df_to_csv(filtered, str(target))


def test_writers_create_the_output_directory(df, tmp_path):
    target = tmp_path / "reports" / "nested" / "out.csv"
    df_to_csv(df_output_filters(df, DEFAULT_COLUMNS, False), str(target))
    assert target.is_file()


# --- Writer failure paths ---------------------------------------------------

@pytest.mark.parametrize("writer_name,method,extension", [
    ("df_to_json", "to_json", "json"),
    ("df_to_xlsx", "to_excel", "xlsx"),
])
def test_every_writer_raises_on_failure(df, tmp_path, monkeypatch, writer_name,
                                        method, extension):
    import xnp.output as output_module

    filtered = df_output_filters(df, DEFAULT_COLUMNS, False)

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(pd.DataFrame, method, boom)
    with pytest.raises(XnpError, match="file not created"):
        getattr(output_module, writer_name)(filtered, str(tmp_path / f"o.{extension}"))


def test_an_unwritable_output_directory_raises(df, tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr("os.makedirs", boom)
    with pytest.raises(XnpError, match="Could not create"):
        df_to_csv(df_output_filters(df, DEFAULT_COLUMNS, False),
                  str(tmp_path / "nested" / "out.csv"))


def test_an_unknown_output_format_is_skipped(df, tmp_path):
    """Unknown formats are ignored rather than crashing the whole run."""
    filtered = df_output_filters(df, DEFAULT_COLUMNS, False)
    write_dataframe(filtered, ["csv", "pdf"], file_xml=str(tmp_path / "scan.xml"))
    assert (tmp_path / "scan.csv").is_file()
    assert not (tmp_path / "scan.pdf").exists()


def test_write_dataframe_skips_none(tmp_path):
    write_dataframe(None, ["csv"], file_xml=str(tmp_path / "scan.xml"))
    assert not (tmp_path / "scan.csv").exists()
