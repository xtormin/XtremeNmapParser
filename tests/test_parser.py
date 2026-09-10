"""XML -> DataFrame conversion, merging and deduplication."""

import pandas as pd
import pytest

from xnp.errors import InvalidNmapReport, NotAnNmapReport
from xnp.models import ScanData, empty_dataframe, to_dataframe
from xnp.parser import NmapParser

pytestmark = pytest.mark.usefixtures("quiet_logs")

ALL_COLUMNS = [
    'Hostname', 'IP', 'State', 'Port', 'Protocol', 'State Port',
    'Service Name', 'Product', 'Version', 'Extrainfo', 'Scripts',
]


def test_single_host_produces_one_row_per_port(xml):
    df = NmapParser(xml("single_host")).parse_file()
    assert list(df.columns) == ALL_COLUMNS
    assert len(df) == 3
    assert list(df["Port"]) == ["80", "22", "443"]          # document order
    assert set(df["IP"]) == {"10.0.0.1"}
    assert set(df["Hostname"]) == {"web.lab.local"}


def test_service_details_land_in_the_right_columns(xml):
    df = NmapParser(xml("single_host")).parse_file()
    ssh = df[df["Port"] == "22"].iloc[0]
    assert ssh["Service Name"] == "ssh"
    assert ssh["Product"] == "OpenSSH"
    assert ssh["Version"] == "8.9p1"
    assert ssh["Extrainfo"] == "Ubuntu Linux; protocol 2.0"
    assert ssh["State Port"] == "open"
    assert ssh["State"] == "up"


def test_port_without_service_details_leaves_empty_cells(xml):
    df = NmapParser(xml("single_host")).parse_file()
    https = df[df["Port"] == "443"].iloc[0]
    assert https["State Port"] == "filtered"
    assert https["Service Name"] == "https"
    assert https["Product"] is None
    assert https["Version"] is None


def test_multiple_hosts_and_protocols(xml):
    df = NmapParser(xml("multi_host")).parse_file()
    assert len(df) == 3
    assert set(df["IP"]) == {"10.0.0.20", "10.0.0.3"}
    assert set(df["Protocol"]) == {"tcp", "udp"}
    assert df[df["Port"] == "53"].iloc[0]["Service Name"] == "domain"


def test_host_without_hostname_leaves_it_empty(xml):
    df = NmapParser(xml("multi_host")).parse_file()
    assert df[df["IP"] == "10.0.0.3"].iloc[0]["Hostname"] is None


def test_report_without_hosts_returns_none(xml):
    assert NmapParser(xml("no_hosts")).parse_file() is None


def test_malformed_xml_raises_a_clear_error(xml):
    """A truncated scan is an error, not a silent empty result."""
    with pytest.raises(InvalidNmapReport) as excinfo:
        NmapParser(xml("malformed")).parse_file()
    assert "Could not parse" in str(excinfo.value)
    assert excinfo.value.exit_code == 2


def test_is_not_ip():
    assert NmapParser.is_not_ip("10.0.0.1") is None
    assert NmapParser.is_not_ip("2001:db8::1") is None
    assert NmapParser.is_not_ip("web.lab.local") == "web.lab.local"


# --- Merging ----------------------------------------------------------------

def test_merge_keeps_the_row_with_the_most_service_detail(xml):
    """dup_a has 80/tcp with no version info; dup_b has the same port with it."""
    df = NmapParser.merge_df([xml("dup_a"), xml("dup_b")])
    port80 = df[df["Port"] == "80"]
    assert len(port80) == 1
    assert port80.iloc[0]["Product"] == "Apache httpd"
    assert port80.iloc[0]["Version"] == "2.4.52"


def test_merge_keeps_ports_seen_in_only_one_scan(xml):
    df = NmapParser.merge_df([xml("dup_a"), xml("dup_b")])
    assert set(df["Port"]) == {"80", "8080"}


def test_merge_propagates_the_hostname_across_rows_of_the_same_ip(xml):
    """dup_a has no hostname; the one resolved in dup_b is filled forward."""
    df = NmapParser.merge_df([xml("dup_a"), xml("dup_b")])
    assert set(df["Hostname"]) == {"dup.lab.local"}


def test_merge_blanks_a_hostname_that_is_just_the_ip(xml):
    df = NmapParser.merge_df([xml("single_host"), xml("multi_host")])
    assert not any(str(h) == ip for h, ip in zip(df["Hostname"], df["IP"]))


def test_parse_file_multiple_tolerates_a_file_with_no_data(xml):
    df = NmapParser.parse_file_multiple([xml("single_host"), xml("no_hosts")])
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 3


def test_ipv6_hosts_keep_their_address(xml):
    df = NmapParser(xml("ipv6_host")).parse_file()
    assert len(df) == 1
    assert df.iloc[0]["IP"] == "2001:db8::1"
    assert df.iloc[0]["Hostname"] == "v6.lab.local"


def test_ipv4_is_preferred_when_a_host_has_both(xml):
    assert NmapParser._host_address(
        _FakeHost([("ipv6", "2001:db8::1"), ("ipv4", "10.0.0.1")])) == "10.0.0.1"


def test_scripts_are_rendered_as_readable_lines(xml):
    df = NmapParser(xml("with_scripts")).parse_file()
    assert df.iloc[0]["Scripts"] == (
        "http-title: Welcome\n"
        "ssl-cert: Subject: commonName=tls.lab.local"
    )


def test_a_port_without_scripts_leaves_the_cell_empty(xml):
    df = NmapParser(xml("single_host")).parse_file()
    assert set(df["Scripts"]) == {None}


# --- Hosts with no ports ----------------------------------------------------

def test_hosts_without_ports_are_dropped_by_default(xml):
    """Default behaviour is unchanged: only host/port rows are emitted."""
    assert NmapParser(xml("host_down")).parse_file() is None


def test_include_hostless_emits_one_row_per_portless_host(xml):
    df = NmapParser(xml("host_down"), include_hostless=True).parse_file()
    assert len(df) == 2
    assert list(df["IP"]) == ["10.0.0.4", "10.0.0.5"]
    assert list(df["State"]) == ["down", "up"]
    assert set(df["Port"]) == {None}
    assert set(df["Protocol"]) == {None}


def test_include_hostless_does_not_change_hosts_that_have_ports(xml):
    with_flag = NmapParser(xml("single_host"), include_hostless=True).parse_file()
    without = NmapParser(xml("single_host")).parse_file()
    pd.testing.assert_frame_equal(with_flag, without)


# --- Merging edge cases -----------------------------------------------------

def test_merging_only_empty_files_returns_an_empty_frame(xml):
    df = NmapParser.merge_df([xml("no_hosts")])
    assert isinstance(df, pd.DataFrame)
    assert df.empty
    assert list(df.columns) == ALL_COLUMNS


def test_merge_does_not_leak_its_helper_column(xml):
    df = NmapParser.merge_df([xml("dup_a"), xml("dup_b")])
    assert list(df.columns) == ALL_COLUMNS


def test_a_non_nmap_xml_raises_a_clear_error(xml):
    with pytest.raises(NotAnNmapReport):
        NmapParser(xml("not_nmap")).parse_file()


def test_validation_can_be_skipped_for_masscan_output(xml):
    df = NmapParser(xml("masscan"), validate=False).parse_file()
    assert list(df["IP"]) == ["10.0.0.8"]
    assert list(df["Port"]) == ["8080"]


class _FakeHost:
    """Minimal stand-in for an nmap <host> with the given addresses."""

    class _Address:
        def __init__(self, addrtype, addr):
            self.addrtype = addrtype
            self.addr = addr

    def __init__(self, addresses):
        self.addresses = [self._Address(t, a) for t, a in addresses]


def test_scan_data_round_trips_through_a_dict():
    row = ScanData()
    row.data["IP"] = "10.0.0.1"
    assert row.to_dict()["IP"] == "10.0.0.1"
    assert row.to_dict() is not row.data          # a copy, not the live mapping
    assert row.to_list()[ALL_COLUMNS.index("IP")] == "10.0.0.1"


def test_to_dataframe_of_nothing_is_none():
    assert to_dataframe([]) is None


def test_empty_dataframe_carries_the_columns():
    df = empty_dataframe()
    assert df.empty
    assert list(df.columns) == ALL_COLUMNS


# --- Watching a directory run go by -----------------------------------------

def test_parse_all_reports_each_file_as_it_finishes(xml):
    """The hook the CLI drives its progress bar from."""
    seen = []
    NmapParser.parse_all([xml("single_host"), xml("multi_host")], on_file=seen.append)

    assert [result.path for result in seen] == [xml("single_host"), xml("multi_host")]
    assert all(result.ok for result in seen)
    assert seen[0].counts.ports == 3
    assert seen[0].ips == {"10.0.0.1"}


def test_a_skipped_file_is_reported_too(xml):
    """The bar must step for a file that failed, or it stalls on a bad input."""
    seen = []
    NmapParser.parse_all([xml("single_host"), xml("masscan")],
                         skip_invalid=True, on_file=seen.append)

    assert [result.ok for result in seen] == [True, False]
    assert seen[1].path == xml("masscan")
    assert seen[1].error is not None
    assert seen[1].counts is None


def test_merge_all_forwards_the_hook(xml):
    seen = []
    NmapParser.merge_all([xml("dup_a"), xml("dup_b")], on_file=seen.append)
    assert len(seen) == 2


def test_parse_one_returns_the_frame_the_result_and_the_parser(xml):
    df, result, parser = NmapParser.parse_one(xml("single_host"))

    assert len(df) == 3
    assert result.ok and result.counts.hosts == 1
    assert parser.report is not None


def test_parse_one_turns_a_bad_file_into_a_result_instead_of_raising(xml):
    df, result, _ = NmapParser.parse_one(xml("masscan"))

    assert df is None
    assert result.ok is False
    assert isinstance(result.error, Exception)


def test_the_counts_property_is_empty_before_parsing(xml):
    parser = NmapParser(xml("single_host"))
    assert parser.counts is None
    parser.parse_file()
    assert parser.counts.ports == 3
