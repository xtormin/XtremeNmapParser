"""XML -> DataFrame conversion, merging and deduplication."""

import pandas as pd
import pytest

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


def test_malformed_xml_is_swallowed_and_returns_none(xml):
    assert NmapParser(xml("malformed")).parse_file() is None


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


# --- Bugs pinned here, fixed in the next commit -----------------------------

def test_CURRENT_ipv6_hosts_lose_their_address(xml):
    """BUG: only addrtype == 'ipv4' is read, so IPv6 hosts get an empty IP."""
    df = NmapParser(xml("ipv6_host")).parse_file()
    assert len(df) == 1
    assert df.iloc[0]["IP"] is None
    assert df.iloc[0]["Hostname"] == "v6.lab.local"


def test_CURRENT_hosts_without_ports_vanish_from_the_report(xml):
    """BUG: rows are only emitted per port, so a down host is dropped silently.

    host_down.xml holds two hosts: one down, one up with every port filtered.
    Neither survives.
    """
    assert NmapParser(xml("host_down")).parse_file() is None


def test_CURRENT_scripts_column_holds_python_reprs(xml):
    """BUG: the cell contains repr() of the Script object, not readable output."""
    df = NmapParser(xml("with_scripts")).parse_file()
    scripts = df.iloc[0]["Scripts"]
    assert scripts == [
        "Script(id=http-title, output=Welcome, content=None)",
        "Script(id=ssl-cert, output=Subject: commonName=tls.lab.local, content=None)",
    ]


def test_CURRENT_merging_only_empty_files_raises(xml):
    """BUG: every file empty -> pd.concat gets an all-None list and blows up."""
    with pytest.raises(ValueError, match="All objects passed were None"):
        NmapParser.merge_df([xml("no_hosts")])


def test_CURRENT_merge_leaks_its_helper_column(xml):
    """BUG: the RelevantDuplicate scratch column is left in the DataFrame.

    It is hidden downstream only because df_output_filters selects columns.
    """
    df = NmapParser.merge_df([xml("dup_a"), xml("dup_b")])
    assert "RelevantDuplicate" in df.columns


def test_CURRENT_a_non_nmap_xml_crashes_with_attributeerror(xml):
    """BUG: DTD rejection surfaces as AttributeError, not a clear message."""
    with pytest.raises(AttributeError):
        NmapParser(xml("not_nmap")).parse_file()
