"""Counting what a run found."""

from collections import Counter

import pytest

from xnp import stats
from xnp.parser import NmapParser
from xnp.xml_report import NmapXMLReport

pytestmark = pytest.mark.usefixtures("quiet_logs")


@pytest.fixture
def report(xml):
    """Return a parsed report by fixture name: ``report("single_host")``."""
    def _report(name, validate=True):
        return NmapXMLReport(xml(name), validate=validate)
    return _report


# --- Per-file counts --------------------------------------------------------

def test_counts_come_from_the_report(report):
    counts = stats.counts_for(report("single_host"))
    assert counts.hosts == 1
    assert counts.hosts_up == 1
    assert counts.ports == 3
    assert counts.open_ports == 2


def test_multi_host_counts_every_host_and_port(report):
    counts = stats.counts_for(report("multi_host"))
    assert counts.hosts == 2
    assert counts.ports == 3


def test_a_host_with_no_ports_is_still_a_host(report):
    """The DataFrame drops it; the summary must not, or hosts undercount."""
    counts = stats.counts_for(report("host_down"))
    assert counts.hosts == 2
    assert counts.hosts_up == 1
    assert counts.ports == 0
    assert counts.open_ports == 0


def test_a_report_with_no_hosts_counts_zero(report):
    assert stats.counts_for(report("no_hosts")) == stats.FileCounts()


def test_no_report_at_all_counts_zero():
    assert stats.counts_for(None) == stats.FileCounts()


# --- Addresses --------------------------------------------------------------

def test_ips_are_a_set_so_runs_can_be_unioned(report):
    assert stats.ips_for(report("single_host")) == {"10.0.0.1"}


def test_an_ipv6_only_host_still_has_an_address(report):
    """Mirrors the parser's ipv4-then-ipv6 fallback."""
    assert stats.ips_for(report("ipv6_host")) == {"2001:db8::1"}


def test_no_report_has_no_addresses():
    assert stats.ips_for(None) == set()


# --- Services ---------------------------------------------------------------

def test_only_open_ports_reach_the_service_counter(report):
    """A -p- scan is mostly filtered ports; counting them is not information."""
    services = stats.services_for(report("single_host"))
    assert services == Counter({"ssh": 1, "http": 1})
    assert "https" not in services


# --- Folding a run together -------------------------------------------------

def test_the_same_host_in_two_files_is_one_host(xml):
    """The merged-mode semantics: hosts are a union, ports are a sum."""
    run = stats.RunStats()
    for name in ("dup_a", "dup_b"):
        parser = NmapParser(xml(name))
        parser.parse_file()
        run.add(stats.FileResult.parsed(xml(name), parser.report))

    assert run.parsed == 2
    assert len(run.ips) == 1
    assert run.ports == stats.counts_for(NmapXMLReport(xml("dup_a"))).ports + \
        stats.counts_for(NmapXMLReport(xml("dup_b"))).ports


def test_a_skipped_file_only_moves_the_skipped_counter():
    run = stats.RunStats()
    run.add(stats.FileResult.failed("bad.xml", ValueError("nope")))

    assert (run.skipped, run.parsed) == (1, 0)
    assert run.ports == 0 and run.ips == set()


def test_top_services_is_ordered_and_truncated():
    run = stats.RunStats()
    run.services = Counter({"http": 9, "ssh": 5, "smb": 3, "ftp": 2, "dns": 1, "rdp": 1})

    assert run.top_services(3) == [("http", 9), ("ssh", 5), ("smb", 3)]
    assert len(run.top_services()) == 5


# --- Written files ----------------------------------------------------------

def test_a_written_file_is_sized_on_disk(tmp_path):
    path = tmp_path / "out.csv"
    path.write_text("a;b\n1;2\n")

    written = stats.written_file("csv", str(path))
    assert written.fmt == "csv"
    assert written.size == path.stat().st_size


def test_a_file_that_vanished_is_reported_as_empty_not_a_crash(tmp_path):
    assert stats.written_file("csv", str(tmp_path / "gone.csv")).size == 0


def test_bytes_written_sums_every_output():
    run = stats.RunStats()
    run.written = [stats.WrittenFile("csv", "a.csv", 10), stats.WrittenFile("json", "a.json", 32)]
    assert run.bytes_written == 42


def test_no_report_has_no_services():
    assert stats.services_for(None) == Counter()


# --- Rescan targets ---------------------------------------------------------

def test_the_targets_carry_every_port_with_its_state(report):
    targets = stats.targets_for(report("multi_host"))
    assert ("10.0.0.3", "tcp", "443", "open") in targets
    assert ("10.0.0.3", "udp", "53", "open") in targets
    assert ("10.0.0.20", "tcp", "5432", "open") in targets


def test_a_host_with_no_address_contributes_no_targets(report):
    assert stats.targets_for(report("host_down")) == frozenset()


def test_the_targets_of_two_files_are_unioned_not_summed(report):
    run = stats.RunStats()
    for name in ("dup_a", "dup_b"):
        run.add(stats.FileResult.parsed(name, report(name)))
    addresses = {target[0] for target in run.targets}
    assert len(addresses) == len({address for address in addresses})
    assert run.targets == (stats.targets_for(report("dup_a"))
                           | stats.targets_for(report("dup_b")))


def test_a_skipped_file_contributes_no_targets():
    run = stats.RunStats()
    run.add(stats.FileResult.failed("broken.xml", ValueError("nope")))
    assert run.targets == set()
