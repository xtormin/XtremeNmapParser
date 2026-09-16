"""What a run found, counted for the terminal summary.

The numbers come from the parsed :class:`~xnp.xml_report.NmapXMLReport`, never
from the DataFrame, because the frame is the wrong source for "what was
scanned":

* with ``include_hostless=False`` (the default) hosts with no ports never reach
  the frame, so ``df["IP"].nunique()`` undercounts them;
* ``--open`` and ``-C`` are applied later, so a frame-derived count would shift
  meaning with the *export* flags -- a summary of what was scanned must not
  move when you change what you write out;
* in merged mode the frame is deduplicated, so its length is rows exported,
  not ports seen.

The same reasoning makes the report the source for the rescan targets: a
command aimed at "what is open" must not shift when you change ``--open``.

Walking the report costs O(hosts + ports) over an already-materialised tree --
the same walk the row builder does.

This module imports nothing from :mod:`xnp` so it can be used from anywhere.
"""

import os
from collections import Counter
from dataclasses import dataclass, field
from typing import NamedTuple, Optional

OPEN = "open"


@dataclass(frozen=True)
class FileCounts:
    """What one report held."""

    hosts: int = 0
    hosts_up: int = 0
    ports: int = 0
    open_ports: int = 0


class WrittenFile(NamedTuple):
    """One generated output file."""

    fmt: str
    path: str
    size: int


def _address(host) -> Optional[str]:
    """The host's address, ipv4 first, ipv6 as fallback.

    Mirrors :meth:`xnp.parser.NmapParser._host_address` so the summary counts
    the same hosts the export does.
    """
    addresses = {a.addrtype: a.addr for a in host.addresses}
    return addresses.get("ipv4") or addresses.get("ipv6")


def _hostname(host) -> str:
    """The host's resolved name, or ``""``.

    Mirrors :meth:`xnp.parser.NmapParser._host_name`, last entry included: nmap
    lists a PTR after the user-supplied name, and the PTR is the one worth
    scanning back.
    """
    name = ""
    for group in host.hostnames:
        for hostname in group.hostnames:
            name = hostname.name or name
    return name or ""


def _is_open(port) -> bool:
    return bool(port.state) and port.state[0].state == OPEN


def counts_for(report) -> FileCounts:
    """Count hosts and ports in one parsed report."""
    if report is None:
        return FileCounts()

    hosts = up = ports = open_ports = 0
    for host in report.hosts:
        hosts += 1
        if host.status and host.status[0].state == "up":
            up += 1
        for port in host.ports:
            ports += 1
            if _is_open(port):
                open_ports += 1
    return FileCounts(hosts=hosts, hosts_up=up, ports=ports, open_ports=open_ports)


def ips_for(report) -> set:
    """The addresses in one report, as a set so runs can be unioned."""
    if report is None:
        return set()
    return {address for address in (_address(host) for host in report.hosts) if address}


def services_for(report) -> Counter:
    """Service names of the **open** ports only.

    Counting every port would be dominated by the ``filtered``/``closed`` noise
    of a ``-p-`` scan, which is not information.
    """
    counter: Counter = Counter()
    if report is None:
        return counter
    for host in report.hosts:
        for port in host.ports:
            if not _is_open(port):
                continue
            for service in port.service:
                if service.name:
                    counter[service.name] += 1
    return counter


def targets_for(report) -> frozenset:
    """Every port with a state, as ``(address, protocol, port, state, hostname)``.

    The hostname rides along because ``--rescan`` arguments may ask for it with
    ``$[HOSTNAME]``; :mod:`xnp.rescan` is what decides whether it is usable.

    Filtering by state is left to :mod:`xnp.rescan` and its configuration, so
    that ``rescan.states`` can mean anything without this function having an
    opinion.  The volume is bounded in practice because nmap collapses the
    dominant state into ``<extraports>`` rather than listing it port by port.
    """
    if report is None:
        return frozenset()

    targets = set()
    for host in report.hosts:
        address = _address(host)
        if not address:
            continue
        hostname = _hostname(host)
        for port in host.ports:
            if not port.portid or not port.state:
                continue
            targets.add((address, port.protocol, port.portid, port.state[0].state,
                         hostname))
    return frozenset(targets)


@dataclass
class FileResult:
    """The outcome of one input file, handed to the CLI as it happens."""

    path: str
    ok: bool
    counts: Optional[FileCounts] = None
    ips: set = field(default_factory=set)
    services: Counter = field(default_factory=Counter)
    targets: frozenset = frozenset()
    error: Optional[BaseException] = None

    @classmethod
    def parsed(cls, path: str, report) -> "FileResult":
        return cls(path=path, ok=True, counts=counts_for(report),
                   ips=ips_for(report), services=services_for(report),
                   targets=targets_for(report))

    @classmethod
    def failed(cls, path: str, error: BaseException) -> "FileResult":
        return cls(path=path, ok=False, error=error)


@dataclass
class RunStats:
    """Totals for one run.

    Created in :func:`xnp.cli.main` and threaded through explicitly -- never a
    module-level accumulator, because ``main()`` is called repeatedly in one
    process by the tests.
    """

    parsed: int = 0
    skipped: int = 0
    ips: set = field(default_factory=set)
    hosts_up: int = 0
    ports: int = 0
    open_ports: int = 0
    services: Counter = field(default_factory=Counter)
    #: Every ``(address, protocol, port, state)`` seen, unioned across files so
    #: the rescan answers "what did this run find", not "what was in each file".
    targets: set = field(default_factory=set)
    written: list = field(default_factory=list)
    #: Rows actually exported.  Only set for a merged run, where the collapse
    #: from ports-seen to rows-written is worth showing rather than hiding.
    rows_exported: Optional[int] = None
    elapsed: float = 0.0

    def add(self, result: FileResult) -> None:
        """Fold one file's outcome in.

        The per-file address set is unioned and then dropped, so memory is
        bounded by the union rather than the sum.
        """
        if not result.ok:
            self.skipped += 1
            return

        self.parsed += 1
        self.ips |= result.ips
        self.services += result.services
        self.targets |= result.targets
        if result.counts is not None:
            self.hosts_up += result.counts.hosts_up
            self.ports += result.counts.ports
            self.open_ports += result.counts.open_ports

    @property
    def bytes_written(self) -> int:
        return sum(item.size for item in self.written)

    def top_services(self, limit: int = 5) -> list:
        return self.services.most_common(limit)


def written_file(fmt: str, path: str) -> WrittenFile:
    """Describe a file that was just written, sizing it on disk."""
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    return WrittenFile(fmt=fmt, path=path, size=size)
