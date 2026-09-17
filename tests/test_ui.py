"""Terminal presentation: colour policy, quiet mode, and the log handler.

The load-bearing test here is the last one.  ``caplog`` attaches its handler
directly to the non-propagating ``xnp`` logger, so a ``setup_logging`` that
cleared the handler list would empty ``caplog.text`` everywhere else -- turning
assertions into false passes rather than failures.
"""

import logging

import pytest
from rich.console import Console
from rich.logging import RichHandler

from xnp import __version__, banner, stats, ui
from xnp.logs import ROOT_LOGGER_NAME, setup_logging


@pytest.fixture(autouse=True)
def fresh_ui():
    """Rebuild the consoles per test and leave the default behind."""
    yield
    ui.setup()


def render(capsys):
    """Both streams, as text, after whatever was just printed."""
    captured = capsys.readouterr()
    return captured.out, captured.err


# --- Colour policy ----------------------------------------------------------

def test_no_color_flag_emits_no_escape_sequences(capsys, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    ui.setup(no_color=True)

    assert ui.console().color_system is None
    assert ui.out().color_system is None

    ui.section("Parsing files")
    assert "\x1b" not in render(capsys)[1]


# The environment cases are asserted against the policy rather than the built
# console, because "auto" also resolves to no colour off a terminal -- and
# under pytest neither stream is one, so the two causes would be
# indistinguishable.

def test_the_no_color_env_var_is_honoured(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert ui._color_system(no_color=False) is None


def test_an_empty_no_color_does_not_disable_colour(monkeypatch):
    """no-color.org specifies a *non-empty* value; rich only checks presence."""
    monkeypatch.setenv("NO_COLOR", "")
    monkeypatch.delenv("TERM", raising=False)
    assert ui._color_system(no_color=False) == "auto"


def test_a_dumb_terminal_disables_colour(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert ui._color_system(no_color=False) is None


def test_the_flag_wins_over_a_permissive_environment(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert ui._color_system(no_color=True) is None


# --- The arguments panel ----------------------------------------------------

def test_the_output_format_is_never_a_python_list_repr(capsys):
    """The bug this panel replaced: -oF csv html rendered as ['csv', 'html']."""
    ui.setup()
    ui.arguments([("Output format (-oF)", ", ".join(["csv", "html"]))])

    err = render(capsys)[1]
    assert "csv, html" in err
    assert "['" not in err and "']" not in err


def test_a_long_path_folds_inside_the_panel_instead_of_overflowing(capsys):
    ui.setup()
    ui.console().width = 60
    long_path = "/very/long/" + "segment/" * 20 + "scan.xml"
    ui.arguments([("Folder (-d)", long_path)])

    err = render(capsys)[1]
    assert max(len(line) for line in err.splitlines()) <= 60
    # Folded, not truncated: every character survives somewhere.
    assert "".join(err.split()).count("segment/" * 2) >= 1


def test_square_brackets_in_a_path_are_not_read_as_markup(capsys):
    """Paths and scanned service names are attacker-influenced input."""
    ui.setup()
    ui.arguments([("File (-f)", "/tmp/scan[bold red]1.xml")])

    assert "[bold red]" in render(capsys)[1]


def test_an_empty_panel_prints_nothing(capsys):
    ui.setup()
    ui.arguments([])
    assert render(capsys)[1] == ""


# --- Quiet ------------------------------------------------------------------

def test_quiet_silences_the_chrome_but_never_the_output_paths(capsys):
    ui.setup(quiet=True)

    ui.banner("ART")
    ui.arguments([("File (-f)", "scan.xml")])
    ui.section("Parsing files")
    ui.file_result(stats.FileResult(path="scan.xml", ok=True, counts=stats.FileCounts(hosts=1)))
    ui.summary(stats.RunStats())
    ui.output_files([stats.WrittenFile("csv", "scan.csv", 12)])

    out, err = render(capsys)
    assert err == ""
    assert out.splitlines() == ["scan.csv"]


def test_is_quiet_reports_the_mode():
    ui.setup(quiet=True)
    assert ui.is_quiet() is True
    ui.setup()
    assert ui.is_quiet() is False


# --- Per-file lines ---------------------------------------------------------

def test_a_parsed_file_reports_its_counts(capsys):
    ui.setup()
    ui.file_result(stats.FileResult(
        path="scan.xml", ok=True,
        counts=stats.FileCounts(hosts=4, hosts_up=4, ports=12, open_ports=11)))

    err = render(capsys)[1]
    assert "scan.xml" in err
    assert "4 hosts" in err and "12 ports" in err and "11 open" in err


def test_a_single_host_is_not_reported_as_1_hosts(capsys):
    ui.setup()
    ui.file_result(stats.FileResult(
        path="scan.xml", ok=True, counts=stats.FileCounts(hosts=1, ports=1)))

    err = render(capsys)[1]
    assert "1 host " in err and "1 hosts" not in err


def test_a_skipped_file_prints_nothing_here(capsys):
    """It already produced one WARNING record; twice would be twice."""
    ui.setup()
    ui.file_result(stats.FileResult(path="bad.xml", ok=False, error=ValueError()))
    assert render(capsys)[1] == ""


# --- Output files -----------------------------------------------------------

def test_output_files_puts_the_table_on_stderr_and_the_paths_on_stdout(capsys):
    ui.setup()
    ui.output_files([stats.WrittenFile("csv", "a.csv", 1024),
                     stats.WrittenFile("html", "a.html", 2048)])

    out, err = render(capsys)
    assert out.splitlines() == ["a.csv", "a.html"]
    assert "csv" in err and "1.0 kB" in err


def test_a_shared_terminal_gets_the_table_only(capsys, monkeypatch):
    """The table already names every path: printing them again below is noise."""
    monkeypatch.setattr(Console, "is_terminal", True)
    ui.setup()
    ui.output_files([stats.WrittenFile("csv", "a.csv", 1024)])

    out, err = render(capsys)
    assert out == ""
    assert "a.csv" in err and "1.0 kB" in err


def test_a_terminal_display_still_pipes_the_paths_out(capsys, monkeypatch):
    """Only stderr is a terminal here -- stdout is a pipe, so it gets its list."""
    monkeypatch.setattr(Console, "is_terminal",
                        property(lambda self: self.stderr))
    ui.setup()
    ui.output_files([stats.WrittenFile("csv", "a.csv", 1024)])

    out, err = render(capsys)
    assert out.splitlines() == ["a.csv"]
    assert "a.csv" in err


def test_quiet_on_a_terminal_keeps_the_paths(capsys, monkeypatch):
    """With the table gone there is nothing to duplicate, and nothing else."""
    monkeypatch.setattr(Console, "is_terminal", True)
    ui.setup(quiet=True)
    ui.output_files([stats.WrittenFile("csv", "a.csv", 1024)])

    out, err = render(capsys)
    assert out.splitlines() == ["a.csv"]
    assert err == ""


def test_nothing_written_says_nothing(capsys):
    ui.setup()
    ui.output_files([])
    assert render(capsys) == ("", "")


# --- Summary ----------------------------------------------------------------

def test_the_summary_reports_what_the_run_found(capsys):
    ui.setup()
    run = stats.RunStats(parsed=2, skipped=1, ips={"10.0.0.1", "10.0.0.2"},
                         hosts_up=2, ports=17, open_ports=9, elapsed=1.25)
    run.services.update(["http", "http", "ssh"])
    run.written = [stats.WrittenFile("csv", "a.csv", 500)]
    ui.summary(run)

    err = render(capsys)[1]
    assert "2 parsed" in err and "1 skipped" in err
    assert "17 total" in err and "9 open" in err
    assert "http 2" in err
    assert "1.2s" in err


def test_the_merged_row_only_appears_for_a_merged_run(capsys):
    ui.setup()
    ui.summary(stats.RunStats(parsed=1))
    assert "Merged" not in render(capsys)[1]

    ui.summary(stats.RunStats(parsed=1, ports=17, rows_exported=12))
    assert "17 ports" in render(capsys)[1]


def test_a_long_run_is_reported_in_minutes(capsys):
    ui.setup()
    ui.summary(stats.RunStats(elapsed=125.0))
    assert "2m 5s" in render(capsys)[1]


# --- Progress ---------------------------------------------------------------

def test_the_bar_is_disabled_off_a_terminal_but_still_advances(capsys):
    ui.setup()
    with ui.progress(3) as bar:
        bar.advance()
        bar.advance(2)

    assert render(capsys) == ("", "")


def test_on_a_terminal_the_bar_is_drawn_and_lines_land_above_it(capsys):
    """The whole point of sharing one console: a line never tears the bar."""
    ui.setup()
    ui._err = Console(stderr=True, force_terminal=True, width=80,
                      color_system=None, markup=False, highlight=False, theme=ui.THEME)

    with ui.progress(3, "Parsing") as bar:
        bar.advance()
        ui.file_result(stats.FileResult(
            path="scan.xml", ok=True, counts=stats.FileCounts(hosts=2, ports=6, open_ports=5)))

    err = render(capsys)[1]
    assert "Parsing" in err and "3" in err
    assert "scan.xml" in err and "2 hosts" in err


def test_a_single_file_gets_no_bar(capsys):
    """A bar over one file is pure noise, and -f is most invocations."""
    ui.setup()
    ui._err = Console(stderr=True, force_terminal=True, width=80,
                      color_system=None, markup=False, highlight=False, theme=ui.THEME)

    with ui.progress(1, "Parsing") as bar:
        bar.advance()

    assert render(capsys)[1] == ""


def test_the_bar_is_released_even_when_the_body_raises():
    """A leaked Live makes the *next* run raise, as an unrelated failure."""
    ui.setup()
    for _ in range(2):
        with pytest.raises(RuntimeError), ui.progress(5) as bar:
            bar.advance()
            raise RuntimeError("boom")


# --- Logging ----------------------------------------------------------------

# --- Encoding fallbacks -----------------------------------------------------

def test_the_tick_falls_back_to_ascii_on_a_narrow_encoding(capsys):
    """A console that cannot encode the tick still gets a marker, not a crash."""
    ui.setup()
    ui._err = Console(stderr=True, width=80, color_system=None, markup=False,
                      highlight=False, theme=ui.THEME,
                      file=_AsciiStream(capsys))

    ui.file_result(stats.FileResult(path="scan.xml", ok=True,
                                    counts=stats.FileCounts(hosts=1)))
    assert ui._err.file.text.startswith("+ scan.xml")


class _AsciiStream:
    """A stream that reports a latin-1 encoding, as a Windows console would."""

    encoding = "ascii"

    def __init__(self, _capsys):
        self.text = ""

    def write(self, text):
        self.text += text

    def flush(self):
        pass

    def isatty(self):
        return False


def test_the_level_follows_the_flags():
    logger = logging.getLogger(ROOT_LOGGER_NAME)

    setup_logging(verbose=True)
    assert logger.level == logging.DEBUG
    setup_logging()
    assert logger.level == logging.INFO
    setup_logging(quiet=True)
    assert logger.level == logging.ERROR


def test_setting_up_twice_leaves_one_handler():
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    setup_logging()
    setup_logging()

    assert len([h for h in logger.handlers if isinstance(h, RichHandler)]) == 1


def test_setup_logging_never_detaches_anyone_elses_handler():
    """The guard on caplog.

    pytest attaches its capture handler straight to the non-propagating ``xnp``
    logger.  Clearing the handler list here would blank ``caplog.text`` for the
    rest of the test -- silently, so assertions would pass on nothing.
    """
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    foreign = logging.NullHandler()
    logger.addHandler(foreign)
    try:
        setup_logging()
        assert foreign in logger.handlers
    finally:
        logger.removeHandler(foreign)


def test_warnings_still_reach_caplog(caplog):
    """The end-to-end version of the guard above."""
    setup_logging()
    with caplog.at_level(logging.WARNING, logger=ROOT_LOGGER_NAME):
        logging.getLogger("xnp.test").warning("something was skipped")

    assert "something was skipped" in caplog.text


def test_a_run_of_milliseconds_is_not_rounded_away_to_zero(capsys):
    """Most runs finish in tens of ms; "0.0s" would say nothing about them."""
    ui.setup()
    ui.summary(stats.RunStats(elapsed=0.025))
    assert "25ms" in render(capsys)[1]


# --- The banner -------------------------------------------------------------

def test_the_banner_uses_the_block_art_when_the_console_can_encode_it(capsys):
    ui.setup()
    banner.main()

    err = render(capsys)[1]
    assert banner.BLOCK[0] in err
    assert f"Xtreme Nmap Parser v{__version__}" in err
    assert banner.REPO in err and banner.AUTHOR in err


def test_the_banner_falls_back_to_ascii_on_a_narrow_encoding(capsys):
    """Block drawing characters are unreadable where they cannot be encoded."""
    ui.setup()
    ui._err = Console(file=_AsciiStream(capsys), width=90, color_system=None,
                      markup=False, highlight=False, theme=ui.THEME)
    banner.main()

    printed = ui._err.file.text
    assert banner.ASCII[0] in printed
    assert banner.BLOCK[0] not in printed
    # The dot separator is not ASCII either.
    assert "  |  " in printed and "·" not in printed


def test_the_tagline_hangs_off_the_wordmark_not_off_a_ragged_line():
    """The reason the art is a tuple: nobody hand-counts the padding."""
    composed = banner.compose(("XX", "YYYYYYYY"), "TAG", "FOOT")
    lines = composed.strip("\n").split("\n")

    assert lines[0] == "   XX"
    assert lines[1] == "   YYYYYYYY      TAG"
    assert lines[-1] == "   FOOT"


def test_a_longer_version_does_not_shift_the_wordmark():
    short = banner.compose(banner.BLOCK, "v1.2.0", "f")
    long = banner.compose(banner.BLOCK, "v10.20.30", "f")

    assert short.split("\n")[1] == long.split("\n")[1]


# --- The rescan block -------------------------------------------------------

def _commands(args="-sV -sC -Pn"):
    from xnp import rescan

    return rescan.commands([("10.0.0.5", "tcp", 22, "open"),
                            ("10.0.0.5", "tcp", 80, "open"),
                            ("10.0.0.9", "udp", 161, "open")], args, ("open",))


def test_the_rescan_block_lands_on_stderr_and_never_on_stdout(capsys):
    ui.setup()
    ui.rescan(_commands(), "service")
    captured = capsys.readouterr()
    assert "nmap " in captured.err
    assert captured.out == ""


def test_every_group_gets_its_own_command(capsys):
    ui.setup()
    ui.rescan(_commands(), "service")
    err = capsys.readouterr().err
    assert err.count("nmap ") == 2
    assert "-p 22,80 10.0.0.5" in err
    assert "-p U:161 10.0.0.9" in err


def test_quiet_prints_the_bare_commands_without_the_chrome(capsys):
    """--rescan was asked for by name, so quiet must not silence it."""
    ui.setup(quiet=True)
    ui.rescan(_commands(), "service")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "nmap -sV -sC -Pn -p 22,80 10.0.0.5",
        "nmap -sV -sC -Pn -sU -p U:161 10.0.0.9",
    ]


def test_a_command_is_never_folded_in_the_middle(capsys):
    """A wrapped command carries real newlines into whatever it is pasted in."""
    from xnp import rescan

    hosts = [(f"10.0.{block}.{host}", "tcp", 80, "open")
             for block in range(4) for host in range(1, 40)]
    ui.setup()
    ui._err.width = 60
    ui.rescan(rescan.commands(hosts, "-sV -Pn", ("open",)), "service")
    lines = [line for line in capsys.readouterr().err.splitlines() if "nmap " in line]
    assert len(lines) == 1
    assert lines[0].endswith("10.0.3.39")


def test_nothing_to_rescan_prints_nothing(capsys):
    ui.setup()
    ui.rescan([], "service")
    assert capsys.readouterr().err == ""


def test_the_root_note_only_shows_when_a_command_needs_root(capsys):
    ui.setup()
    ui.rescan(_commands(args="-sT -sV"), "custom")
    with_udp = capsys.readouterr().err
    ui.rescan([_commands(args="-sT -sV")[0]], "custom")
    tcp_only = capsys.readouterr().err
    assert "root" in with_udp
    assert "root" not in tcp_only
