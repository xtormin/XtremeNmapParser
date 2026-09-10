"""Argument parsing and the process-level entry point."""

import pytest

from xnp import __version__
from xnp.cli import build_parser, parse_args
from xnp.output import WRITERS

pytestmark = pytest.mark.usefixtures("quiet_logs")


def test_defaults():
    # build_parser() on its own: these check parsing, not input validation.
    args = build_parser().parse_args([])
    assert args.file is None
    assert args.directory is None
    # Derived from the writer registry, so adding a format cannot leave
    # the CLI behind.
    assert args.outputformat == sorted(WRITERS)
    assert "html" in args.outputformat
    assert args.outputname is None
    assert args.columns is None
    assert args.merger is False
    assert args.recursive is False
    assert args.open is False
    assert args.verbose is False
    assert args.quiet is False
    assert args.no_color is False


def test_short_and_long_flags_agree():
    parser = build_parser()
    short = parser.parse_args(["-f", "a.xml", "-oF", "csv", "-oN", "n", "-M", "-R",
                               "-C", "all", "-v"])
    long = build_parser().parse_args(["--file", "a.xml", "--outputformat", "csv",
                                      "--outputname", "n", "--merger", "--recursive",
                                      "--columns", "all", "--verbose"])
    assert vars(short) == vars(long)


def test_several_output_formats_are_accepted():
    assert build_parser().parse_args(["-oF", "csv", "json"]).outputformat == ["csv", "json"]


@pytest.mark.parametrize("argv", [
    ["-oF", "pdf"],
    ["-C", "some"],
])
def test_invalid_choices_are_rejected(argv):
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_help_mentions_every_flag(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    out = capsys.readouterr().out
    for flag in ("--file", "--directory", "--outputformat", "--outputname",
                 "--merger", "--recursive", "--columns", "--open",
                 "--quiet", "--no-color"):
        assert flag in out


def test_the_new_flags_default_to_off():
    args = parse_args(["-f", __file__])
    assert args.include_hostless is False
    assert args.validate is True
    assert args.update is False


def test_no_validate_turns_validation_off():
    assert parse_args(["-f", __file__, "--no-validate"]).validate is False


def test_include_hostless_is_opt_in():
    assert parse_args(["-f", __file__, "--include-hostless"]).include_hostless is True


def test_update_needs_no_input_file():
    assert parse_args(["--update"]).update is True


# --- Argument validation ----------------------------------------------------

def error_message(capsys, argv):
    with pytest.raises(SystemExit) as excinfo:
        parse_args(argv)
    assert excinfo.value.code == 2
    return capsys.readouterr().err


def test_no_input_at_all_is_rejected(capsys):
    """XNP used to print its banner and exit 0 without doing anything."""
    assert "nothing to do" in error_message(capsys, [])


def test_a_missing_file_is_rejected_up_front(capsys, tmp_path):
    message = error_message(capsys, ["-f", str(tmp_path / "nope.xml")])
    assert "file not found" in message


def test_a_file_passed_as_a_directory_is_rejected(capsys, tmp_path):
    scan = tmp_path / "scan.xml"
    scan.write_text("<x/>")
    assert "not a directory" in error_message(capsys, ["-d", str(scan)])


@pytest.mark.parametrize("flag", ["-M", "-R"])
def test_directory_only_flags_are_rejected_without_a_directory(capsys, flag):
    message = error_message(capsys, ["-f", __file__, flag])
    assert "only makes sense together with -d" in message


def test_verbose_and_quiet_together_are_rejected(capsys):
    """Two contradictory asks; saying so beats silently picking one."""
    assert "not allowed with" in error_message(capsys, ["-f", __file__, "-v", "-q"])


def test_a_valid_directory_is_accepted(tmp_path):
    assert parse_args(["-d", str(tmp_path), "-M", "-R"]).directory == str(tmp_path)


# --- Runtime paths ----------------------------------------------------------

def test_help_writes_to_stderr(capsys):
    from xnp.cli import help as print_help

    print_help()
    assert "usage: xnp" in capsys.readouterr().err


def test_verbose_turns_on_debug_logging(run_cli, tmp_path, fixtures_dir):
    import logging
    import shutil

    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)
    run_cli(["-f", str(scan), "-oF", "csv", "-v"], cwd=tmp_path)
    assert logging.getLogger("xnp").level == logging.DEBUG


def test_without_verbose_logging_stays_at_info(run_cli, tmp_path, fixtures_dir):
    import logging
    import shutil

    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)
    run_cli(["-f", str(scan), "-oF", "csv"], cwd=tmp_path)
    assert logging.getLogger("xnp").level == logging.INFO


def test_quiet_lifts_the_log_level_to_errors_only(run_cli, tmp_path, fixtures_dir):
    import logging
    import shutil

    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)
    run_cli(["-f", str(scan), "-oF", "csv", "-q"], cwd=tmp_path)
    assert logging.getLogger("xnp").level == logging.ERROR


def test_update_flag_delegates_to_the_update_module(run_cli, tmp_path, monkeypatch):
    import xnp.update as update_module

    calls = []
    monkeypatch.setattr(update_module, "update_program", lambda: calls.append(True) or True)
    assert run_cli(["--update"], cwd=tmp_path) == 0
    assert calls == [True]


def test_update_flag_reports_failure(run_cli, tmp_path, monkeypatch):
    import xnp.update as update_module

    monkeypatch.setattr(update_module, "update_program", lambda: False)
    assert run_cli(["--update"], cwd=tmp_path) == 1


def test_the_module_can_be_run_with_python_dash_m():
    import subprocess
    import sys

    result = subprocess.run([sys.executable, "-m", "xnp", "--version"],
                            capture_output=True, text=True)
    assert result.returncode == 0
    assert __version__ in result.stdout


def test_ctrl_c_exits_cleanly_instead_of_dumping_a_traceback(run_cli, tmp_path,
                                                             fixtures_dir, monkeypatch):
    """Interrupting a run with a live display up should not spew a traceback."""
    import shutil

    import xnp.cli as cli_module

    scan = tmp_path / "scan.xml"
    shutil.copy(fixtures_dir / "single_host.xml", scan)

    def interrupted(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "parse_xml_files", interrupted)
    assert run_cli(["-f", str(scan), "-oF", "csv"], cwd=tmp_path) == 130
