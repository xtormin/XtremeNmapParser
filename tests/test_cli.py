"""Argument parsing and the process-level entry point."""

import pytest

from xnp import __version__
from xnp.cli import build_parser, parse_args

pytestmark = pytest.mark.usefixtures("quiet_logs")


def test_defaults():
    args = parse_args([])
    assert args.file is None
    assert args.directory is None
    assert args.outputformat == ["csv", "xlsx", "json"]
    assert args.outputname is None
    assert args.columns is None
    assert args.merger is False
    assert args.recursive is False
    assert args.open is False
    assert args.verbose is False


def test_short_and_long_flags_agree():
    short = parse_args(["-f", "a.xml", "-oF", "csv", "-oN", "n", "-M", "-R", "-C", "all", "-v"])
    long = parse_args(["--file", "a.xml", "--outputformat", "csv", "--outputname", "n",
                       "--merger", "--recursive", "--columns", "all", "--verbose"])
    assert vars(short) == vars(long)


def test_several_output_formats_are_accepted():
    assert parse_args(["-oF", "csv", "json"]).outputformat == ["csv", "json"]


@pytest.mark.parametrize("argv", [
    ["-oF", "pdf"],
    ["-C", "some"],
])
def test_invalid_choices_are_rejected(argv):
    with pytest.raises(SystemExit):
        parse_args(argv)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        parse_args(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_help_mentions_every_flag(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    out = capsys.readouterr().out
    for flag in ("--file", "--directory", "--outputformat", "--outputname",
                 "--merger", "--recursive", "--columns", "--open"):
        assert flag in out


# --- Bugs pinned here, fixed in the next commit -----------------------------

def test_CURRENT_no_input_is_accepted_and_does_nothing(run_cli, tmp_path, capsys):
    """BUG: with neither -f nor -d, XNP prints its banner and exits 0."""
    assert run_cli([], cwd=tmp_path) == 0
    assert list(tmp_path.iterdir()) == []


def test_CURRENT_a_missing_file_is_not_validated(run_cli, tmp_path):
    """BUG: argparse accepts a path that does not exist; it fails later."""
    args = parse_args(["-f", str(tmp_path / "nope.xml")])
    assert args.file.endswith("nope.xml")


def test_CURRENT_merger_without_a_directory_is_accepted(run_cli, tmp_path):
    """BUG: -M and -R only mean something with -d, but are accepted alone."""
    assert run_cli(["-M", "-R"], cwd=tmp_path) == 0
