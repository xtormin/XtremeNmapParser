"""Argument parsing and the process-level entry point."""

import pytest

from xnp import __version__
from xnp.cli import build_parser, parse_args

pytestmark = pytest.mark.usefixtures("quiet_logs")


def test_defaults():
    # build_parser() on its own: these check parsing, not input validation.
    args = build_parser().parse_args([])
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
                 "--merger", "--recursive", "--columns", "--open"):
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


def test_a_valid_directory_is_accepted(tmp_path):
    assert parse_args(["-d", str(tmp_path), "-M", "-R"]).directory == str(tmp_path)
