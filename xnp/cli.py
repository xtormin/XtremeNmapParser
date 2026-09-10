"""Command line entry point."""

import argparse
import os
import sys
import time
import webbrowser
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from xnp import __version__, banner, i18n, rescan, ui, update
from xnp import files as func
from xnp import output as out
from xnp.config import load_config
from xnp.errors import NoInputFilesError, XnpError
from xnp.logs import get_logger, setup_logging
from xnp.parser import NmapParser
from xnp.stats import FileResult, RunStats

logger = get_logger(__name__)

# A --no-merger run can write one report per XML: opening thirty browser tabs
# helps nobody, so past this many we open the first few and say so.
MAX_SHOWN = 5


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xnp",
        add_help=True,
        description='%(prog)s parse the output information from an nmap XML file')

    parser.add_argument('-f', '--file',
                        help='Nmap XML file. Ej: xnp -f nmapfile.xml',
                        nargs='?',
                        type=str)
    parser.add_argument('-d', '--directory',
                        help='Directory with nmap XML files. Ej: xnp -d nmap/',
                        nargs='?',
                        type=str)
    parser.add_argument('-oF', '--outputformat',
                        # Derived from the writer registry so the two can never
                        # drift apart when a format is added.
                        choices=sorted(out.WRITERS),
                        help='Output file format (%(choices)s). '
                             'Ej: xnp -f nmapfile.xml -oF csv html',
                        nargs='+',
                        type=str,
                        default=sorted(out.WRITERS))
    parser.add_argument('-oN', '--outputname',
                        help='Output file name.',
                        nargs='?',
                        type=str)
    # Both default to on: merging a directory recursively is what a directory
    # run is almost always for, so the flags exist to switch it off, and -M/-R
    # keep working for anyone whose scripts still pass them.
    parser.add_argument('-M', '--merger',
                        action=argparse.BooleanOptionalAction,
                        default=True,
                        help='Merge every XML file in the directory into one report. '
                             'On by default; --no-merger writes one report per file')
    parser.add_argument('-R', '--recursive',
                        action=argparse.BooleanOptionalAction,
                        default=True,
                        help='Descend into subdirectories. On by default; '
                             '--no-recursive stays at the top level')
    parser.add_argument('-C', '--columns',
                        type=str,
                        choices=['default', 'all'],
                        help='Columns for the output dataframe')
    parser.add_argument('--open',
                        help='Export only the ports with "open" value in "State Port"',
                        action="store_true")
    # Not --open: that one is about which ports get exported, and one flag
    # cannot mean both.
    parser.add_argument('--show',
                        help='Open the generated HTML report in the browser '
                             'when the run finishes',
                        action="store_true")
    # No choices= here on purpose: the profile names live in config.yaml, and
    # parse_args() runs outside main()'s try, so a broken config would come out
    # as a traceback rather than as an error.  The name is resolved in main().
    parser.add_argument('--rescan',
                        nargs='?',
                        const='',
                        default=None,
                        metavar='PROFILE',
                        help='Print the nmap commands that rescan only the hosts and '
                             'ports this run found, grouped so no host gets a port it '
                             'does not have. Takes a profile name from config.yaml; '
                             'without one, the configured default')
    parser.add_argument('--rescan-args',
                        dest='rescan_args',
                        default=None,
                        metavar='ARGS',
                        help='Rescan with these nmap arguments instead of a profile. '
                             'Use --rescan-args="-sV --script vuln" so the leading '
                             'dash is not read as a flag')
    parser.add_argument('--include-hostless',
                        dest='include_hostless',
                        action="store_true",
                        help='Also emit a row for hosts with no ports (down or fully filtered)')
    parser.add_argument('--no-validate',
                        dest='validate',
                        action="store_false",
                        help='Skip DTD validation. Needed for nmap-compatible output from '
                             'other scanners, such as masscan -oX')
    # Contradictory on purpose: asking for both is a mistake worth reporting
    # rather than silently resolving in favour of one.
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument('-v', '--verbose',
                           help='Verbose',
                           action="store_true")
    verbosity.add_argument('-q', '--quiet',
                           help='Only errors and the generated output paths',
                           action="store_true")
    parser.add_argument('--no-color',
                        dest='no_color',
                        action="store_true",
                        help='Disable colour (the NO_COLOR env var works too)')
    parser.add_argument('--lang',
                        choices=list(i18n.LANGUAGES),
                        help='Language for the terminal messages, and the default '
                             'the HTML report opens in. Defaults to the environment '
                             '(LC_ALL / LC_MESSAGES / LANG)')
    parser.add_argument('--update',
                        action="store_true",
                        help='Update XNP to the latest release and exit')
    parser.add_argument('--version',
                        action='version',
                        version=f'%(prog)s {__version__}')
    return parser


def validate_args(parser, args):
    """Reject argument combinations that cannot do anything useful."""
    if args.update:
        return

    if not args.file and not args.directory:
        parser.error("nothing to do: pass an XML file with -f or a directory with -d")

    if args.file and not os.path.isfile(args.file):
        parser.error(f"file not found: {args.file}")

    if args.directory and not os.path.isdir(args.directory):
        parser.error(f"not a directory: {args.directory}")

    # Only the negations are worth rejecting: -M/-R now say what already
    # happens, but --no-merger with -f is asking for something that has no
    # meaning at all.
    for flag, name in ((args.merger, "--no-merger"), (args.recursive, "--no-recursive")):
        if not flag and not args.directory:
            parser.error(f"{name} only makes sense together with -d/--directory")

    # html is in the default -oF set, so this only fires when it was explicitly
    # left out -- an ask with nothing to open.
    if args.show and "html" not in args.outputformat:
        parser.error("--show needs the html format: drop -oF, or add html to it")

    # Naming a profile and then replacing its arguments leaves the name
    # meaning nothing; --rescan-args on its own already turns the rescan on.
    # Only a *named* profile conflicts: a bare --rescan with --rescan-args is
    # just turning the rescan on and saying what to run.
    if args.rescan and args.rescan_args is not None:
        parser.error("--rescan-args replaces the profile's arguments: "
                     "pass one or the other")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    return args


def help():
    return build_parser().print_help(sys.stderr)


def argument_rows(args, df_columns, rescan_profile=None) -> list:
    """The run's settings as (label, value) pairs for the arguments panel.

    Values are formatted here rather than in the renderer, and the empty ones
    are dropped, so a directory run does not print "File (-f)  None" -- and no
    row is ever a Python list repr.
    """
    yes = i18n.t("value.yes")

    def on_off(value):
        """Both are on by default, so "no" is the answer worth printing."""
        return yes if value else i18n.t("value.no")

    rows = [
        ("arg.file", args.file),
        ("arg.folder", args.directory),
        # Only for a directory run: with -f neither setting means anything.
        ("arg.merge", on_off(args.merger) if args.directory else ""),
        ("arg.recursive", on_off(args.recursive) if args.directory else ""),
        ("arg.format", ", ".join(args.outputformat)),
        ("arg.name", args.outputname),
        ("arg.columns", ", ".join(df_columns)),
        ("arg.open", yes if args.open else ""),
        ("arg.show", yes if args.show else ""),
        ("arg.rescan", rescan_profile or ""),
        ("arg.hostless", yes if args.include_hostless else ""),
        ("arg.validation", "" if args.validate else i18n.t("value.no_validate")),
        # Only worth a row when it was asked for: otherwise it is just the
        # environment's own language being reported back at you.
        ("arg.language", args.lang or ""),
    ]
    return [(i18n.t(key), value) for key, value in rows if value]


#: The profile name used when --rescan-args supplies the arguments directly.
CUSTOM_PROFILE = "custom"


def resolve_rescan(args, config):
    """Work out ``(label, nmap arguments)`` for the run, or ``None``.

    Called from inside ``main()``'s try block, which is why an unknown name can
    be reported as an :class:`~xnp.errors.XnpError` with the list of the ones
    that exist rather than by argparse, which cannot see the configuration.
    """
    if args.rescan_args is not None:
        return CUSTOM_PROFILE, args.rescan_args
    if args.rescan is None:
        return None

    name = args.rescan or config.rescan_default_profile
    profile = config.rescan_profile(name)
    if profile is None:
        available = ", ".join(config.rescan_profile_names()) or "(none)"
        raise XnpError(f" |x| Error | Unknown rescan profile: {name}. "
                       f"Available: {available}")
    return profile.name, profile.args


def report_rescan(run, config, resolved) -> None:
    """Build and show the rescan commands for what the run found."""
    label, nmap_args = resolved
    built = rescan.commands(run.targets, nmap_args, config.rescan_states)
    if not built:
        logger.warning(i18n.t("warn.rescan_empty",
                              states=", ".join(config.rescan_states)))
        return

    # Every command drops the same profile flags, so this is said once.
    dropped = sorted({flag for item in built for flag in item.dropped})
    if dropped:
        logger.warning(i18n.t("warn.rescan_dropped", flags=" ".join(dropped)))

    ui.rescan(built, label)


def parse_xml_files(single_xml, folder_multiple_xml, list_output_format, file_output_name,
                    merger, recursive, df_columns, only_open_ports, config=None,
                    validate=True, include_hostless=False, run=None):
    """Parse the input and write the requested formats.

    Returns the :class:`~xnp.stats.RunStats` for the run so the caller can show
    a summary.  Generated files are collected rather than announced here: in a
    non-merged directory run the exports happen inside the loop, and writing to
    stdout while the progress bar is live would tear it.
    """
    config = config or load_config()
    run = run if run is not None else RunStats()

    def export(df, xml_file=None, context=None):
        df = out.df_output_filters(df, df_columns, only_open_ports)
        run.written.extend(
            out.export_single_xml(df, xml_file, list_output_format, file_output_name,
                                  config, context=context))

    def html_context(reports, sources, merge=False):
        """Everything the HTML report needs that the DataFrame cannot carry."""
        return {"reports": reports, "sources": sources, "merge": merge,
                "only_open": only_open_ports, "lang": i18n.current()}

    # Single nmap XML file
    if single_xml:
        parser = NmapParser(single_xml, validate, include_hostless)
        df = parser.parse_file()
        result = FileResult.parsed(single_xml, parser.report)
        run.add(result)
        ui.file_result(result)
        if df is None:
            logger.warning(i18n.t("warn.no_data"))
        else:
            export(df, single_xml, html_context([parser.report], [single_xml]))

    # Directory with multiple nmap XML files
    if folder_multiple_xml:
        try:
            xml_files = func.find_xml_files(folder_multiple_xml, recursive, config)
        except FileNotFoundError:
            raise XnpError(f" |-| File {folder_multiple_xml} not found") from None
        except NotADirectoryError:
            raise XnpError(
                f" |-| Are you sure that {folder_multiple_xml} is a directory?") from None

        if not xml_files:
            raise NoInputFilesError(f" |-| XML files in {folder_multiple_xml} not found")

        # A directory run processes what is there: a file that will not parse
        # is reported and left out rather than ending the run.  With -f the
        # error still stops everything, because you named that one file.
        with ui.progress(len(xml_files)) as bar:

            def on_file(result):
                """Fold one file into the totals, step the bar, show its line."""
                run.add(result)
                # Advance first: printing the line redraws the bar underneath
                # it, and a bar that redraws with the previous count reads as
                # permanently one file behind.
                bar.advance()
                # A skipped file already produced one WARNING record from the
                # parser; printing it again here would say the same thing twice.
                ui.file_result(result)

            if merger:
                # Named and placed here, once, so every requested format shares
                # a single timestamp instead of straddling a second boundary.
                merged_name = file_output_name or out.merged_output_name(
                    folder_multiple_xml)
                df, reports, skipped = NmapParser.merge_all(
                    xml_files, validate, include_hostless, skip_invalid=True,
                    on_file=on_file)
                df = out.df_output_filters(df, df_columns, only_open_ports)
                run.rows_exported = 0 if df is None else len(df)
                run.written.extend(
                    out.export_multiple_xml(
                        df, list_output_format, merged_name, merger, config,
                        context=html_context(reports, xml_files, merge=True)))
            else:
                skipped = []
                for xml_file in xml_files:
                    df, result, parser = NmapParser.parse_one(
                        xml_file, validate, include_hostless)
                    on_file(result)
                    if not result.ok:
                        skipped.append((xml_file, result.error))
                        continue
                    if df is None:
                        logger.warning(i18n.t("warn.no_data"))
                    else:
                        export(df, xml_file, html_context([parser.report], [xml_file]))

                if len(skipped) == len(xml_files):
                    raise skipped[0][1]

        report_skipped(skipped, len(xml_files))

    return run


def show_reports(written, limit: int = MAX_SHOWN) -> list:
    """Open the HTML reports the run produced, and return what was opened.

    A file:// URI rather than a bare path: a path with a space or a ``#`` in it
    is not a URL, and every browser reads the URI the same way.
    """
    reports = [item.path for item in written if item.fmt == "html"]
    if not reports:
        # Reaching here means html was asked for and nothing came of it -- an
        # empty scan, most likely.  Silence would read as a broken --show.
        logger.warning(i18n.t("warn.nothing_to_show"))
        return []

    if len(reports) > limit:
        logger.warning(i18n.t("warn.show_limited", shown=limit, total=len(reports)))
        reports = reports[:limit]

    opened = []
    for path in reports:
        try:
            webbrowser.open(Path(path).resolve().as_uri())
        except (webbrowser.Error, OSError) as exc:
            # A headless box has no browser to hand this to.  The report is
            # already written and its path already printed, so this is a
            # warning, not the end of a run that did everything it was asked.
            logger.warning(i18n.t("warn.show_failed", path=path, reason=exc))
            continue
        opened.append(path)
    return opened


def report_skipped(skipped, total):
    """Say plainly what was left out, so a partial run is never a silent one."""
    if not skipped:
        return
    # Its own block: this is the run's verdict, not another parsing line.
    ui.gap()
    logger.warning(i18n.t("warn.skipped_count", count=len(skipped), total=total))
    for xml_file, _ in skipped:
        logger.warning(f"  {xml_file}")
    logger.warning(i18n.t("warn.skipped_hint"))


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run XNP. Returns the process exit code."""
    args = parse_args(argv)
    # After parse_args, so argparse keeps reporting its own errors its own way.
    i18n.setup(args.lang)
    ui.setup(quiet=args.quiet, no_color=args.no_color)
    # The log handler writes to ui's console, so ui must exist first.
    setup_logging(args.verbose, args.quiet)
    # monotonic, so an NTP step mid-run cannot produce a negative duration.
    started = time.monotonic()

    try:
        config = load_config()

        banner.main()

        if args.update:
            return 0 if update.update_program() else 1

        update.check_for_updates()

        df_columns = config.columns_for(args.columns)
        # Resolved before any parsing, so a typo in the profile name fails
        # immediately instead of after a directory has been read.
        resolved = resolve_rescan(args, config)
        ui.arguments(argument_rows(args, df_columns,
                                   resolved[0] if resolved else None))

        ui.section(i18n.t("section.parsing"))
        run = parse_xml_files(single_xml=args.file,
                              folder_multiple_xml=args.directory,
                              list_output_format=args.outputformat,
                              file_output_name=args.outputname,
                              merger=args.merger,
                              recursive=args.recursive,
                              df_columns=df_columns,
                              only_open_ports=args.open,
                              config=config,
                              validate=args.validate,
                              include_hostless=args.include_hostless)

        # Announced here, once, for all three branches -- which is also why a
        # non-merged directory run finally lists what it wrote.
        ui.output_files(run.written)
        # After the paths are out: --show must not cost you the deliverable
        # list if there is no browser to hand it to.
        if args.show:
            show_reports(run.written)
        # Last, so the commands you are about to copy are the closest thing to
        # the prompt -- and after --show, which can fail noisily.
        if resolved:
            report_rescan(run, config, resolved)
        run.elapsed = time.monotonic() - started
        ui.summary(run)
        return 0

    except XnpError as exc:
        logger.error(str(exc))
        return exc.exit_code
    except KeyboardInterrupt:
        # Leave the terminal in a sane state when Ctrl-C lands mid-display.
        return 130


if __name__ == "__main__":
    sys.exit(main())
