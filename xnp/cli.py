"""Command line entry point."""

import argparse
import os
import sys
from collections.abc import Sequence
from typing import Optional

from xnp import __version__, banner, update
from xnp import files as func
from xnp import output as out
from xnp.config import load_config
from xnp.errors import NoInputFilesError, XnpError, short_reason
from xnp.logs import get_logger, setup_logging
from xnp.parser import NmapParser

logger = get_logger(__name__)


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
    parser.add_argument('-v', '--verbose',
                        help='Verbose',
                        action="store_true")
    parser.add_argument('-M', '--merger',
                        help='Merge XML files from directory',
                        action="store_true")
    parser.add_argument('-R', '--recursive',
                        help='Parse XML files from a directory recursively',
                        action="store_true")
    parser.add_argument('-C', '--columns',
                        type=str,
                        choices=['default', 'all'],
                        help='Columns for the output dataframe')
    parser.add_argument('--open',
                        help='Export only the ports with "open" value in "State Port"',
                        action="store_true")
    parser.add_argument('--include-hostless',
                        dest='include_hostless',
                        action="store_true",
                        help='Also emit a row for hosts with no ports (down or fully filtered)')
    parser.add_argument('--no-validate',
                        dest='validate',
                        action="store_false",
                        help='Skip DTD validation. Needed for nmap-compatible output from '
                             'other scanners (masscan, naabu)')
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

    for flag, name in ((args.merger, "-M/--merger"), (args.recursive, "-R/--recursive")):
        if flag and not args.directory:
            parser.error(f"{name} only makes sense together with -d/--directory")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    return args


def help():
    return build_parser().print_help(sys.stderr)


def parse_xml_files(single_xml, folder_multiple_xml, list_output_format, file_output_name,
                    merger, recursive, df_columns, only_open_ports, config=None,
                    validate=True, include_hostless=False):
    config = config or load_config()

    def export(df, xml_file=None, context=None):
        df = out.df_output_filters(df, df_columns, only_open_ports)
        out.export_single_xml(df, xml_file, list_output_format, file_output_name, config,
                              context=context)

    def html_context(reports, sources, merge=False):
        """Everything the HTML report needs that the DataFrame cannot carry."""
        return {"reports": reports, "sources": sources, "merge": merge,
                "only_open": only_open_ports}

    # Single nmap XML file
    if single_xml:
        parser = NmapParser(single_xml, validate, include_hostless)
        df = parser.parse_file()
        if df is None:
            logger.warning(" |?| Warning | The file has no scan data, omitting export")
        else:
            banner.print_output_files_info()
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
        if merger:
            df, reports, skipped = NmapParser.merge_all(
                xml_files, validate, include_hostless, skip_invalid=True)
            banner.print_output_files_info()
            df = out.df_output_filters(df, df_columns, only_open_ports)
            out.export_multiple_xml(df, list_output_format, file_output_name, merger, config,
                                    context=html_context(reports, xml_files, merge=True))
        else:
            skipped = []
            for xml_file in xml_files:
                parser = NmapParser(xml_file, validate, include_hostless)
                try:
                    df = parser.parse_file()
                except XnpError as exc:
                    logger.warning(f" |?| Warning | Skipping {xml_file}: "
                                   f"{short_reason(exc, xml_file)}")
                    skipped.append((xml_file, exc))
                    print("\n")
                    continue
                if df is None:
                    logger.warning(" |?| Warning | The file has no scan data, omitting export")
                else:
                    export(df, xml_file, html_context([parser.report], [xml_file]))
                print("\n")

            if len(skipped) == len(xml_files):
                raise skipped[0][1]

        report_skipped(skipped, len(xml_files))


def report_skipped(skipped, total):
    """Say plainly what was left out, so a partial run is never a silent one."""
    if not skipped:
        return
    logger.warning(f" |?| Warning | {len(skipped)} of {total} files were skipped:")
    for xml_file, _ in skipped:
        logger.warning(f" |?|   {xml_file}")
    logger.warning(" |?| Warning | Pass --no-validate if they come from another scanner")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run XNP. Returns the process exit code."""
    args = parse_args(argv)
    setup_logging(args.verbose)

    try:
        config = load_config()

        banner.main()

        if args.update:
            return 0 if update.update_program() else 1

        update.check_for_updates()

        df_columns = config.columns_for(args.columns)
        banner.print_arguments_info(single_xml=args.file,
                                    folder_multiple_xml=args.directory,
                                    list_output_format=args.outputformat,
                                    file_output_name=args.outputname,
                                    merger=args.merger,
                                    recursive=args.recursive,
                                    df_columns=df_columns,
                                    only_open_ports=args.open)

        banner.print_progress_info()
        parse_xml_files(single_xml=args.file,
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

        print("\n")
        return 0

    except XnpError as exc:
        logger.error(str(exc))
        print("\n")
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
