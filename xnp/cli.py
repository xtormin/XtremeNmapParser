"""Command line entry point."""

import argparse
import sys

from xnp import __version__, banner, update
from xnp import files as func
from xnp import output as out
from xnp.config import load_config
from xnp.errors import NoInputFilesError, XnpError
from xnp.logs import get_logger, setup_logging
from xnp.parser import NmapParser

logger = get_logger(__name__)


def build_parser():
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
                        choices=['csv', 'xlsx', 'json'],
                        help='Output file format (csv, xlsx, json). Ej: xnp -f nmapfile.xml -oF csv xlsx',
                        nargs='+',
                        type=str,
                        default=['csv', 'xlsx', 'json'])
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
    parser.add_argument('--version',
                        action='version',
                        version=f'%(prog)s {__version__}')
    return parser


def parse_args(argv=None):
    return build_parser().parse_args(argv)


def help():
    return build_parser().print_help(sys.stderr)


def parse_xml_files(single_xml, folder_multiple_xml, list_output_format, file_output_name,
                    merger, recursive, df_columns, only_open_ports, config=None):
    config = config or load_config()

    ## Nmap XLM file
    if single_xml:
        # Create dataframe with nmap data
        df = NmapParser(single_xml).parse_file()
        if df is not None:
            df = out.df_output_filters(df, df_columns, only_open_ports)
            banner.print_output_files_info()
            out.export_single_xml(df, single_xml, list_output_format)
        else:
            logger.warning(" |?| Warning | The file has no scan data, omitting export")

    ## Directory with multiple nmap XML files
    if folder_multiple_xml:
        try:

            # Get XML file list to parse
            ## Recursive
            if recursive:
                xml_files = func.get_dir_files_recursive(folder_multiple_xml, config)
            else:
                folder_files = func.get_dir_files(folder_multiple_xml)
                xml_files = [folder_multiple_xml + i for i in folder_files
                             if i.endswith(config.nmap_file_extension)]

            # XML files not found in folder
            if not xml_files:
                raise NoInputFilesError(f" |-| XML files in {folder_multiple_xml} not found")

            # Merge XML files
            if merger:
                # Create dataframe with nmap data merged
                df = NmapParser.merge_df(xml_files)
                if df is not None:
                    banner.print_output_files_info()
                    df = out.df_output_filters(df, df_columns, only_open_ports)
                    out.export_multiple_xml(df, list_output_format, file_output_name, merger)
                else:
                    logger.warning(" |?| Warning | The file has no scan data, omitting export")
            else:
                for xml_file in xml_files:
                    # Create dataframe with nmap data
                    df = NmapParser(xml_file).parse_file()
                    if df is not None:
                        df = out.df_output_filters(df, df_columns, only_open_ports)
                        out.export_single_xml(df, xml_file, list_output_format)
                    else:
                        logger.warning(" |?| Warning | The file has no scan data, omitting export")
                    print("\n")

        except FileNotFoundError:
            logger.error(f" |-| File {folder_multiple_xml} not found")
        except NotADirectoryError:
            logger.error(f" |-| Are you sure that {folder_multiple_xml} is a directory?")


def main(argv=None):
    """Run XNP. Returns the process exit code."""
    args = parse_args(argv)
    setup_logging(args.verbose)

    try:
        config = load_config()

        single_xml = args.file
        folder_multiple_xml = func.add_slash_if_needed(args.directory) if args.directory else None
        df_columns = config.columns_for(args.columns)

        # Banner
        banner.main()

        # Update tool
        update.update_program()

        # Show arguments info
        banner.print_arguments_info(single_xml=single_xml,
                                    folder_multiple_xml=folder_multiple_xml,
                                    list_output_format=args.outputformat,
                                    file_output_name=args.outputname,
                                    merger=args.merger,
                                    recursive=args.recursive,
                                    df_columns=df_columns,
                                    only_open_ports=args.open)

        # Show parsing info
        banner.print_progress_info()
        parse_xml_files(single_xml=single_xml,
                        folder_multiple_xml=folder_multiple_xml,
                        list_output_format=args.outputformat,
                        file_output_name=args.outputname,
                        merger=args.merger,
                        recursive=args.recursive,
                        df_columns=df_columns,
                        only_open_ports=args.open,
                        config=config)

        print("\n")
        return 0

    except XnpError as exc:
        logger.error(str(exc))
        print("\n")
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
