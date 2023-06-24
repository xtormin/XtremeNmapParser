import confuse
from app.utils import cli, banner, functions as func
from app.utils.logs import CustomLogger
from app.utils import update
from app.modules.NmapParser import *
from app.modules import OutputFormat as out

# Logging configuration
logger = CustomLogger('test')

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

APPNAME = config['appname'].get()
NMAP_FILE_EXTENSION = config['nmap_file_extension'].get()
HEADERS_DEFAULT = config['xlsx']['headers_default'].get()

def parse_xml_files(single_xml, folder_multiple_xml, list_output_format, file_output_name, merger, recursive, df_columns, only_open_ports):
    ## Nmap XLM file
    if single_xml:
        # Create dataframe with nmap data
        df = NmapParser(single_xml).parse_file()
        df = out.df_output_filters(df, df_columns, only_open_ports)
        out.export_single_xml(df, single_xml, list_output_format)

    ## Directory with multiple nmap XML files
    if folder_multiple_xml:
        try:

            # Get XML file list to parse
            ## Recursive
            if recursive:
                xml_files = func.get_dir_files_recursive(folder_multiple_xml)
            else:
                 folder_files = func.get_dir_files(folder_multiple_xml)
                 xml_files = [folder_multiple_xml + i for i in folder_files if i.endswith(NMAP_FILE_EXTENSION)]

            # XML files not found in folder
            if not xml_files:
                logger.error(f" |-| XML files in {folder_multiple_xml} not found")
                print("\n")
                exit(1)

            # Merge XML files
            if merger:
                # Create dataframe with nmap data merged
                df = NmapParser.merge_df(xml_files)
                banner.print_output_files_info()
                df = out.df_output_filters(df, df_columns, only_open_ports)
                out.export_multiple_xml(df, list_output_format, file_output_name, merger)
            else:
                for xml_file in xml_files:
                    # Create dataframe with nmap data
                    df = NmapParser(xml_file).parse_file()
                    df = out.df_output_filters(df, df_columns, only_open_ports)
                    out.export_single_xml(df, xml_file, list_output_format)
                    print("\n")

        except FileNotFoundError:
            logger.error(f" |-| File {folder_multiple_xml} not found")
        except NotADirectoryError:
            logger.error(f" |-| Are you sure that {folder_multiple_xml} is a directory?")

def run():

    # Arguments
    try:
        args = cli.get()
        single_xml = args.nmapxmlfile
        folder_multiple_xml = func.add_slash_if_needed(args.nmapxmldir) if args.nmapxmldir else None
        list_output_format = (args.outputformat).split(",")
        file_output_name = args.outputname
        merger = args.merger
        recursive = args.recursive
        only_open_ports = args.open
        df_columns = args.columns if args.columns else HEADERS_DEFAULT

    except AttributeError as AE:
        logger.error(AE)

    # Banner
    banner.main()

    # Update tool
    update.update_program()

    # Show arguments info
    banner.print_arguments_info(single_xml=single_xml,
                                folder_multiple_xml=folder_multiple_xml,
                                list_output_format=list_output_format,
                                file_output_name=file_output_name,
                                merger=merger,
                                recursive=recursive,
                                df_columns=df_columns,
                                only_open_ports=only_open_ports)

    # Show parsing info
    banner.print_progress_info()
    parse_xml_files(single_xml=single_xml,
                    folder_multiple_xml=folder_multiple_xml,
                    list_output_format=list_output_format,
                    file_output_name=file_output_name,
                    merger=merger,
                    recursive=recursive,
                    df_columns=df_columns,
                    only_open_ports=only_open_ports)

    print("\n")

