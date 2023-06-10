import os
from app.utils import cli, banner, functions as func
from app.utils.logs import CustomLogger
from app.modules.NmapParser import *
from app.modules import OutputFormat as out

# Logging configuration
logger = CustomLogger('test')

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

APPNAME = config['appname'].get()
NMAP_FILE_EXTENSION = config['nmap_file_extension'].get()


def export_single_xml(xml_file, list_output_format):
    df = NmapParser(xml_file).parse_file()
    if df is not None:
        out.write_dataframe(df=df, file_xml=xml_file, list_output_format=list_output_format)

def export_multiple_xml(xml_file_list, list_output_format, file_output_name, merger):
    df = NmapParser.merge_df(xml_file_list)
    if df is not None:
        banner.print_output_files_info()
        out.write_dataframe(df=df, list_output_format=list_output_format, file_output_name=file_output_name, merger=merger)

def get_dir_files_recursive(folder):
    xml_files = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.endswith(NMAP_FILE_EXTENSION):
                xml_files.append(os.path.join(root, file))
    return xml_files

def parse_xml_files(single_xml, folder_multiple_xml, list_output_format, file_output_name, merger, recursive):
    ## Nmap XLM file
    if single_xml:
        export_single_xml(single_xml, list_output_format)

    ## Directory with multiple nmap XML files
    if folder_multiple_xml:
        try:
            if not folder_multiple_xml.endswith("/"):
                folder_multiple_xml = f"{folder_multiple_xml}/"

            # Recursive
            if recursive:
                xml_files = get_dir_files_recursive(folder_multiple_xml)
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
                banner.print_output_files_info()
                export_multiple_xml(xml_files, list_output_format, file_output_name, merger)
            else:
                for xml_file in xml_files:
                    export_single_xml(xml_file, list_output_format)
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
        folder_multiple_xml = args.nmapxmldir
        list_output_format = (args.outputformat).split(",")
        file_output_name = args.outputname
        merger = args.merger
        recursive = args.recursive

    except AttributeError as AE:
        logger.error(f" |-| Error | Tried to split a None object.")

    banner.main()

    # Show arguments info
    banner.print_arguments_info(single_xml=single_xml,
                                folder_multiple_xml=folder_multiple_xml,
                                list_output_format=list_output_format,
                                file_output_name=file_output_name,
                                merger=merger,
                                recursive=recursive)

    # Show parsing info
    banner.print_progress_info()
    parse_xml_files(single_xml=single_xml,
                    folder_multiple_xml=folder_multiple_xml,
                    list_output_format=list_output_format,
                    file_output_name=file_output_name,
                    merger=merger,
                    recursive=recursive)

    print("\n")

