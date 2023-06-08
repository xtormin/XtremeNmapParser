import confuse
from app.utils import cli, banner, functions as func
from app.utils.logs import CustomLogger
import app.modules.parser_nmap as nmap
from app.modules import output_format as out

# Logging configuration
logger = CustomLogger('test')

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

APPNAME = config['appname'].get()
NMAP_FILE_EXTENSION = config['nmap_file_extension'].get()


def export_single_xml(file_xml, list_output_format):
    df = nmap.parse_file(file_xml)
    if df is not None:
        out.write_dataframe(df=df, file_xml=file_xml, list_output_format=list_output_format)

def export_multiple_xml(files_xml, list_output_format, file_output_name, merger):
    df = nmap.merge_xml_files(files_xml)
    if df is not None:
        out.write_dataframe(df=df, list_output_format=list_output_format, file_output_name=file_output_name, merger=merger)

def parse_xml_files(single_xml, folder_multiple_xml, list_output_format, file_output_name, merger):
    ## Nmap XLM file
    if single_xml:
        export_single_xml(single_xml, list_output_format)

    ## Directory with multiple nmap XML files
    if folder_multiple_xml:
        try:
            folder_files = func.get_dir_files(folder_multiple_xml)
            files_xml = [folder_multiple_xml + i for i in folder_files if i.endswith(NMAP_FILE_EXTENSION)]

            if merger:
                export_multiple_xml(files_xml, list_output_format, file_output_name, merger)
            else:
                for file_xml in files_xml:
                    export_single_xml(file_xml, list_output_format)
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
        merger = args.mergefiles

    except AttributeError as AE:
        logger.error(f" |-| Error | Tried to split a None object.")

    banner.main()

    # Show arguments info
    banner.print_arguments_info(single_xml=single_xml,
                                folder_multiple_xml=folder_multiple_xml,
                                list_output_format=list_output_format,
                                file_output_name=file_output_name,
                                merger=merger)

    # Show parsing info
    banner.print_progress_info()
    parse_xml_files(single_xml=single_xml,
                    folder_multiple_xml=folder_multiple_xml,
                    list_output_format=list_output_format,
                    file_output_name=file_output_name,
                    merger=merger)

    print("\n")

