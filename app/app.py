import confuse
from app.utils import cli, banner, functions as func
from app.utils.logs import CustomLogger
import app.modules.parser_nmap as nmap
from app.modules import output_format

# Logging configuration
logger = CustomLogger('test')

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

APPNAME = config['appname'].get()
NMAP_FILE_EXTENSION = config['nmap_file_extension'].get()

# Global arguments
args = cli.get()
merger = args.mergefiles
output_format_list = args.outputformat
output_format_list = output_format_list.split(",")
output_name = args.outputname
file_xml_to_parse = args.nmapxmlfile
folder_xml_to_parse = args.nmapxmldir

def export_data(df, file_xml):
    if df.empty:
        logger.warning(f" |?| Warning | {file_xml} has no data, omitting export")
    else:
        if file_xml:
            outputname = file_xml.split(NMAP_FILE_EXTENSION)[0]

        if args.mergefiles:
            if args.outputname:
                outputname = output_name
            else:
                outputname = "merged_nmap_scan_data"

        for output_format_type in output_format_list:
            output_file_xml = f"{outputname}.{output_format_type}"
            if output_format_type == "csv":
                output_format.df_to_csv(df, output_file_xml)
            elif output_format_type == "xlsx":
                output_format.df_to_xlsx(df, output_file_xml)
            elif output_format_type == "json":
                output_format.df_to_json(df, output_file_xml)

def file_parse_output(file_xml):
    df = nmap.parse_file(file_xml)
    if df is not None:
        export_data(df, file_xml)

def parse_and_export_files(file_xml, folder):
    ## Nmap XLM file
    if file_xml:
        file_parse_output(file_xml)

    ## Directory with multiple nmap XML files
    if folder:
        try:
            folder_files = func.get_dir_files(folder)
            files_xml = [folder + i for i in folder_files if i.endswith(NMAP_FILE_EXTENSION)]

            if merger:
                df = nmap.merge_xml_files(files_xml)
                export_data(df, file_xml)

            else:
                for file_xml in files_xml:
                    file_parse_output(file_xml)
                    print("\n")
        except FileNotFoundError:
            logger.error(f"|-| File {folder} not found")
        except NotADirectoryError:
            logger.error(f"|-| Are you sure that {folder} is a directory?")

def run():

    banner.main()

    # Show arguments info
    banner.print_arguments_info(file_xml_to_parse, folder_xml_to_parse, merger, output_format_list, output_name)

    # Show parsing info
    banner.print_progress_info()
    parse_and_export_files(file_xml_to_parse, folder_xml_to_parse)

    print("\n")

