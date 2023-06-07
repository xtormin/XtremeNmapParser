import confuse
import logging
from utils import cli
from utils import banner
from utils import functions as func
from utils.logs import setup_logging
import app.modules.nmap_parser as nmap
from app.modules import file_output

# Logging configuration
setup_logging()

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
file_xml_to_parse = args.nmapxmlfile
folder_xml_to_parse = args.nmapxmldir

def export_data(df, file_xml):
    if df.empty:
        logging.warning(f"    |?| Warning | {file_xml} has no data, omitting export")
    else:
        if file_xml:
            outputname = file_xml.split(NMAP_FILE_EXTENSION)[0]

        if args.mergefiles:
            if args.outputname:
                outputname = args.outputname
            else:
                outputname = "merged_nmap_scan_data"

        for output_format in output_format_list:
            output_file_xml = f"{outputname}.{output_format}"
            if output_format == "csv":
                file_output.df_to_csv(df, output_file_xml)

            if output_format == "xlsx":
                file_output.df_to_xlsx(df, output_file_xml)

def print_arguments_info(file_xml, folder):
    print(f"""  
    --------------------------------------------------------------  
    | Arguments information  
    --------------------------------------------------------------  
    | File (-f)          | {file_xml}  
    | Folder (-d)        | {folder}  
    | Merge files (-M)   | {merger}  
    | Output format (-o) | {output_format_list}  
    --------------------------------------------------------------  
    """)

def print_progress_info():
    # Parse files
    print(f"""
    --------------------------------------------------------------
    | Parsing files
    --------------------------------------------------------------\n""")

def file_parse_output(file_xml):
    df = nmap.parse_file(file_xml)
    export_data(df, file_xml)

def parse_and_export_files(file_xml, folder):
    ## Nmap XLM file
    if file_xml:
        file_parse_output(file_xml)

    ## Directory with multiple nmap XML files
    if folder:
        folder_files = func.get_dir_files(folder)
        files_xml = [folder + i for i in folder_files if i.endswith(".xml")]

        if merger:
            df = nmap.merge_xml_files(files_xml)
            export_data(df, file_xml)

        else:
            for file_xml in files_xml:
                file_parse_output(file_xml)

def run():

    banner.ascii()

    # Show arguments info
    print_arguments_info(file_xml_to_parse, folder_xml_to_parse)

    # Show parsing info
    print_progress_info()
    parse_and_export_files(file_xml_to_parse, folder_xml_to_parse)

    print("\n")

