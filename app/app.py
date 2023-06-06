import os
import confuse
import logging
from utils import cli
from utils import banner
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

def parse_file(filename):
    logging.info(f"    |+| Parsing | {filename}")
    df = nmap.parser(filename)
    return df

def export_data(output_format_list, df, filename):
    filename = filename.split(NMAP_FILE_EXTENSION)[0]
    for output_format in output_format_list:
        output_filename = f"{filename}.{output_format}"
        if output_format == "csv":
            file_output.df_to_csv(df, output_filename)

        if output_format == "xlsx":
            file_output.df_to_xlsx(df, output_filename)

def get_dir_files(dir):
    return os.listdir(dir)

def print_arguments_info(filename, folder, output_format_list):
    print(f"""  
    --------------------------------------------------------------  
    | Arguments information  
    --------------------------------------------------------------  
    | File (-f) | {filename}  
    | Folder (-d) | {folder}  
    | Output format (-o) | {output_format_list}  
    --------------------------------------------------------------  
    """)

def parse_and_export_files(filename, folder, output_format_list):
    ## Nmap XLM file
    if filename:
        df = parse_file(filename)
        export_data(output_format_list, df, filename)

    ## Directory with nmap XML files
    if folder:
        folder_files = get_dir_files(folder)
        files_xml = [i for i in folder_files if i.endswith(".xml")]
        for xmlfile in files_xml:
            full_path = folder + xmlfile
            df = parse_file(full_path)
            if df.empty:
                logging.warning(f"    |?| Warning | {full_path} has no data, omitting export")
            else:
                export_data(output_format_list, df, full_path)

def run():
    try:
        banner.ascii()
        args = cli.get()

        filename = args.nmapxmlfile
        folder = args.nmapxmldir
        # Get output formats
        output_format_list = args.outputformat
        output_format_list = output_format_list.split(",")

        print_arguments_info(filename, folder, output_format_list)

        # Parse files
        print(f"""
    --------------------------------------------------------------
    | Parsing files
    --------------------------------------------------------------\n""")

        parse_and_export_files(filename, folder, output_format_list)

        print("\n")

    except Exception as e:
        logging.error("|-| Error executing script")
        logging.error(e)