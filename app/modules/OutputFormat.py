import confuse
import pandas as pd
from app.utils.logs import CustomLogger

# Logging configuration
logger = CustomLogger('test')

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

NMAP_FILE_EXTENSION = config['nmap_file_extension'].get()
SHEET_NAME = config['xlsx']['sheet']['name'].get()
HEADERS_COLOR = config['xlsx']['header']['color'].get()
HEADERS_TEXT_COLOR = config['xlsx']['header']['text']['color'].get()
TABLE_STYLE = config['xlsx']['table']['style'].get()

def adjust_columns(worksheet, df):
    for i, col in enumerate(df.columns):
        # find length of column i
        column_len = df[col].astype(str).str.len().max()
        # Setting the length if the column header is larger
        # than the max column value length
        column_len = max(column_len, len(col)) + 2
        # set the column length
        worksheet.set_column(i, i, column_len)

def header_format_style(workbook):
    header_format = workbook.add_format()
    header_format.set_bg_color(HEADERS_COLOR)
    header_format.set_bold()
    header_format.set_font_color(HEADERS_TEXT_COLOR)
    header_format.set_center_across()
    return header_format

def df_to_xlsx(df, filename):
    try:
        # Create a Pandas Excel Writer using Xlsxwriter as the engine
        writer = pd.ExcelWriter(filename, engine='xlsxwriter')
        # Converts the dataframe to a Xlsxwriter Excel Object
        df.to_excel(writer, sheet_name=SHEET_NAME, index=False)
        # Get the xlsxwriter workbook and worksheet objects
        workbook = writer.book
        worksheet = writer.sheets[SHEET_NAME]
        # Tab color
        worksheet.set_tab_color(HEADERS_COLOR)
        # Get the dimensions of the database
        (max_row, max_col) = df.shape
        # Columns format
        adjust_columns(worksheet, df)
        # Header format
        header_format = header_format_style(workbook)
        # Table headers with custom format
        table_headers = []
        table_headers = [{'header': column, 'header_format': header_format} for column in df.columns.tolist()]
        # Create table with custom format
        worksheet.add_table(0, 0, max_row, max_col - 1, {'name': 'NmapScanData',
                                                         'style': TABLE_STYLE,
                                                         'columns': table_headers })
        # Close XLSX file
        writer.close()
        logger.info(f" |+| Output | xlsx | {filename}")
    except Exception as e:
        logger.error(f" |x| Error | {filename} file not created")
        logger.error(e)

def df_to_csv(df, filename):
    try:
        df.to_csv(filename, sep=';', encoding='utf-8', index=False)
        logger.info(f" |+| Output | csv | {filename}")
    except Exception as e:
        logger.error(f" |x| Error | {filename} file not created")
        logger.error(e)

def df_to_json(df, filename):
    try:
        df.to_json(filename, orient='records', lines=True)
        logger.info(f" |+| Output | json | {filename}")
    except Exception as e:
        logger.error(f" |x| Error | {filename} file not created")
        logger.error(e)

def get_output_name(file_xml, output_name, merger):
    if file_xml:
        output_name = file_xml.split(NMAP_FILE_EXTENSION)[0]

    if merger:
        if not output_name:
            output_name = "merged_nmap_scan_data"



    return output_name
def write_dataframe(df, list_output_format, file_output_name=None, merger=None, file_xml=None):
    if df.empty:
        logger.warning(f" |?| Warning | The file has no scan data, omitting export")
    else:
        output_name = get_output_name(file_xml, file_output_name, merger)

        for output_format_type in list_output_format:
            output_file_xml = f"{output_name}.{output_format_type}"
            if output_format_type == "csv":
                df_to_csv(df, output_file_xml)
            elif output_format_type == "xlsx":
                df_to_xlsx(df, output_file_xml)
            elif output_format_type == "json":
                df_to_json(df, output_file_xml)

def export_single_xml(df, xml_file, list_output_format):
    write_dataframe(df=df, file_xml=xml_file, list_output_format=list_output_format)

def export_multiple_xml(df, list_output_format, file_output_name, merger):
    write_dataframe(df=df, list_output_format=list_output_format, file_output_name=file_output_name, merger=merger)

def df_output_filters(df, df_columns, only_open_ports):
    # Columns to export
    df = df[df_columns]

    if only_open_ports:
        # Remove rows where port state is not "open"
        df = df.loc[df['State Port'] == 'open']

    # Convert 'Port' to int for proper sorting
    # Create a DataFrame copy
    df_copy = df.copy()

    # Modify DF copy
    column_index = df_copy.columns.get_loc('Port')
    df_copy['Port'] = df_copy['Port'].astype(int)

    # Sort final dataframe by 'IP' and then 'Port'
    df = df_copy.sort_values(by=['IP', 'Port'])

    return df
