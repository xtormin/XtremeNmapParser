import logging
import confuse
import pandas as pd
from utils.logs import setup_logging

# Logging configuration
setup_logging()

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

HEADERS = config['xlsx']['headers'].get()
SHEET_NAME = config['xlsx']['sheet_name'].get()
HEADERS_COLOR = config['xlsx']['headers_color'].get()
HEADERS_TEXT_COLOR = config['xlsx']['headers_text_color'].get()
TABLE_STYLE = config['xlsx']['table_style'].get()

def adjust_columns(worksheet, df):
    for i, col in enumerate(df.columns):
        # find length of column i
        column_len = df[col].astype(str).str.len().max()
        # Setting the length if the column header is larger
        # than the max column value length
        column_len = max(column_len, len(col)) + 2
        # set the column length
        worksheet.set_column(i, i, column_len)

def df_to_xlsx(df, filename):
    try:
        df = df[HEADERS]

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

        # Worksheet format
        center_format = workbook.add_format().set_center_across()
        bold = workbook.add_format().set_bold()

        # Columns format
        adjust_columns(worksheet, df)


        # Header format
        header_format = workbook.add_format()
        header_format.set_bg_color(HEADERS_COLOR)
        header_format.set_bold()
        header_format.set_font_color(HEADERS_TEXT_COLOR)
        header_format.set_center_across()

        # Table headers with custom format
        table_headers = []
        for column in HEADERS: table_headers.append({'header': column, 'header_format': header_format})

        # Create table with custom format
        worksheet.add_table(0, 0, max_row, max_col - 1, {'name': 'NmapScanData',
                                                         'style': TABLE_STYLE,
                                                         'columns': table_headers })

        # Close XLSX file
        writer.close()

        logging.info(f"    |+| Output | xlsx | {filename}")
    except Exception as e:
        logging.error(f"|x| Error output | {filename} file not created")
        logging.error(e)

def df_to_csv(df, filename):
    try:
        df.to_csv(filename,
                  sep=';',
                  encoding='utf-8',
                  header=None,
                  index=False)
        logging.info(f"    |+| Output | csv | {filename}")
    except Exception as e:
        logging.error(f"|x| Error output | {filename} file not created")
        logging.error(e)