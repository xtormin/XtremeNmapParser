"""Filtering and export of the parsed DataFrame (CSV / XLSX / JSON)."""

import os

import pandas as pd

from xnp.config import load_config
from xnp.errors import XnpError
from xnp.logs import get_logger

logger = get_logger(__name__)

DEFAULT_MERGED_NAME = "merged_nmap_scan_data"


def adjust_columns(worksheet, df):
    """Widen each column to fit its longest value."""
    for i, col in enumerate(df.columns):
        column_len = df[col].astype(str).str.len().max()
        column_len = max(column_len, len(col)) + 2
        worksheet.set_column(i, i, column_len)


def header_format_style(workbook, config=None):
    config = config or load_config()
    header_format = workbook.add_format()
    header_format.set_bg_color(config.header_color)
    header_format.set_bold()
    header_format.set_font_color(config.header_text_color)
    header_format.set_center_across()
    return header_format


def _ensure_parent_dir(filename):
    parent = os.path.dirname(filename)
    if parent and not os.path.isdir(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            raise XnpError(f" |x| Error | Could not create {parent}: {exc}") from exc


def df_to_xlsx(df, filename, config=None):
    config = config or load_config()
    _ensure_parent_dir(filename)
    try:
        writer = pd.ExcelWriter(filename, engine='xlsxwriter')
        df.to_excel(writer, sheet_name=config.sheet_name, index=False)
        workbook = writer.book
        worksheet = writer.sheets[config.sheet_name]
        worksheet.set_tab_color(config.header_color)
        (max_row, max_col) = df.shape
        adjust_columns(worksheet, df)
        header_format = header_format_style(workbook, config)
        table_headers = [{'header': column, 'header_format': header_format}
                         for column in df.columns.tolist()]
        worksheet.add_table(0, 0, max_row, max_col - 1, {'name': 'NmapScanData',
                                                         'style': config.table_style,
                                                         'columns': table_headers})
        writer.close()
        logger.info(f" |+| Output | xlsx | {filename}")
    except (OSError, ValueError) as exc:
        raise XnpError(f" |x| Error | {filename} file not created: {exc}") from exc


def df_to_csv(df, filename):
    _ensure_parent_dir(filename)
    try:
        df.to_csv(filename, sep=';', encoding='utf-8', index=False)
        logger.info(f" |+| Output | csv | {filename}")
    except (OSError, ValueError) as exc:
        raise XnpError(f" |x| Error | {filename} file not created: {exc}") from exc


def df_to_json(df, filename):
    _ensure_parent_dir(filename)
    try:
        df.to_json(filename, orient='records', lines=True)
        logger.info(f" |+| Output | json | {filename}")
    except (OSError, ValueError) as exc:
        raise XnpError(f" |x| Error | {filename} file not created: {exc}") from exc


WRITERS = {
    "csv": df_to_csv,
    "xlsx": df_to_xlsx,
    "json": df_to_json,
}


def get_output_name(file_xml, output_name, merger, config=None):
    """Work out the base name (no extension) for the output files.

    An explicit ``-oN`` always wins; it used to be silently dropped whenever
    ``-f`` was given.  Deriving the name from the XML uses splitext so that a
    path containing ``.xml`` in a *directory* component is not truncated.
    """
    if output_name:
        return output_name
    if file_xml:
        return os.path.splitext(file_xml)[0]
    if merger:
        return DEFAULT_MERGED_NAME
    return None


def write_dataframe(df, list_output_format, file_output_name=None, merger=None, file_xml=None,
                    config=None):
    if df is None or df.empty:
        logger.warning(" |?| Warning | The file has no scan data, omitting export")
        return

    output_name = get_output_name(file_xml, file_output_name, merger, config)

    for output_format_type in list_output_format:
        writer = WRITERS.get(output_format_type)
        if writer is None:
            continue
        writer(df, f"{output_name}.{output_format_type}")


def export_single_xml(df, xml_file, list_output_format, file_output_name=None, config=None):
    write_dataframe(df=df, file_xml=xml_file, list_output_format=list_output_format,
                    file_output_name=file_output_name, config=config)


def export_multiple_xml(df, list_output_format, file_output_name, merger, config=None):
    write_dataframe(df=df, list_output_format=list_output_format,
                    file_output_name=file_output_name, merger=merger, config=config)


def df_output_filters(df, df_columns, only_open_ports):
    """Select the requested columns, optionally keep only open ports, and sort."""
    if df is None or df.empty:
        return df

    missing = [c for c in df_columns if c not in df.columns]
    if missing:
        raise XnpError(f" |x| Error | Unknown output columns: {', '.join(missing)}")

    df = df[df_columns].copy()

    if only_open_ports:
        df = df.loc[df['State Port'] == 'open']

    # Ports must sort numerically, not as strings.  to_numeric keeps rows whose
    # port is empty (hosts with no ports) instead of raising on them.
    df['Port'] = pd.to_numeric(df['Port'], errors='coerce').astype('Int64')

    return df.sort_values(by=['IP', 'Port'])
