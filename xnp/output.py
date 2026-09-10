"""Filtering and export of the parsed DataFrame (CSV / XLSX / JSON / HTML)."""

import os
from datetime import datetime
from typing import Optional

import pandas as pd

from xnp import html_report, i18n, stats
from xnp.config import XnpConfig, load_config
from xnp.errors import XnpError
from xnp.logs import get_logger

logger = get_logger(__name__)

DEFAULT_MERGED_NAME = "merged_nmap_scan_data"
# Sortable, and free of the characters a shell or Windows would object to.
TIMESTAMP_FORMAT = "%Y%m%d-%H%M%S"


def merged_output_name(directory: str, when: Optional[datetime] = None) -> str:
    """Base name (no extension) for a merged directory run.

    The report is named after the folder it came from and stamped with the
    time, and it lands *inside* that folder -- next to the scans it was built
    from, like the per-file outputs already do, rather than in whatever
    directory the command happened to be run from.  The stamp means a second
    run adds a report instead of quietly overwriting yesterday's deliverable.

    ``-oN`` still overrides all of this, and is taken exactly as given.
    """
    # normpath first, so "nmap/" is the "nmap" folder and not an empty name;
    # abspath so that "." and ".." are named after the folder they resolve to.
    folder = os.path.basename(os.path.normpath(os.path.abspath(directory)))
    stamp = (when or datetime.now()).strftime(TIMESTAMP_FORMAT)
    # At the filesystem root there is no folder name to borrow.
    return os.path.join(directory, f"{folder or DEFAULT_MERGED_NAME}_{stamp}")


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


def df_to_xlsx(df: pd.DataFrame, filename: str,
               config: Optional[XnpConfig] = None, context: Optional[dict] = None) -> None:
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
    except (OSError, ValueError) as exc:
        raise XnpError(f" |x| Error | {filename} file not created: {exc}") from exc


def df_to_csv(df: pd.DataFrame, filename: str, config: Optional[XnpConfig] = None,
              context: Optional[dict] = None) -> None:
    _ensure_parent_dir(filename)
    try:
        df.to_csv(filename, sep=';', encoding='utf-8', index=False)
    except (OSError, ValueError) as exc:
        raise XnpError(f" |x| Error | {filename} file not created: {exc}") from exc


def df_to_json(df: pd.DataFrame, filename: str, config: Optional[XnpConfig] = None,
               context: Optional[dict] = None) -> None:
    _ensure_parent_dir(filename)
    try:
        df.to_json(filename, orient='records', lines=True)
    except (OSError, ValueError) as exc:
        raise XnpError(f" |x| Error | {filename} file not created: {exc}") from exc


def df_to_html(df: pd.DataFrame, filename: str, config: Optional[XnpConfig] = None,
               context: Optional[dict] = None) -> None:
    """Write the self-contained HTML report.

    ``context`` carries what the flat DataFrame cannot: the parsed reports,
    their source paths and whether ``--open`` was asked for.  Without it the
    report is still produced, just from the DataFrame alone -- see
    :func:`xnp.html_report.payload_from_dataframe`.
    """
    config = config or load_config()
    context = context or {}
    _ensure_parent_dir(filename)
    basename = html_report.basename_for(filename)
    # The language the run was asked for becomes the report's default; a reader
    # who has already picked one in the report keeps theirs.
    lang = context.get("lang") or i18n.current()

    try:
        reports = context.get("reports")
        if reports:
            payload = html_report.build_payload(
                reports=reports,
                sources=context.get("sources"),
                merge=bool(context.get("merge")),
                only_open=bool(context.get("only_open")),
                title=config.html_title,
                title_en=config.html_title_en,
                basename=basename,
                lang=lang)
        else:
            payload = html_report.payload_from_dataframe(
                df, title=config.html_title, title_en=config.html_title_en,
                basename=basename, lang=lang)

        html_report.write(payload, filename, config)
    except (OSError, ValueError, TypeError) as exc:
        raise XnpError(f" |x| Error | {filename} file not created: {exc}") from exc


WRITERS = {
    "csv": df_to_csv,
    "xlsx": df_to_xlsx,
    "json": df_to_json,
    "html": df_to_html,
}


def get_output_name(file_xml: Optional[str], output_name: Optional[str],
                    merger: Optional[bool],
                    config: Optional[XnpConfig] = None) -> Optional[str]:
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
                    config=None, context=None) -> list:
    """Write every requested format, returning what was produced.

    The return value is a list of :class:`~xnp.stats.WrittenFile`, sized on
    disk here because this is the one place all four formats pass through.  The
    caller announces them; the writers no longer log a line each.
    """
    if df is None or df.empty:
        logger.warning(i18n.t("warn.no_data"))
        return []

    output_name = get_output_name(file_xml, file_output_name, merger, config)

    written = []
    for output_format_type in list_output_format:
        writer = WRITERS.get(output_format_type)
        if writer is None:
            continue
        path = f"{output_name}.{output_format_type}"
        writer(df, path, config=config, context=context)
        written.append(stats.written_file(output_format_type, path))
    return written


def export_single_xml(df, xml_file, list_output_format, file_output_name=None, config=None,
                      context=None) -> list:
    return write_dataframe(df=df, file_xml=xml_file, list_output_format=list_output_format,
                           file_output_name=file_output_name, config=config, context=context)


def export_multiple_xml(df, list_output_format, file_output_name, merger, config=None,
                        context=None) -> list:
    return write_dataframe(df=df, list_output_format=list_output_format,
                           file_output_name=file_output_name, merger=merger, config=config,
                           context=context)


def df_output_filters(df: Optional[pd.DataFrame], df_columns: list,
                      only_open_ports: bool) -> Optional[pd.DataFrame]:
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
