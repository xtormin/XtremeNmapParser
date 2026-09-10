"""Turn nmap XML reports into pandas DataFrames."""

import ipaddress
from collections.abc import Iterator
from typing import Optional

import pandas as pd
from lxml import etree

from xnp import stats
from xnp.errors import InvalidNmapReport, XnpError, short_reason
from xnp.logs import get_logger
from xnp.models import ScanData, empty_dataframe, to_dataframe
from xnp.xml_report import NmapXMLReport

logger = get_logger(__name__)

#: Columns used to decide which duplicate row carries the most information.
RELEVANCE_COLUMNS = ['Product', 'Version', 'Extrainfo']
RELEVANCE_HELPER_COLUMN = 'RelevantDuplicate'


class NmapParser:
    """Parse one nmap XML report into a DataFrame."""

    def __init__(self, xml_file: Optional[str] = None, validate: bool = True,
                 include_hostless: bool = False) -> None:
        self.xml_file = xml_file
        self.validate = validate
        self.include_hostless = include_hostless
        #: The parsed object model, kept so callers that need more than the
        #: eleven flat columns (the HTML report) can reach OS detection, scan
        #: metadata and structured NSE output without re-reading the file.
        self.report = None

    # --- Per-host extraction ------------------------------------------------

    @staticmethod
    def _host_address(host) -> Optional[str]:
        """Return the host address, preferring IPv4 but falling back to IPv6.

        Reading only ``addrtype == 'ipv4'`` used to leave every IPv6 host
        without an address.
        """
        addresses = {a.addrtype: a.addr for a in host.addresses}
        return addresses.get('ipv4') or addresses.get('ipv6')

    @staticmethod
    def _host_name(host) -> Optional[str]:
        name = None
        for hostnames in host.hostnames:
            for hostname in hostnames.hostnames:
                name = hostname.name
        return name

    @staticmethod
    def _host_state(host) -> Optional[str]:
        return host.status[0].state if host.status else None

    @staticmethod
    def _scripts(port) -> Optional[str]:
        """Render a port's scripts as readable ``id: output`` lines."""
        return "\n".join(
            f"{script.id}: {script.output}" for script in port.script
        ) or None

    def _row(self, host) -> ScanData:
        row = ScanData()
        row.data["Hostname"] = self._host_name(host)
        row.data["IP"] = self._host_address(host)
        row.data["State"] = self._host_state(host)
        return row

    def _rows_for_host(self, host) -> Iterator[ScanData]:
        """Yield one row per port, or a single port-less row when asked to."""
        if not host.ports:
            if self.include_hostless:
                yield self._row(host)
            return

        for port in host.ports:
            row = self._row(host)
            row.data["Port"] = port.portid
            row.data["Protocol"] = port.protocol
            row.data["Scripts"] = self._scripts(port)
            if port.state:
                row.data["State Port"] = port.state[0].state
            for service in port.service:
                row.data["Service Name"] = service.name
                row.data["Product"] = service.product
                row.data["Version"] = service.version
                row.data["Extrainfo"] = service.extrainfo
            yield row

    # --- Public API ---------------------------------------------------------

    def get_simple_df(self) -> Optional[pd.DataFrame]:
        """Return the report as a DataFrame, or ``None`` if it holds no rows."""
        try:
            report = NmapXMLReport(self.xml_file, validate=self.validate)
        except etree.XMLSyntaxError as exc:
            raise InvalidNmapReport(
                f" |x| Error | Could not parse {self.xml_file}. The scan may not have "
                f"finished properly and the file is truncated.\n   {exc}") from exc

        self.report = report
        rows = [row for host in report.hosts for row in self._rows_for_host(host)]
        return to_dataframe(rows)

    def parse_file(self) -> Optional[pd.DataFrame]:
        """Parse this report.  Progress is reported by the caller, not here.

        This used to print the file name and log a success line, on two
        different streams; both are now one :func:`xnp.ui.file_result` line
        carrying the counts.
        """
        return self.get_simple_df()

    @property
    def counts(self) -> Optional[stats.FileCounts]:
        """What the parsed report held, or ``None`` if nothing parsed yet."""
        return stats.counts_for(self.report) if self.report is not None else None

    @classmethod
    def parse_one(cls, xml_file: str, validate: bool = True,
                  include_hostless: bool = False) -> tuple:
        """Parse one file, returning ``(dataframe, FileResult, parser)``.

        A file that fails to parse comes back as a ``FileResult`` with
        ``ok=False`` and one WARNING record -- it does not raise, so a caller
        looping over a directory keeps going.  Callers that named a single file
        (``-f``) go through :meth:`parse_file` instead, where the error still
        ends the run.
        """
        parser = cls(xml_file, validate, include_hostless)
        try:
            df = parser.parse_file()
        except XnpError as exc:
            logger.warning(f"Skipping {xml_file}: {short_reason(exc, xml_file)}")
            return None, stats.FileResult.failed(xml_file, exc), parser
        return df, stats.FileResult.parsed(xml_file, parser.report), parser

    @staticmethod
    def parse_all(xml_file_list: list, validate: bool = True,
                  include_hostless: bool = False, skip_invalid: bool = False,
                  on_file=None) -> tuple:
        """Parse several reports, returning ``(dataframe, reports, skipped)``.

        Reports with no rows are skipped from the DataFrame; if none of them
        yields data the result is an empty DataFrame with the right columns
        rather than a crash or ``None``.  Every report that *parsed* is
        returned regardless, because a host that is up with no open ports is
        still worth drawing in the HTML report.

        With ``skip_invalid`` a file that fails to parse or validate is
        reported and left out instead of ending the run.  Pointing XNP at a
        directory means "process what is here", and one truncated capture in a
        folder of two hundred should not cost you the other hundred and ninety
        nine.  ``skipped`` carries ``(path, error)`` for each one so the caller
        can say what was left out.

        ``on_file`` is called with a :class:`~xnp.stats.FileResult` as each file
        finishes, successfully or not.  It exists so a caller can drive a
        progress display without owning this loop, which also owns the
        "everything failed is an error" rule below.
        """
        frames, reports, skipped = [], [], []
        for xml_file in xml_file_list:
            if skip_invalid:
                df, result, parser = NmapParser.parse_one(
                    xml_file, validate, include_hostless)
            else:
                # Nothing to skip: the caller wants the first failure to end
                # the run, so let parse_file raise.
                parser = NmapParser(xml_file, validate, include_hostless)
                df = parser.parse_file()
                result = stats.FileResult.parsed(xml_file, parser.report)

            if on_file is not None:
                on_file(result)

            if not result.ok:
                skipped.append((xml_file, result.error))
                continue

            if parser.report is not None:
                reports.append(parser.report)
            if df is not None and not df.empty:
                frames.append(df)

        if skipped and len(skipped) == len(xml_file_list):
            # Everything failed: that is an error, not a run that produced
            # nothing and quietly claimed success.
            raise skipped[0][1]

        if not frames:
            return empty_dataframe(), reports, skipped
        return pd.concat(frames, ignore_index=True), reports, skipped

    @staticmethod
    def parse_file_multiple(xml_file_list: list, validate: bool = True,
                            include_hostless: bool = False) -> pd.DataFrame:
        """Parse several reports and concatenate them into a single DataFrame."""
        return NmapParser.parse_all(xml_file_list, validate, include_hostless)[0]

    @staticmethod
    def is_not_ip(val) -> Optional[str]:
        """Return ``val`` unless it is a bare IP address, in which case ``None``.

        Used to blank out "hostnames" that are really just the IP again.
        """
        try:
            ipaddress.ip_address(val)
            return None
        except ValueError:
            return val

    @staticmethod
    def merge_all(xml_file_list: list, validate: bool = True,
                  include_hostless: bool = False, skip_invalid: bool = False,
                  on_file=None) -> tuple:
        """Merge several reports, returning ``(dataframe, reports, skipped)``."""
        df, reports, skipped = NmapParser.parse_all(
            xml_file_list, validate, include_hostless, skip_invalid, on_file=on_file)
        return NmapParser._merge(df), reports, skipped

    @staticmethod
    def merge_df(xml_file_list: list, validate: bool = True,
                 include_hostless: bool = False) -> pd.DataFrame:
        """Merge several reports, keeping the most informative row per IP/port."""
        return NmapParser.merge_all(xml_file_list, validate, include_hostless)[0]

    @staticmethod
    def _merge(df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return df

        # Rank duplicates by how many service detection fields they filled in.
        df[RELEVANCE_HELPER_COLUMN] = df[RELEVANCE_COLUMNS].notna().sum(axis=1)
        df = df.sort_values(
            by=['IP', 'Port', 'State', RELEVANCE_HELPER_COLUMN],
            ascending=[True, True, False, False])
        df = df.drop_duplicates(subset=['IP', 'Port'], keep='first')
        df = df.drop(columns=RELEVANCE_HELPER_COLUMN)

        # A hostname resolved in one scan applies to every row of the same IP.
        df['Hostname'] = df.groupby('IP')['Hostname'].transform(lambda x: x.ffill().bfill())
        df['Hostname'] = df['Hostname'].apply(NmapParser.is_not_ip)

        return df
