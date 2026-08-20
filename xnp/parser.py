"""Turn nmap XML reports into pandas DataFrames."""

import ipaddress
from collections.abc import Iterator
from typing import Optional

import pandas as pd
from lxml import etree

from xnp.errors import InvalidNmapReport
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

        rows = [row for host in report.hosts for row in self._rows_for_host(host)]
        df = to_dataframe(rows)
        logger.info(f" |+| {self.xml_file} parsed successfully  ")
        return df

    def parse_file(self) -> Optional[pd.DataFrame]:
        print(f" *** Parsing | {self.xml_file}")
        return self.get_simple_df()

    @staticmethod
    def parse_file_multiple(xml_file_list: list, validate: bool = True,
                            include_hostless: bool = False) -> pd.DataFrame:
        """Parse several reports and concatenate them into a single DataFrame.

        Reports with no rows are skipped; if none of them yields data the
        result is an empty DataFrame with the right columns rather than a
        crash or ``None``.
        """
        frames = []
        for xml_file in xml_file_list:
            df = NmapParser(xml_file, validate, include_hostless).parse_file()
            if df is not None and not df.empty:
                frames.append(df)

        if not frames:
            return empty_dataframe()
        return pd.concat(frames, ignore_index=True)

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
    def merge_df(xml_file_list: list, validate: bool = True,
                 include_hostless: bool = False) -> pd.DataFrame:
        """Merge several reports, keeping the most informative row per IP/port."""
        df = NmapParser.parse_file_multiple(xml_file_list, validate, include_hostless)
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
