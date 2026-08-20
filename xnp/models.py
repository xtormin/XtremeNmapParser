"""Row model for the parsed scan data."""

from typing import Optional

import pandas as pd

from xnp.config import XnpConfig, load_config


class ScanData:
    """A single output row: one host/port pair, keyed by output column name."""

    def __init__(self, config: Optional[XnpConfig] = None) -> None:
        config = config or load_config()
        self.data = {header: None for header in config.columns_all}

    def to_list(self) -> list:
        return list(self.data.values())

    def to_dict(self) -> dict:
        return dict(self.data)


def empty_dataframe(config: Optional[XnpConfig] = None) -> pd.DataFrame:
    """An empty DataFrame carrying the full set of output columns."""
    config = config or load_config()
    return pd.DataFrame(columns=list(config.columns_all))


def to_dataframe(scan_data_list: list, config: Optional[XnpConfig] = None) -> Optional[pd.DataFrame]:
    """Build a DataFrame from ``ScanData`` rows.

    Returns ``None`` for an empty list: callers use that to tell "this report
    holds no scan data" apart from "this report failed to parse".
    """
    if not scan_data_list:
        return None
    data_list = [sd.to_list() for sd in scan_data_list]
    return pd.DataFrame(data_list, columns=list(scan_data_list[0].data.keys()))
