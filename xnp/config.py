"""Configuration loading.

The packaged ``xnp/data/config.yaml`` is always resolved through an absolute
path derived from this module's location, so XNP works from any working
directory.  Optional overrides are layered on top of it, from lowest to
highest precedence:

1. ``xnp/data/config.yaml``  (packaged defaults, always present)
2. ``./config/config.yaml``  (project-local override, if it exists)
3. ``$XNP_CONFIG``           (explicit file, if the variable is set)
4. the ``path`` argument of :func:`load_config`

The result is a plain :class:`XnpConfig` dataclass rather than a ``confuse``
view, so the rest of the code never depends on global configuration state and
tests can build a configuration by hand.
"""

import os
from dataclasses import dataclass
from pathlib import Path

import confuse

from xnp import __version__
from xnp.errors import XnpConfigError

PACKAGED_CONFIG = Path(__file__).resolve().parent / "data" / "config.yaml"
LOCAL_CONFIG = Path("config") / "config.yaml"
CONFIG_ENV_VAR = "XNP_CONFIG"

_CACHE = {}


@dataclass(frozen=True)
class XnpConfig:
    """Flat, immutable view of ``config.yaml``."""

    app_name: str
    nmap_file_extension: str
    sheet_name: str
    header_color: str
    header_text_color: str
    table_style: str
    columns_default: tuple
    columns_all: tuple
    version: str = __version__

    def columns_for(self, choice):
        """Return the column list for a ``-C/--columns`` choice.

        ``None`` and unknown values fall back to the default set, matching the
        behaviour of the original ``column_options`` mapping.
        """
        if choice == "all":
            return list(self.columns_all)
        return list(self.columns_default)


def _sources(path=None):
    """Yield the config files to layer, from lowest to highest precedence."""
    yield PACKAGED_CONFIG, True
    yield LOCAL_CONFIG, False
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        yield Path(env_path), True
    if path is not None:
        yield Path(path), True


def _build(path=None):
    config = confuse.Configuration("XNP", __name__, read=False)
    for source, required in _sources(path):
        if source.is_file():
            # set_file() puts the new source on top, so adding them in
            # increasing order of precedence gives the layering we want.
            config.set_file(str(source))
        elif required:
            raise XnpConfigError(f"Configuration file not found: {source}")

    try:
        xlsx = config["xlsx"]
        return XnpConfig(
            app_name=config["app"]["name"].get(str),
            nmap_file_extension=config["nmap_file_extension"].get(str),
            sheet_name=xlsx["sheet"]["name"].get(str),
            header_color=xlsx["header"]["color"].get(str),
            header_text_color=xlsx["header"]["text"]["color"].get(str),
            table_style=xlsx["table"]["style"].get(str),
            columns_default=tuple(xlsx["columns"]["default"].get(list)),
            columns_all=tuple(xlsx["columns"]["all"].get(list)),
        )
    except confuse.ConfigError as exc:
        raise XnpConfigError(f"Invalid configuration: {exc}") from exc


def load_config(path=None):
    """Return the :class:`XnpConfig`, building and caching it on first use."""
    key = (str(path) if path is not None else None, os.environ.get(CONFIG_ENV_VAR))
    if key not in _CACHE:
        _CACHE[key] = _build(path)
    return _CACHE[key]


def reset_config():
    """Drop the cached configuration (used by the test suite)."""
    _CACHE.clear()
