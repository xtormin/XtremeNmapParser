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
from typing import Optional, Union

import confuse

from xnp import __version__
from xnp.errors import XnpConfigError

PACKAGED_CONFIG = Path(__file__).resolve().parent / "data" / "config.yaml"
LOCAL_CONFIG = Path("config") / "config.yaml"
CONFIG_ENV_VAR = "XNP_CONFIG"

_CACHE = {}


@dataclass(frozen=True)
class RescanProfile:
    """One named set of nmap arguments from the ``rescan.profiles`` block."""

    name: str
    args: str
    description: str = ""
    description_en: str = ""


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
    html_title: str = "Informe de superficie de red"
    html_title_en: str = "Network exposure report"
    # Defaults on all three: a configuration built by hand in a test, or by
    # code that predates the rescan, stays valid.  A tuple rather than a dict
    # because XnpConfig is frozen and hashable, and because the order is what
    # populates the report's profile selector.
    rescan_default_profile: str = "service"
    rescan_states: tuple = ("open", "open|filtered")
    rescan_profiles: tuple = ()
    version: str = __version__

    def columns_for(self, choice: Optional[str]) -> list:
        """Return the column list for a ``-C/--columns`` choice.

        ``None`` and unknown values fall back to the default set, matching the
        behaviour of the original ``column_options`` mapping.
        """
        if choice == "all":
            return list(self.columns_all)
        return list(self.columns_default)

    def rescan_profile(self, name: Optional[str]) -> Optional[RescanProfile]:
        """The named profile, or ``None`` -- the caller decides what to say."""
        for profile in self.rescan_profiles:
            if profile.name == name:
                return profile
        return None

    def rescan_profile_names(self) -> list:
        """The profile names, in config order, for help and error messages."""
        return [profile.name for profile in self.rescan_profiles]


def _sources(path=None):
    """Yield the config files to layer, from lowest to highest precedence."""
    yield PACKAGED_CONFIG, True
    yield LOCAL_CONFIG, False
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        yield Path(env_path), True
    if path is not None:
        yield Path(path), True


def _optional(view, default: str = "") -> str:
    """A string setting that need not be there.

    Caught here rather than by the ``ConfigError`` handler around the whole
    block: a profile with no description is normal, a profile with no ``args``
    is a broken configuration, and the two must not report the same way.
    """
    try:
        return view.get(str)
    except confuse.NotFoundError:
        return default


def _rescan_profiles(view) -> tuple:
    """Read ``rescan.profiles``.

    ``ConfigView.keys()`` unions the keys of every source, so a profile added
    in ``config/config.yaml`` joins the packaged ones instead of replacing the
    block, and redefining only ``args`` keeps the packaged description.  The
    flip side, worth knowing: an override can redefine a packaged profile but
    cannot delete it.
    """
    return tuple(
        RescanProfile(name=name,
                      args=profile["args"].get(str),
                      description=_optional(profile["description"]),
                      description_en=_optional(profile["description_en"]))
        for name, profile in view.items())


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
        rescan = config["rescan"]
        profiles = _rescan_profiles(rescan["profiles"])
        default_profile = rescan["default_profile"].get(str)
        if not any(profile.name == default_profile for profile in profiles):
            raise XnpConfigError(
                f"Invalid configuration: rescan.default_profile is "
                f"{default_profile!r}, which is not one of "
                f"{', '.join(profile.name for profile in profiles) or '(none)'}")
        return XnpConfig(
            app_name=config["app"]["name"].get(str),
            nmap_file_extension=config["nmap_file_extension"].get(str),
            sheet_name=xlsx["sheet"]["name"].get(str),
            header_color=xlsx["header"]["color"].get(str),
            header_text_color=xlsx["header"]["text"]["color"].get(str),
            table_style=xlsx["table"]["style"].get(str),
            columns_default=tuple(xlsx["columns"]["default"].get(list)),
            columns_all=tuple(xlsx["columns"]["all"].get(list)),
            html_title=config["html"]["title"].get(str),
            html_title_en=config["html"]["title_en"].get(str),
            rescan_default_profile=rescan["default_profile"].get(str),
            # get(list) resolves from the highest-precedence source without
            # merging, so redefining states replaces them outright.
            rescan_states=tuple(rescan["states"].get(list)),
            rescan_profiles=profiles,
        )
    except confuse.ConfigError as exc:
        raise XnpConfigError(f"Invalid configuration: {exc}") from exc


def load_config(path: Optional[Union[str, Path]] = None) -> XnpConfig:
    """Return the :class:`XnpConfig`, building and caching it on first use."""
    key = (str(path) if path is not None else None, os.environ.get(CONFIG_ENV_VAR))
    if key not in _CACHE:
        _CACHE[key] = _build(path)
    return _CACHE[key]


def reset_config() -> None:
    """Drop the cached configuration (used by the test suite)."""
    _CACHE.clear()
