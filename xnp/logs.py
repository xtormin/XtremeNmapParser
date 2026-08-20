"""Logging setup for XNP.

Modules call :func:`get_logger` at import time; the handlers are installed once
from :func:`xnp.cli.main` via :func:`setup_logging`.
"""

import logging

import coloredlogs

ROOT_LOGGER_NAME = "xnp"
LOG_FORMAT = "%(message)s"
LEVEL_STYLES = {
    "debug": {"color": "cyan"},
    "info": {"color": "green"},
    "warning": {"color": "yellow", "bold": True},
    "error": {"color": "red"},
    "critical": {"color": "red", "bold": True},
}


def get_logger(name):
    """Return the logger for ``name`` (normally the module's ``__name__``)."""
    return logging.getLogger(name)


def setup_logging(verbose=False):
    """Install the coloured console handler on the ``xnp`` logger.

    Safe to call more than once: coloredlogs reconfigures the existing handler
    instead of stacking a new one.
    """
    root = logging.getLogger(ROOT_LOGGER_NAME)
    root.propagate = False
    coloredlogs.install(
        level=logging.DEBUG if verbose else logging.INFO,
        logger=root,
        fmt=LOG_FORMAT,
        level_styles=LEVEL_STYLES,
    )
    return root
