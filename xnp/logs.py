"""Logging setup for XNP.

Modules call :func:`get_logger` at import time; the handler is installed once
from :func:`xnp.cli.main` via :func:`setup_logging`.

The handler writes to :func:`xnp.ui.console` -- the *same* console object the
progress bar owns.  That is what lets a warning interleave with a live bar
without tearing it: ``Progress`` wraps a ``Live`` which pushes itself as a
render hook onto its console, so ``Console.print`` erases the bar, writes the
record and redraws the bar underneath.  The hook only fires for that one object,
so the handler and the bar must share it.
"""

import logging

from rich.highlighter import NullHighlighter
from rich.logging import RichHandler

from xnp import ui

ROOT_LOGGER_NAME = "xnp"

#: Our handler, tracked so :func:`setup_logging` can replace it without
#: touching anyone else's.
_handler = None


def get_logger(name: str) -> logging.Logger:
    """Return the logger for ``name`` (normally the module's ``__name__``)."""
    return logging.getLogger(name)


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Install the rich console handler on the ``xnp`` logger.

    Safe to call more than once: only the handler installed by a previous call
    is removed.

    Never clear ``root.handlers``.  The ``xnp`` logger does not propagate, so
    pytest attaches its capture handler directly to it -- clearing the list
    detaches that handler and silently empties ``caplog.text`` for the rest of
    the test, which turns assertions into false passes rather than failures.
    """
    global _handler

    root = logging.getLogger(ROOT_LOGGER_NAME)
    root.propagate = False

    if _handler is not None:
        root.removeHandler(_handler)

    _handler = RichHandler(
        console=ui.console(),
        show_time=False,      # the old format was a bare "%(message)s"
        show_path=False,      # RichHandler's default module:lineno is noise here
        show_level=True,      # this is what replaces the |+| / |?| / |x| markers
        markup=False,         # messages carry paths and scanned service names
        highlighter=NullHighlighter(),
        rich_tracebacks=False,
    )
    _handler.setLevel(logging.NOTSET)
    root.addHandler(_handler)

    if quiet:
        root.setLevel(logging.ERROR)
    else:
        root.setLevel(logging.DEBUG if verbose else logging.INFO)
    return root
