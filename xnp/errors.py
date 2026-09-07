"""Exception hierarchy for XNP.

Library modules raise these instead of calling ``exit()`` so that the caller
(normally :func:`xnp.cli.main`) is the only place deciding on an exit code.
"""


class XnpError(Exception):
    """Base class for every error raised on purpose by XNP."""

    exit_code = 1


class XnpConfigError(XnpError):
    """The configuration file is missing or cannot be read."""


class NotAnNmapReport(XnpError):
    """The XML file is well formed but its root element is not ``nmaprun``."""

    exit_code = 2


class InvalidNmapReport(XnpError):
    """The XML file could not be parsed or does not validate against nmap.dtd."""

    exit_code = 2


class NoInputFilesError(XnpError):
    """No XML file was found for the requested input."""

    exit_code = 3


def short_reason(exc: Exception, path: str = "") -> str:
    """Condense a parser error into a phrase that reads inside a warning.

    The errors are written to stand alone on a line of their own, so they carry
    a ``|x| Error |`` marker and repeat the file name.  Both are noise once the
    message is being quoted as the reason a file was skipped.
    """
    reason = str(exc).strip().splitlines()[0].strip()
    for prefix in ("|x| Error |", "|-|", "|?|"):
        if reason.startswith(prefix):
            reason = reason[len(prefix):].strip()
    if path and reason.startswith(path):
        reason = reason[len(path):].strip()
    return reason or exc.__class__.__name__
