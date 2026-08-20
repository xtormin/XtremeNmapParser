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
