"""Terminal presentation.  Everything the user sees, in one place.

The rule that keeps this module honest:

    **ui renders, logging reports.**

Diagnostics -- anything a caller might want to grep, capture or assert on --
stay ``logger.info/warning/error`` on the ``xnp`` tree; :mod:`xnp.logs` hands
those records to a ``RichHandler`` pointed at *this* module's stderr console.
``ui`` owns only the chrome: the banner, the panels, the rules, the progress
bar, the per-file lines and the closing summary.

Stream policy, and why:

* **stderr is the display.**  Banner, panels, rules, the live bar, per-file
  lines, every log record, the summary.
* **stdout carries the deliverables only** -- one bare, unstyled path per
  generated file, so ``xnp -d nmap/ > written.txt`` is a useful list instead of
  a wall of ASCII art.

That split is also what makes the live bar safe.  ``Progress`` wraps a ``Live``
which installs itself as a *render hook* on its console, so that every
``Console.print`` erases the bar, writes the line and redraws the bar beneath
it.  The hook only fires for that one console object, so exactly one console may
own the terminal while the bar is up -- and the bar is decoration, so it belongs
on stderr next to the log records.
"""

import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Optional

from rich.console import Console
from rich.filesize import decimal
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from xnp import i18n

#: The level colours are carried over verbatim from the ``coloredlogs`` setup
#: this module replaced, so a warning looks like it always did.
THEME = Theme({
    "logging.level.debug": "cyan",
    "logging.level.info": "green",
    "logging.level.warning": "bold yellow",
    "logging.level.error": "red",
    "logging.level.critical": "bold red",
    # XNP's own vocabulary.
    "xnp.banner": "bold red",
    "xnp.rule": "bold blue",
    "xnp.label": "dim",
    "xnp.ok": "green",
    "xnp.skip": "yellow",
    "xnp.count": "bold cyan",
    "xnp.path": "cyan",
    "xnp.unit": "dim",
})

_err: Optional[Console] = None
_out: Optional[Console] = None
_quiet: bool = False


def _color_system(no_color: bool) -> Optional[str]:
    """``None`` disables ANSI entirely; ``"auto"`` lets rich detect.

    ``color_system=None`` rather than ``Console(no_color=True)``: the latter
    drops colour but still emits bold and dim, and ``--no-color`` should mean
    *no escape sequences at all*.

    ``NO_COLOR`` is read here instead of being left to rich because rich tests
    for presence while no-color.org specifies a non-empty value.
    """
    if no_color:
        return None
    if os.environ.get("NO_COLOR"):
        return None
    if os.environ.get("TERM") == "dumb":
        return None
    return "auto"


def setup(quiet: bool = False, no_color: bool = False) -> None:
    """Build the two consoles.  Called once from :func:`xnp.cli.main`."""
    global _err, _out, _quiet

    _quiet = quiet
    common = {
        "color_system": _color_system(no_color),
        # Paths, service names and products all reach the console and none of
        # them are ours -- they come out of the scanned XML.  With markup on,
        # a path like /tmp/scan[1].xml is parsed as a style tag.
        "markup": False,
        # ReprHighlighter would recolour the version and the URL inside the
        # ASCII banner, which is meant to look exactly as it always has.
        "highlight": False,
        "theme": THEME,
    }
    # Never pass file=sys.stderr: Console.file resolves the stream at write
    # time, and freezing it breaks capsys (pytest swaps the streams per test).
    _err = Console(stderr=True, **common)
    _out = Console(**common)


def console() -> Console:
    """The stderr console: the display, and the one the log handler writes to."""
    if _err is None:
        setup()
    return _err


def out() -> Console:
    """The stdout console: generated file paths, and nothing else."""
    if _out is None:
        setup()
    return _out


def is_quiet() -> bool:
    return _quiet


def supports(text: str) -> bool:
    """Whether the display console's encoding can render ``text``.

    Public because the banner picks its own artwork with it: block-drawing
    characters are unreadable on a console that cannot encode them.
    """
    try:
        text.encode(console().file.encoding or "utf-8")
    except (UnicodeEncodeError, LookupError, AttributeError):
        return False
    return True


def _symbol(preferred: str, fallback: str) -> str:
    return preferred if supports(preferred) else fallback


def _quantity(value, unit: str) -> Text:
    """``4 hosts`` / ``1 host`` -- the number bright, the unit quiet.

    ``unit`` is a message key, not a word: the plural rule belongs with the
    translation, since Spanish inflects the adjectives too.
    """
    text = Text()
    text.append(str(value), style="xnp.count")
    text.append(" " + i18n.t(unit, count=value), style="xnp.unit")
    return text


# --- Chrome -----------------------------------------------------------------


def gap() -> None:
    """One blank line between blocks.

    Every block opens with one of these rather than closing with it, so the
    run never ends on a stray empty line and two adjacent blocks never
    accumulate two gaps.  Display only: the paths on stdout stay a clean list.
    """
    if _quiet:
        return
    console().line()


def banner(text: str) -> None:
    """Print the ASCII art.

    ``soft_wrap`` disables both wrapping and cropping, so the art comes out
    byte for byte even on a narrow terminal -- the same as the bare ``print``
    this replaced.
    """
    if _quiet:
        return
    console().print(Text(text, style="xnp.banner"), soft_wrap=True)


def arguments(rows: Sequence[tuple], title: Optional[str] = None) -> None:
    """Show the run's settings.

    ``rows`` are ``(label, value)`` pairs, **already formatted** -- joined
    strings, never a list repr, and with the empty ones dropped by the caller.
    """
    if _quiet or not rows:
        return

    gap()
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
    table.add_column(style="xnp.label", no_wrap=True)
    # fold, so a long path breaks inside the panel instead of overflowing it.
    table.add_column(overflow="fold")
    for label, value in rows:
        table.add_row(label, value)

    console().print(Panel(table, title=title or i18n.t("panel.arguments"),
                          title_align="left", expand=False))


def section(title: str) -> None:
    if _quiet:
        return
    gap()
    console().print(Rule(title, style="xnp.rule", align="left"))
    console().line()


class _Bar:
    """The handle :func:`progress` yields.

    Exists so the caller has one code shape whether or not a bar is actually
    live -- ``advance()`` is a no-op when the display is disabled.
    """

    def __init__(self, progress: Optional[Progress], task_id=None) -> None:
        self._progress = progress
        self._task_id = task_id

    def advance(self, step: int = 1) -> None:
        if self._progress is not None:
            self._progress.advance(self._task_id, step)


@contextmanager
def progress(total: int, description: Optional[str] = None) -> Iterator[_Bar]:
    """A live progress bar over ``total`` files.

    Disabled when quiet, when stderr is not a terminal, or for a single file
    (where a bar is pure noise -- and ``-f`` is most invocations).

    Anything printed *through the display console* while this is open is lifted
    above the bar by the ``Live`` render hook.  Anything printed to :func:`out`
    is not, and will tear the bar -- which is why the CLI buffers the generated
    paths and emits them after this context exits.
    """
    if _quiet or not console().is_terminal or total <= 1:
        yield _Bar(None)
        return

    bar = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console(),
        # Both off: we own stdout ourselves, and redirecting it here would send
        # the generated paths to the display console -- the wrong stream.
        redirect_stdout=False,
        redirect_stderr=False,
    )
    task_id = bar.add_task(description or i18n.t("progress.parsing"), total=total)
    bar.start()
    try:
        # try/finally, always: a leaked Live makes the *next* run raise
        # "Only one live display may be active at once".
        yield _Bar(bar, task_id)
    finally:
        bar.stop()


# --- Per-file and closing lines ---------------------------------------------


def short_path(path: str) -> str:
    """The path as the reader would type it, when that is shorter.

    Absolute paths make every per-file line wrap for no gain; a path relative
    to the working directory says the same thing.  One that would have to climb
    out with ``..`` is left alone.
    """
    try:
        relative = os.path.relpath(path)
    except ValueError:  # different drive on Windows
        return path
    if relative.startswith("..") or len(relative) >= len(path):
        return path
    return relative


def file_result(result) -> None:
    """One line for a file that parsed, with what it held.

    A file that was *skipped* is not printed here: it already produced one
    WARNING record from the parser.  One event, one message.
    """
    if _quiet or not result.ok:
        return

    counts = result.counts
    path = short_path(result.path)

    tail = Text()
    if counts is not None:
        for value, unit in ((counts.hosts, "unit.host"), (counts.ports, "unit.port"),
                            (counts.open_ports, "unit.open")):
            if tail:
                tail.append("  ")
            tail.append_text(_quantity(value, unit))

    line = Text()
    line.append(_symbol("✓", "+") + " ", style="xnp.ok")
    line.append(path, style="xnp.path")
    if tail:
        # Pad so the counts land in a column, but only while they fit: a path
        # long enough to fill the line just gets two spaces and folds.
        room = console().width - line.cell_len - tail.cell_len
        line.append(" " * room if room >= 2 else "  ")
        line.append_text(tail)
    console().print(line, overflow="fold")


def output_files(written) -> None:
    """Announce the generated files.

    Two audiences, two streams: a readable table on stderr for the person, and
    the bare paths on stdout for whatever they piped this into.  The paths are
    emitted even under ``--quiet`` -- they are the deliverable.
    """
    if not written:
        return

    if not _quiet:
        section(i18n.t("section.output"))
        table = Table(box=None, pad_edge=False, padding=(0, 1))
        table.add_column(i18n.t("table.format"), style="xnp.label", no_wrap=True)
        table.add_column(i18n.t("table.file"), overflow="fold")
        table.add_column(i18n.t("table.size"), justify="right", no_wrap=True)
        for item in written:
            table.add_row(item.fmt, Text(item.path, style="xnp.path"), decimal(item.size))
        console().print(table)

    for item in written:
        # soft_wrap so a long path is never wrapped, folded or cropped: that is
        # the machine-readable contract.
        out().print(item.path, soft_wrap=True)


def _elapsed(seconds: float) -> str:
    """A duration a reader can act on.

    Most runs finish in tens of milliseconds, and rounding those to "0.0s"
    says nothing -- so under a second the unit changes rather than the number
    disappearing.
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(seconds, 60)
    return f"{int(minutes)}m {rest:.0f}s"


def summary(stats) -> None:
    """The closing panel: what was read, what was found, what was written."""
    if _quiet:
        return

    gap()
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
    table.add_column(style="xnp.label", no_wrap=True)
    table.add_column(overflow="fold")

    def row(label: str, value: Text) -> None:
        table.add_row(label, value)

    files = _quantity(stats.parsed, "unit.parsed")
    if stats.skipped:
        files.append("  ")
        files.append_text(_quantity(stats.skipped, "unit.skipped"))
    row(i18n.t("summary.files"), files)

    hosts = _quantity(len(stats.ips), "unit.total")
    hosts.append("  ")
    hosts.append_text(_quantity(stats.hosts_up, "unit.up"))
    row(i18n.t("summary.hosts"), hosts)

    ports = _quantity(stats.ports, "unit.total")
    ports.append("  ")
    ports.append_text(_quantity(stats.open_ports, "unit.open"))
    row(i18n.t("summary.ports"), ports)

    top = stats.top_services()
    if top:
        services = Text()
        for index, (name, count) in enumerate(top):
            if index:
                services.append("  ")
            services.append(name, style="xnp.path")
            services.append(f" {count}", style="xnp.count")
        row(i18n.t("summary.services"), services)

    if stats.rows_exported is not None:
        merged = _quantity(stats.ports, "unit.port")
        merged.append(" → " if supports("→") else " -> ", style="xnp.unit")
        merged.append_text(_quantity(stats.rows_exported, "unit.row"))
        row(i18n.t("summary.merged"), merged)

    if stats.written:
        files_written = _quantity(len(stats.written), "unit.file")
        files_written.append("  ")
        files_written.append(decimal(stats.bytes_written), style="xnp.count")
        row(i18n.t("summary.written"), files_written)

    row(i18n.t("summary.elapsed"), Text(_elapsed(stats.elapsed), style="xnp.count"))

    console().print(Panel(table, title=i18n.t("panel.summary"),
                          title_align="left", expand=False))
    # The one closing gap, so the shell prompt is not glued to the panel.
    gap()
