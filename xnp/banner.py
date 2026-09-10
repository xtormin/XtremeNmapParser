"""Console banner.

The wordmark is kept as a tuple of lines rather than one blob so the tagline
can be laid alongside the last line without hand-counting spaces -- which is
what breaks a hand-drawn banner the first time the version grows a digit.

Printing goes through :mod:`xnp.ui`, and with it the stream: the banner is
chrome, so it lands on stderr and leaves stdout for the generated file paths.
The panels and section rules that used to live here are now ui renderables that
respect the terminal width instead of a hardcoded 62-dash rule.
"""

from xnp import __version__, ui

REPO = "github.com/xtormin/XtremeNmapParser"
AUTHOR = "@xtormin"

#: The wordmark, in block-drawing characters.
BLOCK = (
    "▀████    ▐████▀ ███▄▄▄▄      ▄███████▄",
    "  ███▌   ████▀  ███▀▀▀██▄   ███    ███",
    "   ███  ▐███    ███   ███   ███    ███",
    "   ▀███▄███▀    ███   ███   ███    ███",
    "   ████▀██▄     ███   ███ ▀█████████▀",
    "  ▐███  ▀███    ███   ███   ███",
    " ▄███     ███▄  ███   ███   ███",
    "████       ███▄  ▀█   █▀   ▄████▀",
)

#: The same wordmark in plain ASCII, for a console whose encoding cannot take
#: the blocks -- a Windows code page, or a C locale.  Same number of lines, so
#: the layout below does not care which one it was handed.
ASCII = (
    'Y88b   d88P888b    8888888888b.',
    ' Y88b d88P 8888b   888888   Y88b',
    '  Y88o88P  88888b  888888    888',
    '   Y888P   888Y88b 888888   d88P',
    '   d888b   888 Y88b8888888888P"',
    '  d88888b  888  Y88888888',
    ' d88P Y88b 888   Y8888888',
    'd88P   Y88b888    Y888888',
)


def compose(art, tagline: str, footer: str) -> str:
    """Lay the tagline against the last line of ``art``, the footer beneath."""
    width = max(len(line) for line in art)
    body = list(art)
    body[-1] = f"{body[-1]:<{width}}      {tagline}"
    lines = "\n".join(f"   {line}".rstrip() for line in body)
    # No trailing newline: the block that follows opens with its own gap, and
    # printing a string that ends in one would stack two blank lines.
    return f"\n{lines}\n\n   {footer}"


def main():
    art = BLOCK if ui.supports("".join(BLOCK)) else ASCII
    separator = "  ·  " if ui.supports("·") else "  |  "
    ui.banner(compose(
        art,
        tagline=f"Xtreme Nmap Parser v{__version__}",
        footer=separator.join((REPO, AUTHOR, "HAPPY HACKING! 8)")),
    ))
