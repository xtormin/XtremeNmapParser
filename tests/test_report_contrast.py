"""WCAG AA contrast audit of the report's colour tokens.

The palette is not decoration: a status dot the reader cannot distinguish from
the background is a missing finding.  These pairs are read straight out of the
shipped stylesheet, so a future colour tweak that breaks contrast fails here
rather than in someone's eyes.
"""

import re

import pytest

from xnp.html_report import STYLESHEET

# text/background pairs that must clear 4.5:1, keyed by the role they serve.
TEXT_PAIRS = [
    ("text", "bg"), ("text", "surface"), ("text", "surface-2"), ("text", "surface-3"),
    ("text-2", "bg"), ("text-2", "surface"), ("text-2", "surface-2"),
    ("text-3", "bg"), ("text-3", "surface"), ("text-3", "surface-2"),
    ("accent-text", "bg"), ("accent-text", "surface"), ("accent-text", "surface-2"),
    ("accent-text", "accent-soft"),
    # A selected table row paints body text on the accent wash.
    ("text", "accent-soft"), ("text-2", "accent-soft"),
    ("high", "surface"), ("high", "bg"), ("high", "high-soft"),
    ("medium", "surface"), ("medium", "bg"), ("medium", "medium-soft"),
    ("low", "surface"), ("low", "bg"), ("low", "low-soft"),
    ("text-2", "neutral-soft"),
]

# Non-text: UI boundaries, chart marks and status dots need 3:1.
GRAPHIC_PAIRS = [
    ("border-strong", "bg"), ("border-strong", "surface"),
    ("open", "surface"), ("filtered", "surface"), ("closed", "surface"),
    ("open", "bg"), ("filtered", "bg"), ("closed", "bg"),
    ("accent", "surface"), ("accent", "bg"),
    # Chart bars and arcs carry the data; they must read against the plot ground.
    ("chart-1", "surface"), ("chart-2", "surface"), ("chart-3", "surface"),
]

# Text printed on a saturated accent fill (tabs, chips, the version tag).
# Which ink goes on the fill depends on the theme: the light theme's accent is
# dark enough for white, the dark theme's is light enough to need dark ink.
ON_ACCENT = {"light": [("#ffffff", "accent")], "dark": [("#0d0820", "accent")]}


def parse_block(css, selector):
    start = css.index(selector)
    body = css[css.index("{", start) + 1:css.index("}", start)]
    return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{3,8})\s*;", body))


def srgb(component):
    component /= 255
    return component / 12.92 if component <= 0.04045 else ((component + 0.055) / 1.055) ** 2.4


def luminance(hex_colour):
    hex_colour = hex_colour.lstrip("#")
    if len(hex_colour) == 3:
        hex_colour = "".join(c * 2 for c in hex_colour)
    r, g, b = (int(hex_colour[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * srgb(r) + 0.7152 * srgb(g) + 0.0722 * srgb(b)


def ratio(a, b):
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def resolve(tokens, name):
    return name if name.startswith("#") else tokens.get(name)



@pytest.fixture(scope="module")
def themes():
    css = STYLESHEET.read_text(encoding="utf-8")
    return {"light": parse_block(css, ":root {"),
            "dark": parse_block(css, ':root[data-theme="dark"]')}


def _pairs():
    for theme in ("light", "dark"):
        for fg, bg in TEXT_PAIRS:
            yield theme, fg, bg, 4.5
        for fg, bg in GRAPHIC_PAIRS:
            yield theme, fg, bg, 3.0
        for fg, bg in ON_ACCENT[theme]:
            yield theme, fg, bg, 4.5


@pytest.mark.parametrize("theme,fg,bg,threshold", list(_pairs()),
                         ids=lambda v: str(v).replace("#", ""))
def test_contrast_meets_wcag_aa(themes, theme, fg, bg, threshold):
    tokens = themes[theme]
    fg_hex, bg_hex = resolve(tokens, fg), resolve(tokens, bg)
    assert fg_hex, f"missing token --{fg} in the {theme} theme"
    assert bg_hex, f"missing token --{bg} in the {theme} theme"

    value = ratio(fg_hex, bg_hex)
    assert value >= threshold, (
        f"{theme}: --{fg} ({fg_hex}) on --{bg} ({bg_hex}) is {value:.2f}:1, "
        f"below the {threshold}:1 the role needs")


def test_both_themes_define_every_token(themes):
    """A token defined in one theme only goes invisible in the other."""
    light, dark = set(themes["light"]), set(themes["dark"])
    # The light block also carries the font stacks, which never vary by theme.
    theme_only = {"mono", "sans"}
    assert (light - theme_only) == dark
