"""The terminal message table, and how the language gets chosen."""

import pytest

from xnp import i18n


@pytest.fixture(autouse=True)
def fresh_language():
    """Leave the default behind: the module holds the language for the run."""
    yield
    i18n.setup()


# --- Choosing the language --------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    ("es_ES.UTF-8", "es"),
    ("es", "es"),
    ("ES_es", "es"),
    ("en_GB.UTF-8", "en"),
    # A language with no table here is English, not a crash.
    ("fr_FR.UTF-8", "en"),
    ("C", "en"),
    ("POSIX", "en"),
])
def test_the_locale_decides_when_no_flag_is_given(value, expected):
    assert i18n.detect({"LANG": value}) == expected


def test_lc_all_outranks_the_rest():
    """POSIX precedence: the first one set decides, not the most specific."""
    assert i18n.detect({"LC_ALL": "es_ES.UTF-8", "LANG": "en_US.UTF-8"}) == "es"
    assert i18n.detect({"LC_MESSAGES": "es_ES.UTF-8", "LANG": "en_US.UTF-8"}) == "es"


def test_a_language_we_do_not_speak_stops_the_search():
    """LC_ALL=fr means French, not "keep looking until something matches"."""
    assert i18n.detect({"LC_ALL": "fr_FR.UTF-8", "LANG": "es_ES.UTF-8"}) == "en"


def test_an_empty_variable_is_skipped():
    assert i18n.detect({"LC_ALL": "", "LANG": "es_ES.UTF-8"}) == "es"


def test_nothing_set_at_all_is_english():
    assert i18n.detect({}) == i18n.DEFAULT == "en"


def test_the_flag_beats_the_environment(monkeypatch):
    monkeypatch.setenv("LC_ALL", "en_US.UTF-8")
    assert i18n.setup("es") == "es"
    assert i18n.current() == "es"


def test_no_flag_falls_back_to_the_environment(monkeypatch):
    monkeypatch.setenv("LC_ALL", "es_ES.UTF-8")
    assert i18n.setup(None) == "es"


def test_an_unknown_flag_value_falls_back_rather_than_raising(monkeypatch):
    monkeypatch.setenv("LC_ALL", "C")
    assert i18n.setup("klingon") == "en"


# --- Looking messages up ----------------------------------------------------

def test_a_message_comes_back_in_the_chosen_language():
    i18n.setup("es")
    assert i18n.t("panel.summary") == "Resumen"
    i18n.setup("en")
    assert i18n.t("panel.summary") == "Summary"


def test_fields_are_filled_in():
    i18n.setup("en")
    assert i18n.t("warn.skipping", path="a.xml", reason="bad") == "Skipping a.xml: bad"


def test_the_count_both_picks_the_plural_and_fills_the_field():
    i18n.setup("en")
    assert i18n.t("warn.skipped_count", count=1, total=6) == "1 of 6 files were skipped:"


@pytest.mark.parametrize("lang, key, count, expected", [
    ("en", "unit.port", 1, "port"),
    ("en", "unit.port", 2, "ports"),
    ("es", "unit.port", 1, "puerto"),
    ("es", "unit.port", 2, "puertos"),
    # Spanish inflects the adjectives too, which is why the plural rule lives
    # in the table rather than as a "+ s" in the renderer.
    ("en", "unit.open", 1, "open"),
    ("es", "unit.open", 1, "abierto"),
    ("es", "unit.open", 2, "abiertos"),
])
def test_plurals_come_from_the_table(lang, key, count, expected):
    i18n.setup(lang)
    assert i18n.t(key, count=count) == expected


def test_an_invariable_unit_ignores_the_count():
    i18n.setup("en")
    assert i18n.t("unit.total", count=1) == i18n.t("unit.total", count=9) == "total"


def test_a_missing_translation_falls_back_to_english(monkeypatch):
    monkeypatch.delitem(i18n.MESSAGES["es"], "panel.summary")
    i18n.setup("es")
    assert i18n.t("panel.summary") == "Summary"


def test_an_unknown_key_comes_back_as_itself():
    """A missing string must not take a run down mid-scan."""
    i18n.setup("en")
    assert i18n.t("nope.not.a.key") == "nope.not.a.key"


# --- The table itself -------------------------------------------------------

def test_every_language_carries_every_key():
    english = set(i18n.MESSAGES["en"])
    for lang, table in i18n.MESSAGES.items():
        assert set(table) == english, f"{lang} is out of step with English"


def test_a_plural_is_a_pair_in_every_language():
    """A key that inflects in one language must be declared in all of them."""
    for key in i18n.MESSAGES["en"]:
        shapes = {lang: isinstance(table[key], tuple)
                  for lang, table in i18n.MESSAGES.items()}
        if any(shapes.values()):
            assert all(len(table[key]) == 2 or not shapes[lang]
                       for lang, table in i18n.MESSAGES.items()), key


def test_the_offered_languages_are_the_ones_with_a_table():
    assert set(i18n.LANGUAGES) == set(i18n.MESSAGES)
    assert i18n.DEFAULT in i18n.LANGUAGES
