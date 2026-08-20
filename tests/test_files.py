"""Locating the XML files to parse."""

import os

import pytest

from xnp import files
from xnp.config import load_config


@pytest.fixture
def tree(tmp_path):
    """A directory tree with XML at two levels plus some noise."""
    (tmp_path / "top.xml").write_text("<x/>")
    (tmp_path / "notes.txt").write_text("ignore me")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "deep.xml").write_text("<x/>")
    return tmp_path


def test_get_dir_files_lists_the_top_level(tree):
    assert set(files.get_dir_files(tree)) == {"top.xml", "notes.txt", "nested"}


def test_recursive_search_finds_nested_xml_and_skips_other_files(tree):
    found = files.get_dir_files_recursive(str(tree), load_config())
    assert {os.path.basename(p) for p in found} == {"top.xml", "deep.xml"}


def test_recursive_search_returns_empty_for_a_tree_without_xml(tmp_path):
    (tmp_path / "readme.md").write_text("nothing here")
    assert files.get_dir_files_recursive(str(tmp_path), load_config()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX separators")
def test_add_slash_if_needed_is_idempotent():
    assert files.add_slash_if_needed("nmap") == "nmap/"
    assert files.add_slash_if_needed("nmap/") == "nmap/"


# --- Bugs pinned here, fixed in the next commit -----------------------------

def test_CURRENT_a_directory_named_like_an_xml_is_treated_as_a_file(tmp_path):
    """BUG: the non-recursive branch filters by name only, never by file type.

    A subdirectory called `something.xml` ends up in the list of files to parse.
    """
    (tmp_path / "trap.xml").mkdir()
    listed = [n for n in files.get_dir_files(tmp_path) if n.endswith(".xml")]
    assert listed == ["trap.xml"]
    assert (tmp_path / "trap.xml").is_dir()
