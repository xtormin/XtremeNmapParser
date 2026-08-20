"""Locating the XML files to parse."""

import os

import pytest

from xnp.files import find_xml_files


@pytest.fixture
def tree(tmp_path):
    """A directory tree with XML at two levels plus assorted noise."""
    (tmp_path / "top.xml").write_text("<x/>")
    (tmp_path / "notes.txt").write_text("ignore me")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "deep.xml").write_text("<x/>")
    return tmp_path


def names(paths):
    return {os.path.basename(p) for p in paths}


def test_non_recursive_search_stays_at_the_top_level(tree):
    assert names(find_xml_files(tree)) == {"top.xml"}


def test_recursive_search_descends_into_subdirectories(tree):
    assert names(find_xml_files(tree, recursive=True)) == {"top.xml", "deep.xml"}


def test_non_xml_files_are_ignored(tree):
    assert "notes.txt" not in names(find_xml_files(tree, recursive=True))


def test_results_are_sorted(tree):
    (tree / "a.xml").write_text("<x/>")
    found = find_xml_files(tree)
    assert found == sorted(found)


def test_a_tree_without_xml_returns_empty(tmp_path):
    (tmp_path / "readme.md").write_text("nothing here")
    assert find_xml_files(tmp_path, recursive=True) == []


def test_a_missing_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        find_xml_files(tmp_path / "nope")


def test_a_file_instead_of_a_directory_raises(tmp_path):
    target = tmp_path / "scan.xml"
    target.write_text("<x/>")
    with pytest.raises(NotADirectoryError):
        find_xml_files(target)


def test_a_directory_named_like_an_xml_is_not_treated_as_a_file(tmp_path):
    """Matching on the name alone used to let `something.xml/` into the list."""
    (tmp_path / "trap.xml").mkdir()
    (tmp_path / "real.xml").write_text("<x/>")
    assert names(find_xml_files(tmp_path)) == {"real.xml"}


def test_the_directory_argument_needs_no_trailing_slash(tree):
    assert find_xml_files(str(tree)) == find_xml_files(str(tree) + "/")
