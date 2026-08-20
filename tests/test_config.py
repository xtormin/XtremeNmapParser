"""Configuration loading.

The whole point of these tests is the bug that used to make XNP untestable:
the configuration was read from the relative path ``config/config.yaml`` at
import time, so nothing worked outside the repository root.
"""

import dataclasses

import pytest

from xnp import __version__
from xnp.config import PACKAGED_CONFIG, XnpConfig, load_config, reset_config
from xnp.errors import XnpConfigError

DEFAULT_COLUMNS = [
    'Hostname', 'IP', 'State', 'Port', 'Protocol', 'State Port',
    'Service Name', 'Product', 'Version', 'Extrainfo',
]


def test_packaged_config_ships_with_the_package():
    assert PACKAGED_CONFIG.is_file()


def test_loads_from_an_unrelated_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    reset_config()
    config = load_config()
    assert config.app_name == "Xtreme Nmap Parser"
    assert config.nmap_file_extension == ".xml"


def test_default_columns_and_all_columns():
    config = load_config()
    assert config.columns_default == tuple(DEFAULT_COLUMNS)
    assert config.columns_all == tuple(DEFAULT_COLUMNS + ['Scripts'])


@pytest.mark.parametrize("choice,expected_last", [
    ("default", "Extrainfo"),
    ("all", "Scripts"),
    (None, "Extrainfo"),
    ("nonsense", "Extrainfo"),
])
def test_columns_for(choice, expected_last):
    assert load_config().columns_for(choice)[-1] == expected_last


def test_version_comes_from_the_package_not_from_yaml():
    assert load_config().version == __version__


def test_env_var_overrides_the_packaged_config(tmp_path, monkeypatch):
    override = tmp_path / "custom.yaml"
    override.write_text('app:\n  name: "Custom XNP"\n')
    monkeypatch.setenv("XNP_CONFIG", str(override))
    reset_config()
    config = load_config()
    # The override only redefines app.name; everything else falls through.
    assert config.app_name == "Custom XNP"
    assert config.nmap_file_extension == ".xml"


def test_explicit_path_wins_over_the_env_var(tmp_path, monkeypatch):
    env_file = tmp_path / "env.yaml"
    env_file.write_text('app:\n  name: "From env"\n')
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text('app:\n  name: "From argument"\n')
    monkeypatch.setenv("XNP_CONFIG", str(env_file))
    reset_config()
    assert load_config(explicit).app_name == "From argument"


def test_missing_explicit_config_raises(tmp_path):
    reset_config()
    with pytest.raises(XnpConfigError, match="not found"):
        load_config(tmp_path / "does_not_exist.yaml")


def test_config_is_cached():
    reset_config()
    assert load_config() is load_config()


def test_config_is_immutable():
    with pytest.raises(dataclasses.FrozenInstanceError):
        load_config().app_name = "nope"


def test_xnp_config_can_be_built_by_hand():
    """Tests must be able to build a config without touching the filesystem."""
    config = XnpConfig(
        app_name="test", nmap_file_extension=".xml", sheet_name="Sheet",
        header_color="#000000", header_text_color="#FFFFFF", table_style="Table Style Medium 16",
        columns_default=("IP", "Port"), columns_all=("IP", "Port", "Scripts"),
    )
    assert config.columns_for("all") == ["IP", "Port", "Scripts"]


def test_a_broken_config_file_raises_a_config_error(tmp_path, monkeypatch):
    broken = tmp_path / "broken.yaml"
    broken.write_text("app:\n  name: 123\nnmap_file_extension: []\n")
    reset_config()
    with pytest.raises(XnpConfigError, match="Invalid configuration"):
        load_config(broken)


def test_a_local_config_directory_is_picked_up(tmp_path, monkeypatch):
    local = tmp_path / "config"
    local.mkdir()
    (local / "config.yaml").write_text('app:\n  name: "Local override"\n')
    monkeypatch.chdir(tmp_path)
    reset_config()
    assert load_config().app_name == "Local override"
