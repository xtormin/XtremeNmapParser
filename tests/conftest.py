"""Shared pytest fixtures."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def xml(fixtures_dir):
    """Return the path to a fixture XML as a string: ``xml("single_host")``."""
    def _xml(name):
        return str(fixtures_dir / f"{name}.xml")
    return _xml


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Keep every test away from the network and from a stale config cache."""
    from xnp import config as config_module

    monkeypatch.setenv("XNP_NO_UPDATE_CHECK", "1")
    monkeypatch.delenv("XNP_CONFIG", raising=False)
    config_module.reset_config()
    yield
    config_module.reset_config()


@pytest.fixture
def run_cli(monkeypatch):
    """Run ``xnp.cli.main`` inside ``cwd`` and return its exit code."""
    def _run(args, cwd=None):
        from xnp.cli import main

        if cwd is not None:
            monkeypatch.chdir(cwd)
        return main(list(args))
    return _run


@pytest.fixture
def quiet_logs():
    """Silence XNP log output for tests that only care about return values."""
    import logging

    logger = logging.getLogger("xnp")
    previous = logger.level
    logger.setLevel(logging.CRITICAL)
    yield
    logger.setLevel(previous)
