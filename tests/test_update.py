"""The startup version check."""

import pytest
import requests

from xnp import __version__, update

pytestmark = pytest.mark.usefixtures("quiet_logs")


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


@pytest.fixture
def spy(monkeypatch):
    """Capture the requests/subprocess calls made by the update module."""
    calls = {"get": [], "run": []}

    def fake_get(url, **kwargs):
        calls["get"].append((url, kwargs))
        return FakeResponse(200, {"tag_name": "9.9.9"})

    def fake_run(cmd, *a, **kw):
        calls["run"].append(cmd)

    monkeypatch.setattr(update.requests, "get", fake_get)
    monkeypatch.setattr(update.subprocess, "run", fake_run)
    return calls


def test_skip_env_var_disables_the_check_entirely(spy, monkeypatch):
    monkeypatch.setenv(update.SKIP_ENV_VAR, "1")
    update.update_program()
    assert spy["get"] == []
    assert spy["run"] == []


def test_get_latest_version_reads_the_tag_name(spy, monkeypatch):
    monkeypatch.delenv(update.SKIP_ENV_VAR, raising=False)
    assert update.get_latest_version() == "9.9.9"
    assert spy["get"][0][0] == update.REPO_URL


def test_a_failed_request_returns_none(monkeypatch):
    monkeypatch.setattr(update.requests, "get", lambda url, **kw: FakeResponse(404))
    assert update.get_latest_version() is None


def test_network_errors_never_escape(monkeypatch):
    def boom(url, **kwargs):
        raise requests.ConnectionError("no network")

    monkeypatch.delenv(update.SKIP_ENV_VAR, raising=False)
    monkeypatch.setattr(update.requests, "get", boom)
    update.update_program()  # must not raise


def test_same_version_does_not_trigger_an_update(spy, monkeypatch):
    monkeypatch.delenv(update.SKIP_ENV_VAR, raising=False)
    monkeypatch.setattr(update, "get_latest_version", lambda: __version__)
    update.update_program()
    assert spy["run"] == []


# --- Bugs pinned here, fixed in the next commit -----------------------------

def test_CURRENT_a_new_release_runs_git_pull_without_asking(spy, monkeypatch):
    """BUG: every startup can silently `git pull` over the user's checkout."""
    monkeypatch.delenv(update.SKIP_ENV_VAR, raising=False)
    update.update_program()
    assert spy["run"] == [["git", "pull"]]


def test_CURRENT_the_request_has_no_timeout(spy, monkeypatch):
    """BUG: no timeout, so XNP can hang at startup on a dead network."""
    monkeypatch.delenv(update.SKIP_ENV_VAR, raising=False)
    update.get_latest_version()
    assert "timeout" not in spy["get"][0][1]
