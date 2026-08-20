"""The startup version check and the explicit --update path."""

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
    """Capture the requests / subprocess calls made by the update module."""
    calls = {"get": [], "run": []}

    def fake_get(url, **kwargs):
        calls["get"].append((url, kwargs))
        return FakeResponse(200, {"tag_name": "9.9.9"})

    def fake_run(cmd, *a, **kw):
        calls["run"].append(cmd)
        class Result:
            returncode = 0
        return Result()

    monkeypatch.setattr(update.requests, "get", fake_get)
    monkeypatch.setattr(update.subprocess, "run", fake_run)
    monkeypatch.delenv(update.SKIP_ENV_VAR, raising=False)
    return calls


# --- The startup check ------------------------------------------------------

def test_a_new_release_only_warns_and_never_touches_the_checkout(spy, caplog):
    """The startup check used to run `git pull` over the user's repository."""
    assert update.check_for_updates() == "9.9.9"
    assert spy["run"] == []


def test_the_warning_names_both_versions_and_the_command(spy, caplog):
    with caplog.at_level("WARNING", logger="xnp.update"):
        update.check_for_updates()
    message = caplog.text
    assert "9.9.9" in message
    assert __version__ in message
    assert "xnp --update" in message


def test_the_skip_env_var_disables_the_check_entirely(spy, monkeypatch):
    monkeypatch.setenv(update.SKIP_ENV_VAR, "1")
    assert update.check_for_updates() is None
    assert spy["get"] == []


def test_the_request_carries_a_timeout(spy):
    """No timeout meant XNP could hang at startup on a dead network."""
    update.get_latest_version()
    assert spy["get"][0][1]["timeout"] == update.REQUEST_TIMEOUT


def test_the_same_version_produces_no_warning(spy, monkeypatch, caplog):
    monkeypatch.setattr(update.requests, "get",
                        lambda url, **kw: FakeResponse(200, {"tag_name": __version__}))
    with caplog.at_level("WARNING", logger="xnp.update"):
        update.check_for_updates()
    assert "available" not in caplog.text


# --- Failure modes ----------------------------------------------------------

def test_a_non_200_response_returns_none(monkeypatch):
    monkeypatch.setattr(update.requests, "get", lambda url, **kw: FakeResponse(404))
    assert update.get_latest_version() is None


def test_a_network_error_is_contained(monkeypatch):
    def boom(url, **kwargs):
        raise requests.ConnectionError("no network")

    monkeypatch.setattr(update.requests, "get", boom)
    assert update.get_latest_version() is None


def test_a_network_error_does_not_break_startup(monkeypatch):
    def boom(url, **kwargs):
        raise requests.Timeout("too slow")

    monkeypatch.delenv(update.SKIP_ENV_VAR, raising=False)
    monkeypatch.setattr(update.requests, "get", boom)
    assert update.check_for_updates() is None


def test_a_response_without_a_tag_name_returns_none(monkeypatch):
    monkeypatch.setattr(update.requests, "get", lambda url, **kw: FakeResponse(200, {}))
    assert update.get_latest_version() is None


# --- The explicit --update path --------------------------------------------

def test_update_program_pulls_when_a_new_release_exists(spy):
    assert update.update_program() is True
    assert spy["run"] == [["git", "pull"]]


def test_update_program_does_nothing_when_already_up_to_date(spy, monkeypatch):
    monkeypatch.setattr(update, "get_latest_version", lambda: __version__)
    assert update.update_program() is False
    assert spy["run"] == []


def test_update_pulls_anyway_when_the_version_cannot_be_checked(spy, monkeypatch):
    monkeypatch.setattr(update, "get_latest_version", lambda: None)
    assert update.update_program() is True
    assert spy["run"] == [["git", "pull"]]
