"""Version check against the GitHub releases API.

XNP used to run ``git pull`` on its own checkout at every startup.  It now only
reports that a new release exists and tells the user how to update; the update
itself runs only when explicitly asked for with ``--update``.
"""

import os
import subprocess
from typing import Optional

import requests

from xnp import __version__
from xnp.logs import get_logger

logger = get_logger(__name__)

REPO_URL = "https://api.github.com/repos/xtormin/XtremeNmapParser/releases/latest"
SKIP_ENV_VAR = "XNP_NO_UPDATE_CHECK"
REQUEST_TIMEOUT = 5


def get_latest_version() -> Optional[str]:
    """Return the latest release tag, or ``None`` if it cannot be fetched."""
    try:
        response = requests.get(REPO_URL, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        logger.debug(f"Version check failed: {exc}")
        return None

    if response.status_code == 200:
        return response.json().get('tag_name')

    logger.debug(f"Version check returned HTTP {response.status_code}.")
    return None


def check_for_updates() -> Optional[str]:
    """Warn the user if a newer release exists. Never modifies the checkout."""
    if os.environ.get(SKIP_ENV_VAR):
        return None

    latest_version = get_latest_version()
    if latest_version and latest_version != __version__:
        logger.warning(
            f"XNP {latest_version} is available (you have {__version__}) "
            f"- update with: xnp --update")
    return latest_version


def update_program() -> bool:
    """Update the checkout with ``git pull``. Only called for ``--update``."""
    latest_version = get_latest_version()
    if latest_version and latest_version == __version__:
        logger.info(f"XNP {__version__} is already the latest version.")
        return False

    if latest_version:
        logger.info(f"Updating to {latest_version}...")
    else:
        logger.warning("Could not check the latest version; pulling anyway.")

    # This assumes that the program was installed using git.
    result = subprocess.run(["git", "pull"], cwd=os.path.dirname(os.path.dirname(
        os.path.realpath(__file__))))
    return result.returncode == 0
