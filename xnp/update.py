"""Self-update check against the GitHub releases API."""

import os
import subprocess

import requests

from xnp import __version__
from xnp.logs import get_logger

logger = get_logger(__name__)

REPO_URL = "https://api.github.com/repos/xtormin/XtremeNmapParser/releases/latest"
SKIP_ENV_VAR = "XNP_NO_UPDATE_CHECK"


def get_latest_version():
    """Return the latest release tag, or ``None`` if it cannot be fetched."""
    response = requests.get(REPO_URL)
    if response.status_code == 200:
        return response.json()['tag_name']
    logger.error("Could not fetch the latest version.")
    return None


def update_program():
    if os.environ.get(SKIP_ENV_VAR):
        return
    try:
        latest_version = get_latest_version()
        if latest_version and latest_version != __version__:
            logger.info(f" A new version is available: {latest_version}. Updating...")
            # This assumes that the program was installed using git
            subprocess.run(["git", "pull"])
    except Exception:
        pass
