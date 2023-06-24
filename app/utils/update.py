import confuse
import requests
import subprocess
from app.utils.logs import CustomLogger

# Logging configuration
logger = CustomLogger('test')

# LOAD CONFIG FROM YAML FILE
config = confuse.Configuration('XNP', __name__)
config.set_file('config/config.yaml')

APPVER = config['app']['version'].get()

# Define the URL of the GitHub repository
REPO_URL = "https://api.github.com/repos/xtormin/XtremeNmapParser/releases/latest"


def get_latest_version():
    # Get the latest version from GitHub
    response = requests.get(REPO_URL)
    if response.status_code == 200:
        return response.json()['tag_name']
    else:
        logger.error("Could not fetch the latest version.")
        return None

def update_program():
    try:
        latest_version = get_latest_version()
        if latest_version and latest_version != APPVER:
            logger.info(f" A new version is available: {latest_version}. Updating...")
            # This assumes that the program was installed using git
            subprocess.run(["git", "pull"])
    except Exception as e:
        pass