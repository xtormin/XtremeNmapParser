"""Filesystem helpers for locating nmap XML files."""

import os

from xnp.config import load_config

def get_dir_files(dir):
    return os.listdir(dir)

def get_dir_files_recursive(folder, config=None):
    config = config or load_config()
    xml_files = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.endswith(config.nmap_file_extension):
                xml_files.append(os.path.join(root, file))
    return xml_files

def add_slash_if_needed(directory):
    if os.name == 'posix':  # Linux/Mac
        return directory if directory.endswith('/') else directory + '/'
    elif os.name == 'nt':  # Windows
        return directory if directory.endswith('\\') else directory + '\\'
    else:
        raise Exception(f'Unsupported OS: {os.name}')