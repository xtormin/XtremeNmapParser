"""Filesystem helpers for locating nmap XML files."""

from pathlib import Path
from typing import Optional, Union

from xnp.config import XnpConfig, load_config


def find_xml_files(directory: Union[str, Path], recursive: bool = False,
                   config: Optional[XnpConfig] = None) -> list:
    """Return the sorted nmap XML files in ``directory``.

    Only regular files are returned: matching on the name alone used to let a
    *subdirectory* called ``something.xml`` through into the parse list.

    Raises:
        FileNotFoundError: the directory does not exist.
        NotADirectoryError: the path exists but is not a directory.
    """
    config = config or load_config()
    root = Path(directory)

    if not root.exists():
        raise FileNotFoundError(directory)
    if not root.is_dir():
        raise NotADirectoryError(directory)

    pattern = f"*{config.nmap_file_extension}"
    matches = root.rglob(pattern) if recursive else root.glob(pattern)
    return sorted(str(path) for path in matches if path.is_file())
