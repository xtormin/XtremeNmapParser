#!/usr/bin/python3
"""Legacy launcher kept for backwards compatibility.

Prefer the installed ``xnp`` command or ``python -m xnp``.
"""
import sys

from xnp.cli import main

if __name__ == "__main__":
    sys.exit(main())
