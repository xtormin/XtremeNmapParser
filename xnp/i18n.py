"""Terminal messages, in the reader's language.

Scope, decided deliberately: this covers what the tool *says about its own
work* -- panels, section rules, per-file lines, the summary and the warnings.
It does **not** cover exception messages or argparse's help.  An error is the
string that gets pasted into a GitHub issue or searched for verbatim, so it
stays in one language.

Structure mirrors the HTML report's I18N table (``xnp/data/report/report.js``)
on purpose: same idea, same key style, so the two stay recognisable as one
system.  A value is either a string or a ``(singular, plural)`` pair.

This module imports nothing from :mod:`xnp`, so anything may import it.
"""

import os
from typing import Optional

#: The language used when nothing else is known.  English rather than Spanish
#: because it is what every message in this project was written in first.
DEFAULT = "en"

MESSAGES = {
    "en": {
        # Panels and section rules
        "panel.arguments": "Arguments",
        "panel.summary": "Summary",
        "section.parsing": "Parsing files",
        "section.output": "Output files",
        "section.rescan": "Targeted rescan",
        "rescan.root": "Commands with a raw-socket scan need root (sudo).",
        "progress.parsing": "Parsing",

        # The arguments panel
        "arg.file": "File (-f)",
        "arg.folder": "Folder (-d)",
        "arg.merge": "Merge files",
        "arg.recursive": "Recursive",
        "arg.format": "Output format (-oF)",
        "arg.name": "Output name (-oN)",
        "arg.columns": "Columns (-C)",
        "arg.open": "Open ports (--open)",
        "arg.show": "Open the report (--show)",
        "arg.rescan": "Rescan profile (--rescan)",
        "arg.hostless": "Include hostless",
        "arg.validation": "DTD validation",
        "arg.language": "Language (--lang)",
        "value.yes": "yes",
        "value.no": "no",
        "value.no_validate": "off (--no-validate)",

        # The output files table
        "table.format": "Format",
        "table.file": "File",
        "table.size": "Size",

        # The summary panel
        "summary.files": "Files",
        "summary.hosts": "Hosts",
        "summary.ports": "Ports",
        "summary.services": "Services",
        "summary.merged": "Merged",
        "summary.written": "Written",
        "summary.elapsed": "Elapsed",

        # Units.  A pair is (singular, plural).
        "unit.host": ("host", "hosts"),
        "unit.port": ("port", "ports"),
        "unit.file": ("file", "files"),
        "unit.row": ("row", "rows"),
        "unit.open": "open",
        "unit.up": "up",
        "unit.total": "total",
        "unit.parsed": "parsed",
        "unit.skipped": "skipped",

        # Warnings.  Their English wording is load-bearing: several tests match
        # on it, and people grep their logs for these exact phrases.
        "warn.skipping": "Skipping {path}: {reason}",
        "warn.no_data": "The file has no scan data, omitting export",
        "warn.skipped_count": "{count} of {total} files were skipped:",
        "warn.skipped_hint": "Pass --no-validate if they come from another scanner",
        "warn.nothing_to_show": "--show: the run produced no HTML report to open",
        "warn.show_failed": "--show: could not open {path}: {reason}",
        "warn.show_limited": "--show: {total} reports were written, opening the first {shown}",
        "warn.rescan_empty": "--rescan: nothing in the configured states "
                             "({states}) to aim at",
        "warn.rescan_dropped": "--rescan: {flags} dropped -- the ports and scan "
                               "types are decided per group",

        # The update check
        "update.available": ("XNP {latest} is available (you have {current}) "
                             "- update with: xnp --update"),
        "update.current": "XNP {version} is already the latest version.",
        "update.updating": "Updating to {version}...",
        "update.unknown": "Could not check the latest version; pulling anyway.",
    },
    "es": {
        "panel.arguments": "Argumentos",
        "panel.summary": "Resumen",
        "section.parsing": "Analizando ficheros",
        "section.output": "Ficheros generados",
        "section.rescan": "Reescaneo dirigido",
        "rescan.root": "Los comandos con escaneo de socket crudo necesitan root (sudo).",
        "progress.parsing": "Analizando",

        "arg.file": "Fichero (-f)",
        "arg.folder": "Carpeta (-d)",
        "arg.merge": "Fusionar ficheros",
        "arg.recursive": "Recursivo",
        "arg.format": "Formato de salida (-oF)",
        "arg.name": "Nombre de salida (-oN)",
        "arg.columns": "Columnas (-C)",
        "arg.open": "Solo puertos abiertos (--open)",
        "arg.show": "Abrir el informe (--show)",
        "arg.rescan": "Perfil de reescaneo (--rescan)",
        "arg.hostless": "Incluir hosts sin puertos",
        "arg.validation": "Validación DTD",
        "arg.language": "Idioma (--lang)",
        "value.yes": "sí",
        "value.no": "no",
        "value.no_validate": "desactivada (--no-validate)",

        "table.format": "Formato",
        "table.file": "Fichero",
        "table.size": "Tamaño",

        "summary.files": "Ficheros",
        "summary.hosts": "Hosts",
        "summary.ports": "Puertos",
        "summary.services": "Servicios",
        "summary.merged": "Fusionado",
        "summary.written": "Escrito",
        "summary.elapsed": "Duración",

        "unit.host": ("host", "hosts"),
        "unit.port": ("puerto", "puertos"),
        "unit.file": ("fichero", "ficheros"),
        "unit.row": ("fila", "filas"),
        "unit.open": ("abierto", "abiertos"),
        "unit.up": ("activo", "activos"),
        "unit.total": "total",
        "unit.parsed": ("analizado", "analizados"),
        "unit.skipped": ("omitido", "omitidos"),

        # The reason inside this one comes from an exception, so it stays in
        # English -- see the module docstring.
        "warn.skipping": "Omitiendo {path}: {reason}",
        "warn.no_data": "El fichero no tiene datos de escaneo, se omite la exportación",
        "warn.skipped_count": "{count} de {total} ficheros omitidos:",
        "warn.skipped_hint": "Usa --no-validate si vienen de otro escáner",
        "warn.nothing_to_show": "--show: la ejecución no generó ningún informe HTML que abrir",
        "warn.show_failed": "--show: no se pudo abrir {path}: {reason}",
        "warn.show_limited": "--show: se generaron {total} informes, se abren los {shown} primeros",
        "warn.rescan_empty": "--rescan: no hay nada en los estados configurados "
                             "({states}) a lo que apuntar",
        "warn.rescan_dropped": "--rescan: se descarta {flags}; los puertos y los "
                               "tipos de escaneo se deciden por grupo",

        "update.available": ("XNP {latest} está disponible (tienes {current}) "
                             "- actualiza con: xnp --update"),
        "update.current": "XNP {version} ya es la última versión.",
        "update.updating": "Actualizando a {version}...",
        "update.unknown": "No se pudo comprobar la última versión; se actualiza igualmente.",
    },
}

#: Offered by ``--lang``, sorted so the help text is stable.
LANGUAGES = tuple(sorted(MESSAGES))

#: POSIX precedence: the first one that is set decides, even if it names a
#: language this project does not speak.
_LOCALE_VARS = ("LC_ALL", "LC_MESSAGES", "LANG")

_lang = DEFAULT


def detect(environ: Optional[dict] = None) -> str:
    """The language the environment asks for, or :data:`DEFAULT`.

    ``es_ES.UTF-8`` and ``es`` both mean Spanish; ``C``, ``POSIX`` and any
    language with no table here mean English.
    """
    env = os.environ if environ is None else environ
    for name in _LOCALE_VARS:
        value = env.get(name)
        if not value:
            continue
        code = value.split(".")[0].split("_")[0].lower()
        return code if code in MESSAGES else DEFAULT
    return DEFAULT


def setup(lang: Optional[str] = None) -> str:
    """Set the language for this run.  ``None`` means "ask the environment"."""
    global _lang
    _lang = lang if lang in MESSAGES else detect()
    return _lang


def current() -> str:
    return _lang


def t(key: str, count: Optional[int] = None, **fields) -> str:
    """Look up ``key``, pick the plural form, and fill in ``fields``.

    An unknown key falls back to English and then to the key itself, so a
    missing translation degrades to something readable instead of raising in
    the middle of a run.
    """
    value = MESSAGES[_lang].get(key)
    if value is None:
        value = MESSAGES[DEFAULT].get(key, key)
    if isinstance(value, tuple):
        value = value[0] if count == 1 else value[1]
    # ``count`` selects the plural form *and* stays available as a field, so a
    # message can say both "how many" and inflect for it.
    if count is not None:
        fields.setdefault("count", count)
    return value.format(**fields) if fields else value
