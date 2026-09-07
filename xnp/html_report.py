"""Render a self-contained HTML report from parsed nmap data.

The result is one file with no external references: stylesheet, script, the
vendored Chart.js build and the scan data are all inlined, so the report opens
from a USB stick on a machine with no network.  That is deliberate -- a
deliverable that needs a CDN to render is a deliverable that stops rendering.
"""

import base64
import datetime
import html
import json
import os
import re
from pathlib import Path
from typing import Optional

import pandas as pd

from xnp import __version__
from xnp.config import XnpConfig, load_config
from xnp.errors import XnpError
from xnp.report_model import build_hosts, classify_port, scan_to_dict

ASSETS = Path(__file__).resolve().parent / "data" / "report"
TEMPLATE = ASSETS / "report.html"
STYLESHEET = ASSETS / "report.css"
SCRIPT = ASSETS / "report.js"
CHARTJS = ASSETS / "vendor" / "chart.umd.js"
FONTS_DIR = ASSETS / "vendor" / "fonts"

#: (file, css family, weight) for every face inlined into the report.  The type
#: is most of the design, so the faces travel inside the file rather than being
#: fetched -- a report that has to reach a CDN to look right is a report that
#: stops looking right.
FONT_FACES = (
    ("plex-sans-400.woff2", "Plex Sans", 400),
    ("plex-sans-500.woff2", "Plex Sans", 500),
    ("plex-sans-600.woff2", "Plex Sans", 600),
    ("plex-mono-400.woff2", "Plex Mono", 400),
    ("plex-mono-500.woff2", "Plex Mono", 500),
)

_PLACEHOLDER = re.compile(r"\{\{([A-Z_]+)\}\}")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise XnpError(f" |x| Error | Missing report asset {path}: {exc}") from exc


def _font_faces() -> str:
    """Return @font-face rules with each woff2 embedded as a data: URI."""
    rules = []
    for filename, family, weight in FONT_FACES:
        path = FONTS_DIR / filename
        try:
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        except OSError as exc:
            raise XnpError(f" |x| Error | Missing report font {path}: {exc}") from exc
        rules.append(
            f"@font-face{{font-family:'{family}';font-style:normal;"
            f"font-weight:{weight};font-display:swap;"
            f"src:url(data:font/woff2;base64,{encoded}) format('woff2')}}")
    return "\n".join(rules)


def _json_for_script(payload: dict) -> str:
    """Serialise the payload so it cannot break out of its <script> block.

    ``</script>`` inside a service banner would end the element early, and a
    banner is attacker controlled, so the three characters that can start a
    tag or an HTML comment are escaped even though they are legal JSON.
    """
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
    return (text.replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029"))


def build_payload(reports: Optional[list] = None, sources: Optional[list] = None,
                  merge: bool = False, only_open: bool = False,
                  title: Optional[str] = None, basename: Optional[str] = None,
                  title_en: Optional[str] = None) -> dict:
    """Assemble the JSON payload embedded in the report."""
    reports = reports or []
    sources = sources or [None] * len(reports)
    return {
        "title": title or "Informe de superficie de red",
        "title_en": title_en or title or "Network exposure report",
        "basename": basename or "xnp-report",
        "generated_at": datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "xnp_version": __version__,
        "only_open": bool(only_open),
        "scans": [scan_to_dict(report, source) for report, source in zip(reports, sources)],
        "hosts": build_hosts(reports, sources, merge=merge, only_open=only_open),
    }


def payload_from_dataframe(df: pd.DataFrame, title: Optional[str] = None,
                           basename: Optional[str] = None,
                           title_en: Optional[str] = None) -> dict:
    """Build a reduced payload when only the flat DataFrame is available.

    The writer contract is ``writer(df, filename)``, so ``df_to_html`` has to
    produce *something* useful when it is called without the parsed reports --
    directly, or by a caller that predates the rich context.  Scan metadata, OS
    detection and structured NSE output are simply absent in that case.
    """
    hosts: dict = {}
    for record in df.to_dict("records"):
        ip = record.get("IP")
        key = ip if ip is not None else f"?{len(hosts)}"
        host = hosts.setdefault(key, {
            "ip": ip, "ipv4": ip, "ipv6": None, "mac": None, "mac_vendor": None,
            "hostname": record.get("Hostname"), "hostnames": [],
            "state": record.get("State"), "state_reason": None,
            "starttime": None, "endtime": None, "comment": None,
            "distance": None, "uptime": None,
            "os": {"matches": [], "used_ports": [], "fingerprints": [],
                   "best": None, "accuracy": None, "family": None},
            "ports": [], "extraports": [], "trace": [], "source": None,
        })
        host["hostname"] = host["hostname"] or record.get("Hostname")

        port = record.get("Port")
        if port is None or (isinstance(port, float) and pd.isna(port)):
            continue
        try:
            portid = int(port)
        except (TypeError, ValueError):
            continue

        service_name = _clean(record.get("Service Name"))
        classification = classify_port(portid, service_name, None)
        scripts = _clean(record.get("Scripts"))
        host["ports"].append({
            "port": portid,
            "protocol": _clean(record.get("Protocol")),
            "state": _clean(record.get("State Port")),
            "reason": None, "reason_ttl": None, "owner": None,
            "service": {
                "name": service_name,
                "product": _clean(record.get("Product")),
                "version": _clean(record.get("Version")),
                "extrainfo": _clean(record.get("Extrainfo")),
                "tunnel": None, "method": None, "conf": None,
                "ostype": None, "devicetype": None, "hostname": None, "cpe": [],
            },
            "scripts": ([{"id": "script", "output": scripts, "tables": []}] if scripts else []),
            "risk": classification["risk"],
            "risk_reasons": classification["reasons"],
            "cleartext": classification["cleartext"],
        })

    return {
        "title": title or "Informe de superficie de red",
        "title_en": title_en or title or "Network exposure report",
        "basename": basename or "xnp-report",
        "generated_at": datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "xnp_version": __version__,
        "only_open": False,
        "scans": [],
        "hosts": list(hosts.values()),
    }


def _clean(value):
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    value = str(value).strip()
    return value or None


def render(payload: dict, config: Optional[XnpConfig] = None) -> str:
    """Inline every asset into the template and return the finished document."""
    config = config or load_config()
    values = {
        "TITLE": html.escape(payload.get("title") or config.html_title),
        "TITLE_EN": html.escape(payload.get("title_en") or payload.get("title") or ""),
        "VERSION": html.escape(__version__),
        "GENERATED": html.escape(payload.get("generated_at", "")),
        "FONTS": _font_faces(),
        "CSS": _read(STYLESHEET),
        "JS": _read(SCRIPT),
        "CHARTJS": _read(CHARTJS),
        "PAYLOAD": _json_for_script(payload),
    }
    # One pass, so a placeholder-looking string inside an asset is never
    # expanded (Chart.js and NSE output are not template sources).
    return _PLACEHOLDER.sub(lambda match: values.get(match.group(1), match.group(0)),
                            _read(TEMPLATE))


def write(payload: dict, filename: str, config: Optional[XnpConfig] = None) -> None:
    document = render(payload, config)
    with open(filename, "w", encoding="utf-8") as handle:
        handle.write(document)


def basename_for(filename: str) -> str:
    return os.path.splitext(os.path.basename(filename))[0] or "xnp-report"
