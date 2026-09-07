"""Rich, JSON-serialisable view of one or more parsed nmap reports.

The CSV/XLSX/JSON writers only ever see the flat eleven-column DataFrame, which
throws away everything the HTML report needs: the nmap command line, OS
detection, CPEs, port state reasons and structured NSE output.  This module
walks :class:`~xnp.xml_report.NmapXMLReport` instead and produces plain dicts.

Nothing here computes aggregates.  The HTML report recomputes every statistic
in the browser from the *filtered* set of ports, so a number shown next to a
chart can never disagree with the rows the reader is looking at.
"""

from typing import Optional

#: Services whose exposure is worth flagging on its own: remote administration,
#: data stores that historically ship unauthenticated, and cleartext credential
#: protocols.  Keyed by port because a service name is often absent (-sS only).
#:
#: This is a triage aid, not a vulnerability assessment: a port lands here
#: because *finding it open on an internet-facing host is usually a finding*,
#: not because this host is known to be vulnerable.  Every classification is
#: reported alongside the reason that produced it so a reader can disagree.
#:
#: Reasons are ``(english, spanish)``: the HTML report is bilingual, and the
#: prose explaining why something is flagged is the part most worth reading, so
#: it travels in both languages rather than only the one this file is written in.
HIGH_RISK_PORTS = {
    21: ("FTP, credentials in cleartext", "FTP, credenciales en claro"),
    23: ("Telnet, credentials in cleartext", "Telnet, credenciales en claro"),
    69: ("TFTP, no authentication", "TFTP, sin autenticación"),
    111: ("rpcbind, enumerates RPC services", "rpcbind, enumera servicios RPC"),
    135: ("MSRPC endpoint mapper", "Mapeador de extremos MSRPC"),
    137: ("NetBIOS name service", "Servicio de nombres NetBIOS"),
    138: ("NetBIOS datagram service", "Servicio de datagramas NetBIOS"),
    139: ("NetBIOS session service (SMB)", "Servicio de sesión NetBIOS (SMB)"),
    161: ("SNMP, often left on a default community string",
          "SNMP, a menudo con la comunidad por defecto"),
    389: ("LDAP without TLS", "LDAP sin TLS"),
    445: ("SMB, a standing lateral movement path",
          "SMB, vía habitual de movimiento lateral"),
    512: ("rexec, credentials in cleartext", "rexec, credenciales en claro"),
    513: ("rlogin, credentials in cleartext", "rlogin, credenciales en claro"),
    514: ("rsh, host-based trust", "rsh, confianza basada en el host"),
    623: ("IPMI, out-of-band management", "IPMI, gestión fuera de banda"),
    873: ("rsync, frequently exported without authentication",
          "rsync, a menudo exportado sin autenticación"),
    1433: ("Microsoft SQL Server exposed", "Microsoft SQL Server expuesto"),
    1521: ("Oracle TNS listener exposed", "Listener TNS de Oracle expuesto"),
    2049: ("NFS export", "Exportación NFS"),
    2375: ("Docker API without TLS, equivalent to root",
           "API de Docker sin TLS, equivale a root"),
    2376: ("Docker API, root-equivalent if the client cert is weak",
           "API de Docker, equivale a root si el certificado es débil"),
    3306: ("MySQL exposed", "MySQL expuesto"),
    3389: ("RDP, a standing brute-force and CVE target",
           "RDP, objetivo habitual de fuerza bruta y CVE"),
    4444: ("Common implant/handler port", "Puerto habitual de implante o handler"),
    5432: ("PostgreSQL exposed", "PostgreSQL expuesto"),
    5900: ("VNC, often without a password", "VNC, a menudo sin contraseña"),
    5901: ("VNC, often without a password", "VNC, a menudo sin contraseña"),
    5902: ("VNC, often without a password", "VNC, a menudo sin contraseña"),
    5984: ("CouchDB exposed", "CouchDB expuesto"),
    6379: ("Redis, unauthenticated by default", "Redis, sin autenticación por defecto"),
    7001: ("WebLogic, a recurrent deserialisation target",
           "WebLogic, objetivo recurrente de deserialización"),
    9200: ("Elasticsearch, unauthenticated by default",
           "Elasticsearch, sin autenticación por defecto"),
    9300: ("Elasticsearch transport", "Transporte de Elasticsearch"),
    11211: ("Memcached, unauthenticated and a UDP amplifier",
            "Memcached, sin autenticación y amplificador UDP"),
    27017: ("MongoDB exposed", "MongoDB expuesto"),
    50000: ("SAP / DB2 management", "Gestión de SAP / DB2"),
}

#: Same idea, keyed by the service name nmap reports, so a database moved off
#: its default port is still caught when -sV identified it.
HIGH_RISK_SERVICES = {
    "telnet": HIGH_RISK_PORTS[23],
    "ftp": HIGH_RISK_PORTS[21],
    "tftp": HIGH_RISK_PORTS[69],
    "rsh": HIGH_RISK_PORTS[514],
    "rlogin": HIGH_RISK_PORTS[513],
    "exec": HIGH_RISK_PORTS[512],
    "vnc": HIGH_RISK_PORTS[5900],
    "ms-wbt-server": HIGH_RISK_PORTS[3389],
    "microsoft-ds": HIGH_RISK_PORTS[445],
    "netbios-ssn": ("SMB over NetBIOS", "SMB sobre NetBIOS"),
    "mysql": HIGH_RISK_PORTS[3306],
    "ms-sql-s": HIGH_RISK_PORTS[1433],
    "postgresql": HIGH_RISK_PORTS[5432],
    "mongodb": HIGH_RISK_PORTS[27017],
    "redis": HIGH_RISK_PORTS[6379],
    "memcached": HIGH_RISK_PORTS[11211],
    "elasticsearch": HIGH_RISK_PORTS[9200],
    "rpcbind": HIGH_RISK_PORTS[111],
    "snmp": HIGH_RISK_PORTS[161],
    "ipmi": HIGH_RISK_PORTS[623],
    "docker": ("Docker API, root-equivalent", "API de Docker, equivale a root"),
    "x11": ("X11 display exposed", "Display X11 expuesto"),
    "jdwp": ("Java debug wire protocol, unauthenticated code execution",
             "Java debug wire protocol, ejecución de código sin autenticación"),
}

#: Remote access and management surface that is normally authenticated: worth
#: counting, not worth alarming about.
MEDIUM_RISK_PORTS = {
    22: ("SSH, remote administration", "SSH, administración remota"),
    25: ("SMTP", "SMTP"),
    53: ("DNS", "DNS"),
    80: ("HTTP without TLS", "HTTP sin TLS"),
    110: ("POP3 without TLS", "POP3 sin TLS"),
    143: ("IMAP without TLS", "IMAP sin TLS"),
    3128: ("HTTP proxy", "Proxy HTTP"),
    5985: ("WinRM over HTTP", "WinRM sobre HTTP"),
    5986: ("WinRM over HTTPS", "WinRM sobre HTTPS"),
    8000: ("HTTP without TLS", "HTTP sin TLS"),
    8080: ("HTTP without TLS", "HTTP sin TLS"),
    8081: ("HTTP without TLS", "HTTP sin TLS"),
    8888: ("HTTP without TLS", "HTTP sin TLS"),
    10000: ("Webmin", "Webmin"),
}

MEDIUM_RISK_SERVICES = {
    "ssh": MEDIUM_RISK_PORTS[22],
    "http": MEDIUM_RISK_PORTS[80],
    "http-proxy": MEDIUM_RISK_PORTS[3128],
    "http-alt": MEDIUM_RISK_PORTS[80],
    "smtp": MEDIUM_RISK_PORTS[25],
    "pop3": MEDIUM_RISK_PORTS[110],
    "imap": MEDIUM_RISK_PORTS[143],
    "domain": MEDIUM_RISK_PORTS[53],
    "wsman": ("WinRM", "WinRM"),
}

#: Service names that carry credentials or session data in the clear.  A port
#: whose service is tunnelled through TLS (``tunnel="ssl"``) never counts.
CLEARTEXT_SERVICES = {
    "ftp", "telnet", "http", "http-alt", "http-proxy", "imap", "pop3", "smtp",
    "ldap", "rsh", "rlogin", "exec", "snmp", "vnc", "tftp", "rsync", "mysql",
    "ms-sql-s", "postgresql", "mongodb", "redis", "memcached", "elasticsearch",
}

#: Reasons that stop applying once the service is wrapped in TLS.
_TLS_SENSITIVE = ("without TLS", "sin TLS")


def _text(value: Optional[str]) -> Optional[str]:
    """Normalise an XML attribute to a non-empty string or ``None``."""
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --- Risk classification ----------------------------------------------------

def classify_port(portid: Optional[int], service_name: Optional[str],
                  tunnel: Optional[str]) -> dict:
    """Return ``{"risk": ..., "reasons": [...], "cleartext": bool}`` for a port.

    Both the port number and the service name are consulted so that a database
    listening somewhere unusual is still classified once ``-sV`` has named it.
    Each reason is ``{"en": ..., "es": ...}`` and is carried into the report: a
    reader has to be able to see *why* something was painted red and overrule it.
    """
    name = (service_name or "").lower()
    tunnelled = (tunnel or "").lower() == "ssl"
    reasons = []

    def add(entry):
        if entry and entry not in reasons:
            reasons.append(entry)

    add(HIGH_RISK_PORTS.get(portid))
    add(HIGH_RISK_SERVICES.get(name))

    if reasons:
        risk = "high"
    else:
        add(MEDIUM_RISK_PORTS.get(portid))
        add(MEDIUM_RISK_SERVICES.get(name))
        risk = "medium" if reasons else "low"

    cleartext = bool(name in CLEARTEXT_SERVICES and not tunnelled)
    if tunnelled and risk == "medium":
        # An HTTP service behind TLS is just HTTPS; stop calling it cleartext.
        reasons = [r for r in reasons
                   if not any(marker in r[0] or marker in r[1] for marker in _TLS_SENSITIVE)]
        if not reasons:
            risk = "low"

    return {"risk": risk,
            "reasons": [{"en": en, "es": es} for en, es in reasons],
            "cleartext": cleartext}


# --- Node -> dict -----------------------------------------------------------

def _table_to_dict(table) -> dict:
    """Flatten one structured NSE ``<table>`` into plain nested data."""
    return {
        "key": _text(table.key),
        "elements": [{"key": _text(elem.key), "value": _text(elem.content)}
                     for elem in table.table_elements],
        "tables": [_table_to_dict(nested) for nested in table.nested_tables],
    }


def _script_to_dict(script) -> dict:
    return {
        "id": _text(script.id),
        "output": _text(script.output),
        "tables": [_table_to_dict(table) for table in script.tables],
    }


def _service_to_dict(service) -> dict:
    return {
        "name": _text(service.name),
        "product": _text(service.product),
        "version": _text(service.version),
        "extrainfo": _text(service.extrainfo),
        "tunnel": _text(service.tunnel),
        "method": _text(service.method),
        "conf": _text(service.conf),
        "ostype": _text(service.ostype),
        "devicetype": _text(service.devicetype),
        "hostname": _text(service.hostname),
        "cpe": [c for c in (_text(cpe) for cpe in service.cpe) if c],
    }


EMPTY_SERVICE = {
    "name": None, "product": None, "version": None, "extrainfo": None,
    "tunnel": None, "method": None, "conf": None, "ostype": None,
    "devicetype": None, "hostname": None, "cpe": [],
}


def _port_to_dict(port) -> dict:
    state = port.state[0] if port.state else None
    service = _service_to_dict(port.service[0]) if port.service else dict(EMPTY_SERVICE)
    portid = _int(port.portid)
    classification = classify_port(portid, service["name"], service["tunnel"])

    return {
        "port": portid,
        "protocol": _text(port.protocol),
        "state": _text(state.state) if state else None,
        "reason": _text(state.reason) if state else None,
        "reason_ttl": _text(state.reason_ttl) if state else None,
        "owner": _text(port.owner[0].name) if port.owner else None,
        "service": service,
        "scripts": [_script_to_dict(script) for script in port.script],
        "risk": classification["risk"],
        "risk_reasons": classification["reasons"],
        "cleartext": classification["cleartext"],
    }


def _os_to_dict(host) -> dict:
    matches, used_ports, fingerprints = [], [], []
    for os_node in host.os:
        for match in os_node.osmatch:
            matches.append({
                "name": _text(match.name),
                "accuracy": _int(match.accuracy),
                "classes": [{
                    "vendor": _text(osclass.vendor),
                    "family": _text(osclass.osfamily),
                    "gen": _text(osclass.osgen),
                    "type": _text(osclass.type),
                    "accuracy": _int(osclass.accuracy),
                    "cpe": [c for c in (_text(cpe) for cpe in osclass.cpe) if c],
                } for osclass in match.osclass],
            })
        used_ports.extend({
            "port": _int(pu.portid), "protocol": _text(pu.proto), "state": _text(pu.state),
        } for pu in os_node.portused)
        fingerprints.extend(
            fp for fp in (_text(f.fingerprint) for f in os_node.osfingerprint) if fp)

    matches.sort(key=lambda m: m["accuracy"] or 0, reverse=True)
    best = matches[0] if matches else None
    family = None
    if best and best["classes"]:
        family = best["classes"][0]["family"] or best["classes"][0]["vendor"]

    return {
        "matches": matches,
        "used_ports": used_ports,
        "fingerprints": fingerprints,
        "best": best["name"] if best else None,
        "accuracy": best["accuracy"] if best else None,
        "family": family,
    }


def _addresses(host) -> dict:
    found = {"ipv4": None, "ipv6": None, "mac": None, "vendor": None}
    for address in host.addresses:
        addrtype = _text(address.addrtype)
        if addrtype == "ipv4":
            found["ipv4"] = _text(address.addr)
        elif addrtype == "ipv6":
            found["ipv6"] = _text(address.addr)
        elif addrtype == "mac":
            found["mac"] = _text(address.addr)
            found["vendor"] = _text(address.vendor)
    return found


def _hostnames(host) -> list:
    return [{"name": _text(hostname.name), "type": _text(hostname.type)}
            for group in host.hostnames for hostname in group.hostnames
            if _text(hostname.name)]


def host_to_dict(host, source: Optional[str] = None) -> dict:
    """Convert one ``<host>`` node into the report's host record."""
    addresses = _addresses(host)
    hostnames = _hostnames(host)
    status = host.status[0] if host.status else None
    uptime = host.uptime[0] if host.uptime else None

    return {
        "ip": addresses["ipv4"] or addresses["ipv6"],
        "ipv4": addresses["ipv4"],
        "ipv6": addresses["ipv6"],
        "mac": addresses["mac"],
        "mac_vendor": addresses["vendor"],
        "hostname": hostnames[-1]["name"] if hostnames else None,
        "hostnames": hostnames,
        "state": _text(status.state) if status else None,
        "state_reason": _text(status.reason) if status else None,
        "starttime": _text(host.starttime),
        "endtime": _text(host.endtime),
        "comment": _text(host.comment),
        "distance": _int(host.distance[0].value) if host.distance else None,
        "uptime": ({"seconds": _int(uptime.seconds), "lastboot": _text(uptime.lastboot)}
                   if uptime else None),
        "os": _os_to_dict(host),
        "ports": [_port_to_dict(port) for port in host.ports],
        "extraports": [{
            "state": _text(extra.state),
            "count": _int(extra.count),
            "reasons": [{"reason": _text(r.reason), "count": _int(r.count),
                         "proto": _text(r.proto)} for r in extra.extrareasons],
        } for extra in host.extraports],
        "trace": [{"ttl": _int(hop.ttl), "rtt": _text(hop.rtt),
                   "ip": _text(hop.ipaddr), "host": _text(hop.host)}
                  for trace in host.trace for hop in trace.hops],
        "source": source,
    }


def scan_to_dict(report, source: Optional[str] = None) -> dict:
    """Summarise the run-level metadata of one report."""
    run = report.nmaprun
    return {
        "file": source,
        "scanner": _text(run.scanner) if run else None,
        "args": _text(run.args) if run else None,
        "start": _text(run.start) if run else None,
        "startstr": _text(run.startstr) if run else None,
        "version": _text(run.version) if run else None,
        "xmloutputversion": _text(run.xmloutputversion) if run else None,
        "scaninfo": [{
            "type": _text(info.type),
            "protocol": _text(info.protocol),
            "numservices": _int(info.numservices),
            "services": _text(info.services),
        } for info in report.scaninfo],
    }


# --- Merging ----------------------------------------------------------------

def _service_richness(port: dict) -> int:
    """How many service detection fields a port record actually filled in."""
    service = port["service"]
    return sum(1 for key in ("product", "version", "extrainfo") if service.get(key))


def merge_hosts(hosts: list) -> list:
    """Collapse hosts scanned more than once into one record per address.

    Mirrors :meth:`xnp.parser.NmapParser.merge_df`: ports are keyed by
    protocol and number, and the record that identified the most service
    detail wins.  A hostname resolved by any one scan applies to the address.
    """
    merged: dict = {}
    for host in hosts:
        key = host["ip"]
        if key is None:
            # Nothing to merge on; keep it as its own entry.
            merged[id(host)] = host
            continue

        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(host, ports=list(host["ports"]))
            continue

        existing["hostname"] = existing["hostname"] or host["hostname"]
        existing["mac"] = existing["mac"] or host["mac"]
        existing["mac_vendor"] = existing["mac_vendor"] or host["mac_vendor"]
        if host["state"] == "up":
            existing["state"] = "up"
        if not existing["os"]["matches"] and host["os"]["matches"]:
            existing["os"] = host["os"]

        by_key = {(p["protocol"], p["port"]): p for p in existing["ports"]}
        for port in host["ports"]:
            port_key = (port["protocol"], port["port"])
            current = by_key.get(port_key)
            if current is None or _service_richness(port) > _service_richness(current):
                by_key[port_key] = port
        existing["ports"] = list(by_key.values())

    return list(merged.values())


def build_hosts(reports: list, sources: Optional[list] = None,
                merge: bool = False, only_open: bool = False) -> list:
    """Turn parsed reports into the report's list of host records."""
    sources = sources or [None] * len(reports)
    hosts = [host_to_dict(host, source)
             for report, source in zip(reports, sources)
             for host in report.hosts]

    if merge:
        hosts = merge_hosts(hosts)

    if only_open:
        for host in hosts:
            host["ports"] = [p for p in host["ports"] if p["state"] == "open"]

    for host in hosts:
        host["ports"].sort(key=lambda p: (p["protocol"] or "", p["port"] or 0))

    hosts.sort(key=_host_sort_key)
    return hosts


def _host_sort_key(host: dict):
    """Sort IPv4 numerically, then everything else lexically."""
    ip = host.get("ip") or ""
    octets = ip.split(".")
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        return (0, tuple(int(o) for o in octets), "")
    return (1, (), ip)
