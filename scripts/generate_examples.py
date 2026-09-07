"""Generate the example scans shipped in examples/.

They are written once and committed; this script exists so the set can be
regenerated or extended without hand-editing XML.  Every address is RFC 1918 and
every hostname sits under a non-routable .local domain: nothing here points at a
real target.
"""

import html
import random
from pathlib import Path

OUT = Path("examples")
random.seed(1312)


def esc(value):
    return html.escape(str(value), quote=True)


def service(name, product=None, version=None, extrainfo=None, tunnel=None,
            ostype=None, cpe=()):
    attrs = f'name="{esc(name)}" method="probed" conf="10"'
    if product:
        attrs += f' product="{esc(product)}"'
    if version:
        attrs += f' version="{esc(version)}"'
    if extrainfo:
        attrs += f' extrainfo="{esc(extrainfo)}"'
    if tunnel:
        attrs += f' tunnel="{esc(tunnel)}"'
    if ostype:
        attrs += f' ostype="{esc(ostype)}"'
    cpes = "".join(f"<cpe>{esc(c)}</cpe>" for c in cpe)
    return f"<service {attrs}>{cpes}</service>"


def script(sid, output):
    return f'<script id="{esc(sid)}" output="{esc(output)}"/>'


def port(num, state="open", proto="tcp", svc=None, scripts=(), reason="syn-ack"):
    body = f'<state state="{state}" reason="{reason}" reason_ttl="63"/>'
    if svc:
        body += svc
    body += "".join(scripts)
    return f'<port protocol="{proto}" portid="{num}">{body}</port>'


def os_block(name, vendor, family, gen, otype, accuracy=96, portused=22):
    return (f'<os><portused state="open" proto="tcp" portid="{portused}"/>'
            f'<osmatch name="{esc(name)}" accuracy="{accuracy}" line="1">'
            f'<osclass vendor="{esc(vendor)}" osgen="{esc(gen)}" type="{esc(otype)}" '
            f'accuracy="{accuracy}" osfamily="{esc(family)}">'
            f'<cpe>cpe:/o:{vendor.lower()}:{family.lower().replace(" ", "_")}</cpe>'
            f"</osclass></osmatch></os>")


def host(ip, hostname, ports, os_xml="", mac=None, vendor=None, closed=None,
         distance=None, uptime=None, trace=None, state="up"):
    parts = [f'<status state="{state}" reason="echo-reply" reason_ttl="63"/>',
             f'<address addr="{ip}" addrtype="ipv4"/>']
    if mac:
        parts.append(f'<address addr="{mac}" addrtype="mac"'
                     + (f' vendor="{esc(vendor)}"' if vendor else "") + "/>")
    if hostname:
        parts.append(f'<hostnames><hostname name="{esc(hostname)}" type="PTR"/></hostnames>')
    else:
        parts.append("<hostnames/>")

    closed = closed if closed is not None else 1000 - len(ports)
    ports_xml = (f'<extraports state="closed" count="{closed}">'
                 f'<extrareasons reason="reset" count="{closed}"/></extraports>'
                 + "".join(ports))
    parts.append(f"<ports>{ports_xml}</ports>")
    if os_xml:
        parts.append(os_xml)
    if distance:
        parts.append(f'<distance value="{distance}"/>')
    if uptime:
        parts.append(f'<uptime seconds="{uptime[0]}" lastboot="{esc(uptime[1])}"/>')
    if trace:
        hops = "".join(
            f'<hop ttl="{i + 1}" rtt="{rtt}" ipaddr="{addr}"'
            + (f' host="{esc(h)}"' if h else "") + "/>"
            for i, (rtt, addr, h) in enumerate(trace))
        parts.append(f'<trace proto="tcp" port="443">{hops}</trace>')

    return ('<host starttime="1725000000" endtime="1725000480">'
            + "".join(parts) + "</host>")


def document(args, hosts, up, total, scanner="nmap", version="7.94",
             scan_type="syn", protocol="tcp", numservices=1000,
             services="1-1000", startstr="Fri Sep  5 09:20:00 2026"):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<!-- Example scan shipped with Xtreme Nmap Parser. Synthetic data, private
     addresses only: nothing here refers to a real host. -->
<nmaprun scanner="{scanner}" args="{esc(args)}" start="1725000000" \
startstr="{esc(startstr)}" version="{version}" xmloutputversion="1.05">
<scaninfo type="{scan_type}" protocol="{protocol}" numservices="{numservices}" \
services="{esc(services)}"/>
<verbose level="1"/>
<debugging level="0"/>
{chr(10).join(hosts)}
<runstats>
<finished time="1725000900" timestr="Fri Sep  5 09:35:00 2026" elapsed="900.00" exit="success"/>
<hosts up="{up}" down="{total - up}" total="{total}"/>
</runstats>
</nmaprun>
'''


def write(path, text):
    target = OUT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    print(f"  {target}  ({len(text) // 1024 or 1} KB)")


LINUX = os_block("Ubuntu 22.04 (Linux 5.15 - 5.19)", "Linux", "Linux", "5.X",
                 "general purpose", 98)
DEBIAN = os_block("Debian 12 (Linux 6.1)", "Linux", "Linux", "6.X", "general purpose", 95)
WIN2019 = os_block("Microsoft Windows Server 2019", "Microsoft", "Windows", "2019",
                   "general purpose", 97, portused=445)
WIN10 = os_block("Microsoft Windows 10 21H2", "Microsoft", "Windows", "10",
                 "general purpose", 92, portused=445)
CISCO = os_block("Cisco IOS 15.2", "Cisco", "IOS", "15.X", "router", 94, portused=22)

SSH = service("ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.4", "Ubuntu Linux; protocol 2.0",
              ostype="Linux", cpe=("cpe:/a:openbsd:openssh:8.9p1",))
SSH_OLD = service("ssh", "OpenSSH", "7.4", "protocol 2.0", ostype="Linux")
HOSTKEY = script("ssh-hostkey",
                 "2048 SHA256:9aB7xY2ZqLmN0pQrStUvWxYz1234567890abcdefg (RSA)\n"
                 "256 SHA256:kLmNoPqRsTuVwXyZ0123456789abcdefghijklmn (ED25519)")


def corporate_lan():
    """Two flat subnets, scanned separately: the case for -M -R."""
    subnet_a = [
        host("10.10.10.5", "gw01.corp.local",
             [port(22, svc=SSH_OLD, scripts=[HOSTKEY]),
              port(23, svc=service("telnet", "Cisco IOS telnetd")),
              port(161, proto="udp", svc=service("snmp", "net-snmp SNMPv3 server"))],
             CISCO, distance=1, mac="00:1A:2B:3C:4D:5E", vendor="Cisco Systems"),
        host("10.10.10.20", "fileserver.corp.local",
             [port(139, svc=service("netbios-ssn", "Samba smbd", "4.15.13")),
              port(445, svc=service("microsoft-ds", "Samba smbd", "4.15.13",
                                    "workgroup: CORP"),
                   scripts=[script("smb2-security-mode",
                                   "3.1.1:\n  Message signing enabled but not required")]),
              port(2049, svc=service("nfs", "Linux nfsd", "3-4")),
              port(22, svc=SSH, scripts=[HOSTKEY])],
             DEBIAN, distance=2, uptime=(1893600, "Tue Aug 12 09:14:02 2026")),
        host("10.10.10.31", "backup.corp.local",
             [port(873, svc=service("rsync", "rsync", "3.2.7", "protocol version 31")),
              port(22, svc=SSH),
              port(3306, state="filtered", svc=service("mysql"))],
             LINUX, distance=2),
        host("10.10.10.44", None,
             [port(9100, svc=service("jetdirect", "HP JetDirect")),
              port(631, svc=service("ipp", "CUPS", "2.4"))],
             distance=2, mac="00:11:22:33:44:55", vendor="Hewlett Packard"),
    ]
    subnet_b = [
        host("10.10.20.10", "app01.corp.local",
             [port(22, svc=SSH, scripts=[HOSTKEY]),
              port(8080, svc=service("http-proxy", "Apache Tomcat", "9.0.71")),
              port(5432, svc=service("postgresql", "PostgreSQL DB", "14.9")),
              port(6379, svc=service("redis", "Redis key-value store", "6.0.16"))],
             LINUX, distance=3, uptime=(432000, "Sun Aug 31 09:14:02 2026")),
        host("10.10.20.11", "app02.corp.local",
             [port(22, svc=SSH),
              port(8080, svc=service("http-proxy", "Apache Tomcat", "9.0.71")),
              port(9200, svc=service("elasticsearch", "Elasticsearch REST API", "7.17.9"))],
             LINUX, distance=3),
        host("10.10.20.50", "mon.corp.local",
             [port(22, svc=SSH),
              port(80, svc=service("http", "nginx", "1.18.0", "Ubuntu")),
              port(11211, svc=service("memcached", "Memcached", "1.6.14")),
              port(27017, svc=service("mongodb", "MongoDB", "5.0.14"))],
             LINUX, distance=3),
    ]
    write("corporate-lan/subnet-10.10.10.0.xml",
          document("nmap -sS -sV -O -oX subnet-10.10.10.0.xml 10.10.10.0/24",
                   subnet_a, 4, 254))
    write("corporate-lan/subnet-10.10.20.0.xml",
          document("nmap -sS -sV -O -oX subnet-10.10.20.0.xml 10.10.20.0/24",
                   subnet_b, 3, 254))


def dmz():
    """Web tier: the case for the URL target shape and TLS-aware risk."""
    cert = script("ssl-cert",
                  "Subject: commonName=*.corp.local/organizationName=Corp SA\n"
                  "Issuer: commonName=Corp Internal CA\n"
                  "Public Key type: rsa\nPublic Key bits: 2048\n"
                  "Not valid before: 2026-01-15T00:00:00\n"
                  "Not valid after:  2027-01-15T23:59:59")
    title = script("http-title", "Corp SA - Portal de clientes")
    headers = script("http-server-header", "nginx/1.24.0")

    hosts = [
        host("192.168.100.10", "www.corp.local",
             [port(80, svc=service("http", "nginx", "1.24.0", cpe=("cpe:/a:igor_sysoev:nginx:1.24.0",)),
                   scripts=[title, headers]),
              port(443, svc=service("https", "nginx", "1.24.0", tunnel="ssl"),
                   scripts=[cert, title]),
              port(22, state="filtered", svc=service("ssh"))],
             LINUX, distance=4),
        host("192.168.100.11", "api.corp.local",
             [port(443, svc=service("https", "Envoy", "1.28", tunnel="ssl"), scripts=[cert]),
              port(8443, svc=service("https-alt", "Envoy", "1.28", tunnel="ssl")),
              port(9901, svc=service("http", "Envoy admin"))],
             LINUX, distance=4),
        host("192.168.100.25", "legacy.corp.local",
             [port(80, svc=service("http", "Apache httpd", "2.2.15", "(CentOS)"),
                   scripts=[script("http-title", "Index of /")]),
              port(21, svc=service("ftp", "vsftpd", "2.3.4"),
                   scripts=[script("ftp-anon", "Anonymous FTP login allowed (FTP code 230)")]),
              port(3306, svc=service("mysql", "MySQL", "5.5.68-MariaDB"))],
             os_block("CentOS 6 (Linux 2.6.32)", "Linux", "Linux", "2.6.X",
                      "general purpose", 91),
             distance=4, uptime=(31536000, "Thu Sep  5 09:14:02 2025")),
        host("192.168.100.60", "mail.corp.local",
             [port(25, svc=service("smtp", "Postfix smtpd")),
              port(110, svc=service("pop3", "Dovecot pop3d")),
              port(143, svc=service("imap", "Dovecot imapd")),
              port(993, svc=service("imaps", "Dovecot imapd", tunnel="ssl")),
              port(587, svc=service("smtp", "Postfix smtpd"))],
             DEBIAN, distance=4),
    ]
    write("dmz/web-tier.xml",
          document("nmap -sS -sV -sC -oX web-tier.xml 192.168.100.0/24", hosts, 4, 254))


def windows_domain():
    """An AD segment: nearly everything here is high risk by design."""
    hosts = [
        host("10.30.0.10", "dc01.corp.local",
             [port(53, svc=service("domain", "Microsoft DNS", "6.1.7601")),
              port(88, svc=service("kerberos-sec", "Microsoft Windows Kerberos")),
              port(135, svc=service("msrpc", "Microsoft Windows RPC")),
              port(139, svc=service("netbios-ssn", "Microsoft Windows netbios-ssn")),
              port(389, svc=service("ldap", "Microsoft Windows Active Directory LDAP",
                                    extrainfo="Domain: corp.local")),
              port(445, svc=service("microsoft-ds", "Windows Server 2019 microsoft-ds"),
                   scripts=[script("smb2-security-mode",
                                   "3.1.1:\n  Message signing enabled and required")]),
              port(636, svc=service("ldapssl", tunnel="ssl")),
              port(3268, svc=service("ldap", "Microsoft Windows AD LDAP")),
              port(3389, svc=service("ms-wbt-server", "Microsoft Terminal Services"),
                   scripts=[script("rdp-ntlm-info",
                                   "Target_Name: CORP\nNetBIOS_Domain_Name: CORP\n"
                                   "DNS_Domain_Name: corp.local\nProduct_Version: 10.0.17763")]),
              port(5985, svc=service("wsman", "Microsoft HTTPAPI httpd", "2.0"))],
             WIN2019, distance=2),
        host("10.30.0.11", "sql01.corp.local",
             [port(135, svc=service("msrpc", "Microsoft Windows RPC")),
              port(445, svc=service("microsoft-ds", "Windows Server 2019 microsoft-ds")),
              port(1433, svc=service("ms-sql-s", "Microsoft SQL Server 2019", "15.00.2000")),
              port(3389, svc=service("ms-wbt-server", "Microsoft Terminal Services")),
              port(5985, svc=service("wsman", "Microsoft HTTPAPI httpd", "2.0"))],
             WIN2019, distance=2),
        host("10.30.0.55", "ws-042.corp.local",
             [port(135, svc=service("msrpc", "Microsoft Windows RPC")),
              port(139, svc=service("netbios-ssn", "Microsoft Windows netbios-ssn")),
              port(445, svc=service("microsoft-ds", "Microsoft Windows 10 microsoft-ds")),
              port(5900, svc=service("vnc", "VNC", "protocol 3.8")),
              port(3389, state="filtered", svc=service("ms-wbt-server"))],
             WIN10, distance=3),
        host("10.30.0.99", "print01.corp.local",
             [port(135, svc=service("msrpc", "Microsoft Windows RPC")),
              port(445, svc=service("microsoft-ds", "Windows Server 2019 microsoft-ds")),
              port(9100, svc=service("jetdirect"))],
             WIN2019, distance=2),
    ]
    write("windows-domain/ad-segment.xml",
          document("nmap -sS -sV -sC -O -oX ad-segment.xml 10.30.0.0/24", hosts, 4, 254))


def single_host_deep():
    """One host with everything -sC -A can produce: the drawer's showcase."""
    scripts = [
        HOSTKEY,
        script("ssl-cert",
               "Subject: commonName=jump.lab.local\nIssuer: commonName=Lab CA\n"
               "Not valid after:  2026-11-30T23:59:59"),
        script("http-methods", "Supported Methods: GET HEAD POST OPTIONS"),
        script("http-robots.txt", "2 disallowed entries\n/admin\n/backup"),
        script("vulners", "cpe:/a:openbsd:openssh:8.9p1:\n"
                          "  CVE-2023-38408  9.8  https://vulners.com/cve/CVE-2023-38408"),
    ]
    target = host(
        "192.168.56.101", "jump.lab.local",
        [port(22, svc=SSH, scripts=[scripts[0], scripts[4]]),
         port(80, svc=service("http", "Apache httpd", "2.4.52", "(Ubuntu)"),
              scripts=[scripts[2], scripts[3]]),
         port(443, svc=service("ssl/http", "Apache httpd", "2.4.52", tunnel="ssl"),
              scripts=[scripts[1]]),
         port(3000, svc=service("http", "Node.js Express framework")),
         port(5432, svc=service("postgresql", "PostgreSQL DB", "14.9")),
         port(8000, svc=service("http", "SimpleHTTPServer", "0.6", "Python 3.10.12")),
         port(111, svc=service("rpcbind", "2-4", "RPC #100000")),
         port(631, state="closed", svc=service("ipp")),
         port(5000, state="filtered", svc=service("upnp"))],
        LINUX,
        mac="08:00:27:AB:CD:EF", vendor="Oracle VirtualBox virtual NIC",
        distance=1, uptime=(864000, "Tue Aug 26 09:14:02 2026"),
        trace=[("0.42", "192.168.56.1", "gateway.lab.local"),
               ("0.51", "192.168.56.101", "jump.lab.local")])
    write("single-host-deep.xml",
          document("nmap -A -p- -oX single-host-deep.xml 192.168.56.101",
                   [target], 1, 1, numservices=65535, services="1-65535"))


def masscan_compatible():
    """nmap-compatible output from another scanner: needs --no-validate."""
    hosts = [
        host("10.40.0.7", None, [port(443, reason="syn-ack")], closed=0),
        host("10.40.0.19", None, [port(80, reason="syn-ack"),
                                  port(8080, reason="syn-ack")], closed=0),
        host("10.40.0.23", None, [port(22, reason="syn-ack")], closed=0),
    ]
    write("other-scanners/masscan.xml",
          document("masscan -p22,80,443,8080 10.40.0.0/24 -oX masscan.xml",
                   hosts, 3, 254, scanner="masscan", version="1.3.2",
                   startstr="Fri Sep  5 09:20:00 2026"))


if __name__ == "__main__":
    print("writing examples:")
    corporate_lan()
    dmz()
    windows_domain()
    single_host_deep()
    masscan_compatible()
