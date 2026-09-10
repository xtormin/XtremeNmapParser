# Example scans

Synthetic nmap output for trying XNP out without running a scan first. Every
address is RFC 1918 and every hostname sits under a non-routable `.local`
domain: **nothing here refers to a real host**, and none of it was produced by
scanning anything.

They are shaped to exercise different parts of the tool rather than to be
realistic in bulk — between them they cover OS detection, NSE output (plain and
structured), TLS-wrapped services, UDP, filtered and closed ports, hosts with no
reverse DNS, MAC vendors, traceroute and uptime.

| File | Hosts | What it is for |
| --- | --- | --- |
| `corporate-lan/subnet-10.10.10.0.xml` | 4 | Flat internal segment: file server, backup, a printer with no hostname, a Cisco gateway with telnet open |
| `corporate-lan/subnet-10.10.20.0.xml` | 3 | Application tier: Tomcat, PostgreSQL, Redis, Elasticsearch, MongoDB, Memcached |
| `dmz/web-tier.xml` | 4 | Web-facing hosts — the one to use for the `URL` target shape, TLS-aware risk and `ssl-cert` output |
| `windows-domain/ad-segment.xml` | 4 | A domain controller, a SQL server, a workstation and a print server: SMB, RDP, LDAP, Kerberos, WinRM |
| `single-host-deep.xml` | 1 | One host scanned with `-A -p-`: OS matches, traceroute, uptime, MAC vendor and five NSE scripts. The one to open the side panel on |
| `other-scanners/masscan.xml` | 3 | nmap-compatible output from masscan. **Needs `--no-validate`** — see below |

## Try it

The HTML report, on the host with the most detail in it:

```bash
xnp -f examples/single-host-deep.xml -oF html --show
```

Two subnets merged into one report, which is where the `Origen` column and the
deduplication show up:

```bash
xnp -d examples/corporate-lan/ -oF html -oN /tmp/lan --show
```

Everything at once, recursively:

```bash
xnp -d examples/ -oF html -oN /tmp/all --show
```

That one warns that `other-scanners/masscan.xml` was skipped and carries on with
the rest. Add `--no-validate` to include it too.

Only what is open, as a spreadsheet:

```bash
xnp -d examples/windows-domain/ --open -C all -oF xlsx -oN /tmp/ad
```

Once a report is open, things worth trying:

- Click the `445/tcp` bar on the Resumen tab — you land on Datos filtered to
  that port and protocol.
- Type `service:` in the query bar and it offers the services present in *this*
  scan, with counts.
- On the Servicios tab, expand `microsoft-ds` and copy its targets as
  `host:puerto`, or expand `http` and copy them as URLs.
- Click any row for the side panel: `single-host-deep.xml` is the one with
  traceroute and NSE output to look at.

## About `--no-validate`

XNP validates input against the bundled `nmap.dtd`, and that DTD pins
`scanner="nmap"`. `other-scanners/masscan.xml` is legitimate nmap-compatible
output from a different tool, so it fails validation by design — it is here so
you can see that failure and the flag that gets past it.

In a directory run that failure is a warning, not the end of the run: the file
is named, skipped, and everything else still gets parsed. With `-f` it stops,
because there you named that one file and there is nothing else to do.

## Regenerating these

They are committed as static files. `scripts/generate_examples.py` rebuilds
them if you want to extend the set:

```bash
python3 scripts/generate_examples.py
```
