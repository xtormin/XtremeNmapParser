# The HTML report

The long version. [← Back to the README](../README.md) · [Español](html-report.es.md)

```bash
xnp -f scan.xml -oF html
```

## Copying targets out

On the **Services** tab, each group of open ports copies in the shape the next
tool wants:

| Shape | What you get |
| --- | --- |
| `host:port` | `10.0.0.14:445`, one per line — for most tooling's `-iL` |
| IP only | deduplicated addresses, one per line |
| `URL` | `https://web01.corp.local:8443` — HTTP services only, scheme inferred from the TLS tunnel and the port, hostname preferred over the address |
| `nmap` | a ready `nmap -sV -sC -p <ports> <hosts>` line for the group |

*Download every target* writes every group to one file with a comment header per
group. *Detail* on any row jumps to it in the table with its side panel open.

## The table

Every field nmap produced, sortable columns, and an Excel-style filter on every
column header. Click the `▾` and you get a searchable list of the values
actually present, each with its count; *Only those shown* turns whatever the
search box matched into a filter in one click. Counts in a column always exclude
that column's own filter, so a menu shows what you could still pick rather than
only what you already picked. Active filters appear as chips above the table and
clear individually.

Clicking a row slides out a side panel with the whole record: why the row carries
its interest label, port and service detail, host detail, OS matches, CPEs, the
other ports on the same host as clickable chips, the raw NSE output and the
traceroute. `↑` `↓` walk the rows without closing it, `Esc` closes it.

## The query bar

```
state:open service:http port<1024 -interest:low
ip=10.0.0.14 script:smb
"Apache Tomcat"
```

Type a field and `:` and it offers the values that are actually in this scan,
with their counts — `port:` lists the ports found, `service:` the services
identified, and so on for `ip` `host` `proto` `state` `reason` `product`
`version` `os` `family` `interest` `tag` `cleartext` `source`. `↑` `↓` `Enter`
to pick, and a value containing spaces comes back quoted for you. `cpe`
`script` and `extrainfo` are searched as free text rather than picked from a
list.

Operators: `:` (contains) `=` (exact) `<` `<=` `>` `>=` `!=`; prefix `-`
negates; a bare word searches the whole row. The query and the column filters
compose, and they apply to all three tabs at once — narrow to
`interest:high -state:closed` on Data and the Services tab hands you target
lists for exactly that set. *Export selection to CSV* saves what you are
currently looking at.

## Several scans in one report

```bash
xnp -d nmap/ -oF html
```

Walks the folder recursively, merges every scan into a single report and
deduplicates hosts and ports across files, keeping whichever scan identified the
most service detail. The header says how many files went in, and the table grows
a *Source* column — with its own filter — so you can still tell which scan a row
came from. `--no-merger` gives you one report per XML instead, and
`--no-recursive` keeps the walk at the top level.

## The interest label and the tags

Every open port gets an interest level — high / medium / low — and a set of tags
saying what kind of thing it is: *database*, *unauthenticated*, *cleartext
credentials*, *remote administration*, and a dozen more. Both come from a lookup keyed on **both** the
port number and the service name, so a database moved off its default port is
still caught once `-sV` has named it (see `HIGH_INTEREST_PORTS` in
[report_model.py](../xnp/report_model.py)).

The tags are what make a hundred rows summarisable: the Summary tab charts them,
clicking one filters to it, and `tag:` in the query bar completes them. The
sentence behind each tag stays in the side panel, so you can always see *why* a
port was flagged — and disagree with it.

**It is called interest, not risk, on purpose.** The lookup reads only the port
number, the service name, and whether TLS wraps it. It does not read the
version, the CVE history, the NSE output, whether the host faces the internet,
or even whether the port is open — a `filtered` 3306 is still labelled high,
because the label describes what that protocol is, not what this host is exposed
to. It says what deserves a look; it does not say what is vulnerable.

## Language

A selector next to the theme toggle switches between Spanish and English.
Whoever opens the report decides, and their choice is remembered in
`localStorage`; `--lang` only sets where a reader who has not chosen yet
starts, and the browser's own language is the last resort. Both languages are
always inside the file, so the selector never runs out of anything.

Nothing is baked into the markup, and a test fails the build if a hard-coded
string sneaks back in. That includes the reasons behind each label, which are
translated at the source (`report_model.py` holds `(english, spanish)` pairs)
rather than left in whichever language the source file happens to be written
in.

The terminal follows `--lang` too, with one deliberate exception: **error
messages stay in English**, along with `--help`. An error is the string you
paste into an issue or search for verbatim, so it is worth keeping in one
language even when everything around it is translated.

Set the two titles in `config.yaml`:

```yaml
html:
  title: "Informe de superficie de red"
  title_en: "Network exposure report"
```

## Theming and colour

The report follows the reader's system theme and remembers an explicit choice.
`Ctrl+P` prints a clean copy with both tabs expanded and the interactive chrome
hidden.

Colour carries meaning here, so it is constrained rather than decorative. Red,
amber and green belong to the interest level and the port state; the accent is
cyan precisely so that "you can click this" never looks like "this is
dangerous". Ink is a soft charcoal rather than pure black, and the dark theme
sets body text in a soft grey rather than pure white — full contrast over full
contrast buzzes on a page this dense.

Every text pair in both themes clears WCAG AA at 4.5:1, and every UI boundary,
status dot and chart series clears 3:1 —
[test_report_contrast.py](../tests/test_report_contrast.py) reads the tokens
straight out of the shipped stylesheet and fails the build if a future tweak
drops below that.

IBM Plex Sans and IBM Plex Mono (SIL OFL 1.1) are vendored as latin woff2
subsets and inlined as data URIs, adding about 140 KB per report. The type is
most of the design, so the faces travel with the file: a report that needs a CDN
to look right is a report that stops looking right.
