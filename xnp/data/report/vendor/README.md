# Vendored third-party assets

## chart.umd.js

- Library: Chart.js
- Version: 4.5.1
- Source: https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.js
- sha256: ecc3cd1eeb8c34d2178e3f59fd63ec5a3d84358c11730af0b9958dc886d7652a
- Licence: MIT (c) Chart.js Contributors

It is vendored, not fetched at runtime, because the HTML report has to open
from a USB stick on an air-gapped laptop three years from now.  Refresh it by
downloading the same path at a newer version and updating the hash above.

## fonts/plex-*.woff2

- Family: IBM Plex Sans (400, 500, 600) and IBM Plex Mono (400, 500)
- Version: 5.2.6, latin subset
- Source: https://cdn.jsdelivr.net/fontsource/fonts/ibm-plex-{sans,mono}@5.2.6/latin-<weight>-normal.woff2
- Licence: SIL Open Font License 1.1 (c) IBM Corp.

Inlined as data: URIs at render time by `xnp.html_report`.  A report that falls
back to the reader's system fonts still works, but the type is most of the
design, so the faces travel with it rather than being fetched.
