/* XNP HTML report -- interaction layer.
 *
 * Everything downstream of the payload is recomputed from the *filtered* set
 * of ports, so a KPI, a chart slice and a table row can never disagree.
 *
 * Security note: service banners, script output and hostnames all come from
 * the scanned target and are therefore attacker controlled.  Nothing in this
 * file interpolates them into innerHTML without going through esc().
 */
(function () {
  "use strict";

  var DATA = window.XNP_DATA;
  var HOSTS = DATA.hosts || [];

  // --- helpers -------------------------------------------------------------

  function esc(value) {
    if (value === null || value === undefined) return "";
    return String(value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function el(id) { return document.getElementById(id); }

  /** Levels are stored language-neutral and shown in the reader's language. */
  function levelLabel(level) {
    return level ? t("level." + level) : "";
  }

  function dash(value) { return (value === null || value === undefined || value === "") ? "—" : value; }

  function counter(list, key) {
    var map = new Map();
    list.forEach(function (item) {
      var k = key(item);
      if (k === null || k === undefined || k === "") return;
      map.set(k, (map.get(k) || 0) + 1);
    });
    return map;
  }

  /** Like counter(), but a row contributes one count per element it carries. */
  function multiCounter(list, key) {
    var map = new Map();
    list.forEach(function (item) {
      (key(item) || []).forEach(function (value) {
        if (value === null || value === undefined || value === "") return;
        map.set(value, (map.get(value) || 0) + 1);
      });
    });
    return map;
  }

  function topN(map, n) {
    return Array.from(map.entries()).sort(function (a, b) {
      return b[1] - a[1] || String(a[0]).localeCompare(String(b[0]));
    }).slice(0, n);
  }

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  // --- Language -------------------------------------------------------------
  //
  // The report is bilingual because the person running the scan and the person
  // reading the findings are often not the same person, and not always in the
  // same language.  Every string the reader can see lives here.

  var I18N = {
    es: {
      "tab.summary": "Resumen", "tab.targets": "Servicios", "tab.data": "Datos",
      "theme.dark": "◐ Oscuro", "theme.light": "◑ Claro",
      "q.placeholder": "state:open service:http port<1024   ( / para enfocar )",
      "q.rows": "{n} / {total} filas",
      "btn.clear": "Limpiar",
      "hint": "Escribe un campo y <code>:</code> y te sugiere los valores compatibles con lo que ya has escrito. Las cifras y las gráficas también filtran al pulsarlas (<code>↑</code> <code>↓</code> y <code>Enter</code>). Operadores <code>=</code> <code>&lt;</code> <code>&gt;</code> <code>!=</code>, prefijo <code>-</code> para negar, y una palabra suelta busca en toda la fila.",
      "kpi.hosts": "Hosts", "kpi.hosts.sub": "{n} con puertos abiertos",
      "kpi.open": "Puertos abiertos", "kpi.open.sub": "{n} puertos en total",
      "kpi.services": "Servicios distintos", "kpi.services.sub": "identificados por -sV",
      "kpi.cleartext": "Sin cifrar", "kpi.cleartext.sub": "puertos que no cifran el tráfico",
      "tag.cleartext-creds": "credenciales en claro",
      "tag.cleartext-data": "tráfico sin cifrar",
      "tag.remote-admin": "administración remota",
      "tag.database": "base de datos",
      "tag.file-share": "ficheros compartidos",
      "tag.no-auth": "sin autenticación",
      "tag.enumeration": "enumerable",
      "tag.directory": "directorio",
      "tag.oob-management": "gestión fuera de banda",
      "tag.known-target": "objetivo recurrente",
      "tag.code-exec": "ejecución de código",
      "tag.container": "contenedores",
      "tag.display": "display remoto",
      "tag.amplification": "amplificador UDP",
      "tag.web": "web",
      "tag.mail": "correo",
      "tag.dns": "dns",
      "chart.tags": "Categorías de exposición",
      "col.tags": "Motivos",
      "chart.states": "Estados de puerto",
      "chart.services": "Servicios más expuestos", "chart.ports": "Puertos más abiertos",
      "chart.hosts": "Hosts más expuestos", "chart.os": "Sistemas operativos",
      "chart.clickToFilter": "clic para filtrar",
      "targets.groupBy": "Agrupar por", "targets.exportAll": "Descargar todos los objetivos",
      "targets.summary": "{groups} grupos · {hosts} hosts · {ports} puertos abiertos",
      "targets.hint": "Solo puertos abiertos. Despliega un grupo y copia sus objetivos en el formato que espere la siguiente herramienta.",
      "targets.copyAs": "Copiar objetivos como", "targets.copied": "copiado",
      "targets.empty": "Ningún puerto abierto en la selección actual.",
      "targets.unidentified": "sin identificar", "targets.detail": "detalle",
      "targets.hosts": "hosts", "targets.ports": "puertos",
      "shape.hostport": "host:puerto", "shape.ip": "solo IP",
      "shape.url": "URL", "shape.nmap": "nmap",
      "rescan.profile": "Reescanear con", "rescan.custom": "personalizado",
      "rescan.argsPlaceholder": "-sV --script vuln -Pn",
      "rescan.hint": "nmap {args} — solo puertos abiertos de la selección, agrupados por firma",
      "rescan.copyAll": "Copiar {n} comandos nmap",
      "rescan.copyOne": "Copiar 1 comando nmap",
      "rescan.copyNone": "Nada abierto que reescanear",
      "rescan.vars": "Variables: $[IP] $[HOSTNAME] $[PORTS] $[TCP_PORTS] $[UDP_PORTS] "
        + "— $[IP] y $[HOSTNAME] generan un comando por host",
      "rescan.unknownVars": "{names} se deja tal cual: las variables son {known}",
      "group.service": "Servicio", "group.product": "Producto", "group.num": "Puerto",
      "group.ip": "Host", "group.osFamily": "Sistema operativo",
      "table.hint": "▾ en cada columna para filtrar · clic en una fila abre el detalle · ↑ ↓ recorre · Esc cierra",
      "table.resize": "Arrastra para cambiar el ancho · doble clic ajusta al contenido",
      "table.csv": "Exportar selección a CSV",
      "table.empty": "Ninguna fila cumple el filtro actual.",
      "table.capped": "Mostrando {shown} de {total} filas. Afina el filtro o exporta a CSV para verlas todas.",
      "col.ip": "IP", "col.hostname": "Hostname", "col.num": "Puerto", "col.protocol": "Proto",
      "col.state": "Estado", "col.service": "Servicio", "col.product": "Producto",
      "col.version": "Versión", "col.extrainfo": "Extrainfo", "col.interest": "Interés",
      "level.high": "alto", "level.medium": "medio", "level.low": "bajo",
      "col.os": "SO", "col.sourceName": "Origen",
      "filters.label": "Filtros:", "filters.clearAll": "Quitar todos",
      "filters.values": "{n} valores",
      "fm.search": "Buscar valor…", "fm.all": "Todos", "fm.only": "Solo los mostrados",
      "fm.unfiltered": "sin filtrar", "fm.selected": "{n} seleccionados",
      "fm.noMatch": "Ningún valor coincide con «{q}».",
      "sg.field": "campo", "sg.value": "valor", "sg.freeText": "texto libre",
      "drawer.close": "Cerrar el detalle", "drawer.noPorts": "sin puertos",
      "drawer.why": "Marcado como interés {level}",
      "drawer.portService": "Puerto y servicio", "drawer.host": "Host",
      "drawer.os": "Sistema operativo", "drawer.otherPorts": "Otros puertos de este host",
      "drawer.nse": "Salida NSE", "drawer.trace": "Traceroute",
      "f.port": "Puerto", "f.state": "Estado", "f.ttl": "TTL", "f.service": "Servicio",
      "f.product": "Producto", "f.version": "Versión", "f.extrainfo": "Extrainfo",
      "f.tunnel": "Túnel", "f.method": "Detección", "f.conf": "Confianza",
      "f.ostype": "Tipo de SO", "f.devicetype": "Dispositivo", "f.owner": "Propietario",
      "f.cpe": "CPE", "f.ip": "IP", "f.ipv6": "IPv6", "f.hostname": "Hostname",
      "f.mac": "MAC", "f.vendor": "Fabricante", "f.distance": "Saltos",
      "f.lastboot": "Último arranque", "f.source": "Origen",
      "meta.hosts": "hosts", "meta.files": "ficheros", "meta.nmap": "nmap",
      "foot.generated": "Generado por Xtreme Nmap Parser {v} el {d}",
      "foot.repo": "Código y novedades",
      "export.header": "# {title} -- agrupado por {by}",
      "export.generated": "# generado por xnp {v} el {d}",
      "blank": "(vacío)",
      "lang.select": "Idioma / Language",
      "a11y.suggestions": "Sugerencias",
      "a11y.hint_toggle": "Cómo se busca",
      "a11y.filter_menu": "Filtro de columna",
      "a11y.drawer": "Detalle de la fila seleccionada",
      "a11y.scanList": "Comando de nmap de cada fichero"
    },
    en: {
      "tab.summary": "Summary", "tab.targets": "Services", "tab.data": "Data",
      "theme.dark": "◐ Dark", "theme.light": "◑ Light",
      "q.placeholder": "state:open service:http port<1024   ( / to focus )",
      "q.rows": "{n} / {total} rows",
      "btn.clear": "Clear",
      "hint": "Type a field and <code>:</code> and it offers the values that fit what you have typed so far. The figures and charts filter on click too (<code>↑</code> <code>↓</code> and <code>Enter</code>). Operators <code>=</code> <code>&lt;</code> <code>&gt;</code> <code>!=</code>, prefix <code>-</code> to negate, and a bare word searches the whole row.",
      "kpi.hosts": "Hosts", "kpi.hosts.sub": "{n} with open ports",
      "kpi.open": "Open ports", "kpi.open.sub": "{n} ports in total",
      "kpi.services": "Distinct services", "kpi.services.sub": "identified by -sV",
      "kpi.cleartext": "Cleartext", "kpi.cleartext.sub": "ports that do not encrypt traffic",
      "tag.cleartext-creds": "cleartext credentials",
      "tag.cleartext-data": "unencrypted traffic",
      "tag.remote-admin": "remote administration",
      "tag.database": "database",
      "tag.file-share": "file sharing",
      "tag.no-auth": "unauthenticated",
      "tag.enumeration": "enumerable",
      "tag.directory": "directory",
      "tag.oob-management": "out-of-band management",
      "tag.known-target": "recurrent target",
      "tag.code-exec": "code execution",
      "tag.container": "containers",
      "tag.display": "remote display",
      "tag.amplification": "UDP amplifier",
      "tag.web": "web",
      "tag.mail": "mail",
      "tag.dns": "dns",
      "chart.tags": "Exposure categories",
      "col.tags": "Reasons",
      "chart.states": "Port states",
      "chart.services": "Most exposed services", "chart.ports": "Most open ports",
      "chart.hosts": "Most exposed hosts", "chart.os": "Operating systems",
      "chart.clickToFilter": "click to filter",
      "targets.groupBy": "Group by", "targets.exportAll": "Download every target",
      "targets.summary": "{groups} groups · {hosts} hosts · {ports} open ports",
      "targets.hint": "Open ports only. Expand a group and copy its targets in the shape the next tool expects.",
      "targets.copyAs": "Copy targets as", "targets.copied": "copied",
      "targets.empty": "No open ports in the current selection.",
      "targets.unidentified": "unidentified", "targets.detail": "detail",
      "targets.hosts": "hosts", "targets.ports": "ports",
      "shape.hostport": "host:port", "shape.ip": "IP only",
      "shape.url": "URL", "shape.nmap": "nmap",
      "rescan.profile": "Rescan with", "rescan.custom": "custom",
      "rescan.argsPlaceholder": "-sV --script vuln -Pn",
      "rescan.hint": "nmap {args} — open ports in the selection only, grouped by signature",
      "rescan.copyAll": "Copy {n} nmap commands",
      "rescan.copyOne": "Copy 1 nmap command",
      "rescan.copyNone": "Nothing open to rescan",
      "rescan.vars": "Variables: $[IP] $[HOSTNAME] $[PORTS] $[TCP_PORTS] $[UDP_PORTS] "
        + "— $[IP] and $[HOSTNAME] give one command per host",
      "rescan.unknownVars": "{names} left as typed: the variables are {known}",
      "group.service": "Service", "group.product": "Product", "group.num": "Port",
      "group.ip": "Host", "group.osFamily": "Operating system",
      "table.hint": "▾ on any column to filter · click a row for its detail · ↑ ↓ to walk · Esc to close",
      "table.resize": "Drag to resize · double-click to fit the content",
      "table.csv": "Export selection to CSV",
      "table.empty": "No row matches the current filter.",
      "table.capped": "Showing {shown} of {total} rows. Narrow the filter or export to CSV to see them all.",
      "col.ip": "IP", "col.hostname": "Hostname", "col.num": "Port", "col.protocol": "Proto",
      "col.state": "State", "col.service": "Service", "col.product": "Product",
      "col.version": "Version", "col.extrainfo": "Extrainfo", "col.interest": "Interest",
      "level.high": "high", "level.medium": "medium", "level.low": "low",
      "col.os": "OS", "col.sourceName": "Source",
      "filters.label": "Filters:", "filters.clearAll": "Clear all",
      "filters.values": "{n} values",
      "fm.search": "Search value…", "fm.all": "All", "fm.only": "Only those shown",
      "fm.unfiltered": "unfiltered", "fm.selected": "{n} selected",
      "fm.noMatch": "No value matches \u201c{q}\u201d.",
      "sg.field": "field", "sg.value": "value", "sg.freeText": "free text",
      "drawer.close": "Close the detail", "drawer.noPorts": "no ports",
      "drawer.why": "Flagged {level} interest",
      "drawer.portService": "Port and service", "drawer.host": "Host",
      "drawer.os": "Operating system", "drawer.otherPorts": "Other ports on this host",
      "drawer.nse": "NSE output", "drawer.trace": "Traceroute",
      "f.port": "Port", "f.state": "State", "f.ttl": "TTL", "f.service": "Service",
      "f.product": "Product", "f.version": "Version", "f.extrainfo": "Extrainfo",
      "f.tunnel": "Tunnel", "f.method": "Detection", "f.conf": "Confidence",
      "f.ostype": "OS type", "f.devicetype": "Device", "f.owner": "Owner",
      "f.cpe": "CPE", "f.ip": "IP", "f.ipv6": "IPv6", "f.hostname": "Hostname",
      "f.mac": "MAC", "f.vendor": "Vendor", "f.distance": "Hops",
      "f.lastboot": "Last boot", "f.source": "Source",
      "meta.hosts": "hosts", "meta.files": "files", "meta.nmap": "nmap",
      "foot.generated": "Generated by Xtreme Nmap Parser {v} on {d}",
      "foot.repo": "Source and releases",
      "export.header": "# {title} -- grouped by {by}",
      "export.generated": "# generated by xnp {v} on {d}",
      "blank": "(empty)",
      "lang.select": "Idioma / Language",
      "a11y.suggestions": "Suggestions",
      "a11y.hint_toggle": "How to search",
      "a11y.filter_menu": "Column filter",
      "a11y.drawer": "Detail of the selected row",
      "a11y.scanList": "The nmap command of each file"
    }
  };

  /**
   * The reader wins, then the run, then the browser.
   *
   * `DATA.lang` is what --lang asked for when the report was generated: it is a
   * *default*, so a reader who has already picked a language in the selector
   * keeps theirs.  Falling through to navigator.language matters for a report
   * generated on a machine whose locale says nothing about who reads it.
   */
  function preferredLang() {
    try {
      var saved = localStorage.getItem("xnp-lang");
      if (I18N[saved]) return saved;
    } catch (err) { /* private mode: fall through to the run, then the browser */ }
    if (I18N[DATA.lang]) return DATA.lang;
    return (navigator.language || "en").toLowerCase().indexOf("es") === 0 ? "es" : "en";
  }

  var lang = preferredLang();

  /** Look up a string, filling {placeholders} from `vars`. */
  function t(key, vars) {
    var text = (I18N[lang] && I18N[lang][key]);
    if (text === undefined) text = I18N.en[key];
    if (text === undefined) return key;
    if (!vars) return text;
    return text.replace(/\{(\w+)\}/g, function (whole, name) {
      return Object.prototype.hasOwnProperty.call(vars, name) ? vars[name] : whole;
    });
  }

  /** The report title travels in both languages; the reader picks. */
  function reportTitle() {
    return (lang === "en" ? DATA.title_en : DATA.title) || DATA.title || "";
  }

  function applyStaticText() {
    document.documentElement.setAttribute("lang", lang);
    document.title = reportTitle();
    document.querySelectorAll("[data-i18n]").forEach(function (node) {
      node.textContent = t(node.getAttribute("data-i18n"));
    });
    document.querySelectorAll("[data-i18n-html]").forEach(function (node) {
      node.innerHTML = t(node.getAttribute("data-i18n-html"));
    });
    document.querySelectorAll("[data-i18n-ph]").forEach(function (node) {
      node.setAttribute("placeholder", t(node.getAttribute("data-i18n-ph")));
    });
    document.querySelectorAll("[data-i18n-aria]").forEach(function (node) {
      node.setAttribute("aria-label", t(node.getAttribute("data-i18n-aria")));
    });
    el("lang-select").value = lang;
    // The theme button carries a word, so it has to follow the language too.
    var theme = document.documentElement.getAttribute("data-theme");
    el("theme-btn").textContent = theme === "dark" ? t("theme.light") : t("theme.dark");
    renderMeta();
  }

  /** Header chips: built here rather than in Python so they can be translated. */
  function renderMeta() {
    var scans = DATA.scans || [];
    var chips = [];
    function chip(label, value) {
      if (!value) return;
      chips.push('<span class="chip">' + (label ? "<b>" + esc(label) + "</b> " : "") +
                 esc(value) + "</span>");
    }

    if (scans.length === 1) {
      chip(t("meta.nmap"), scans[0].version);
      chip("", scans[0].startstr);
      chip("$", scans[0].args);
    } else if (scans.length) {
      // Several files means several command lines, and they do not fit in a
      // chip -- the count opens the list that carries one command per file.
      chips.push('<button type="button" id="scans-toggle" aria-controls="scan-list"' +
                 ' class="chip chip-btn' + (state.scansOpen ? " on" : "") + '"' +
                 ' aria-expanded="' + (state.scansOpen ? "true" : "false") + '">' +
                 "<b>" + esc(t("meta.files")) + "</b> " + scans.length + "</button>");
      var versions = [];
      scans.forEach(function (scan) {
        if (scan.version && versions.indexOf(scan.version) === -1) versions.push(scan.version);
      });
      chip(t("meta.nmap"), versions.join(", "));
    }
    chip(t("meta.hosts"), String((DATA.hosts || []).length));
    el("meta").innerHTML = chips.join("");
    renderScanList();

    el("brand-title").textContent = reportTitle();
    el("foot-generated").textContent = t("foot.generated",
      { v: DATA.xnp_version, d: DATA.generated_at });
  }

  /**
   * The list behind the "files" chip: which arguments produced which file.
   * Only a multi-file report has it; a single scan shows its command in a chip.
   */
  function renderScanList() {
    var scans = DATA.scans || [];
    var box = el("scan-list");
    if (scans.length < 2) {
      box.innerHTML = "";
      box.hidden = true;
      return;
    }
    box.innerHTML = scans.map(function (scan) {
      // The full path goes in the tooltip: the rows line up on the basename,
      // and a directory run of a deep tree would push the command off-screen.
      var name = scan.file ? String(scan.file).split(/[\\/]/).pop() : blank();
      // The name filters the table down to that file, the way every other
      // value in the report drills: it is the same field as the Origen column.
      var file = scan.file
        ? '<button type="button" class="scan-file" data-source="' + esc(scan.file) + '"' +
          ' title="' + esc(scan.file) + '">' + esc(name) + "</button>"
        : '<span class="scan-file">' + esc(name) + "</span>";
      return '<div class="scan-row">' + file +
        '<span class="scan-when">' + esc(scan.startstr || "") + "</span>" +
        '<code class="scan-args">' + esc(scan.args || blank()) + "</code></div>";
    }).join("");
    box.hidden = !state.scansOpen;
  }

  function showScans(open) {
    state.scansOpen = !!open;
    var toggle = el("scans-toggle");
    el("scan-list").hidden = !open;
    if (toggle) {
      toggle.setAttribute("aria-expanded", String(!!open));
      toggle.classList.toggle("on", !!open);
    }
  }

  function showHint(open) {
    el("hint").hidden = !open;
    el("hint-toggle").setAttribute("aria-expanded", String(!!open));
    el("hint-toggle").classList.toggle("on", !!open);
    try { localStorage.setItem("xnp-hint", open ? "1" : "0"); } catch (err) { /* private mode */ }
  }

  function setLang(next) {
    if (!I18N[next]) return;
    var wasBlank = blank();
    lang = next;
    try { localStorage.setItem("xnp-lang", next); } catch (err) { /* nothing to do */ }
    // Column filters store the value they matched on, and the empty-cell
    // marker is one of those values.  Without this, filtering on "(vacío)" and
    // then switching to English would silently match nothing.
    renameFilterValue(wasBlank, blank());
    applyStaticText();
    // The "custom" entry and the hint are written by hand rather than through
    // a data-i18n attribute, so applyStaticText does not reach them.
    syncRescanBar();
    closeSuggestions();
    render();
    if (state.selected !== null) syncDrawer();
  }

  // --- row model -----------------------------------------------------------
  // One row per host/port pair.  A host with no ports still gets a row so that
  // "up but fully filtered" hosts do not silently vanish from the report.

  var ROWS = [];
  HOSTS.forEach(function (host, hostIndex) {
    host._i = hostIndex;
    if (!host.ports.length) {
      ROWS.push(makeRow(host, null));
      return;
    }
    host.ports.forEach(function (port) { ROWS.push(makeRow(host, port)); });
  });

  function makeRow(host, port) {
    var service = (port && port.service) || {};
    var scriptText = port ? port.scripts.map(function (s) {
      return s.id + " " + (s.output || "");
    }).join("\n") : "";
    var row = {
      host: host,
      port: port,
      ip: host.ip,
      hostname: host.hostname,
      hostState: host.state,
      num: port ? port.port : null,
      protocol: port ? port.protocol : null,
      state: port ? port.state : null,
      reason: port ? port.reason : null,
      service: service.name || null,
      product: service.product || null,
      version: service.version || null,
      extrainfo: service.extrainfo || null,
      tunnel: service.tunnel || null,
      cpe: (service.cpe || []).join(" "),
      os: host.os.best || null,
      osFamily: host.os.family || null,
      interest: port ? port.interest : "low",
      tags: port ? (port.tags || []) : [],
      cleartext: port ? port.cleartext : false,
      scripts: scriptText,
      source: host.source,
      // The basename is what fits in a column; the drawer shows the full path.
      sourceName: host.source ? String(host.source).split(/[\\/]/).pop() : null
    };
    row.blob = [row.ip, row.hostname, row.num, row.protocol, row.state, row.service,
      row.product, row.version, row.extrainfo, row.os, row.cpe, row.scripts,
      row.source, row.tags.join(" ")].join(" ").toLowerCase();
    return row;
  }

  // --- query language ------------------------------------------------------
  // Terms are ANDed.  `-` negates.  Bare words match anywhere in the row.
  //   state:open  service:http  port<1024  port>=8000  -state:closed  nginx

  var FIELDS = {
    ip: "ip", host: "hostname", hostname: "hostname", name: "hostname",
    port: "num", proto: "protocol", protocol: "protocol",
    state: "state", reason: "reason",
    service: "service", svc: "service",
    product: "product", version: "version", extrainfo: "extrainfo",
    os: "os", family: "osFamily", interest: "interest", cpe: "cpe",
    script: "scripts", nse: "scripts", source: "source", file: "source",
    // The "sin cifrar" figure had no way to say itself in the query language,
    // so clicking it could not fill the bar like every other drill-down.
    cleartext: "cleartext", tag: "tags", tags: "tags"
  };

  var TERM_RE = /^(-?)([a-z]+)(>=|<=|!=|[:=<>])(.*)$/i;

  function parseQuery(text) {
    var terms = [];
    var tokens = (text || "").match(/(?:[^\s"]+|"[^"]*")+/g) || [];
    tokens.forEach(function (token) {
      var negate = false;
      var match = TERM_RE.exec(token);
      if (match && FIELDS[match[2].toLowerCase()]) {
        // "service:" on its own is a half-typed term, not a search for that
        // literal text.  Ignoring it until it has a value is what keeps the
        // table from collapsing to nothing the moment you open the suggestions.
        if (!match[4]) return;
        negate = match[1] === "-";
        terms.push(buildTerm(FIELDS[match[2].toLowerCase()], match[3], unquote(match[4]), negate));
        return;
      }
      if (token[0] === "-" && token.length > 1) { negate = true; token = token.slice(1); }
      var needle = unquote(token).toLowerCase();
      if (!needle) return;
      terms.push({ negate: negate, test: function (row) { return row.blob.indexOf(needle) !== -1; } });
    });
    return terms;
  }

  function unquote(value) {
    return value.replace(/^"(.*)"$/, "$1");
  }

  function buildTerm(field, op, rawValue, negate) {
    var numeric = field === "num";
    var value = numeric ? parseInt(rawValue, 10) : rawValue.toLowerCase();

    return {
      negate: negate,
      test: function (row) {
        var actual = row[field];
        if (actual === null || actual === undefined) return false;

        // A row carries several tags at once, so a term matches if any of them
        // does -- "=" against one whole tag, ":" inside one.
        if (Array.isArray(actual)) {
          return actual.some(function (item) {
            item = String(item).toLowerCase();
            if (op === "=") return item === value;
            if (op === "!=") return item.indexOf(value) === -1;
            return item.indexOf(value) !== -1;
          });
        }

        if (numeric) {
          if (isNaN(value)) return false;
          switch (op) {
            case "<": return actual < value;
            case "<=": return actual <= value;
            case ">": return actual > value;
            case ">=": return actual >= value;
            case "!=": return actual !== value;
            default: return actual === value;
          }
        }
        actual = String(actual).toLowerCase();
        if (op === "=") return actual === value;
        if (op === "!=") return actual.indexOf(value) === -1;
        return actual.indexOf(value) !== -1;
      }
    };
  }

  function runQuery(rows, terms) {
    if (!terms.length) return rows;
    return rows.filter(function (row) {
      for (var i = 0; i < terms.length; i++) {
        var hit = terms[i].test(row);
        if (terms[i].negate ? hit : !hit) return false;
      }
      return true;
    });
  }

  // --- state ---------------------------------------------------------------

  var state = {
    query: "",
    terms: [],
    filters: {},          // column key -> Set of chosen cell values
    sort: { key: "ip", dir: 1 },
    selected: null,       // id of the row shown in the side panel
    menu: null,           // key of the column whose filter menu is open
    groupBy: "service",   // how the Servicios tab buckets the open ports
    openGroups: new Set(),
    scansOpen: false,     // the per-file command list under the footer chips
    rescanProfile: "",    // which set of nmap arguments the nmap shape uses
    rescanArgs: "",       // typed by hand when the profile is "custom"
    colWidths: {}         // column key -> pinned width in px, once resized
  };

  /** Recomputed on every language change: it shows in filters and in the CSV. */
  function blank() { return t("blank"); }

  /** Carry a chosen filter value across a rename, keeping the selection alive. */
  function renameFilterValue(from, to) {
    if (from === to) return;
    Object.keys(state.filters).forEach(function (key) {
      var chosen = state.filters[key];
      if (chosen && chosen.has(from)) {
        chosen.delete(from);
        chosen.add(to);
      }
    });
  }

  /** The value a column filter matches on: never null, always a string. */
  function cellValue(row, key) {
    var value = row[key];
    return (value === null || value === undefined || value === "") ? blank() : String(value);
  }

  function facetMatch(row, skip) {
    var keys = Object.keys(state.filters);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (key === skip) continue;
      var chosen = state.filters[key];
      if (!chosen || !chosen.size) continue;
      if (!chosen.has(cellValue(row, key))) return false;
    }
    return true;
  }

  /** Rows passing everything (the query and every column filter). */
  function selected() {
    return runQuery(ROWS, state.terms).filter(function (row) {
      return facetMatch(row, null);
    });
  }

  /** Rows passing everything except one column's filter -- used for its counts. */
  function selectedExcept(group) {
    return runQuery(ROWS, state.terms).filter(function (row) {
      return facetMatch(row, group);
    });
  }

  // --- rendering: KPIs -----------------------------------------------------

  function renderKpis(rows) {
    var ports = rows.filter(function (r) { return r.num !== null; });
    var open = ports.filter(function (r) { return r.state === "open"; });
    var hosts = new Set(rows.map(function (r) { return r.ip; }));
    var hostsWithOpen = new Set(open.map(function (r) { return r.ip; }));
    var cleartext = open.filter(function (r) { return r.cleartext; });
    var services = new Set(open.map(function (r) { return r.service; }).filter(Boolean));

    // `terms` makes a figure clickable, and only the figures that can actually
    // say themselves in the query language get it: "hosts" and "distinct
    // services" are counts of a projection, not a subset you can filter to.
    var items = [
      { label: t("kpi.hosts"), value: hosts.size, sub: t("kpi.hosts.sub", { n: hostsWithOpen.size }) },
      { label: t("kpi.open"), value: open.length, sub: t("kpi.open.sub", { n: ports.length }),
        terms: [["state", "open"]] },
      { label: t("kpi.services"), value: services.size, sub: t("kpi.services.sub") },
      { label: t("kpi.cleartext"), value: cleartext.length, sub: t("kpi.cleartext.sub"),
        cls: cleartext.length ? "is-medium" : "",
        terms: [["state", "open"], ["cleartext", "true"]] }
    ];

    el("kpis").innerHTML = items.map(function (item, index) {
      var tag = item.terms ? "button" : "div";
      return "<" + tag + ' class="kpi ' + (item.cls || "") +
        (item.terms ? " clickable" : "") + '"' +
        (item.terms ? ' data-kpi="' + index + '" type="button"' : "") + ">" +
        '<div class="label">' + esc(item.label) + "</div>" +
        '<div class="value">' + esc(item.value) + "</div>" +
        '<div class="sub">' + esc(item.sub) + "</div></" + tag + ">";
    }).join("");

    KPI_TERMS = items.map(function (item) { return item.terms || null; });
  }

  //: Filled by renderKpis so the click handler can find the terms by index.
  var KPI_TERMS = [];

  /** A short label for a chart axis: the host part of a FQDN, else the IP. */
  function shortLabel(hostname, ip) {
    var label = hostname ? String(hostname).split(".")[0] : ip;
    if (!label) return ip || "?";
    return label.length > 16 ? label.slice(0, 15) + "\u2026" : label;
  }

  // --- rendering: charts ---------------------------------------------------

  var charts = {};

  function drawChart(id, config) {
    if (charts[id]) charts[id].destroy();
    var canvas = el(id);
    if (!canvas) return;
    charts[id] = new Chart(canvas.getContext("2d"), config);
  }

  function clip(text, max) {
    text = String(text);
    return text.length > max ? text.slice(0, max - 1) + "\u2026" : text;
  }

  /* Clicking a mark drills into it.
   *
   * An entry is [value, count, label]: the value is what the filter needs, the
   * label is what fits on an axis.  Keeping them apart matters -- the host
   * chart shows "host07" for 10.20.30.7, and filtering on the truncated label
   * would match nothing. */

  /* A drill-down writes into the query bar rather than setting a hidden
   * filter, because the bar is the surface you can then edit: click "ssh",
   * see `service=ssh`, and add `-state:closed` to it without starting over.
   * Exact match, not contains: clicking "http" should not drag in
   * "http-proxy" as well. */

  function drillTo(spec, value) {
    if (value === null || value === undefined || value === blank()) return;
    var terms = typeof spec === "function" ? spec(value) : [[spec, String(value)]];
    if (!terms || !terms.length) return;
    // render() destroys and rebuilds every chart, including the one whose
    // click handler we are standing in; let the event finish dispatching first.
    setTimeout(function () { applyTerms(terms); }, 0);
  }

  /** The ports chart buckets on "443/tcp", which is two terms' worth. */
  function drillToPort(value) {
    var parts = String(value).split("/");
    var terms = [["port", parts[0]]];
    if (parts[1]) terms.push(["proto", parts[1]]);
    return terms;
  }

  /** Replace any term already naming these fields, then append the new ones. */
  function applyTerms(terms) {
    var text = el("q").value;
    var replaced = {};
    terms.forEach(function (term) {
      var property = FIELDS[term[0]];
      if (property) replaced[property] = true;
    });

    var kept = tokenSpans(text)
      .map(function (span) { return text.slice(span.start, span.end); })
      .filter(function (token) {
        var match = TOKEN_SPLIT.exec(token);
        if (!match) return true;
        var property = FIELDS[match[2].toLowerCase()];
        return !property || !replaced[property];
      });

    terms.forEach(function (term) {
      kept.push(term[0] + "=" + quoteIfNeeded(term[1]));
    });

    setQuery(kept.join(" "));
    showTab("data");
  }

  function clickable(entries, spec) {
    return {
      onClick: function (event, elements) {
        if (!elements.length) return;
        var entry = entries[elements[0].index];
        if (entry) drillTo(spec, entry[0]);
      },
      onHover: function (event, elements) {
        event.native.target.style.cursor = elements.length ? "pointer" : "default";
      }
    };
  }

  /** A legend entry stands for the same slice, so it drills the same way. */
  function legendDrill(entries, spec) {
    return function (event, item) {
      var entry = entries[item.index];
      if (entry) drillTo(spec, entry[0]);
    };
  }

  function labelOf(entry) { return clip(entry.length > 2 ? entry[2] : entry[0], 22); }

  function barConfig(entries, color, spec) {
    var handlers = clickable(entries, spec);
    return {
      type: "bar",
      data: {
        labels: entries.map(labelOf),
        datasets: [{ data: entries.map(function (e) { return e[1]; }), backgroundColor: color, borderRadius: 3 }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        onClick: handlers.onClick,
        onHover: handlers.onHover,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { footer: function () { return t("chart.clickToFilter"); } } }
        },
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: cssVar("--grid") } },
          y: { grid: { display: false }, ticks: { autoSkip: false, crossAlign: "far" } }
        }
      }
    };
  }

  function doughnutConfig(entries, colors, spec) {
    var handlers = clickable(entries, spec);
    return {
      type: "doughnut",
      data: {
        labels: entries.map(function (e) { return String(labelOf(e)); }),
        datasets: [{ data: entries.map(function (e) { return e[1]; }), backgroundColor: colors, borderWidth: 0 }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "58%",
        onClick: handlers.onClick,
        onHover: handlers.onHover,
        plugins: {
          legend: {
            position: "right",
            labels: { boxWidth: 10, boxHeight: 10, padding: 10, usePointStyle: false },
            // The default toggles a slice's visibility, which would put the
            // chart out of step with every other number on the page.
            onClick: legendDrill(entries, spec)
          },
          tooltip: { callbacks: { footer: function () { return t("chart.clickToFilter"); } } }
        }
      }
    };
  }

  function renderCharts(rows) {
    var ports = rows.filter(function (r) { return r.num !== null; });
    var open = ports.filter(function (r) { return r.state === "open"; });

    Chart.defaults.color = cssVar("--text-2");
    Chart.defaults.borderColor = cssVar("--grid");
    Chart.defaults.font.family = cssVar("--sans") || "sans-serif";
    Chart.defaults.font.size = 11;

    var stateEntries = topN(counter(ports, function (r) { return r.state; }), 6);
    drawChart("chart-states", doughnutConfig(stateEntries, stateEntries.map(function (e) {
      if (e[0] === "open") return cssVar("--open");
      if (e[0] === "filtered") return cssVar("--filtered");
      return cssVar("--closed");
    }), "state"));

    var serviceEntries = topN(counter(open, function (r) { return r.service; }), 10);
    drawChart("chart-services", barConfig(serviceEntries, cssVar("--chart-1"), "service"));

    var portEntries = topN(counter(open, function (r) { return r.num + "/" + r.protocol; }), 10);
    drawChart("chart-ports", barConfig(portEntries, cssVar("--chart-2"), drillToPort));

    var tagEntries = topN(multiCounter(open, function (r) { return r.tags; }), 12)
      .map(function (e) { return [e[0], e[1], t("tag." + e[0])]; });
    drawChart("chart-tags", barConfig(tagEntries, cssVar("--chart-1"), "tag"));

    var osEntries = topN(counter(rows, function (r) { return r.osFamily; }), 8);
    drawChart("chart-os", barConfig(osEntries, cssVar("--chart-3"), "family"));

    // Keyed on the address, labelled with the short name: the label is lossy.
    var hostCounts = counter(open, function (r) { return r.ip; });
    var hostLabels = new Map();
    open.forEach(function (r) { hostLabels.set(r.ip, shortLabel(r.hostname, r.ip)); });
    var hostEntries = topN(hostCounts, 10).map(function (e) {
      return [e[0], e[1], hostLabels.get(e[0]) || e[0]];
    });
    drawChart("chart-hosts", barConfig(hostEntries, cssVar("--chart-1"), "ip"));

    // An empty pair of axes reads as "nothing was scanned" rather than
    // "nothing here matches your filter"; hide the card instead.
    toggleChartCard("card-states", stateEntries.length);
    toggleChartCard("card-tags", tagEntries.length);
    toggleChartCard("card-services", serviceEntries.length);
    toggleChartCard("card-ports", portEntries.length);
    toggleChartCard("card-hosts", hostEntries.length);
    toggleChartCard("card-os", osEntries.length);
  }

  function toggleChartCard(id, hasData) {
    var card = el(id);
    if (card) card.style.display = hasData ? "" : "none";
  }

  // --- Query autocomplete ---------------------------------------------------
  //
  // Suggestions come from the scan itself: typing "port:" offers the ports that
  // are actually in this report, with their counts.  A filter language whose
  // vocabulary you have to guess is a filter language nobody uses.

  //: [token as typed, row property, can its values be suggested?]
  //  Free-text fields are excluded: a CPE string or a block of NSE output is
  //  something you search inside, not something you pick off a list.
  var SUGGEST_FIELDS = [
    ["ip", "ip", true], ["host", "hostname", true], ["port", "num", true],
    ["proto", "protocol", true], ["state", "state", true], ["reason", "reason", true],
    ["service", "service", true], ["product", "product", true],
    ["version", "version", true], ["os", "os", true], ["family", "osFamily", true],
    ["interest", "interest", true], ["source", "sourceName", true],
    ["cleartext", "cleartext", true], ["tag", "tags", true],
    ["extrainfo", "extrainfo", false], ["cpe", "cpe", false], ["script", "scripts", false]
  ];

  /* Suggestions come from the rows the rest of the query has already narrowed
   * to, not from the whole scan.  After `ip:10.30.0.10`, `service:` offers the
   * services on that host; after `service:ssh`, `ip:` offers the hosts running
   * it.  A menu that offers values yielding zero rows is a menu that wastes a
   * keystroke to find that out. */

  var suggestCache = { key: null, rows: [], values: {} };

  function filtersSignature() {
    return Object.keys(state.filters).sort().map(function (key) {
      return key + "=" + Array.from(state.filters[key]).sort().join(",");
    }).join(";");
  }

  /** Rows matching everything except the term currently under the caret. */
  function contextFor(token) {
    var text = el("q").value;
    var without = (text.slice(0, token.start) + text.slice(token.end)).trim();
    var key = without + "\u0000" + filtersSignature();

    // Typing more of a value does not change the context, so the row scan is
    // done once per context rather than once per keystroke.
    if (suggestCache.key !== key) {
      var terms = parseQuery(without);
      suggestCache = {
        key: key,
        rows: runQuery(ROWS, terms).filter(function (row) { return facetMatch(row, null); }),
        values: {}
      };
    }
    return suggestCache;
  }

  function valuesFor(context, property) {
    if (!context.values[property]) {
      var counts = property === "tags"
        ? multiCounter(context.rows, function (row) { return row.tags; })
        : counter(context.rows, function (row) {
            var value = row[property];
            return (value === null || value === undefined || value === "") ? null : String(value);
          });
      var entries = Array.from(counts.entries());
      if (property === "num") {
        entries.sort(function (a, b) { return parseInt(a[0], 10) - parseInt(b[0], 10); });
      } else {
        entries.sort(function (a, b) {
          return b[1] - a[1] || String(a[0]).localeCompare(String(b[0]), undefined, { numeric: true });
        });
      }
      context.values[property] = entries;
    }
    return context.values[property];
  }

  /** Token spans of the query, so a quoted value counts as one token. */
  function tokenSpans(text) {
    var spans = [];
    var start = -1;
    var quoted = false;
    for (var i = 0; i <= text.length; i++) {
      var ch = text[i];
      if (ch === '"') quoted = !quoted;
      var isBreak = (i === text.length) || (ch === " " && !quoted);
      if (isBreak) {
        if (start !== -1) { spans.push({ start: start, end: i }); start = -1; }
      } else if (start === -1) {
        start = i;
      }
    }
    return spans;
  }

  function tokenAt(text, caret) {
    var spans = tokenSpans(text);
    for (var i = 0; i < spans.length; i++) {
      if (caret >= spans[i].start && caret <= spans[i].end) {
        return { start: spans[i].start, end: spans[i].end,
                 text: text.slice(spans[i].start, spans[i].end) };
      }
    }
    return { start: caret, end: caret, text: "" };
  }

  var TOKEN_SPLIT = /^(-?)([a-z]+)(>=|<=|!=|[:=<>])(.*)$/i;

  function suggestionsFor(token) {
    var negate = "";
    var raw = token.text;
    var context = contextFor(token);
    var match = TOKEN_SPLIT.exec(raw);

    if (match) {
      negate = match[1];
      var field = SUGGEST_FIELDS.filter(function (f) {
        return f[0] === match[2].toLowerCase();
      })[0];
      if (!field) return [];
      if (!field[2]) return [];
      var op = match[3];
      var partial = match[4].replace(/^"/, "").toLowerCase();
      var isTag = field[1] === "tags";
      return valuesFor(context, field[1])
        .filter(function (entry) {
          var text = String(entry[0]).toLowerCase();
          if (text.indexOf(partial) !== -1) return true;
          // Tag slugs are English; let the reader search by the label they see.
          return isTag && t("tag." + entry[0]).toLowerCase().indexOf(partial) !== -1;
        })
        .slice(0, 12)
        .map(function (entry) {
          return { insert: negate + field[0] + op + quoteIfNeeded(entry[0]),
                   label: String(entry[0]), count: entry[1],
                   kind: isTag ? t("tag." + entry[0]) : t("sg.value") };
        });
    }

    if (raw[0] === "-") { negate = "-"; raw = raw.slice(1); }
    var prefix = raw.toLowerCase();
    return SUGGEST_FIELDS
      .filter(function (f) { return f[0].indexOf(prefix) === 0; })
      .slice(0, 12)
      .map(function (f) {
        return { insert: negate + f[0] + ":", label: f[0] + ":",
                 count: f[2] ? valuesFor(context, f[1]).length : null,
                 kind: f[2] ? t("sg.field") : t("sg.freeText") };
      });
  }

  function quoteIfNeeded(value) {
    value = String(value);
    return /[\s"]/.test(value) ? '"' + value.replace(/"/g, "") + '"' : value;
  }

  var ac = { items: [], index: -1, token: null };

  function renderSuggestions() {
    var box = el("suggest");
    if (!ac.items.length) { box.hidden = true; return; }
    box.hidden = false;
    box.innerHTML = ac.items.map(function (item, i) {
      return '<button class="sg' + (i === ac.index ? " on" : "") + '" data-i="' + i + '">' +
        '<span class="sg-label">' + esc(item.label) + "</span>" +
        '<span class="sg-kind">' + esc(item.kind) + "</span>" +
        (item.count === null ? "" : '<span class="sg-n">' + item.count + "</span>") +
        "</button>";
    }).join("");
  }

  function updateSuggestions() {
    var input = el("q");
    ac.token = tokenAt(input.value, input.selectionStart);
    ac.items = suggestionsFor(ac.token);
    ac.index = ac.items.length ? 0 : -1;
    renderSuggestions();
  }

  function closeSuggestions() {
    ac.items = [];
    ac.index = -1;
    el("suggest").hidden = true;
  }

  function acceptSuggestion(index) {
    var item = ac.items[index];
    if (!item) return;
    var input = el("q");
    var value = input.value;
    // A field name leaves the caret ready for its value; a value ends the term.
    var trailing = item.insert.slice(-1) === ":" || /[<>=]$/.test(item.insert) ? "" : " ";
    var next = value.slice(0, ac.token.start) + item.insert + trailing + value.slice(ac.token.end);
    input.value = next;
    var caret = ac.token.start + item.insert.length + trailing.length;
    input.setSelectionRange(caret, caret);
    input.focus();

    state.query = input.value;
    state.terms = parseQuery(input.value);
    render();
    updateSuggestions();
  }

  // --- Targets: grouping and hand-off --------------------------------------
  //
  // This is what the report is for.  A scan is only worth anything once it
  // turns into "these are the hosts running this service, here is the list, go
  // test them", so every group hands its targets over in the shapes the next
  // tool actually wants: bare addresses, host:port, or URLs.

  var GROUP_KEYS = ["service", "product", "num", "ip", "osFamily"];

  //: Services reachable over HTTP, so a target list can be handed over as URLs.
  var HTTP_SERVICES = {
    http: "http", "http-alt": "http", "http-proxy": "http", https: "https",
    "https-alt": "https", "ssl/http": "https", "http-mgmt": "http"
  };

  function urlFor(row) {
    var scheme = HTTP_SERVICES[(row.service || "").toLowerCase()];
    if (!scheme) return null;
    if (row.tunnel === "ssl" || row.num === 443 || row.num === 8443) scheme = "https";
    var host = row.hostname || row.ip;
    var isDefault = (scheme === "http" && row.num === 80) || (scheme === "https" && row.num === 443);
    return scheme + "://" + host + (isDefault ? "" : ":" + row.num);
  }

  // --- Targeted rescan ------------------------------------------------------
  //
  // A port list in nmap applies to every target of the invocation, so one
  // command over a whole group would probe ports most of its hosts do not
  // have.  The fix is to group by port signature: hosts whose open ports are
  // exactly the same set share a command, and nobody gets a port they lack.
  //
  // This is a port of xnp/rescan.py.  KEEP THE TWO IN SYNC -- the rules about
  // scan types, -6 and address validation are the same on both sides, and the
  // Python one is the one with tests.

  //: The profiles come from the reader's config.yaml, through the payload.  The
  //: fallback only matters for a payload built without a configuration.
  var RESCAN = (DATA.rescan && DATA.rescan.profiles && DATA.rescan.profiles.length)
    ? DATA.rescan
    : { "default": "service",
        profiles: [{ id: "service", args: "-sV -sC --version-all -Pn" }] };

  var CUSTOM_PROFILE = "__custom__";
  var PORT_SPEC_FLAGS = ["-p", "--top-ports", "--exclude-ports", "--exclude-port"];
  //: $[NAME] in the arguments: ours to replace, bracketed to tell it from an
  //: environment variable.  Nothing here reaches a shell unresolved, so the
  //: box needs no quoting rules.  Mirrors rescan.py.
  var VARIABLE_RE = /\$\[([A-Za-z_][A-Za-z0-9_]*)\]/g;
  var PER_HOST_VARIABLES = ["IP", "HOSTNAME"];
  var TCP_SCAN_TYPES = ["-sS", "-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX"];
  var INCOMPATIBLE_SCANS = ["-sn", "-sL", "-sP", "-sO", "-sY", "-sZ"];

  //: An nmap command is a shell line, and its addresses came out of a scanned
  //: host's XML, where addr is CDATA.  Anything that is not an address is
  //: dropped rather than escaped.  Mirrors rescan.address_family().
  function addressFamily(address) {
    var value = String(address === null || address === undefined ? "" : address);
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
      return value.split(".").every(function (octet) {
        return Number(octet) <= 255;
      }) ? "ipv4" : "";
    }
    // Conservative on purpose: hex groups and colons, at least one colon, and
    // a trailing IPv4 tail allowed for ::ffff:10.0.0.1.
    if (value.length <= 45 && value.indexOf(":") !== -1 &&
        /^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(\.\d{1,3}){0,3}$/.test(value)) return "ipv6";
    return "";
  }

  //: A hostname reaches a shell line and a file name and comes from the XML:
  //: what is not one of these characters is dropped, not escaped.
  //: Mirrors rescan.safe_hostname().
  function safeHostname(name) {
    var cleaned = String(name === null || name === undefined ? "" : name)
      .replace(/[^A-Za-z0-9._-]/g, "").replace(/^[.-]+/, "").replace(/[.-]+$/, "");
    return cleaned.slice(0, 253);
  }

  function addressKey(address) {
    if (address.indexOf(":") !== -1) return address;
    return address.split(".").reduce(function (acc, octet) {
      return acc * 256 + Number(octet);
    }, 0);
  }

  /** Bucket rows into groups that share a port signature. */
  function signatureGroups(rows) {
    var perHost = new Map();
    rows.forEach(function (row) {
      if (row.num === null) return;
      var protocol = String(row.protocol || "").toLowerCase();
      if (protocol !== "tcp" && protocol !== "udp") return;
      var family = addressFamily(row.ip);
      if (!family) return;
      var port = Number(row.num);
      if (!(port > 0 && port < 65536)) return;
      var key = family + "|" + row.ip;
      if (!perHost.has(key)) {
        perHost.set(key, { family: family, ip: row.ip, name: "",
                           tcp: new Set(), udp: new Set() });
      }
      var host = perHost.get(key);
      host[protocol].add(port);
      // Rows of one address can carry different names; the smallest wins, so
      // the same selection always produces the same command.
      var name = safeHostname(row.hostname);
      if (name && (!host.name || name < host.name)) host.name = name;
    });

    function sortedPorts(set) {
      return Array.from(set).sort(function (a, b) { return a - b; });
    }

    var signatures = new Map();
    perHost.forEach(function (host) {
      var tcp = sortedPorts(host.tcp), udp = sortedPorts(host.udp);
      var key = host.family + "|" + tcp.join(",") + "|" + udp.join(",");
      if (!signatures.has(key)) {
        signatures.set(key, { family: host.family, tcp: tcp, udp: udp,
                              hosts: [], names: [] });
      }
      signatures.get(key).hosts.push(host);
    });

    var groups = Array.from(signatures.values());
    groups.forEach(function (group) {
      // Sorted as host objects, then split into the two parallel arrays, so
      // names can never end up against the wrong address.
      group.hosts.sort(function (a, b) {
        var ka = addressKey(a.ip), kb = addressKey(b.ip);
        return ka < kb ? -1 : ka > kb ? 1 : 0;
      });
      group.names = group.hosts.map(function (host) { return host.name; });
      group.hosts = group.hosts.map(function (host) { return host.ip; });
    });
    groups.sort(function (a, b) {
      return b.hosts.length - a.hosts.length ||
        (b.tcp.length + b.udp.length) - (a.tcp.length + a.udp.length) ||
        String(a.hosts[0]).localeCompare(String(b.hosts[0]), undefined, { numeric: true });
    });
    return groups;
  }

  /** Tokenise like a shell, keeping the text as it was written.
   *
   * Each token comes back as { value, raw }: the value is what the flags are
   * matched against, the raw is what the author typed and what gets printed
   * back, so quotes they wrote survive.  Mirrors rescan.split_args().
   */
  //: The bare part is one character, not a run of them: (?:[^\s"']+)+ is a
  //: nested quantifier and backtracks exponentially, which here means a blown
  //: stack and a report that never finishes starting.
  var TOKEN_RE = /(?:"[^"]*"|'[^']*'|[^\s"']|["'])+/g;

  function splitArgs(text) {
    var raws = String(text || "").match(TOKEN_RE) || [];
    return raws.map(function (raw) {
      return {
        raw: raw,
        value: raw.replace(/"([^"]*)"|'([^']*)'/g, function (part, double, single) {
          return double !== undefined ? double : single;
        })
      };
    });
  }

  function quoteArg(token) {
    if (/^[A-Za-z0-9_@%+=:,.\/-]+$/.test(token)) return token;
    return "'" + token.replace(/'/g, "'\\''") + "'";
  }

  function portSpec(group) {
    var tcp = group.tcp.join(","), udp = group.udp.join(",");
    if (tcp && udp) return "T:" + tcp + ",U:" + udp;
    if (udp) return "U:" + udp;
    return tcp;
  }

  /** Split a profile into what it keeps and the TCP type it asked for.
   *
   * Ports, -6 and the scan types are the group's to decide, so they come out
   * here -- which is also what lets the bar's hint show what will actually be
   * run instead of echoing flags that are about to be dropped.
   * Mirrors rescan._split_profile().
   */
  function splitProfile(args) {
    var kept = [], tcpType = "", skipValue = false;
    splitArgs(args).forEach(function (token) {
      var value = token.value;
      if (skipValue) { skipValue = false; return; }
      if (PORT_SPEC_FLAGS.indexOf(value) !== -1) { skipValue = true; return; }
      if (value.indexOf("-p") === 0 && value.indexOf("--") !== 0 && value.length > 2) return;
      if (value === "-F" || value === "-6") return;
      if (INCOMPATIBLE_SCANS.indexOf(value) !== -1) return;
      if (TCP_SCAN_TYPES.indexOf(value) !== -1) { if (!tcpType) tcpType = value; return; }
      if (value === "-sU") return;
      kept.push(token);
    });
    return { kept: kept, tcpType: tcpType };
  }

  /** The host's name, falling back to its address.  Mirrors group.name_of(). */
  function nameOf(group, index) {
    if (!group.hosts.length) return "";
    var names = group.names || [];
    return names[index || 0] || group.hosts[index || 0];
  }

  /** What each variable stands for in this group.  Mirrors rescan._values(). */
  function variableValues(group) {
    return {
      IP: group.hosts.length ? group.hosts[0] : "",
      HOSTNAME: nameOf(group, 0),
      PORTS: portSpec(group),
      TCP_PORTS: group.tcp.join(","),
      UDP_PORTS: group.udp.join(",")
    };
  }

  /** Replace the $[...] of one token; an unknown name stays literal. */
  function substitute(token, group) {
    var values = variableValues(group);
    return String(token).replace(VARIABLE_RE, function (match, name) {
      return Object.prototype.hasOwnProperty.call(values, name) ? values[name] : match;
    });
  }

  //: Every variable an argument string may use.  Mirrors rescan.VARIABLES.
  var VARIABLES = PER_HOST_VARIABLES.concat(["PORTS", "TCP_PORTS", "UDP_PORTS"]);

  /** The $[...] names that are not ours -- left literal, named in the hint. */
  function unknownVariables(args) {
    var names = String(args || "").match(VARIABLE_RE) || [];
    var unknown = [];
    names.forEach(function (token) {
      var name = token.slice(2, -1);
      if (VARIABLES.indexOf(name) === -1 && unknown.indexOf(name) === -1) {
        unknown.push(name);
      }
    });
    return unknown;
  }

  function usesPerHostVariable(args) {
    var names = String(args || "").match(VARIABLE_RE) || [];
    return names.some(function (token) {
      return PER_HOST_VARIABLES.indexOf(token.slice(2, -1)) !== -1;
    });
  }

  /** One group per host when a variable names a single host.  Mirrors expand(). */
  function expandGroups(groups, args) {
    if (!usesPerHostVariable(args)) return groups;
    var expanded = [];
    groups.forEach(function (group) {
      group.hosts.forEach(function (host, index) {
        expanded.push({ family: group.family, tcp: group.tcp, udp: group.udp,
                        hosts: [host], names: [nameOf(group, index)] });
      });
    });
    return expanded;
  }

  /** One kept token, variables replaced, quoted as its author quoted it.
   *
   * Quotes someone wrote are kept: they may be load-bearing, and only the
   * person writing them knows whether the path has a space in it.  A bare
   * token is quoted only if it needs it.  Mirrors rescan.render_token().
   */
  function renderToken(token, group) {
    if (token.raw.indexOf('"') !== -1 || token.raw.indexOf("'") !== -1) {
      return substitute(token.raw, group);
    }
    return quoteArg(substitute(token.value, group));
  }

  /** The nmap line for one signature group.  Mirrors rescan.build_command(). */
  function nmapCommand(group, args) {
    var profile = splitProfile(args);
    var tcpType = profile.tcpType;
    // After the split, so a profile's flags are recognised as themselves: what
    // a variable expands to is a value, never a flag the generator reacts to.
    var kept = profile.kept.map(function (token) { return renderToken(token, group); });

    var parts = ["nmap"].concat(kept);
    if (group.family === "ipv6") parts.push("-6");
    // Only when needed: on a TCP-only group nmap's own choice beats forcing
    // sudo, but -sU without a TCP type makes it ignore the T: half of the spec.
    if (group.tcp.length && (group.udp.length || tcpType)) parts.push(tcpType || "-sS");
    if (group.udp.length) parts.push("-sU");
    parts.push("-p", portSpec(group));
    // The kept tokens are already quoted the way their author wrote them, and
    // what this function adds -- flags and a port spec -- never needs quoting.
    return parts.join(" ") + " " + group.hosts.join(" ");
  }

  /** Every command for a set of rows: group, expand, build.  Mirrors commands(). */
  function commandsFor(rows, args) {
    return expandGroups(signatureGroups(rows), args).map(function (group) {
      return nmapCommand(group, args);
    });
  }

  /** The arguments in force: a profile's, or what was typed for "custom". */
  function rescanArgs() {
    if (state.rescanProfile === CUSTOM_PROFILE) return state.rescanArgs;
    var chosen = RESCAN.profiles.filter(function (profile) {
      return profile.id === state.rescanProfile;
    })[0];
    return chosen ? chosen.args : "";
  }

  var TARGET_SHAPES = [
    { id: "hostport", build: function (rows) {
        return unique(rows.map(function (r) { return r.ip + ":" + r.num; })); } },
    { id: "ip", build: function (rows) {
        return unique(rows.map(function (r) { return r.ip; })); } },
    { id: "url", build: function (rows) {
        return unique(rows.map(urlFor).filter(Boolean)); } },
    // One command per port signature, so the badge counts commands.  No "#"
    // comment lines: they would make that count a lie, and the whole list goes
    // to the clipboard to be pasted straight into a shell.
    { id: "nmap", build: function (rows) {
        return commandsFor(rows, rescanArgs()); } }
  ];

  // --- Copying the filtered selection ---------------------------------------
  //
  // Servicios hands over one group at a time; here the unit is the whole
  // filtered set, which is what the query bar and the column filters have just
  // been used to arrive at.  The order is the table's own sort, so what lands
  // on the clipboard reads like what is on screen.

  var COPY_SHAPES = {
    // A host with no port at all (a host that answered but has nothing in the
    // scan) has nothing to say in this shape, so it is left out rather than
    // copied as "10.0.0.1:null".
    hostport: function (rows) {
      return unique(rows.filter(function (row) { return row.num !== null; })
        .map(function (row) { return row.ip + ":" + row.num; }));
    },
    ip: function (rows) {
      return unique(rows.map(function (row) { return row.ip; }));
    }
  };

  function copyShapeLines(id) {
    var build = COPY_SHAPES[id];
    return build ? build(sortRows(selected())) : [];
  }

  /** Each button says how many lines it would copy, recomputed with the table. */
  function syncCopyTargets() {
    Array.prototype.slice.call(document.querySelectorAll(".copy-shape"))
      .forEach(function (button) {
        var id = button.getAttribute("data-copy-shape");
        var count = copyShapeLines(id).length;
        button.innerHTML = esc(t("shape." + id)) +
          ' <span class="n">' + count + "</span>";
        button.disabled = count === 0;
      });
  }

  // --- The rescan bar -------------------------------------------------------
  //
  // The same control appears in Servicios and in Datos, because both tabs show
  // the same filtered set and either is a reasonable place to hand the
  // commands over.  There is one piece of state behind them; every bar is
  // written from it, so the two can never disagree.

  function rescanBars(selector) {
    return Array.prototype.slice.call(document.querySelectorAll(selector));
  }

  /** The commands for the current selection: what the copy button will give. */
  function rescanCommands() {
    return commandsFor(selected().filter(isOpen), rescanArgs());
  }

  /** Fill every profile selector from the payload, plus a free-text entry. */
  function fillRescanProfiles() {
    var wanted = RESCAN["default"];
    var known = RESCAN.profiles.some(function (profile) { return profile.id === wanted; });
    state.rescanProfile = known ? wanted : (RESCAN.profiles[0] || {}).id || CUSTOM_PROFILE;

    rescanBars(".rescan-profile").forEach(function (select) {
      // The names are the reader's, out of config.yaml, so they are escaped.
      select.innerHTML = RESCAN.profiles.map(function (profile) {
        return '<option value="' + esc(profile.id) + '">' + esc(profile.id) + "</option>";
      }).join("") + '<option value="' + CUSTOM_PROFILE + '"></option>';
      select.value = state.rescanProfile;
    });
    syncRescanBar();
  }

  /** Write the state into every bar: selection, free-text box, count, hint. */
  function syncRescanBar() {
    var custom = state.rescanProfile === CUSTOM_PROFILE;
    // What survives, not what was typed: the ports, -6 and the scan types are
    // the group's to decide, and promising them here would be a lie.
    var profile = splitProfile(rescanArgs());
    var kept = profile.kept.map(function (token) { return token.raw; })
      .concat(profile.tcpType ? [profile.tcpType] : []);
    var hint = kept.length ? t("rescan.hint", { args: kept.join(" ") }) : "";
    // A name that is not a variable is left in the command, so the line that
    // explains the command is where it gets named: there is no other way to
    // find out that $[HOST] was never going to become anything.
    var unknown = unknownVariables(rescanArgs());
    if (unknown.length) {
      hint = t("rescan.unknownVars", {
        names: unknown.map(function (name) { return "$[" + name + "]"; }).join(" "),
        known: VARIABLES.map(function (name) { return "$[" + name + "]"; }).join(" ")
      });
    }
    var count = rescanCommands().length;
    var label = count === 0 ? t("rescan.copyNone")
      : count === 1 ? t("rescan.copyOne") : t("rescan.copyAll", { n: count });

    rescanBars(".rescan-profile").forEach(function (select) {
      select.value = state.rescanProfile;
      // The custom entry's label is the only translated one; the rest are
      // profile names and stay as the reader wrote them.
      var last = select.options[select.options.length - 1];
      if (last && last.value === CUSTOM_PROFILE) last.textContent = t("rescan.custom");
    });
    rescanBars(".rescan-args").forEach(function (input) {
      input.hidden = !custom;
      // The variables are only discoverable if something names them, and the
      // box is where they would be typed.
      input.title = t("rescan.vars");
      // Never write into the box someone is typing in: a render landing
      // mid-word would take the word back, and mid-composition it would eat
      // an IME candidate.  The other copy still gets the value.
      if (input !== document.activeElement && input.value !== state.rescanArgs) {
        input.value = state.rescanArgs;
      }
    });
    rescanBars(".rescan-copy").forEach(function (button) {
      button.textContent = label;
      button.disabled = count === 0;
    });
    rescanBars(".rescan-hint").forEach(function (span) {
      // A named profile is described by its name; only hand-typed arguments
      // need a line saying which of them survived.
      span.textContent = hint;
      span.hidden = !custom || !hint;
    });
    // The named profiles get the same sentence, out of the way, on the button.
    rescanBars(".rescan-copy").forEach(function (button) { button.title = hint; });
  }

  /** Wire every bar to the one piece of state behind them. */
  function initRescanBars() {
    fillRescanProfiles();

    rescanBars(".rescan-profile").forEach(function (select) {
      select.addEventListener("change", function () {
        state.rescanProfile = select.value;
        syncRescanBar();
        renderGroups(selected());
      });
    });

    rescanBars(".rescan-args").forEach(function (input) {
      var pending;
      input.addEventListener("input", function () {
        // The state takes the keystroke at once; only the work it causes is
        // debounced.  Letting it lag would leave the two out of step for as
        // long as the timer runs, and any render in that window would win.
        state.rescanArgs = input.value;
        clearTimeout(pending);
        pending = setTimeout(function () {
          syncRescanBar();
          renderGroups(selected());
        }, 140);
      });
    });

    rescanBars(".rescan-copy").forEach(function (button) {
      button.addEventListener("click", function () {
        var commands = rescanCommands();
        if (!commands.length) return;
        // The feedback lives beside the unit in the toolbar, not inside it:
        // growing the control on click would shift what you just clicked.
        copyText(commands.join("\n"),
                 button.closest(".targets-bar, .table-tools")
                       .querySelector(".rescan-copied"));
      });
    });
  }

  function unique(values) {
    var seen = new Set();
    return values.filter(function (value) {
      if (value === null || value === undefined || value === "") return false;
      var key = String(value);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function groupRows(rows) {
    var key = state.groupBy;
    var map = new Map();
    rows.forEach(function (row) {
      if (row.num === null) return;
      var value = cellValue(row, key);
      if (!map.has(value)) map.set(value, []);
      map.get(value).push(row);
    });
    return Array.from(map.entries()).sort(function (a, b) {
      var openA = a[1].filter(isOpen).length, openB = b[1].filter(isOpen).length;
      return openB - openA || b[1].length - a[1].length ||
        String(a[0]).localeCompare(String(b[0]), undefined, { numeric: true });
    });
  }

  function isOpen(row) { return row.state === "open"; }

  function interestRank(rows) {
    if (rows.some(function (r) { return r.interest === "high"; })) return "high";
    if (rows.some(function (r) { return r.interest === "medium"; })) return "medium";
    return "low";
  }

  function renderGroups(rows) {
    var open = rows.filter(isOpen);
    var groups = groupRows(open);
    var box = el("groups");

    if (!groups.length) {
      box.innerHTML = '<p class="empty">' + esc(t("targets.empty")) + "</p>";
      el("groups-summary").textContent = "";
      return;
    }

    el("groups-summary").textContent = t("targets.summary", {
      groups: groups.length,
      hosts: unique(open.map(function (r) { return r.ip; })).length,
      ports: open.length
    });

    box.innerHTML = groups.map(function (entry) {
      var name = entry[0], groupRowsList = entry[1];
      var hosts = unique(groupRowsList.map(function (r) { return r.ip; }));
      var products = unique(groupRowsList.map(function (r) {
        return [r.product, r.version].filter(Boolean).join(" ");
      }));
      var expanded = state.openGroups.has(name);

      var head = '<button class="g-head" data-group="' + esc(name) + '" aria-expanded="' +
        expanded + '">' +
        '<span class="g-caret">' + (expanded ? "\u25be" : "\u25b8") + "</span>" +
        '<span class="g-name">' + esc(name) + "</span>" +
        '<span class="pill ' + esc(interestRank(groupRowsList)) + '">' +
        esc(levelLabel(interestRank(groupRowsList))) + "</span>" +
        '<span class="g-count"><b>' + hosts.length + "</b> " + esc(t("targets.hosts")) + "</span>" +
        '<span class="g-count"><b>' + groupRowsList.length + "</b> " + esc(t("targets.ports")) + "</span>" +
        '<span class="g-products">' +
        esc(products.slice(0, 3).join(" · ") || t("targets.unidentified")) +
        (products.length > 3 ? " +" + (products.length - 3) : "") + "</span></button>";

      return '<div class="group' + (expanded ? " open" : "") + '">' + head +
        (expanded ? groupBody(name, groupRowsList) : "") + "</div>";
    }).join("");
  }

  function groupBody(name, rows) {
    var shapes = TARGET_SHAPES.map(function (shape) {
      var lines = shape.build(rows);
      if (!lines.length) return "";
      return '<button class="shape" data-shape="' + esc(shape.id) + '" data-group="' +
        esc(name) + '">' + esc(t("shape." + shape.id)) +
        ' <span class="n">' + lines.length + "</span></button>";
    }).join("");

    var listing = rows.slice().sort(function (a, b) {
      return ipKey(a.ip) - ipKey(b.ip) || a.num - b.num;
    }).map(function (row) {
      var url = urlFor(row);
      var target = url || (row.ip + ":" + row.num);
      return '<li><code>' + esc(target) + "</code>" +
        (row.hostname ? '<span class="g-host">' + esc(row.hostname) + "</span>" : "") +
        (row.version ? '<span class="g-ver">' + esc([row.product, row.version].filter(Boolean).join(" ")) + "</span>" : "") +
        '<button class="g-open" data-goto-row="' + esc(rowId(row)) + '">' +
        esc(t("targets.detail")) + "</button></li>";
    }).join("");

    return '<div class="g-body">' +
      '<div class="g-actions"><span class="g-actions-label">' + esc(t("targets.copyAs")) +
      "</span>" + shapes +
      '<span class="g-copied" hidden>' + esc(t("targets.copied")) + "</span></div>" +
      '<ul class="g-list">' + listing + "</ul></div>";
  }

  // --- Excel-style column filters ------------------------------------------

  function filterEntries(key, search) {
    // Counts exclude this column's own filter, so a menu always shows what you
    // could still pick rather than only what you already picked.
    var counts = counter(selectedExcept(key), function (row) { return cellValue(row, key); });

    var entries = Array.from(counts.entries());
    (state.filters[key] || new Set()).forEach(function (chosen) {
      if (!counts.has(chosen)) entries.push([chosen, 0]);
    });

    if (search) {
      var needle = search.toLowerCase();
      entries = entries.filter(function (entry) {
        return String(entry[0]).toLowerCase().indexOf(needle) !== -1;
      });
    }

    var numeric = key === "num";
    entries.sort(function (a, b) {
      if (numeric) {
        var x = parseInt(a[0], 10), y = parseInt(b[0], 10);
        if (!isNaN(x) && !isNaN(y)) return x - y;
      }
      return b[1] - a[1] || String(a[0]).localeCompare(String(b[0]), undefined, { numeric: true });
    });
    return entries;
  }

  /** What a stored value looks like to the reader. */
  function displayValue(key, value) {
    if (key === "interest") return levelLabel(value) || value;
    if (key === "tags") return t("tag." + value);
    return value;
  }

  function renderFilterList() {
    var key = state.menu;
    if (!key) return;
    var search = el("fm-search").value.trim();
    var entries = filterEntries(key, search);
    var chosen = state.filters[key] || new Set();

    el("fm-list").innerHTML = entries.length
      ? entries.map(function (entry) {
          return '<label' + (entry[1] === 0 ? ' class="stale"' : "") + '>' +
            '<input type="checkbox" value="' + esc(entry[0]) + '"' +
            (chosen.has(entry[0]) ? " checked" : "") + ">" +
            '<span class="v">' + esc(displayValue(key, entry[0])) + "</span>" +
            '<span class="n">' + entry[1] + "</span></label>";
        }).join("")
      : '<p class="fm-empty">' + esc(t("fm.noMatch", { q: search })) + "</p>";

    el("fm-count").textContent = chosen.size
      ? t("fm.selected", { n: chosen.size })
      : t("fm.unfiltered");
    el("fm-only").disabled = !entries.length;
  }

  function openFilterMenu(key, anchor) {
    state.menu = key;
    el("fm-title").textContent = columnLabel(key);
    el("fm-search").value = "";
    renderFilterList();

    var menu = el("filter-menu");
    menu.hidden = false;

    // Anchor under the header cell, then pull it back inside the viewport.
    var box = anchor.getBoundingClientRect();
    var width = menu.offsetWidth;
    var left = Math.min(box.left, window.innerWidth - width - 8);
    menu.style.left = Math.max(8, left) + "px";
    menu.style.top = Math.min(box.bottom + 4, window.innerHeight - menu.offsetHeight - 8) + "px";

    el("fm-search").focus();
    markFilterButtons();
  }

  function closeFilterMenu() {
    state.menu = null;
    el("filter-menu").hidden = true;
    markFilterButtons();
  }

  function markFilterButtons() {
    var buttons = el("thead-row").querySelectorAll("button[data-filter]");
    for (var i = 0; i < buttons.length; i++) {
      var key = buttons[i].getAttribute("data-filter");
      var active = !!(state.filters[key] && state.filters[key].size);
      buttons[i].classList.toggle("on", active);
      buttons[i].classList.toggle("open", state.menu === key);
    }
  }

  function setFilter(key, values) {
    // An empty selection means "no filter", never "show nothing": unchecking
    // the last value should give you the column back, not an empty table.
    if (!values || !values.size) delete state.filters[key];
    else state.filters[key] = values;
  }

  function renderActiveFilters() {
    var keys = Object.keys(state.filters);
    var bar = el("active-filters");
    if (!keys.length) { bar.hidden = true; bar.innerHTML = ""; return; }

    bar.hidden = false;
    bar.innerHTML = '<span class="af-label">' + esc(t("filters.label")) + "</span>" +
      keys.map(function (key) {
        var chosen = Array.from(state.filters[key]);
        var text = chosen.length <= 2
          ? chosen.map(function (v) { return displayValue(key, v); }).join(", ")
          : t("filters.values", { n: chosen.length });
        return '<button class="af" data-drop="' + esc(key) + '">' +
          "<b>" + esc(columnLabel(key)) + ":</b> " + esc(text) + " \u2715</button>";
      }).join("") +
      '<button class="af-clear" data-drop="*">' + esc(t("filters.clearAll")) + "</button>";
  }

  // --- rendering: table ----------------------------------------------------

  var COLUMNS = [
    { key: "ip", cls: "mono" },
    { key: "hostname", cls: "mono trunc" },
    { key: "num", cls: "mono num" },
    { key: "protocol", cls: "mono" },
    { key: "state" },
    { key: "service", cls: "mono" },
    { key: "product", cls: "trunc" },
    { key: "version", cls: "mono trunc" },
    { key: "extrainfo", cls: "trunc" },
    { key: "os", cls: "trunc" },
    { key: "interest" },
    { key: "tags", cls: "tags" }
  ];

  function columnLabel(key) { return t("col." + key); }

  // With -d/-R over a folder the report can cover many scans; when it does,
  // which file a row came from is part of the answer.
  if ((DATA.scans || []).length > 1) {
    COLUMNS.push({ key: "sourceName", cls: "mono trunc" });
  }

  //: The rows currently painted, in display order, so the side panel can walk
  //: them with the arrow keys and find its row again after a re-render.
  var VISIBLE = [];

  function rowId(row) {
    return row.ip + "|" + row.num + "|" + row.protocol;
  }

  function sortRows(rows) {
    var key = state.sort.key, dir = state.sort.dir;
    return rows.slice().sort(function (a, b) {
      var x = a[key], y = b[key];
      if (x === null || x === undefined) return 1;
      if (y === null || y === undefined) return -1;
      if (key === "ip") { return dir * (ipKey(a.ip) - ipKey(b.ip) || a.num - b.num); }
      if (typeof x === "number" && typeof y === "number") return dir * (x - y);
      return dir * String(x).localeCompare(String(y), undefined, { numeric: true });
    });
  }

  function ipKey(ip) {
    var octets = String(ip || "").split(".");
    if (octets.length !== 4) return Number.MAX_SAFE_INTEGER;
    return octets.reduce(function (acc, part) { return acc * 256 + (parseInt(part, 10) || 0); }, 0);
  }

  function stateDot(value) {
    var color = value === "open" ? "--open" : (value === "filtered" ? "--filtered" : "--closed");
    return '<span class="dot" style="background:' + cssVar(color) + '"></span>' + esc(dash(value));
  }

  // --- column widths --------------------------------------------------------
  //
  // The table sizes itself to its content until a border is dragged.  From
  // that first drag every column is pinned in pixels, including the ones
  // nobody touched: leaving the rest free to reflow would move the very border
  // being dragged, and the column would never land where it was aimed.

  var MIN_COL = 46;
  //: A column wide enough to hold the longest NSE-fed extrainfo stops being a
  //: column; past this, the cell keeps its ellipsis and the detail panel has
  //: the whole value anyway.
  var MAX_AUTOFIT = 560;

  function tableNode() { return el("table-scroll").querySelector("table"); }

  /** True once every column has a width, i.e. once anything has been resized. */
  function columnsPinned() {
    return COLUMNS.every(function (column) { return state.colWidths[column.key]; });
  }

  /** Freeze at their current on-screen width the columns not yet pinned. */
  function pinColumns() {
    var cells = el("thead-row").children;
    COLUMNS.forEach(function (column, index) {
      if (!state.colWidths[column.key] && cells[index]) {
        state.colWidths[column.key] = Math.round(cells[index].getBoundingClientRect().width);
      }
    });
  }

  /** Write the pinned widths into the colgroup; unpinned means "size yourself". */
  function renderColumnWidths() {
    var pinned = columnsPinned();
    var total = 0;
    el("colgroup").innerHTML = COLUMNS.map(function (column) {
      var width = state.colWidths[column.key];
      if (!pinned) return "<col>";
      total += width;
      return '<col style="width:' + width + 'px">';
    }).join("");

    var table = tableNode();
    table.classList.toggle("sized", pinned);
    // As wide as its columns and no wider: with `width: 100%` the browser
    // hands any slack back to the columns, which would undo the drag.
    table.style.width = pinned ? total + "px" : "";
  }

  /** Give one column the width its longest cell actually needs. */
  function autofitColumn(index) {
    var table = tableNode();
    var saved = {};
    COLUMNS.forEach(function (column) { saved[column.key] = state.colWidths[column.key]; });

    // Measured with the browser's own table algorithm rather than by adding up
    // characters: drop every constraint, let it lay the table out once, and
    // read the column back.  `measuring` lifts the truncation caps so what
    // comes back is the content's width and not the cap's.
    el("colgroup").innerHTML = COLUMNS.map(function () { return "<col>"; }).join("");
    table.classList.remove("sized");
    table.classList.add("measuring");
    table.style.width = "";
    var natural = Math.ceil(el("thead-row").children[index].getBoundingClientRect().width);
    table.classList.remove("measuring");

    COLUMNS.forEach(function (column) { state.colWidths[column.key] = saved[column.key]; });
    // The rest keep what the reader sees now, which is what they were just
    // measured at, so only the double-clicked column moves.
    pinColumns();
    state.colWidths[COLUMNS[index].key] = Math.max(MIN_COL, Math.min(MAX_AUTOFIT, natural));
    renderColumnWidths();
  }

  /** Drag one border. Every column is pinned first so only this one moves. */
  function startColumnDrag(grip, event) {
    var index = parseInt(grip.getAttribute("data-col"), 10);
    var key = COLUMNS[index].key;
    pinColumns();
    renderColumnWidths();

    var startX = event.clientX;
    var startWidth = state.colWidths[key];
    grip.classList.add("dragging");
    document.body.classList.add("resizing");

    function move(moved) {
      state.colWidths[key] = Math.max(MIN_COL, startWidth + (moved.clientX - startX));
      renderColumnWidths();
    }
    function stop() {
      document.removeEventListener("mousemove", move);
      document.removeEventListener("mouseup", stop);
      grip.classList.remove("dragging");
      document.body.classList.remove("resizing");
    }
    document.addEventListener("mousemove", move);
    document.addEventListener("mouseup", stop);
  }

  function renderTable(rows) {
    var sorted = sortRows(rows);

    el("thead-row").innerHTML = COLUMNS.map(function (column, index) {
      var arrow = state.sort.key === column.key
        ? '<span class="arrow">' + (state.sort.dir === 1 ? "↑" : "↓") + "</span>" : "";
      return '<th><span class="th-label" data-sort="' + esc(column.key) + '">' +
        esc(columnLabel(column.key)) + arrow + "</span>" +
        '<button class="filter-btn" data-filter="' + esc(column.key) +
        '" aria-label="' + esc(columnLabel(column.key)) + '">\u25be</button>' +
        '<span class="col-grip" data-col="' + index + '" title="' +
        esc(t("table.resize")) + '"></span></th>';
    }).join("");
    markFilterButtons();
    renderColumnWidths();

    if (!sorted.length) {
      VISIBLE = [];
      el("tbody").innerHTML = '<tr><td colspan="' + COLUMNS.length +
        '" class="empty">' + esc(t("table.empty")) + "</td></tr>";
      return;
    }

    // Rendering every row of a /16 sweep locks the browser up; cap it and say so.
    var LIMIT = 3000;
    var visible = sorted.slice(0, LIMIT);

    // The side panel needs to find its row again after any re-render.
    VISIBLE = visible;

    el("tbody").innerHTML = visible.map(function (row, index) {
      var id = rowId(row);
      var cells = COLUMNS.map(function (column) {
        var value = row[column.key];
        if (column.key === "state") return "<td>" + stateDot(value) + "</td>";
        if (column.key === "interest") {
          return '<td><span class="pill ' + esc(value) + '">' +
            esc(levelLabel(value)) + "</span></td>";
        }
        if (column.key === "tags") {
          if (!value.length) return '<td class="tags"><span class="muted">—</span></td>';
          var shown = value.slice(0, 3).map(function (tag) {
            return '<span class="tag">' + esc(t("tag." + tag)) + "</span>";
          }).join("");
          if (value.length > 3) shown += '<span class="tag more">+' + (value.length - 3) + "</span>";
          return '<td class="tags" title="' +
            esc(value.map(function (tag) { return t("tag." + tag); }).join(", ")) +
            '">' + shown + "</td>";
        }
        return '<td class="' + (column.cls || "") + '" title="' + esc(dash(value)) + '">' +
          esc(dash(value)) + "</td>";
      }).join("");
      return '<tr class="row' + (state.selected === id ? " selected" : "") +
        '" data-row="' + esc(id) + '" data-index="' + index + '">' + cells + "</tr>";
    }).join("");

    if (sorted.length > LIMIT) {
      el("tbody").insertAdjacentHTML("beforeend", '<tr><td colspan="' + COLUMNS.length +
        '" class="empty">' + esc(t("table.capped", { shown: LIMIT, total: sorted.length })) +
        "</td></tr>");
    }
  }

  function defList(pairs) {
    var body = pairs.filter(function (p) { return p[1] !== null && p[1] !== undefined && p[1] !== ""; })
      .map(function (p) { return "<dt>" + esc(p[0]) + "</dt><dd>" + esc(p[1]) + "</dd>"; }).join("");
    return body ? "<dl>" + body + "</dl>" : '<dl><dt>—</dt><dd></dd></dl>';
  }

  function drawerBody(row) {
    var host = row.host;
    var port = row.port;
    var blocks = [];

    if (port && port.reasons.length) {
      // The reason a row is coloured belongs at the top, not buried under
      // fifteen fields the reader has to scroll past first.  Reasons arrive
      // from the parser in both languages.
      blocks.push('<section class="why ' + esc(port.interest) + '"><h4>' +
        esc(t("drawer.why", { level: levelLabel(port.interest) })) + "</h4><ul>" +
        port.reasons.map(function (reason) {
          return "<li>" + esc(reason[lang] || reason.en || reason) + "</li>";
        }).join("") + "</ul>" +
        ((port.tags || []).length
          ? '<div class="why-tags">' + port.tags.map(function (tag) {
              return '<button class="tag" data-tag="' + esc(tag) + '">' +
                esc(t("tag." + tag)) + "</button>";
            }).join("") + "</div>"
          : "") + "</section>");
    }

    if (port) {
      var service = port.service;
      blocks.push("<section><h4>" + esc(t("drawer.portService")) + "</h4>" + defList([
        [t("f.port"), port.port + "/" + port.protocol],
        [t("f.state"), port.state + (port.reason ? " (" + port.reason + ")" : "")],
        [t("f.ttl"), port.reason_ttl], [t("f.service"), service.name],
        [t("f.product"), service.product], [t("f.version"), service.version],
        [t("f.extrainfo"), service.extrainfo], [t("f.tunnel"), service.tunnel],
        [t("f.method"), service.method], [t("f.conf"), service.conf],
        [t("f.ostype"), service.ostype], [t("f.devicetype"), service.devicetype],
        [t("f.owner"), port.owner], [t("f.cpe"), service.cpe.join(", ")]
      ]) + "</section>");
    }

    blocks.push("<section><h4>" + esc(t("drawer.host")) + "</h4>" + defList([
      [t("f.ip"), host.ip], [t("f.ipv6"), host.ipv6], [t("f.hostname"), host.hostname],
      [t("f.mac"), host.mac], [t("f.vendor"), host.mac_vendor],
      [t("f.state"), host.state + (host.state_reason ? " (" + host.state_reason + ")" : "")],
      [t("f.distance"), host.distance],
      [t("f.lastboot"), host.uptime ? host.uptime.lastboot : null],
      [t("f.source"), host.source]
    ]) + "</section>");

    if (host.os.matches.length) {
      blocks.push("<section><h4>" + esc(t("drawer.os")) + "</h4>" + defList(
        host.os.matches.slice(0, 5).map(function (match) {
          return [match.accuracy + "%", match.name];
        })
      ) + "</section>");
    }

    var otherPorts = host.ports.filter(function (p) {
      return !port || p.port !== port.port || p.protocol !== port.protocol;
    });
    if (otherPorts.length) {
      blocks.push("<section><h4>" + esc(t("drawer.otherPorts")) +
        '</h4><div class="chips">' +
        otherPorts.map(function (p) {
          return '<button class="portchip ' + esc(p.interest) + '" data-goto="' +
            esc(host.ip) + "|" + esc(p.port) + "|" + esc(p.protocol) + '">' +
            esc(p.port) + "/" + esc(p.protocol) +
            (p.service.name ? " " + esc(p.service.name) : "") + "</button>";
        }).join("") + "</div></section>");
    }

    if (port && port.scripts.length) {
      blocks.push("<section><h4>" + esc(t("drawer.nse")) + "</h4>" +
        port.scripts.map(function (script) {
        return '<div class="script"><b>' + esc(script.id) + "</b><pre>" +
          esc(script.output || flattenTables(script.tables)) + "</pre></div>";
      }).join("") + "</section>");
    }

    if (host.trace.length) {
      blocks.push("<section><h4>" + esc(t("drawer.trace")) + "</h4>" +
        defList(host.trace.map(function (hop) {
        return [hop.ttl, (hop.ip || "") + (hop.host ? " (" + hop.host + ")" : "") +
          (hop.rtt ? "  " + hop.rtt + " ms" : "")];
      })) + "</section>");
    }

    return blocks.join("");
  }

  function flattenTables(tables, depth) {
    depth = depth || 0;
    var pad = "  ".repeat(depth);
    return (tables || []).map(function (table) {
      var head = table.key ? pad + table.key + ":\n" : "";
      var elems = table.elements.map(function (e) {
        return pad + "  " + (e.key ? e.key + ": " : "") + (e.value || "");
      }).join("\n");
      return head + elems + flattenTables(table.tables, depth + 1);
    }).join("\n");
  }

  // --- Side panel ----------------------------------------------------------

  function openDrawer(row) {
    state.selected = rowId(row);
    var port = row.port;

    el("drawer-title").textContent = row.ip + (port ? ":" + port.port : "");
    el("drawer-sub").textContent = [
      row.hostname,
      port ? port.protocol : null,
      port && port.service && port.service.name ? port.service.name : null
    ].filter(Boolean).join(" · ") || t("drawer.noPorts");

    var badge = el("drawer-interest");
    badge.textContent = port ? levelLabel(port.interest) : "—";
    badge.className = "pill " + (port ? port.interest : "low");

    el("drawer-body").innerHTML = drawerBody(row);
    el("drawer-body").scrollTop = 0;

    document.body.classList.add("drawer-open");
    el("drawer").setAttribute("aria-hidden", "false");
    markSelectedRow();
  }

  function closeDrawer() {
    state.selected = null;
    document.body.classList.remove("drawer-open");
    el("drawer").setAttribute("aria-hidden", "true");
    markSelectedRow();
  }

  function markSelectedRow() {
    var rows = el("tbody").querySelectorAll("tr.row");
    for (var i = 0; i < rows.length; i++) {
      rows[i].classList.toggle("selected", rows[i].getAttribute("data-row") === state.selected);
    }
  }

  function findVisible(id) {
    for (var i = 0; i < VISIBLE.length; i++) {
      if (rowId(VISIBLE[i]) === id) return i;
    }
    return -1;
  }

  /** Keep the panel honest: a row filtered away must not stay on screen. */
  function syncDrawer() {
    if (state.selected === null) return;
    var index = findVisible(state.selected);
    if (index === -1) { closeDrawer(); return; }
    openDrawer(VISIBLE[index]);
  }

  function step(delta) {
    if (state.selected === null) return;
    var index = findVisible(state.selected);
    if (index === -1) return;
    var next = index + delta;
    if (next < 0 || next >= VISIBLE.length) return;
    openDrawer(VISIBLE[next]);
    var tr = el("tbody").querySelector('tr[data-row="' + cssEscape(rowId(VISIBLE[next])) + '"]');
    if (tr) tr.scrollIntoView({ block: "nearest" });
  }

  function cssEscape(value) {
    return window.CSS && CSS.escape ? CSS.escape(value) : String(value).replace(/["\\]/g, "\\$&");
  }

  function copyText(text, feedback) {
    function done() {
      if (!feedback) return;
      feedback.hidden = false;
      clearTimeout(feedback._timer);
      feedback._timer = setTimeout(function () { feedback.hidden = true; }, 1400);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  }

  /** file:// pages do not always get the async clipboard; keep a way out. */
  function fallbackCopy(text, done) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); } catch (err) { /* nothing else to try */ }
    document.body.removeChild(area);
    done();
  }

  function download(name, text, type) {
    var blob = new Blob([text], { type: (type || "text/plain") + ";charset=utf-8" });
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  }

  /** Every group, every host:port, as one file with a comment per group. */
  function exportAllTargets() {
    var groups = groupRows(selected().filter(isOpen));
    if (!groups.length) return;
    var lines = [
      t("export.header", { title: reportTitle(),
                           by: t("group." + state.groupBy).toLowerCase() }),
      t("export.generated", { v: DATA.xnp_version, d: DATA.generated_at }), ""];
    groups.forEach(function (entry) {
      lines.push("# " + entry[0] + " (" +
        unique(entry[1].map(function (r) { return r.ip; })).length + " hosts)");
      unique(entry[1].map(function (r) { return r.ip + ":" + r.num; })).forEach(function (target) {
        lines.push(target);
      });
      lines.push("");
    });
    download((DATA.basename || "xnp") +
             (lang === "en" ? "-targets.txt" : "-objetivos.txt"), lines.join("\n"));
  }

  // --- CSV export ----------------------------------------------------------

  function exportCsv() {
    var rows = sortRows(selected());
    var head = COLUMNS.map(function (c) { return columnLabel(c.key); });
    var lines = [head.join(";")];
    rows.forEach(function (row) {
      lines.push(COLUMNS.map(function (column) {
        var value = row[column.key];
        if (value === null || value === undefined) return "";
        value = Array.isArray(value) ? value.join(" ") : String(value);
        return /[";\n]/.test(value) ? '"' + value.replace(/"/g, '""') + '"' : value;
      }).join(";"));
    });
    var blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = (DATA.basename || "xnp-report") +
      (lang === "en" ? "-filtered.csv" : "-filtrado.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  }

  // --- theme ---------------------------------------------------------------

  function preferredTheme() {
    try {
      var saved = localStorage.getItem("xnp-theme");
      if (saved === "dark" || saved === "light") return saved;
    } catch (err) { /* private mode: fall through to the media query */ }
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark" : "light";
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    el("theme-btn").textContent = theme === "dark" ? t("theme.light") : t("theme.dark");
    try { localStorage.setItem("xnp-theme", theme); } catch (err) { /* nothing to do */ }
  }

  // --- tabs ----------------------------------------------------------------

  var TABS = ["summary", "targets", "data"];

  function showTab(name) {
    TABS.forEach(function (tab) {
      el("tab-" + tab).setAttribute("aria-selected", String(tab === name));
      el("panel-" + tab).classList.toggle("active", tab === name);
    });
    // A canvas in a display:none panel measures zero, so anything drawn while
    // the tab was hidden comes back blank.  Redraw on the way in.
    if (name === "summary") renderCharts(selected());
  }

  function setQuery(text) {
    state.query = text;
    el("q").value = text;
    state.terms = parseQuery(text);
    render();
  }

  // --- main render ---------------------------------------------------------

  function render() {
    var rows = selected();
    el("count").textContent = t("q.rows", { n: rows.length, total: ROWS.length });
    renderKpis(rows);
    renderCharts(rows);
    renderActiveFilters();
    renderGroups(rows);
    renderTable(rows);
    // Last of the three: the buttons say how many lines and how many commands
    // the *current* selection produces, so both are recomputed with everything
    // else.
    syncCopyTargets();
    syncRescanBar();
    if (state.menu) renderFilterList();
    syncDrawer();
  }

  // --- wiring --------------------------------------------------------------

  function init() {
    applyStaticText();
    applyTheme(preferredTheme());

    el("lang-select").addEventListener("change", function () {
      setLang(el("lang-select").value);
    });
    el("theme-btn").addEventListener("click", function () {
      applyTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
      render();
    });

    TABS.forEach(function (tab) {
      el("tab-" + tab).addEventListener("click", function () { showTab(tab); });
    });

    el("kpis").addEventListener("click", function (event) {
      var card = event.target.closest("button[data-kpi]");
      if (!card) return;
      var terms = KPI_TERMS[parseInt(card.getAttribute("data-kpi"), 10)];
      if (terms) applyTerms(terms);
    });

    el("group-by").addEventListener("change", function () {
      state.groupBy = el("group-by").value;
      state.openGroups.clear();
      renderGroups(selected());
    });

    initRescanBars();

    // The query syntax is a one-off read: shown on ask, and remembered for
    // the reader who wants it up, the same way the theme and language are.
    var hintOpen = false;
    try { hintOpen = localStorage.getItem("xnp-hint") === "1"; } catch (err) { /* private mode */ }
    showHint(hintOpen);
    el("hint-toggle").addEventListener("click", function () {
      showHint(el("hint").hidden);
    });

    // The chip is rebuilt on every language change, so the listener hangs on
    // the footer row, which survives it.
    el("meta").addEventListener("click", function (event) {
      if (event.target.closest("#scans-toggle")) showScans(el("scan-list").hidden);
    });

    el("scan-list").addEventListener("click", function (event) {
      var file = event.target.closest("button[data-source]");
      if (file) applyTerms([["source", file.getAttribute("data-source")]]);
    });

    el("export-targets").addEventListener("click", exportAllTargets);

    el("groups").addEventListener("click", function (event) {
      var head = event.target.closest("button[data-group]:not([data-shape])");
      if (head) {
        var name = head.getAttribute("data-group");
        if (state.openGroups.has(name)) state.openGroups.delete(name);
        else state.openGroups.add(name);
        renderGroups(selected());
        return;
      }

      var shape = event.target.closest("button[data-shape]");
      if (shape) {
        var groupName = shape.getAttribute("data-group");
        var wanted = TARGET_SHAPES.filter(function (shapeDef) {
          return shapeDef.id === shape.getAttribute("data-shape");
        })[0];
        var bucket = groupRows(selected().filter(isOpen)).filter(function (entry) {
          return entry[0] === groupName;
        })[0];
        if (!wanted || !bucket) return;
        copyText(wanted.build(bucket[1]).join("\n"),
                 shape.closest(".g-actions").querySelector(".g-copied"));
        return;
      }

      // "detalle" jumps to the row's side panel without leaving the tab behind.
      var goto = event.target.closest("button[data-goto-row]");
      if (goto) {
        showTab("data");
        renderTable(selected());
        var index = findVisible(goto.getAttribute("data-goto-row"));
        if (index !== -1) openDrawer(VISIBLE[index]);
      }
    });

    var input = el("q");
    var debounce;
    input.addEventListener("input", function () {
      updateSuggestions();
      clearTimeout(debounce);
      debounce = setTimeout(function () {
        state.query = input.value;
        state.terms = parseQuery(input.value);
        render();
      }, 140);
    });

    input.addEventListener("focus", updateSuggestions);
    input.addEventListener("click", updateSuggestions);
    input.addEventListener("blur", function () {
      // Let a click on a suggestion land before the list disappears.
      setTimeout(closeSuggestions, 120);
    });

    input.addEventListener("keydown", function (event) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        if (!ac.items.length) { updateSuggestions(); if (!ac.items.length) return; }
        event.preventDefault();
        var step = event.key === "ArrowDown" ? 1 : -1;
        ac.index = (ac.index + step + ac.items.length) % ac.items.length;
        renderSuggestions();
        return;
      }
      if ((event.key === "Enter" || event.key === "Tab") && ac.index !== -1) {
        event.preventDefault();
        acceptSuggestion(ac.index);
        return;
      }
      if (event.key === "Escape") {
        if (ac.items.length) { event.preventDefault(); closeSuggestions(); return; }
        input.blur();
      }
    });

    el("suggest").addEventListener("mousedown", function (event) {
      // mousedown, not click: blur would tear the list down first.
      var button = event.target.closest("button[data-i]");
      if (!button) return;
      event.preventDefault();
      acceptSuggestion(parseInt(button.getAttribute("data-i"), 10));
    });

    var searchTimer;
    el("fm-search").addEventListener("input", function () {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(renderFilterList, 90);
    });

    el("fm-list").addEventListener("change", function (event) {
      var box = event.target.closest("input[type=checkbox]");
      if (!box || !state.menu) return;
      var chosen = new Set(state.filters[state.menu] || []);
      if (box.checked) chosen.add(box.value); else chosen.delete(box.value);
      setFilter(state.menu, chosen);
      render();
    });

    el("fm-all").addEventListener("click", function () {
      if (!state.menu) return;
      setFilter(state.menu, null);
      el("fm-search").value = "";
      render();
    });

    // "Only these" is the move people actually want after typing a search:
    // it beats ticking twelve boxes one at a time.
    el("fm-only").addEventListener("click", function () {
      if (!state.menu) return;
      var visible = filterEntries(state.menu, el("fm-search").value.trim())
        .map(function (entry) { return entry[0]; });
      setFilter(state.menu, new Set(visible));
      render();
    });

    el("filter-menu").addEventListener("keydown", function (event) {
      if (event.key === "Escape") { closeFilterMenu(); return; }
      if (event.key === "Enter" && event.target === el("fm-search")) {
        event.preventDefault();
        el("fm-only").click();
      }
    });

    el("active-filters").addEventListener("click", function (event) {
      var chip = event.target.closest("[data-drop]");
      if (!chip) return;
      var key = chip.getAttribute("data-drop");
      if (key === "*") state.filters = {};
      else delete state.filters[key];
      render();
    });

    document.addEventListener("mousedown", function (event) {
      if (!state.menu) return;
      if (event.target.closest("#filter-menu")) return;
      if (event.target.closest("button[data-filter]")) return;
      closeFilterMenu();
    });

    el("table-scroll").addEventListener("scroll", function () {
      if (state.menu) closeFilterMenu();
    });

    el("thead-row").addEventListener("click", function (event) {
      var button = event.target.closest("button[data-filter]");
      if (button) {
        var key = button.getAttribute("data-filter");
        if (state.menu === key) closeFilterMenu();
        else openFilterMenu(key, button.parentNode);
        return;
      }
      var label = event.target.closest("[data-sort]");
      if (!label) return;
      var sortKey = label.getAttribute("data-sort");
      if (state.sort.key === sortKey) state.sort.dir *= -1;
      else { state.sort.key = sortKey; state.sort.dir = 1; }
      renderTable(selected());
    });

    el("tbody").addEventListener("click", function (event) {
      var tr = event.target.closest("tr.row");
      if (!tr) return;
      var id = tr.getAttribute("data-row");
      if (state.selected === id) { closeDrawer(); return; }
      var index = findVisible(id);
      if (index !== -1) openDrawer(VISIBLE[index]);
    });

    el("drawer-close").addEventListener("click", closeDrawer);
    el("drawer-scrim").addEventListener("click", closeDrawer);

    // Jumping between the ports of one host is the commonest move in triage.
    el("drawer-body").addEventListener("click", function (event) {
      var tag = event.target.closest("button[data-tag]");
      if (tag) { applyTerms([["tag", tag.getAttribute("data-tag")]]); return; }
      var chip = event.target.closest("button[data-goto]");
      if (!chip) return;
      var index = findVisible(chip.getAttribute("data-goto"));
      if (index !== -1) openDrawer(VISIBLE[index]);
    });

    el("reset").addEventListener("click", function () {
      closeDrawer();
      state.filters = {};
      closeFilterMenu();
      setQuery("");
    });

    // The grip sits inside the header cell, so its events have to be taken off
    // the sort and filter handlers before they reach them.
    el("thead-row").addEventListener("mousedown", function (event) {
      var grip = event.target.closest(".col-grip");
      if (!grip) return;
      event.preventDefault();
      startColumnDrag(grip, event);
    });

    el("thead-row").addEventListener("dblclick", function (event) {
      var grip = event.target.closest(".col-grip");
      if (!grip) return;
      event.preventDefault();
      autofitColumn(parseInt(grip.getAttribute("data-col"), 10));
    });

    el("panel-data").addEventListener("click", function (event) {
      var button = event.target.closest(".copy-shape");
      if (!button) return;
      copyText(copyShapeLines(button.getAttribute("data-copy-shape")).join("\n"),
               document.querySelector(".copy-targets-copied"));
    });

    el("csv").addEventListener("click", exportCsv);

    // A keystroke that lands in a field belongs to the field: the rescan
    // arguments carry paths, and a shortcut that eats the "/" of -oN /tmp/out
    // leaves the field unusable. The same goes for j and k inside text.
    function typing(node) {
      if (!node) return false;
      if (node.isContentEditable) return true;
      var tag = node.tagName;
      return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
    }

    document.addEventListener("keydown", function (event) {
      if (typing(document.activeElement)) return;
      if (state.menu) return;
      if (event.key === "/") { event.preventDefault(); input.focus(); return; }
      if (event.key === "Escape" && state.selected !== null) { closeDrawer(); return; }
      if (state.selected === null) return;
      if (event.key === "ArrowDown" || event.key === "j") { event.preventDefault(); step(1); }
      if (event.key === "ArrowUp" || event.key === "k") { event.preventDefault(); step(-1); }
    });

    showTab("summary");
    render();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
