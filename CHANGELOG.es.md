# Registro de cambios

Versiones publicadas de [XNP](https://github.com/xtormin/XtremeNmapParser).

[← Volver al README](README.es.md) · [English](CHANGELOG.md)

## XNP v1.2.0 — el informe HTML

- **Una carpeta se fusiona y se recorre entera por defecto.** `xnp -d nmap/` es
  el comando completo: `-M` y `-R` ya no hacen falta (se siguen aceptando, así
  que los scripts de siempre funcionan igual) y los nuevos `--no-merger` /
  `--no-recursive` desactivan cada mitad.
- Nuevo `--show`: abre el informe HTML generado en el navegador al terminar, que
  es justo lo que quieres ahora que el nombre lleva fecha y hora. Una máquina
  sin navegador recibe un aviso, no un run fallido.
- **El informe fusionado se nombra con la carpeta y se escribe dentro de ella**,
  con la fecha y la hora: `xnp -d nmap/` genera
  `nmap/nmap_20260910-134500.html` en lugar de `merged_nmap_scan_data.html` en
  el directorio desde el que lanzaras el comando. Todos los formatos de una
  misma pasada comparten la marca de tiempo, y una segunda pasada añade un
  informe en vez de pisar el entregable de ayer. `-oN` sigue mandando sobre
  todo esto y se respeta tal cual.
- Nuevo formato de salida `html`: un informe interactivo autocontenido en temas
  claro y oscuro, dentro del conjunto por defecto de `-oF`. Tres pestañas:
  cifras de cabecera y gráficas, puertos abiertos agrupados por servicio con
  listas de objetivos copiables, y la tabla completa con filtros de columna
  estilo Excel, un lenguaje de consulta y un panel lateral de detalle por fila.
  Cada cifra, barra y sector filtra la tabla al pulsarlo y se escribe solo en la
  barra de consulta.
- Los puertos llevan un nivel de *interés* y un conjunto de etiquetas
  (`database`, `no-auth`, `cleartext-creds`, …) en lugar de una puntuación de
  "riesgo": la etiqueta dice qué merece un vistazo y no afirma nada sobre
  vulnerabilidad.
- El informe HTML llega a datos que los otros formatos nunca vieron. Los
  escritores solo recibían las once columnas planas, así que la línea de comando
  de nmap, la detección de SO, los CPE, los motivos del estado de cada puerto y
  la salida NSE estructurada se parseaban y se tiraban; ahora
  `NmapParser.parse_all` / `merge_all` entregan los informes parseados al
  escritor junto al DataFrame.
- Las opciones de `-oF` se derivan del registro de escritores, así que el CLI ya
  no puede quedarse atrás cuando se añade un formato.
- Chart.js 4.5.1 (MIT) va incluido; el informe no hace peticiones de red.
- La paleta del informe la audita la suite de tests contra el AA de WCAG, y el
  color de acento de interacción ya no comparte tono con los colores de nivel.
- Parsear un directorio ya no se detiene en el primer fichero que falla la
  validación: se avisa del fichero, se salta y se sigue, y al final se nombran
  todos los que se saltaron. Un fichero nombrado con `-f` sigue terminando la
  ejecución.
- Nuevo directorio `examples/` con escaneos de muestra, y
  `scripts/generate_examples.py` para regenerarlos.
- IBM Plex Sans/Mono (SIL OFL) van incluidas e incrustadas, así que el informe se
  ve con su tipografía en una máquina que no la ha visto nunca.
- El informe es bilingüe (español/inglés), conmutable junto al selector de tema.
  Los motivos que hay detrás de cada etiqueta se traducen en el origen y no en la
  página.

## XNP v1.1.0 — paquete instalable y validación de entrada

- XNP es ya un paquete instalable (`pip install .`) con un comando `xnp`, y
  funciona desde cualquier directorio. Antes la configuración se leía de una ruta
  relativa, así que solo funcionaba desde la raíz del repositorio.
- Validación de entrada en tres capas: parser XML endurecido, comprobación de la
  raíz `<nmaprun>` y validación DTD con `--no-validate` como escape para salida
  compatible con nmap de otros escáneres. Una entrada inválida ahora sale limpia
  en vez de lanzar un `AttributeError`.
- La autoactualización del arranque ya no ejecuta `git pull` por su cuenta.
  Avisa de que existe una versión nueva; `xnp --update` es quien actualiza.
- Correcciones: los hosts IPv6 se quedaban sin dirección; la columna `Scripts`
  contenía reprs de objetos de Python; se ignoraba `-oN` junto con `-f`; los
  nombres de salida se truncaban cuando la ruta contenía `.xml`; una escritura
  fallida seguía reportando éxito; fusionar solo escaneos vacíos petaba.
- Nuevo flag `--include-hostless`: emite una fila para los hosts sin puertos, que
  antes se descartaban en silencio.
- Suite de tests y CI en Python 3.9 – 3.13.

## v1.0.x — versiones anteriores

- **24/06/2023 — v1.0.5** — `-C` acepta ya `default` y `all`; las columnas de
  cada caso se definen en `config.yaml`.
- **24/06/2023 — v1.0.4** — Refactor de los argumentos `outputformat` y
  `outputname`.
- **24/06/2023 — v1.0.3** — Comprobación de versión al arrancar y
  autoactualización.
- **13/06/2023 — v1.0.2** — Cabeceras personalizadas, columna opcional
  `Scripts`, exportar solo puertos abiertos.
- **07/06/2023 — v1.0.1** — Código refactorizado, clase `NmapXMLReport.py` para
  parsear el XML, opción recursiva.
- **05/06/2023 — v1.0.0** — Publicación oficial.
