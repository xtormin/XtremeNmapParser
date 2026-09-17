# El informe HTML

La versión larga. [← Volver al README](../README.es.md) · [English](html-report.md)

```bash
xnp -f scan.xml -oF html
```

## Sacar los objetivos

En la pestaña **Servicios**, cada grupo de puertos abiertos se copia con el
formato que espera la siguiente herramienta:

| Formato | Qué te llevas |
| --- | --- |
| `host:puerto` | `10.0.0.14:445`, uno por línea — para el `-iL` de casi cualquier herramienta |
| `solo IP` | direcciones deduplicadas, una por línea |
| `URL` | `https://web01.corp.local:8443` — solo para servicios HTTP; el esquema se deduce del túnel TLS y del puerto, y se prefiere el hostname a la dirección |
| `nmap` | comandos de reescaneo para el grupo — ver más abajo |

*Descargar todos los objetivos* escribe todos los grupos en un fichero con una
cabecera de comentario por grupo. *Detalle* en cualquier fila salta a ella en la
tabla con su panel lateral abierto.

## Reescaneo dirigido

El control de reescaneo está en la barra de herramientas de las pestañas
*Servicios* y *Datos*, junto al otro botón de entrega de esa pestaña
—*Descargar todos los objetivos* y *Exportar selección a CSV*—, porque es de la
misma clase de cosa: coge lo que hay en pantalla y dámelo. El perfil y el botón
son un único control segmentado, y las dos pestañas comparten estado: cambia el
perfil en una y la otra la sigue.

Copia los comandos de **la selección actual**: todo si no hay filtro, y lo que
el filtro haya dejado si lo hay. El número de la etiqueta sigue al filtro en
vivo, así que ver cómo `service:ssh` convierte *Copiar 7 comandos nmap* en
*Copiar 1 comando nmap* te dice lo que te vas a llevar antes de pulsar. Solo
puertos abiertos: un puerto cerrado no merece una segunda pasada, así que una
selección sin ninguno deshabilita el botón y lo dice.

Dentro de un grupo desplegado, el formato `nmap` hace lo mismo para ese grupo
solo, junto a `host:puerto`, `solo IP` y `URL`.

En nmap la lista de puertos se aplica a todos los objetivos de la invocación,
así que un único comando sobre un grupo de hosts sondearía puertos que la
mayoría no tiene. En su lugar los hosts se dividen **por firma de puertos**: los
que tienen exactamente el mismo conjunto de puertos abiertos comparten comando,
y a ninguno se le manda un puerto que no tiene.

Los perfiles salen de tu propio `config.yaml` (ver
[Configuración](../README.es.md#configuración)), así que la lista es la que tú
pongas. `personalizado` abre una caja para escribirlos a mano, y con ella una
línea que muestra lo que se va a ejecutar de verdad: los flags que sobreviven,
no los que escribiste. Con un perfil con nombre esa misma frase está en el
tooltip del botón, donde no estorba.

Tres cosas las decide el generador, diga lo que diga el perfil:

- **La lista de puertos.** `-p`, `-p-`, `-F` y `--top-ports` en un perfil se
  descartan: la gracia es precisamente escanear los puertos que ya se
  encontraron.
- **Los tipos de escaneo.** Un grupo UDP lleva `-sU` y prefijos `U:`; uno mixto
  lleva además un tipo TCP explícito, porque `-sU` sin él hace que nmap ignore
  la mitad `T:` de la especificación. A un grupo solo TCP se le deja el
  comportamiento por defecto de nmap (`-sS` como root, `-sT` si no) salvo que el
  perfil pidiera uno concreto, de modo que un `-sT` deliberado se respeta.
- **`-6`.** Se añade en un grupo IPv6 y se descarta en uno IPv4. Los hosts IPv4
  e IPv6 nunca comparten comando.

Los argumentos admiten variables `$[...]` —`$[IP]`, `$[HOSTNAME]`, `$[PORTS]`,
`$[TCP_PORTS]`, `$[UDP_PORTS]`— que se sustituyen en cada comando: es lo que
convierte `-oA scans/$[HOSTNAME]` en un fichero de salida por objetivo en vez de
uno que sobrescribe cada comando. `$[IP]` y `$[HOSTNAME]` nombran a un solo
host, así que usar una divide su grupo en un comando por host: un valor que
cambia de un host a otro no se puede escribir una sola vez en un comando que
comparten. `$[HOSTNAME]` cae a la dirección si el escaneo no resolvió el nombre,
y un nombre que no sea de esos se queda en el comando en vez de vaciarse: la
línea de debajo de la caja dice cuál, así que un `$[HOST]` que nunca iba a
convertirse en nada lo dice en vez de viajar callado hasta tu shell. Las
comillas que escribas dentro de los argumentos se respetan, así que
`-oA "scans/$[HOSTNAME] deep"` sigue funcionando cuando un valor lleva un
espacio. Ver
[Variables](../README.es.md#variables) para el lado de la terminal, donde el
shell obliga a usar comillas simples; en la caja de aquí no hay nada que
entrecomillar.

Las direcciones se validan antes de llegar a una línea de comandos: `addr` es
CDATA en `nmap.dtd`, así que lo que no sea una dirección IP se descarta en vez
de escaparse. Un hostname recibe el mismo trato antes de llegar a
`$[HOSTNAME]`.

Los mismos comandos están en la terminal con `--rescan`, que lee `rescan.states`
de la configuración y por tanto apunta también a `open|filtered` —el estado
normal de un puerto UDP—. El informe apunta a lo que sus propias pestañas
cuentan como abierto.

## La tabla

Todos los campos que produjo nmap, columnas ordenables y un filtro estilo Excel
en cada cabecera. Pulsa el `▾` y tienes una lista buscable de los valores que
hay realmente, cada uno con su recuento; *Solo los mostrados* convierte de un
clic lo que haya encontrado el buscador en el filtro. Los recuentos de una
columna siempre excluyen el filtro de esa misma columna, así que el menú enseña
lo que todavía podrías elegir en vez de solo lo que ya elegiste. Los filtros
activos aparecen como chips sobre la tabla y se quitan uno a uno.

El ancho de cada columna se ajusta arrastrando su borde derecho en la cabecera,
y un doble clic sobre ese mismo borde la ajusta a su contenido. En cuanto tocas
una, todas quedan fijadas: si las demás siguieran recolocándose, el borde que
estás arrastrando se movería contigo y la columna nunca acabaría donde apuntas.

*Copiar objetivos como* se lleva al portapapeles la selección entera —no solo
la página que se ve— en el mismo orden en que está ordenada la tabla:
`host:puerto` una línea por puerto, `solo IP` una línea por host sin repetir.
El número de cada botón es el número de líneas que va a copiar, así que sabes
lo que te llevas antes de pulsar.

Al pulsar una fila se despliega un panel lateral con el registro completo: por
qué la fila lleva su etiqueta de interés, detalle del puerto y del servicio,
detalle del host, coincidencias de SO, CPE, los demás puertos del mismo host
como chips pulsables, la salida NSE en crudo y el traceroute. `↑` `↓` recorren
las filas sin cerrarlo y `Esc` lo cierra.

## La barra de consulta

```
state:open service:http port<1024 -interest:low
ip=10.0.0.14 script:smb
"Apache Tomcat"
```

Escribe un campo y `:` y te ofrece los valores que hay en *este* escaneo, con
sus recuentos: `port:` lista los puertos encontrados, `service:` los servicios
identificados, y lo mismo con `ip` `host` `proto` `state` `reason` `product`
`version` `os` `family` `interest` `tag` `cleartext` `source`. `↑` `↓` `Enter`
para elegir, y un valor con espacios vuelve ya entrecomillado. `cpe` `script` y
`extrainfo` se buscan como texto libre en vez de elegirse de una lista.

Operadores: `:` (contiene) `=` (exacto) `<` `<=` `>` `>=` `!=`; el prefijo `-`
niega, y una palabra suelta busca en toda la fila. La consulta y los filtros de
columna se combinan, y se aplican a las tres pestañas a la vez: acota a
`interest:high -state:closed` en Datos y la pestaña Servicios te da las listas
de objetivos de exactamente ese conjunto. *Exportar selección a CSV* guarda lo
que estés viendo en ese momento.

## Varios escaneos en un solo informe

```bash
xnp -d nmap/ -oF html
```

Recorre la carpeta recursivamente, fusiona todos los escaneos en un único
informe y deduplica hosts y puertos entre ficheros, quedándose con el escaneo
que identificó más detalle de servicio. La tabla gana una columna *Origen*
—con su propio filtro— para que sigas sabiendo de qué escaneo vino cada fila.
Con `--no-merger` obtienes un informe por XML, y con `--no-recursive` el
recorrido se queda en el primer nivel.

En el pie, el chip *ficheros* dice cuántos entraron y se despliega en una lista
con una fila por fichero: nombre, fecha de inicio y la línea de comandos de
nmap que lo produjo. Cuando el informe viene de un solo XML no hay lista: ese
comando se ve directamente en el chip `$` del pie. Al imprimir, la lista sale
siempre, esté desplegada o no.

El nombre de cada fichero se pulsa y deja la tabla en `source="…"`, que es el
mismo campo que filtra la columna *Origen*: de «con qué se escaneó esto» a «qué
salió de ahí» en un clic. Pulsar otro fichero sustituye el filtro en vez de
sumarse a él.

## La etiqueta de interés y las etiquetas

Cada puerto abierto recibe un nivel de interés —alto / medio / bajo— y un
conjunto de etiquetas que dicen de qué tipo de cosa se trata: *base de datos*,
*sin autenticación*, *credenciales en claro*, *administración remota*, y una
docena más. Ambas cosas salen de una tabla indexada **a la vez** por el número
de puerto y por el nombre del servicio, así que una base de datos movida de su
puerto por defecto se sigue detectando en cuanto `-sV` la nombra (mira
`HIGH_INTEREST_PORTS` en [report_model.py](../xnp/report_model.py)).

Las etiquetas son lo que hace resumibles cien filas: la pestaña Resumen las
grafica, al pulsar una se filtra por ella y `tag:` las autocompleta en la barra
de consulta. La frase que hay detrás de cada etiqueta se queda en el panel
lateral, así que siempre puedes ver *por qué* se marcó un puerto — y no estar de
acuerdo.

**Se llama interés y no riesgo, y es a propósito.** La tabla solo lee el número
de puerto, el nombre del servicio y si hay TLS por medio. No lee la versión, ni
el historial de CVE, ni la salida NSE, ni si el host da a internet, ni siquiera
si el puerto está abierto: un 3306 `filtered` sigue siendo interés alto, porque
la etiqueta describe qué es ese protocolo, no a qué está expuesto este host.
Dice qué merece un vistazo; no dice qué es vulnerable.

## Idioma

Un selector junto al conmutador de tema cambia entre español e inglés, y la
elección se recuerda en `localStorage`, partiendo del idioma del navegador de
quien lo lee. No hay nada incrustado en el marcado, y un test tumba la build si
se cuela una cadena escrita a mano. Eso incluye los motivos que hay detrás de
cada etiqueta, que se traducen en el origen (`report_model.py` guarda parejas
`(inglés, español)`) en lugar de quedarse en el idioma en que esté escrito el
fichero fuente.

Los dos títulos se ponen en `config.yaml`:

```yaml
html:
  title: "Informe de superficie de red"
  title_en: "Network exposure report"
```

## Tema y color

El informe sigue el tema del sistema de quien lo lee y recuerda la elección
explícita. `Ctrl+P` imprime una copia limpia con las pestañas desplegadas y sin
los adornos interactivos.

Aquí el color significa algo, así que está contenido en vez de ser decorativo.
El rojo, el ámbar y el verde pertenecen al nivel de interés y al estado del
puerto; el color de acento es cian precisamente para que "esto se puede pulsar"
no parezca nunca "esto es peligroso". La tinta es un carbón suave en vez de
negro puro, y el tema oscuro pone el texto en un gris suave en vez de blanco
puro: contraste máximo sobre contraste máximo vibra en una página tan densa.

Cada pareja de texto en ambos temas supera el AA de WCAG con 4,5:1, y cada
borde, punto de estado y serie de gráfica supera 3:1 —
[test_report_contrast.py](../tests/test_report_contrast.py) lee los tokens
directamente de la hoja de estilos que se publica y tumba la build si un cambio
futuro baja de ahí.

IBM Plex Sans e IBM Plex Mono (SIL OFL 1.1) van incluidas como subconjuntos
woff2 latinos e incrustadas como data URI, lo que suma unos 140 KB por informe.
La tipografía es casi todo el diseño, así que las fuentes viajan con el fichero:
un informe que necesita un CDN para verse bien es un informe que deja de verse
bien.
