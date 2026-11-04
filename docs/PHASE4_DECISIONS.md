# Fase 4 — decisiones ratificadas y estado de implementación

**Versión:** 1.0
**Estado:** decisiones consolidadas. Este documento distingue las decisiones
ratificadas del estado actual de implementación y de los aspectos pendientes.

Esta nota registra las decisiones provistas para Fase 4. La evaluación local
del dataset se conserva por separado y no se modifica aquí. Dashboard y PDF no
formaban parte del alcance de implementación original I0–I6; actualmente están
integrados como capas de presentación y exportación del MVP. Su implementación
no cambia las reglas ni el contrato parcial descritos en esta nota.

## Alcance y contrato

- Decisión ratificada: Fase 4 comprende I0–I6; el contrato inicial de API
  contempla `GET /health`, `GET /meta` y `POST /analyze`, sin persistencia.
- Implementación actual del producto: además de esos endpoints, el backend
  expone `POST /reports/executive` y `POST /reports/technical`; el frontend
  presenta el dashboard y las acciones para descargar ambos PDF.
- Los informes PDF vuelven a analizar el archivo recibido, exigen el SHA-256
  esperado y no conservan el workbook ni el informe generado.
- `analysis_id` es content-addressed, no una clave de almacenamiento.
- `AnalysisResult` usa `schema_version="1.0"` y `canon_version="cj/1"`.
- Timestamps naive conservan `timezone_status="undefined"`.
- El archivo original es de solo lectura.
- La carga está limitada a 10 MiB y valida firma ZIP y lectura con OpenPyXL.
- Los mensajes se presentan en español y conservan los nombres técnicos.
- P-4: la detección de contradicciones está diferida y no bloquea esta fase.
- Pendiente: faltan los vectores y la serialización aprobados para verificar
  completamente `cj/1`; tampoco se completan E/K ni se materializan chains.

## Canonicalización y hashes (`cj/1`)

Decisiones ratificadas:

- Referencia de ejecución: CPython 3.12.3 y Unicode Database 15.0.0.
- Se preserva el tipo de los floats; scores se expresan como enteros en escala
  `10^-4`, con redondeo ties-to-even.
- Los timestamps canónicos usan ISO 8601 con precisión fija; la zona queda
  indefinida cuando el timestamp de origen es naive.
- `file_sha256` se calcula sobre los bytes originales.
- `content_sha256` se calcula sobre filas canónicas y no depende del orden.
- `logical_fingerprint` excluye `file_sha256`, `generated_at`, `row_index`,
  rutas, duración y memoria.
- `finding_id` usa el prefijo `F-` y los primeros 16 caracteres del SHA-256 de
  `rule_id + rule_version + sorted log_ids`.
- La identidad lógica no incorpora `row_index`, `generated_at` ni rutas.
- Hay tres vectores de canonicalización verificados; sus entradas y salidas no
  están disponibles en los documentos actuales. No se sustituirán por vectores
  inventados.

## Metodología E/K y score

- El catálogo de afirmaciones materiales E debe estar versionado y congelado
  antes de evaluar evidencia; cada afirmación tiene ID estable y peso igual.
- Estados E: `supported`, `unsupported`, `not_evaluable`.
- `E = supported / total` únicamente si todas las afirmaciones son evaluables.
  Si existe `not_evaluable`, `E=null`; catálogo vacío significa `pending`.
- K usa cinco controles fijos K1–K5 con estados `passed`, `failed`,
  `not_evaluable`. `K = passed / 5` solo si los cinco son evaluables; de otro
  modo `K=null`.
- K se evalúa de forma distinta para reglas (calidad y reproducibilidad) y
  chains (calidad de enlaces, claves y ventanas).
- K4 evalúa tratamiento determinista de evidencia faltante, ambigua o
  contradictoria. K5 admite fixtures hipotéticos documentados y separados de
  eventos observados.
- Si E o K no son evaluables, `Score=null`; no se permiten scores parciales ni
  imputaciones neutrales.
- Fórmula: `Score = 0.15 + 0.35E + 0.30C + 0.20K`.
- C: un dominio/un aspecto `0.30`; un dominio/dos o más aspectos `0.50`; dos
  dominios `0.65`; tres o más dominios `1.00`.
- `lexical_overlap` y `string_similarity` pertenecen a una familia heurística
  de peso cero. S representa contradicción, no limitación. El guard ratificado
  es `no_contradictions_detected`; la referencia tenía S=1.00.

## Confianza, niveles y topes

Bandas de confianza en basis points: High `7000–10000`, Medium `5000–6999`,
Low `2500–4999`, Info `0–2499`.

| Objeto | Nivel máximo | Tope |
|---|---:|---:|
| R01 | L1 | 0.75 |
| R02 | L2 | 0.78 |
| R03 | L1 | 0.75 |
| R04 | L0 | 0.55 |
| R05 | L1 | 0.75 |
| R06 | L3 | 0.85 |
| R07 | L1 | 0.75 |
| R08 | Sin tope | — |
| R09 | L1 | 0.75 |
| R10 | L1 | 0.75 |
| R11 | L3 | 0.85 |
| R12 | L1 | 0.75 |
| R13 | L1 | 0.75 |
| C1 | L2 | 0.78 |
| C2 | `pending_reconciliation` | — |
| C3 | L2 | 0.78 |
| C4 | L1 | 0.75 |
| C5 | L3 | 0.85 |
| C6 | L1 | 0.75 |

Los topes se aplican con `min()`, nunca por precedencia.

- L0: observación individual.
- L1: repetición del mismo tipo/Event_ID o evidencia compuesta dentro de un
  registro cuando se cumplen las condiciones explícitas de la regla.
- L2: al menos dos Event_ID del mismo aspecto/dominio.
- L3: al menos dos aspectos del mismo dominio.
- L4: al menos dos dominios demostrablemente independientes.

La asignación de nivel no demuestra causalidad ni éxito.

Scores de referencia ratificados: R01 `.7500`, R02 `.7800`, R03 `.5500`,
R04 `.5500`, R05 `.5500`, R06 `.7975`, R07 `.7375`, R08 `.7500`, R09 `.7500`,
R10 `.7500`, R11 `.7975`, R12 `.6900`, R13 `.7500`, C1 `.4500`, C2 `null`,
C3 `.4500`, C4 `.6900`, C5 `.7975`, C6 `.6900`.

C2 conserva `.5500` solo como `historical_unvalidated_score`; su score y
confidence operativos son nulos. No se alteran E o K para forzar los valores
de referencia. Las asociaciones ratificadas explícitas son C1/C3 `.4500` →
4500 bp (Low), C4 `.6900` → 6900 bp (Medium), R08 `.7500` (High) y C5 `.7975`
(High).

## Severidad

Severidades ratificadas:

- R03: Low.
- R11: Medium.
- C1: Medium.
- C2: Low, derivada de política ratificada; `severity_status=
  "derived_from_ratified_policy"` y caveat de alcance.
- C3: Medium; C4: Medium; C5: Medium; C6: Low.

La severidad de R01, R02, R04–R10, R12 y R13 sigue pendiente. No se deriva
automáticamente de confidence.

## Reglas y correlaciones

Las condiciones documentadas de R01–R13 se resumen en este diagnóstico. No se
amplían ni se convierten hipótesis del dataset en hechos.

### R09/1.0 — Transferencia saliente volumétrica

Estado: decisiones metodológicas ratificadas e implementación temporal
integrada en el pipeline. La implementación fue verificada mediante pruebas
unitarias, de integración y con el workbook original. Esta sección es la fuente
de verdad para R09/1.0.

1. **Ventana:** deslizante de 15 minutos.
2. **Anclaje:** cada evento `PROXY_ACCESS` elegible es ancla y extremo derecho
   de la ventana.
3. **Límites:** para un ancla en `t`, se evalúa `(t - 15 minutos, t]`; el límite
   izquierdo es exclusivo y el derecho inclusivo.
4. **Cantidad:** contar eventos únicos por `Log_ID`.
5. **Bytes:** sumar solo valores válidos y no negativos. Los registros sin un
   valor válido no aportan bytes.
6. **Duplicados e identidad:** el mismo `Log_ID` con contenido idéntico cuenta
   una sola vez. Si el mismo `Log_ID` está asociado a contenidos diferentes,
   excluir de R09 todas sus versiones en conflicto; no seleccionar una versión.
7. **Claves incompletas:** excluir del agrupamiento los registros cuyo
   `Hostname`, `User` o `Destination` esté ausente o sea inválido.
8. **Solapamiento:** consolidar todas las ventanas calificadas de una misma
   clave en una observación, con la unión de todas las evidencias contribuyentes.

La fuente es `PROXY_ACCESS`; la clave es `(Hostname, User, Destination)`.
Cada ventana califica si `count >= 10 OR observed_bytes_out_sum >= 52,428,800`;
ambos umbrales son inclusivos. Para una detección que califique únicamente por
bytes, `severity_eligible=false`.

Los valores de bytes son observaciones neutrales: no demuestran exfiltración,
transferencia exitosa, impacto ni intención maliciosa.

### R07/1.0 — Lectura masiva de archivos en un share

Estado: criterios metodológicos ratificados e implementación integrada en el
pipeline. R07 solo observa eventos `Event_ID=4663` y no usa `Log_Source` para
seleccionarlos. La clave exacta es `(User, Hostname, Destination)`; sus tres
componentes deben ser texto presente y no vacío ni compuesto solo por espacios.
Se preservan literalmente, sin normalización.

Cada evento elegible puede anclar una ventana deslizante de 10 minutos,
`(t - 10 minutos, t]`. Se cuentan valores distintos de `Process_CommandLine`
por igualdad literal exacta: sin trim, cambio de mayúsculas/minúsculas ni otra
normalización. Valores nulos, vacíos o solo con espacios no cuentan. La ventana
califica con al menos 10 valores distintos.

Se deduplican registros con `Log_ID` y contenido completo idéntico. Si un
`Log_ID` tiene contenido diferente, se excluyen todas sus versiones de R07.
Las ventanas calificadas de una misma clave se consolidan en una observación;
su evidencia es la unión sin duplicados de los registros de esas ventanas,
ordenada por timestamp y `Log_ID`. Timestamps inválidos y claves incompletas
se excluyen de la evaluación. Solo se evalúan los registros disponibles; no se
infiere cobertura completa ni actividad fuera del workbook. El campo
`Process_CommandLine` puede describir accesos a archivos y no demuestra
ejecución de comandos, exfiltración ni impacto.

### R08/1.0 — Archivado y asociación contextual

Estado: decisiones metodológicas ratificadas e implementación integrada en el
pipeline. Solo se evalúan eventos `Event_ID=4688`. Las herramientas reconocidas
son los tokens ejecutables/cmdlet `7z.exe`/`7z`, `rar.exe`/`rar`, `tar.exe`/`tar`
y `Compress-Archive`; no se aceptan coincidencias dentro de otros tokens.
El parser reconoce `7z`/`rar` con operación `a` y la ruta de archivo como
primer argumento posterior, `tar` en modo creación `-c` con salida indicada
por `-f`/`--file`, y `Compress-Archive` con `-DestinationPath`. Sintaxis
ambigua o no admitida no califica.

La ruta de salida se clasifica como `local_staging` para `C:\Temp`, `%TEMP%` o
`C:\Users\Public`, y como `network_destination` para una ruta UNC inequívoca.
No se expande `%TEMP%`; no se infiere una ruta ausente; las carpetas locales,
incluida `C:\Users\Public`, no se presentan como destinos públicos de Internet.
No se interpreta una IP de documentación como conectividad pública real.

El evento R08 es el ancla: solo evidencias pertenecientes a observaciones R07
y/o R09 efectivamente calificadas se relacionan si su timestamp cae en
`[t_R08 - 15 minutos, t_R08 + 15 minutos]` y coinciden exactamente `Hostname`
y `User` (sin normalización). R07 OR R09 es suficiente; si califican ambas,
se conservan ambas relaciones. Se emite una observación por evento R08; se
unen las evidencias relacionadas sin duplicar `Log_ID`, ordenadas por timestamp
y `Log_ID`. La asociación no implica causalidad.

Los `Log_ID` con contenido completo idéntico se deduplican; si hay contenido
distinto, se excluyen todas sus versiones, también ante conflictos con otros
`Event_ID`. Se excluyen eventos con timestamp/identidad inválidos, comando no
textual o salida no identificable, y evidencias relacionadas sin timestamp o
identidad válidos. Solo se analizan registros disponibles; no se infiere
transferencia exitosa, exfiltración, impacto ni intención.

R08 no tiene cap de nivel ni de confidence. El score `.7500` es una referencia
histórica/metodológica, no un valor forzado; score y confidence permanecen
nulos mientras E/K no sean evaluables. No se asigna severidad, que sigue sin
política ratificada.

### R13/1.0 — Enumeración web automatizada

Estado: criterios ratificados e implementación integrada en el pipeline. R13
selecciona exclusivamente `Event_ID=HTTP_ACCESS` y agrupa por `Source_IP`.
Cada solicitud elegible puede ser ancla de una ventana deslizante de cinco
minutos `(t - 5 minutos, t]`; el límite izquierdo es exclusivo y el derecho
inclusivo. Timestamps iguales se procesan juntos. Se consolidan las ventanas
calificadas de una misma IP en una observación.

Una ventana califica cuando `request_count >= 10` y, además,
`error_rate >= 30%` o `sensitive_route_count >= 1`. El `error_rate` es
`error_count / valid_result_count`: se consideran errores los códigos HTTP
400–599 y el denominador incluye únicamente códigos HTTP válidos 100–599.
Se acepta un entero no booleano en ese rango o texto de tres dígitos ASCII con
espacios ASCII externos. Resultados ausentes, vacíos, inválidos o fuera de
rango no eliminan la solicitud de `request_count` y no participan en el
numerador ni denominador. Si `valid_result_count=0`, la tasa no es calculable;
la condición de ruta sensible se evalúa de forma independiente. El umbral de
tasa se evalúa con enteros: `error_count * 100 >= valid_result_count * 30`.

Las rutas sensibles son `/admin`, `/login`, `/api` y `/upload`. Solo se aceptan
URI origin-form que comienzan con `/`; query y fragmento no participan en la
comparación. Se rechazan controles, backslash y escapes percent-encoded
malformados. Se decodifican una sola vez caracteres percent-encoded no
reservados; `%2F` y `%5C` no se convierten en separadores. Los segmentos
ASCII se comparan sin distinguir mayúsculas; segmentos vacíos por barras
repetidas o finales se ignoran. Solo cuentan segmentos exactos; por ejemplo,
`/administrator`, `/apiary`, `/login2`, `/upload-test` y `/uploads` no
coinciden. Una URI inválida o ausente no aporta ruta sensible, pero la
solicitud todavía puede contar.

`Log_ID` debe ser texto no vacío ni compuesto solo por espacios. Filas
idénticas con el mismo ID se cuentan una vez; si un ID tiene contenido
conflictivo, se excluyen todas sus versiones, incluso cuando el conflicto
incluye otro `Event_ID`. La firma considera el registro completo y preserva
tipos y valores. IP ausente o sintácticamente inválida y timestamps ausentes o
inválidos se excluyen de la evaluación temporal. Se incluyen IP válidas de
cualquier categoría (`public`, `private`, `special`, `documentation`,
`unknown`); se conserva su clasificación y las IPv4-mapped IPv6 mantienen su
identidad de grupo IPv6 sin mezclarse automáticamente con IPv4. `Hostname` y
`User` no son requisitos de elegibilidad.

La evidencia consolidada es la unión única de `Log_ID` que pertenecen a al
menos una ventana calificante, ordenada por timestamp y luego `Log_ID`. La
descripción de la observación muestra las métricas de la primera ventana
calificante en orden temporal; no son métricas agregadas sobre la unión.
El contrato `analysis-partial/1` no agrega campos. R13 no consulta ni se
correlaciona con R12. La regla observa solicitudes y no confirma
automatización, intención maliciosa, éxito, impacto o atribución. No se infiere
actividad antes o después de los registros disponibles.

R13 tiene nivel máximo L1 y cap de score 0.7500, aplicado como
`min(score_1e4, 7500)` únicamente si el score es evaluable. El cap de
confidence es una decisión separada; con E/K no evaluables ambos valores
operativos permanecen nulos. La severidad continúa sin ratificar y no se
asigna.

Decisiones específicas:

- R03 puede reportar `documentation` y `public` como observaciones; excluye
  `private` y `special`. `unknown`, `missing` e `invalid` no satisfacen la
  condición. RFC5737 es documentación, no evidencia de conexión pública
  operativa ni atribución.
- R09/1.0 tiene ratificadas la clave, la semántica temporal, el conteo por
  `Log_ID`, el tratamiento de bytes y duplicados, la exclusión de claves
  incompletas y la consolidación de ventanas, según la especificación que sigue.
- R09 requiere pruebas count-only, volume-only, below-threshold y
  inclusive-boundary. `bytes_out` es una observación neutral; por sí solo no
  demuestra impacto y `severity_eligible=false`.
- Los campos observacionales nombrados para I5 son
  `proxy_bytes_out_field_observed`, `proxy_recorded_bytes_out`,
  `observed_bytes_out_value` y `observed_bytes_out_sum`.
- R08 no tiene tope de nivel. R10/R12 admiten L1 por evidencia compuesta en
  un registro, sin inferir éxito o causalidad. R03 puede alcanzar L1 por
  repetición de 4624.
- I7 es elegible como cambio de estado observado. I2 representa la misma
  máquina con asociación provisional. I9 está insuficientemente especificada
  y no se cuenta.
- Las chains usan ventanas direccionales y enlaces admisibles. C1/C3 son L2;
  C4/C6 son L1 (no L4); C5 es L3. C4 relaciona host y red sin independencia
  demostrada; Firewall está contenido en el dominio host. Host y aplicación
  pueden estar correlacionados según H-02 para C6.
- C2 permanece `pending_reconciliation`. C7 es candidato separado con
  `ratified=false`, sin score, confidence ni severidad operativa. No crear
  I11.

No se inventan condiciones de membership para C1–C6 cuando no estén descritas.

## Fuentes IANA para clasificación IP

Decisión ratificada: preservar las cuatro fuentes XML con URL, fecha `updated`,
formato, fecha de recuperación y SHA-256 calculado sobre bytes reales. La
implementación actual conserva los archivos en `data/iana/` y sus metadatos en
`data/iana/manifest.json`; el cargador comprueba identidad de la fuente, fecha,
estructura XML y SHA-256 antes de utilizarlos. Los valores declarados a
continuación corresponden al manifiesto incorporado; no son hashes inferidos.

| Registro | URL | `updated` | Formato | Recuperado | Archivo relativo | SHA-256 |
|---|---|---|---|---|---|---|
| `iana-ipv4-special-registry` | `https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xml` | `2025-10-09` | XML | `2026-11-03` | `data/iana/iana-ipv4-special-registry.xml` | `37f334466c842387a8aee8d1ae7a6d5b2208ef27eb8964072538b73ee2f5b21d` |
| `iana-ipv6-special-registry` | `https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xml` | `2025-10-09` | XML | `2026-11-03` | `data/iana/iana-ipv6-special-registry.xml` | `660acf0201b462b8d820605ba1cb20c4ed216acd883ee4a55a17453d73d4c3aa` |
| `ipv4-address-space` | `https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xml` | `2025-10-10` | XML | `2026-11-03` | `data/iana/ipv4-address-space.xml` | `013bf87df7b24401ab6143bcad83bd61eeaf0f9c976d2cf1aedcdd5795865222` |
| `ipv6-address-space` | `https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xml` | `2025-10-23` | XML | `2026-11-03` | `data/iana/ipv6-address-space.xml` | `15481d1e549b481f3bd0321c5cd2c0327a00cbd3d5a6fc35fc7b53b51e70b1cb` |

Las filas NAT64/DNS64 `192.0.0.170/32` y `192.0.0.171/32` pertenecen a una
entrada IANA. Con los snapshots presentes y verificados, la clasificación
indica `verified`; si faltan archivos o no coinciden con el manifiesto, se
degrada a `declared_unverified` y la lógica no consume prefijos IANA no
verificados. RFC 5737 se clasifica como `documentation`, nunca como IP pública
operativa.

## Diagnóstico por componente

| Componente | Definición disponible | Falta concreta | ¿Puede implementarse? |
|---|---|---|---|
| `AnalysisResult` | `schema_version=1.0`, `canon_version=cj/1`, `timezone_status=undefined`, API sin persistencia y `analysis_id` content-addressed. | Esquema completo, identidad canónica verificable y formato definitivo de chains/findings; no equiparar el contrato parcial con el definitivo. | Parcial. `analysis-partial/1` responde HTTP 200 y declara incompletitud. |
| Canonicalización `cj/1` | Tipos de floats, score entero `10^-4`, ties-to-even, timestamp ISO de precisión fija, exclusiones de `logical_fingerprint`, regla conceptual de `finding_id`, SHA de bytes originales y filas canónicas sin depender del orden. | Los tres vectores aprobados y los detalles exactos de serialización/concatenación. | Solo `file_sha256`; `analysis_id`, `content_sha256` y `logical_fingerprint` quedan nulos/no evaluables. |
| Catálogo E | Estados `supported`/`unsupported`/`not_evaluable`, mismo peso, catálogo vacío `pending`, score solo cuando todas son evaluables. | Catálogo versionado de afirmaciones materiales e IDs por regla/chain y sus criterios de evaluación. | Función genérica de agregación E; no se asigna E a observaciones reales. |
| Controles K1–K5 | Cinco controles fijos, estados, denominador 5, diferencia rules/chains, propósito de K4 y admisión de fixtures en K5. | Criterios de aprobación/fallo/no evaluable de cada K para cada regla y chain. | Función genérica de agregación K; K operativo de resultados reales sigue nulo. |
| Dominios y aspectos | Valores C ratificados por cantidad de dominios/aspectos; criterios de L2–L4 y límites de independencia para C4/C6. | Asignación concreta de cada evidencia y objeto a dominio/aspecto y registro de independencia. | Fórmula C genérica; C por observación/chain no se imputa. |
| R01 | `4625`, grupo por `Source_IP`, `count>=5`, `distinct(User)>=3`, ventana 10 min. | No se materializan chains ni se infiere relación con otras reglas. | Integrada en el pipeline con su evaluación temporal documentada y observaciones trazables; no equivale a una chain. |
| R02 | Mismo `(User, Hostname)`, al menos 3 `4625` seguidos por `4624` dentro de 15 min. | Sin carencia bloqueante para evaluación direccional anclada en el `4624`. | Sí; ejecutada con referencias a fallos y éxito. |
| R03 | `4624` y clasificación de origen con tratamiento de `documentation`/`public`/`special` ratificado. | No hay evidencia en los logs de que una IP RFC 5737 represente una conexión pública operativa. | Integrada con el clasificador basado en snapshots IANA verificados; RFC 5737 se devuelve como `documentation`, nunca como público operativo. |
| R04 | `4624`, `LogonType=10` en descripción y origen externo. | La severidad ratificada no está definida para R04. | Sí, como observación; severidad queda `not_defined`. |
| R05 | `4688` y `-EncodedCommand`, `-enc `, `-NoProfile` o `FromBase64String`. | No hay carencia para la condición puntual; severidad no está ratificada. | Sí, como observación sin afirmar que el payload sea malicioso. |
| R06 | Eventos `4688`/`4104` y detección puntual de los comandos catalogados; no se infiere éxito ni intención. | Ninguna para el predicado puntual; la mención de 10 min no está ratificada y no se aplica. | Sí; predicado léxico puntual con evidencia por `Log_ID`, sin agrupación temporal. |
| R07/1.0 | `4663`, clave exacta `(User, Hostname, Destination)`, 10 valores literales distintos de `Process_CommandLine` en ventana deslizante `(t-10 min,t]`; tratamiento explícito de duplicados, conflictos, claves inválidas y consolidación. | Ninguna para los criterios R07/1.0 ratificados. | Integrada en el pipeline; estado `executed`. La severidad sigue pendiente y no se asigna. |
| R08/1.0 | Herramientas `7z`/`rar`/`tar`/`Compress-Archive`, salida local de staging o UNC, relación OR con findings calificados R07/R09 dentro de ±15 min inclusivos y Hostname/User exactos; duplicados/conflictos y consolidación ratificados. Sin cap de nivel/confidence. | Ninguna para los criterios R08/1.0 ratificados; el parser excluye sintaxis ambigua/no admitida. | Integrada en el pipeline; una observación por evento 4688 relacionado. Severidad no definida; `.7500` no se fuerza como score. |
| R09/1.0 | Ventana deslizante de 15 min anclada en cada evento con `Event_ID=PROXY_ACCESS`; `(t-15 min,t]`; eventos únicos por `Log_ID`; valores válidos/no negativos; exclusión de conflictos y claves incompletas; consolidación por clave. Umbrales inclusivos `count>=10 OR observed_bytes_out_sum>=52,428,800`; `severity_eligible=false` si solo califica por bytes. | Ninguna de las ocho decisiones de R09/1.0 queda pendiente. | Integrada en el pipeline; estado `executed`. Registra exclusiones/deduplicaciones en `rule_execution.R09.reason` cuando corresponda y produce observaciones consolidadas con evidencias `Log_ID`. |
| R10 | Condiciones textuales explícitas para `vssadmin`, `wmic` o `bcdedit`, `4688`. | Ninguna para la detección de comando; no hay evidencia de éxito del comando. | Sí, como observación de ejecución, no de efecto. |
| R11 | `4698` o `7045` con una ruta catalogada en el mismo registro; severidad Medium ratificada. | La agrupación por usuario/host en 30 min y la periodicidad aparecen como propuestas documentadas, no como criterios ratificados. | Sí; coincidencia puntual por registro, sin agrupación ni periodicidad y sin afirmar persistencia confirmada. |
| R12 | `4688`, identidad `IIS APPPOOL\` o padre `w3wp.exe`, y comando listado. | Ninguna para el predicado puntual; severidad pendiente. | Sí, como observación compuesta de un registro. |
| R13/1.0 | `HTTP_ACCESS`, por `Source_IP`, ventana deslizante `(t-5 min,t]`, mínimo 10 solicitudes y `error_rate>=30%` o al menos una ruta sensible por segmento exacto. Manejo de resultados inválidos, deduplicación, conflictos, URI e IP está especificado en su sección. | Severidad pendiente; score/confidence operativos no evaluables sin catálogos E/K. | Integrada; una observación consolidada por IP y evidencias trazables. Sin correlación R12 ni afirmación de automatización maliciosa o impacto. |
| C1–C6 | Hay niveles ratificados y C2 conserva `pending_reconciliation`; C7 es candidato no ratificado. | Las condiciones exactas de membresía y enlaces admisibles no están formalizadas para construir chains reproducibles. | No se materializan chains. C1/C3–C6 quedan `not_evaluable`; C2 queda `pending_reconciliation`; C7 queda no ratificada y no evaluable. Ninguno se presenta como incidente confirmado. |
| Clasificación IP | Categorías y reglas P-3; cuatro snapshots XML IANA y manifiesto presentes en `data/iana/`. | La clasificación no demuestra reputación, actividad maliciosa ni conectividad operativa. | Clasificador integrado con hashes y metadatos verificados contra el manifiesto; si la validación falla, estado `declared_unverified` y uso conservador. |
| Severidades | Valores exactos R03, R11, C1–C6 y política especial de C2 ratificados. | Severidad de R01, R02, R04–R10, R12 y R13 sigue pendiente. | Solo se asigna a observaciones R03/R11; demás severidades nulas/no definidas. |
| M01–M14 | Ningún desglose de esos módulos está en los documentos de proyecto. | Nombres, responsabilidades, interfaces y relaciones M01–M14. | No puede afirmarse una implementación alineada a M01–M14; el pipeline actual se limita al alcance verificable. |
| I0–I6 | Alcance de Fase 4, endpoints, upload, ingestión y evaluación determinista están ratificados. El dashboard y los PDF quedaron fuera del alcance original de I0–I6. | La correspondencia completa módulo por módulo con M01–M14 no está especificada. | El backend parcial y las capas actuales de dashboard/PDF están implementados. Esto no completa E/K, `cj/1` ni las chains, ni implica que toda Fase 4 esté certificada como completa. |

Las referencias de score, confidence y topes no se sustituyen por ajustes
forzados: si E/K/C no se pueden evaluar con sus catálogos, el score permanece
nulo. Los umbrales de banda y caps son conocidos; no hay una función adicional
aprobada que derive confidence de cualquier score.

## Contrato de análisis parcial implementado

`POST /analyze` devuelve `analysis-partial/1` con HTTP 200 para un XLSX válido.
El contrato no se denomina `AnalysisResult` definitivo y contiene:

- `status=partial`, conteos de filas y de reglas ejecutadas/parciales/pendientes.
- Un estado por regla y una razón explícita para las reglas pendientes.
- Un estado por chain: membership no definido se marca `not_evaluable`, C2
  `pending_reconciliation` y C7 no ratificado/no evaluable.
- `observations` deterministas con referencias a `Log_ID`, timestamp, host,
  Event_ID, usuario e IP/clasificación.
- `impact_demonstrated=false` e `incident_attribution=false`; severidad solo
  cuando está ratificada, y score/confidence nulos si E/K no son evaluables.
- `analysis_id` y `content_sha256` nulos/no evaluables hasta verificar
  `cj/1` con sus vectores y serialización aprobados; sí devuelve SHA-256 de los
  bytes originales.
- `activity_summary` distingue cero coincidencias de regla de cero actividad.

## Estado comprobable en este repositorio

- Implementados: `GET /health`, `GET /meta`, `POST /analyze`, carga XLSX de
  solo lectura, validación de hoja/columnas y rechazo de archivos vacíos,
  corruptos, no XLSX y superiores a 10 MiB.
- Implementados: `POST /reports/executive` y `POST /reports/technical`, con
  validación de `expected_file_sha256`; frontend React/TypeScript con carga,
  dashboard y descargas asociadas al archivo del análisis visible. La descarga
  en curso se cancela al desmontar el análisis asociado.
- Implementados: ingestión/normalización para las columnas SIEM, timestamps
  naive y evaluación parcial explícita de filas inválidas.
- Reglas implementadas en los predicados disponibles: R01–R13, con estado y
  alcance por regla expuestos en `rule_execution`. R06 reporta coincidencias
  puntuales sin inferir éxito o intención; R07 evalúa ventanas deslizantes
  R07/1.0 por
  `Event_ID=4663`; R09 evalúa ventanas deslizantes R09/1.0 por
  `Event_ID=PROXY_ACCESS`; R08 correlaciona eventos 4688 elegibles con
  evidencia calificada de R07 o R09; R11 evalúa rutas catalogadas por registro,
  sin agrupación/periodicidad ni afirmación de persistencia confirmada; R13
  evalúa ventanas deslizantes HTTP_ACCESS por Source_IP sin correlación R12.
- Implementada: clasificación IP por snapshots IANA verificados desde
  `data/iana/`, junto con tratamiento explícito de rangos privados,
  documentación y especiales.
- El motor E/K/C y los caps siguen como funciones puras; el pipeline no afirma
  un score/confidence operativo sin los catálogos evaluables.
- R09/1.0 está integrada: parsea el campo neutral `bytes_out` y evalúa ventanas
  deslizantes de 15 minutos, deduplica por `Log_ID`, excluye identificadores en
  conflicto y claves incompletas, y consolida solo evidencias contribuyentes.
  La selección de fuente usa `Event_ID=PROXY_ACCESS`; en el workbook original,
  `Log_Source` toma el valor `Proxy`. Los bytes observados no se interpretan
  como transferencia exitosa, exfiltración ni impacto.
- Los endpoints PDF comparan el hash recibido con `expected_file_sha256`; las
  pruebas con el workbook original verifican su hash documentado.
- `POST /analyze` devuelve resultado parcial; no crea chains ni presenta
  hipótesis como incidentes.
- Los PDF resumen observaciones/evidencias y limitaciones del resultado
  parcial; no materializan chains ni producen puntuaciones no evaluables.

## Pendiente

- Vectores aprobados y serialización completa para verificar `cj/1`;
  `analysis_id` y `content_sha256` continúan no evaluables.
- Catálogos evaluables E/K por regla/chain; por ello no se presentan scores ni
  confidence operativos cuando no se pueden evaluar.
- Condiciones reproducibles de membership/enlaces para materializar chains.
- Correspondencia formal del pipeline con el diseño modular M01–M14.
- No se implementan persistencia/historial, IA/Ollama, respuesta automática ni
  detección de contradicciones.
