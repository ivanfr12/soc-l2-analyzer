# Fase 4 — decisiones ratificadas y estado de implementación

**Versión:** 1.0
**Estado:** decisiones consolidadas; implementación I0–I6 en curso.

Esta nota registra las decisiones provistas para Fase 4. La evaluación local
del dataset se conserva fuera de este commit y no se modifica.

## Alcance y contrato

- Fase 4 comprende I0–I6. Dashboard y PDF quedan fuera de alcance.
- API sin persistencia: `GET /health`, `GET /meta`, `POST /analyze`.
- `analysis_id` es content-addressed, no una clave de almacenamiento.
- `AnalysisResult` usa `schema_version="1.0"` y `canon_version="cj/1"`.
- Timestamps naive conservan `timezone_status="undefined"`.
- El archivo original es de solo lectura.
- La carga está limitada a 10 MiB y valida firma ZIP y lectura con OpenPyXL.
- Los mensajes se presentan en español y conservan los nombres técnicos.
- P-4: la detección de contradicciones está diferida y no bloquea esta fase.

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

Decisiones específicas:

- R03 puede reportar `documentation` y `public` como observaciones; excluye
  `private` y `special`. `unknown`, `missing` e `invalid` no satisfacen la
  condición. RFC5737 es documentación, no evidencia de conexión pública
  operativa ni atribución.
- R09 agrupa `(Hostname, User, Destination)` en ventana de 15 minutos y
  dispara si `count >= 10 OR observed_bytes_out_sum >= 52428800`. Ambos
  umbrales son inclusivos.
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

Las cuatro fuentes XML deben preservarse con URL, fecha `updated`, formato,
fecha de recuperación y SHA-256 calculado sobre bytes reales. Snapshots de
registros especiales: `2025-10-09`; de asignación: `2025-10-10`. Las filas
NAT64/DNS64 `192.0.0.170/32` y `192.0.0.171/32` pertenecen a una entrada IANA.
Las asignaciones de `ip_table v1` permanecen `declared_unverified` hasta
validar la fuente. No se registran hashes ficticios.

## Diagnóstico por componente

| Componente | Definición disponible | Falta concreta | ¿Puede implementarse? |
|---|---|---|---|
| `AnalysisResult` | `schema_version=1.0`, `canon_version=cj/1`, `timezone_status=undefined`, API sin persistencia y `analysis_id` content-addressed. | Esquema completo, identidad canónica verificable y formato definitivo de chains/findings; no equiparar el contrato parcial con el definitivo. | Parcial. `analysis-partial/1` responde HTTP 200 y declara incompletitud. |
| Canonicalización `cj/1` | Tipos de floats, score entero `10^-4`, ties-to-even, timestamp ISO de precisión fija, exclusiones de `logical_fingerprint`, regla conceptual de `finding_id`, SHA de bytes originales y filas canónicas sin depender del orden. | Los tres vectores aprobados y los detalles exactos de serialización/concatenación. | Solo `file_sha256`; `analysis_id`, `content_sha256` y `logical_fingerprint` quedan nulos/no evaluables. |
| Catálogo E | Estados `supported`/`unsupported`/`not_evaluable`, mismo peso, catálogo vacío `pending`, score solo cuando todas son evaluables. | Catálogo versionado de afirmaciones materiales e IDs por regla/chain y sus criterios de evaluación. | Función genérica de agregación E; no se asigna E a observaciones reales. |
| Controles K1–K5 | Cinco controles fijos, estados, denominador 5, diferencia rules/chains, propósito de K4 y admisión de fixtures en K5. | Criterios de aprobación/fallo/no evaluable de cada K para cada regla y chain. | Función genérica de agregación K; K operativo de resultados reales sigue nulo. |
| Dominios y aspectos | Valores C ratificados por cantidad de dominios/aspectos; criterios de L2–L4 y límites de independencia para C4/C6. | Asignación concreta de cada evidencia y objeto a dominio/aspecto y registro de independencia. | Fórmula C genérica; C por observación/chain no se imputa. |
| R01 | `4625`, grupo por `Source_IP`, `count>=5`, `distinct(User)>=3`, ventana 10 min. | Anclaje/alineación de ventanas y superposición. | Condición conocida; ejecución pendiente, no se inventa una política de ventana. |
| R02 | Mismo `(User, Hostname)`, al menos 3 `4625` seguidos por `4624` dentro de 15 min. | Sin carencia bloqueante para evaluación direccional anclada en el `4624`. | Sí; ejecutada con referencias a fallos y éxito. |
| R03 | `4624` y origen fuera de rangos privados; tratamiento de documentación/public/special ratificado. | Snapshots XML IANA para validar y versionar la tabla completa. | Sí, con clasificador provisional; RFC5737 se devuelve como `documentation`, nunca como público operativo. |
| R04 | `4624`, `LogonType=10` en descripción y origen externo. | Validación de IP depende de la tabla provisional; severidad ratificada no está definida para R04. | Sí, como observación; severidad queda `not_defined`. |
| R05 | `4688` y `-EncodedCommand`, `-enc `, `-NoProfile` o `FromBase64String`. | No hay carencia para la condición puntual; severidad no está ratificada. | Sí, como observación sin afirmar que el payload sea malicioso. |
| R06 | Eventos `4688`/`4104`, comandos enumerados, agrupación por usuario/host en 10 min. | Alineación de la ventana y criterio operacional para consolidar eventos. | Parcial: se reporta el predicado por registro; no se agrupan eventos ni se afirma actividad sostenida. |
| R07 | `4663`, clave `(User, Hostname, Destination)`, al menos 10 comandos distintos en 10 min. | Alineación/superposición de ventana; el campo tiene la convención específica descrita en la evaluación. | Condición conocida; ejecución pendiente. |
| R08 | Herramientas de archivado y rutas temporales/públicas; contexto ±15 min de R07/R09; sin tope L. | Membership temporal depende de R07/R09 y no debe inferir acceso o exfiltración. | Condición puntual candidata definida; asociación completa pendiente. |
| R09 | Clave `(Hostname, User, Destination)`, ventana de 15 min, `count>=10 OR observed_bytes_out_sum>=52428800`; inclusivo y severidad no elegible por bytes. | No hay definición de ventana deslizante/fija, anclaje ni superposición. | Parser y umbrales puros implementados; el detector temporal queda pendiente y no se ejecuta. |
| R10 | Condiciones textuales explícitas para `vssadmin`, `wmic` o `bcdedit`, `4688`. | Ninguna para la detección de comando; no hay evidencia de éxito del comando. | Sí, como observación de ejecución, no de efecto. |
| R11 | `4698` o `7045`, rutas enumeradas; grupo por usuario/host en 30 min y ejemplos de ejecuciones periódicas. Severidad Medium ratificada. | Correlación/periodicidad completa requiere agrupación temporal; el nombre del archivo no demuestra persistencia maliciosa. | Parcial: reporta coincidencias puntuales con rutas, sin afirmar periodicidad ni persistencia confirmada. |
| R12 | `4688`, identidad `IIS APPPOOL\` o padre `w3wp.exe`, y comando listado. | Ninguna para el predicado puntual; severidad pendiente. | Sí, como observación compuesta de un registro. |
| R13 | `HTTP_ACCESS`, al menos 10 en 5 min, condición de 30% 4xx/5xx o rutas sensibles. | Alineación/superposición temporal no definida. | Condición conocida; ejecución pendiente. |
| C1–C6 | Hay ventanas temporales observadas e hipótesis en la evaluación local; niveles ratificados para C1–C6 y C2 `pending_reconciliation`. C7 está definido como candidato no ratificado. | Condiciones exactas de membership y enlaces admisibles no están formalizadas para construir chains reproducibles. | No se emiten chains. C2 no se calcula; C7 no se activa. |
| Ventanas R09 | 15 min, grupo por las tres claves, dos umbrales inclusivos y OR están ratificados. | Estrategia de ventanas (alineación, anclaje y superposición). | No; solo parsing/suma de valores y comparador aislado. |
| Clasificación IP | Categorías y reglas P-3; redes RFC5737 documentadas en la evaluación. | Payloads/URL de snapshots, fechas `updated` y hashes reales para reproducir `ip_table v1`. | Parcial/provisional con rangos RFC explícitos y `ipaddress`; no se presenta como validación IANA. |
| Severidades | Valores exactos R03, R11, C1–C6 y política especial de C2 ratificados. | Severidad de R01, R02, R04–R10, R12 y R13 sigue pendiente. | Solo se asigna a observaciones R03/R11; demás severidades nulas/no definidas. |
| M01–M14 | Ningún desglose de esos módulos está en los documentos de proyecto. | Nombres, responsabilidades, interfaces y relaciones M01–M14. | No puede afirmarse una implementación alineada a M01–M14; el pipeline actual se limita al alcance verificable. |
| I0–I6 | Alcance de Fase 4, endpoints, upload, ingestión, reglas/scoring determinista y exclusión de dashboard/PDF están ratificados. | Criterios de aceptación y correspondencia módulo por módulo con M01–M14. | Parcial por componentes definidos; no se declara Fase 4 completa. |

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
- `analysis_id` y `content_sha256` nulos/no evaluables hasta implementar
  `cj/1` con sus vectores y serialización aprobados; sí devuelve SHA-256 de los
  bytes originales.
- `activity_summary` distingue cero coincidencias de regla de cero actividad.

## Estado comprobable en este repositorio

- Implementados: `GET /health`, `GET /meta`, carga XLSX de solo lectura,
  validación de hoja/columnas y rechazo de archivos vacíos, corruptos, no XLSX
  y superiores a 10 MiB.
- Implementados: ingestión/normalización para las columnas SIEM, timestamps
  naive y evaluación parcial explícita de filas inválidas.
- Reglas ejecutadas en el predicado disponible: R02, R03, R04, R05, R10 y R12.
  R06 y R11 reportan coincidencias puntuales como `partially_executed`; no
  infieren agrupación/periodicidad. R01, R07–R09 y R13 quedan pendientes por
  ventanas/correlaciones.
- Implementados: clasificadores de rangos privados/documentación/special y
  global `public` mediante `ipaddress`; clasificación marcada provisional
  hasta incorporar los snapshots IANA.
- El motor E/K/C y los caps siguen como funciones puras; el pipeline no afirma
  un score/confidence operativo sin los catálogos evaluables.
- R09 solo tiene parsing y comparador inclusivo aislado. No calcula ventanas.
- `file_sha256` se comprueba contra el hash documentado del workbook original.
- `POST /analyze` devuelve resultado parcial; no crea chains ni presenta
  hipótesis como incidentes.
