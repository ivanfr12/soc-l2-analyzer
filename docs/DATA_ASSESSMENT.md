# DATA ASSESSMENT — SOC L2 Analyzer

> **Estado:** evaluación histórica de Fase 2 — Identificación y evaluación del dataset.
> **Fecha del análisis:** 2026-10-29.
> **Método:** inspección de solo lectura con `openpyxl` (`read_only=True`, `data_only=True`).
> **Alcance:** este documento describe **hechos observados** en el workbook, **indicadores sospechosos**, **hipótesis de investigación** y **datos insuficientes**. No declara incidentes confirmados.
> **Ubicación:** el workbook original se mantiene fuera del repositorio. Para
> reproducir la evaluación, se referencia mediante la variable de entorno
> `SOC_L2_CHALLENGE_WORKBOOK`; no se publica una ruta local.

---

## 0. Resumen ejecutivo del dataset

| Aspecto | Valor observado |
|---|---|
| Archivo | Workbook SIEM original del desafío (fuera del repositorio; ruta local omitida) |
| Tamaño | 44.723 bytes |
| SHA-256 (antes y después del análisis) | `0E5D5DE56DA596BF6B279A07F51E29498AD86782256CD842F42328543708A0C9` |
| Última modificación | 2026-10-26 21:20:00 |
| Hojas | 1 (`SIEM Export`, visible) |
| Filas de datos | 715 |
| Columnas | 12 |
| Rango temporal | 2026-10-23 07:46:07 → 2026-10-23 13:44:06 (5 h 57 min 59 s) |
| `Log_ID` | `EVT-00001` … `EVT-00715`, únicos y sin huecos |
| Tipos de evento | 15 valores distintos en `Event_ID` |
| Hosts | 11 cadenas (10 hosts + 1 variante de nombre) |
| Usuarios | 13 valores distintos |
| IPs de origen | 10 valores distintos (7 internas + 3 externas) |

El workbook **no fue modificado**: el hash SHA-256 calculado antes y después del análisis es idéntico y el archivo se abrió en modo lectura.

**Observación de contexto:** todas las IPs "externas" (`203.0.113.74`, `198.51.100.77`, `192.0.2.91`, `203.0.113.88`, `198.51.100.88`) pertenecen a los rangos de documentación RFC 5737 (TEST-NET-1/2/3). Esto, junto con identificadores sintéticos (`EVT-00001`), la marca `[REDACTED_SYNTHETIC]` y el usuario `CORP\...`, indica que el dataset es **una exportación sintética o anonimizada de laboratorio**, no una captura de producción. Las conclusiones son válidas para el desafío, pero no deben extrapolarse a una red real.

---

## 1. Método de inspección

1. Localización del archivo original en el entorno de evaluación, sin registrar su ruta absoluta. Para reproducir la lectura, se puede proporcionar la ruta autorizada mediante `SOC_L2_CHALLENGE_WORKBOOK`; el workbook no se copia al repositorio.
2. Apertura en modo lectura con `openpyxl.load_workbook(..., read_only=True, data_only=True)`.
3. Perfilado por columna: tipo Python real, nulos, valores distintos.
4. Validación de timestamps con formatos explícitos; verificación de orden cronológico.
5. Detección de duplicados (fila completa y `Log_ID`).
6. Frecuencias de `Event_ID`, `Hostname`, `User`, `Source_IP`, `Log_Source`, `Severity`, `Result`, `Destination`.
7. Reconstrucción de secuencias temporales por host, usuario, IP y ventana de tiempo.
8. Verificación de integridad del archivo (hash) al finalizar.

Ningún registro fue eliminado, filtrado ni reescrito. Los cálculos se hicieron sobre las 715 filas completas. Las rutas de Windows que aparecen más adelante son valores literales observados en campos del dataset sintético; no son ubicaciones del repositorio ni del equipo del evaluador.

---

## 2. Esquema y tipos reales

Nombres de columna **preservados exactamente** como aparecen en el workbook:

| # | Columna | Tipo(s) observado(s) | Nulos/vacíos | Distintos |
|---|---|---|---|---|
| 1 | `Log_ID` | `str` (715) | 0 | 715 |
| 2 | `Timestamp` | `str` (715) | 0 | 698 |
| 3 | `Hostname` | `str` (715) | 0 | 11 |
| 4 | `Event_ID` | `int` (672) + `str` (43) | 0 | 15 |
| 5 | `User` | `str` (715) | 0 | 13 |
| 6 | `Source_IP` | `str` (715) | 0 | 10 |
| 7 | `Destination` | `str` (453) + `None` (262) | **262 (36,6 %)** | 9 |
| 8 | `Log_Source` | `str` (715) | 0 | 6 |
| 9 | `Event_Description` | `str` (715) | 0 | 26 |
| 10 | `Process_CommandLine` | `str` (155) + `None` (560) | **560 (78,3 %)** | 57 |
| 11 | `Result` | `str` (715) | 0 | 6 |
| 12 | `Severity` | `str` (715) | 0 | 4 |

**Consecuencia técnica:** `Event_ID` es una columna de tipo mixto. Los 43 valores de tipo texto corresponden a eventos no-Windows (`PROXY_ACCESS` 22, `HTTP_ACCESS` 21). Cualquier comparación debe normalizar a `str` antes de agrupar.

---

## 3. Estadísticas generales

### 3.1 Frecuencia de `Event_ID`

| Event_ID | Eventos | Descripción funcional | `Log_Source` |
|---|---:|---|---|
| 4624 | 111 | Logon exitoso | Security |
| 4625 | 102 | Logon fallido | Security |
| 4634 | 94 | Logoff | Security |
| 4688 | 92 | Creación de proceso | Security |
| 5140 | 74 | Acceso a recurso compartido | Security |
| 5156 | 67 | Conexión permitida por WFP | Security |
| 4663 | 64 | Acceso a objeto | Security |
| 7036 | 55 | Servicio en ejecución | System |
| `PROXY_ACCESS` | 22 | POST HTTPS saliente | Proxy |
| `HTTP_ACCESS` | 21 | Petición HTTP | IIS |
| 4672 | 8 | Privilegios especiales | Security |
| 5145 | 2 | Acceso detallado a share | Security |
| 4104 | 1 | Script block de PowerShell | PowerShell |
| 4698 | 1 | Tarea programada creada | Security |
| 7045 | 1 | Servicio instalado | System |

### 3.2 Frecuencia de `Hostname`

| Host | Eventos | | Host | Eventos |
|---|---:|---|---|---:|
| DC-01 | 91 | | WS-023 | 57 |
| FS-SRV01 | 91 | | WS-031 | 48 |
| WEB-01 | 87 | | DC01 | 30 |
| APP-SRV01 | 83 | | WS-022 | 25 |
| WS-018 | 71 | | | |
| WS-014 | 68 | | | |
| DB-SRV01 | 64 | | | |

### 3.3 Frecuencia de `User`

| Usuario | Eventos | | Usuario | Eventos |
|---|---:|---|---|---:|
| `CORP\jlopez` | 104 | | `CORP\mruiz` | 34 |
| `CORP\helpdesk` | 94 | | `CORP\svc_backup` | 24 |
| `CORP\aperez` | 80 | | `-` (sin usuario) | 21 |
| `CORP\backupsvc` | 76 | | `CORP\admin` | 16 |
| `CORP\rrojas` | 72 | | `IIS APPPOOL\DefaultAppPool` | 1 |
| `CORP\slopez` | 70 | | | |
| `CORP\mgarcia` | 66 | | | |
| `CORP\dtorres` | 57 | | | |

### 3.4 Frecuencia de `Source_IP`

| IP | Eventos | Clasificación |
|---|---:|---|
| 10.10.1.31 | 115 | interna |
| 10.10.1.44 | 108 | interna |
| 10.10.2.24 | 106 | interna |
| 10.10.2.15 | 102 | interna |
| 10.10.1.22 | 98 | interna |
| 10.10.3.18 | 83 | interna |
| 10.10.1.14 | 35 | interna |
| 203.0.113.74 | 35 | **externa (RFC 5737)** |
| 192.0.2.91 | 22 | **externa (RFC 5737)** |
| 198.51.100.77 | 11 | **externa (RFC 5737)** |

### 3.5 Frecuencia de `Log_Source` y `Severity`

| `Log_Source` | Eventos | | `Severity` | Eventos |
|---|---:|---|---|---:|
| Security | 615 | | Informational | 603 |
| System | 55 | | Warning | 97 |
| Proxy | 22 | | High | 8 |
| IIS | 21 | | Medium | 7 |
| Firewall | 1 | | | |
| PowerShell | 1 | | | |

### 3.6 `Result`

`Success` 570 · `Failure` 102 · `Allowed` 22 · `500` 9 · `200` 6 · `404` 6.

> `Result` mezcla semántica de autenticación (`Success`/`Failure`), de firewall (`Allowed`) y códigos HTTP (`200`/`404`/`500`). No es un campo homogéneo.

---

## 4. Distribución temporal

| Hora | Eventos |
|---|---:|
| 07 | 20 |
| 08 | 150 |
| 09 | 176 |
| 10 | 128 |
| 11 | 88 |
| 12 | 91 |
| 13 | 62 |

- Un único día: **2026-10-23**.
- Los datos comienzan a las 07:46:07 (la hora 07 está incompleta) y terminan a las 13:44:06 (la hora 13 también está incompleta).
- El archivo está **ordenado cronológicamente de forma ascendente**.
- **No hay periodo de baseline previo ni posterior**: solo ~6 horas de un día. Cualquier umbral es heurístico, no estadísticamente derivado.
- Se observan "picos" de actividad entre 08:00 y 10:00, coincidentes con las secuencias descritas en la sección 7.

---

## 5. Calidad de datos

### 5.1 Verificaciones que pasaron

| Verificación | Resultado |
|---|---|
| Timestamps inválidos | **0 de 715** |
| Formatos de timestamp | 100 % `YYYY-MM-DD HH:MM:SS` |
| `Log_ID` duplicados | **0** |
| Filas duplicadas completas | **0** |
| `Log_ID` faltantes en la secuencia 1–715 | **0** |
| Longitud de fila uniforme | 12 columnas en las 715 filas |
| Hojas ocultas | ninguna |
| Nulos en `Timestamp`, `Hostname`, `Event_ID`, `User`, `Source_IP`, `Log_Source`, `Event_Description`, `Result`, `Severity` | **0** |

### 5.2 Problemas detectados

| ID | Problema | Evidencia | Impacto |
|---|---|---|---|
| Q1 | `Event_ID` con tipo mixto | 672 `int` + 43 `str` | Agrupaciones incorrectas si no se normaliza |
| Q2 | `Hostname` inconsistente para el mismo equipo | `DC-01` (91 eventos) y `DC01` (30 eventos) | Un mismo host se cuenta dos veces; rompe correlaciones por host |
| Q3 | Cuentas de servicio con nombres casi idénticos | `CORP\backupsvc` (76) y `CORP\svc_backup` (24) | Riesgo de confundir dos identidades distintas |
| Q4 | `Source_IP` **no identifica al host** | Cada IP interna aparece asociada a 5–11 hosts distintos; p. ej. `10.10.1.22` aparece en 11 hosts | **No se puede correlacionar por IP→host**. Solo las IPs externas son consistentes con un host |
| Q5 | `Source_IP` contradice a `Event_Description` | `EVT-00222`/`EVT-00225` tienen `Source_IP=10.10.2.15` pero la descripción dice `source=APP-SRV01` | Ambigüedad de origen en accesos laterales |
| Q6 | `Destination` nulo en 262 filas (36,6 %) | Nulo en 67 de 111 `4624`, 54 de 92 `4688`, 41 de 94 `4634` | No se puede reconstruir el destino en muchos eventos |
| Q7 | `Process_CommandLine` nulo en 560 filas (78,3 %) | Solo 155 eventos tienen línea de comandos | Detección de ejecución limitada a una minoría de eventos |
| Q8 | `Severity` no refleja la criticidad real | `EVT-00123` (logon externo exitoso tras *spraying*) = `Informational`; `EVT-00428` (`7z` de `C:\Legal`) = `Informational`; 33 fallos de *spraying* = `Warning` | **No usar `Severity` como señal de detección**; debe derivarse de reglas |
| Q9 | Timestamps duplicados | 17 valores repetidos, 34 filas afectadas (p. ej. `09:42:00` en `EVT-00313` y `EVT-00314`) | Orden relativo ambiguo dentro del mismo segundo; no invalida el análisis |
| Q10 | Contenido de payload redactado | `[REDACTED_SYNTHETIC]` (`EVT-00198`), `<base64_redacted>` (`EVT-00280`) | **No es posible decodificar** los comandos ofuscados |
| Q11 | Sin hashes, sin PID, sin GUID de proceso, sin padre estructurado | El padre solo aparece como texto en `Event_Description` (`parent=cmd.exe`) | No se puede construir un árbol de procesos real |
| Q12 | Sin `bytes_in`, sin DNS, sin EDR, sin logs de VPN/MFA | No existen esas columnas | Varias hipótesis quedan sin poder validarse |
| Q13 | `Log_Source` "Firewall" con 1 solo evento | `EVT-00235` | La telemetría de red es prácticamente inexistente (67 eventos `5156` son de WFP, no de firewall perimetral) |
| Q14 | `7036` (servicio en ejecución) con 55 eventos | 7,7 % del dataset | Ruido de fondo que debe excluirse de las reglas |

### 5.3 Campos que permiten correlacionar

| Campo | ¿Sirve para correlacionar? | Motivo |
|---|---|---|
| `Timestamp` | **Sí** | Único, válido, ordenado |
| `Hostname` | **Sí, con normalización** | Requiere unificar `DC-01`/`DC01` |
| `User` | **Sí** | 13 identidades estables |
| `Event_ID` | **Sí** | 15 tipos, semántica clara |
| `Log_ID` | **Sí** | Clave primaria perfecta para trazabilidad |
| `Source_IP` | **Solo para IPs externas** | Las internas no mapean a hosts (Q4) |
| `Destination` | **Parcialmente** | 36,6 % nulo; mezcla hostnames, `host:puerto` y rutas UNC |
| `Process_CommandLine` | **Parcialmente** | Solo 21,7 % de las filas |
| `Event_Description` | **Parcialmente** | Texto libre; contiene datos clave (`LogonType=10`, `parent=`, nombre de archivo) que no están en columnas propias |
| `Severity` | **No** | Inconsistente (Q8) |
| `Result` | **Parcialmente** | Semántica heterogénea |

---

## 6. Secuencias observadas (candidatas a incidente)

> En cada caso se separa **hecho observado** (lo que dicen los registros) de **hipótesis** (lo que podría significar). Ninguna secuencia se declara incidente confirmado.

### C1 — Rociado de credenciales contra DC-01 desde IP externa

**Hechos observados**

- 33 eventos `4625` con `Source_IP = 203.0.113.74` contra `Hostname = DC-01`, entre `08:25:00` y `08:35:08`.
- Afectan a **8 cuentas distintas**: `jlopez` (5), `aperez` (4), `helpdesk` (4), `mgarcia` (4), `rrojas` (4), `slopez` (4), `backupsvc` (4), `dtorres` (4).
- Cadencia **exactamente regular de 19 segundos** entre intentos consecutivos (33 eventos, 32 intervalos, todos de 19 s).
- Descripción constante: `An account failed to log on - bad password`.
- `Log_ID`: `EVT-00057, 00058, 00060, 00061, 00063, 00065, 00066, 00068, 00069, 00071, 00073, 00074, 00075, 00077, 00078, 00079, 00081, 00084, 00085, 00086, 00088, 00092, 00094, 00096, 00099, 00100, 00101, 00104, 00105, 00107, 00108, 00110, 00111`.
- **3 min 52 s después** del último fallo: `EVT-00123` — `4624` exitoso de `CORP\mgarcia` en `DC-01` desde la **misma IP** `203.0.113.74`, `08:39:00`, `Severity=Informational`.
- **1 minuto después**: `EVT-00126` — `4672` ("Special privileges assigned to new logon") de `CORP\mgarcia` en `WS-031`, también con `Source_IP=203.0.113.74`, `08:40:00`.
- No existe en el dataset un `4624` previo de `mgarcia` en `WS-031` desde esa IP que explique el `4672` (posible hueco de telemetría).
- Contexto de baseline: `mgarcia` tiene 66 eventos; solo 6 involucran `203.0.113.74` (4 fallos + 1 logon + 1 `4672`). Sus demás accesos provienen de IPs internas.

**Indicadores sospechosos**

- Múltiples cuentas atacadas desde una IP externa (patrón de *password spraying*, no de fuerza bruta sobre una sola cuenta).
- Cadencia automatizada perfecta.
- Logon exitoso desde la misma IP externa minutos después.
- Asignación de privilegios especiales inmediatamente después, en otro host.

**Hipótesis**

- H1.1: un actor externo roció credenciales y **obtuvo acceso válido** con `CORP\mgarcia`, y luego se movió a `WS-031`.
- H1.2 (alternativa): `mgarcia` se autenticó legítimamente desde una ubicación externa (VPN/teletrabajo) y los fallos previos son intentos del mismo usuario con contraseña desactualizada.

**Por qué no se confirma:** no hay evidencia de que la IP externa sea maliciosa, ni logs de VPN/MFA, ni `4740` (bloqueo de cuenta), ni `4771` (Kerberos), ni el `4624` que precede al `4672` en `WS-031`. El propio dataset marca el logon exitoso como `Informational`, lo que sugiere —pero no prueba— que el generador no lo consideró malicioso.

**Falsos positivos posibles:** usuario legítimo viajando; servicio mal configurado con credenciales vencidas; prueba de penetración autorizada.

---

### C2 — Acceso RDP a APP-SRV01, reconocimiento, acceso a Finance y conexión saliente

**Hechos observados** (todos con `Source_IP = 198.51.100.77` salvo donde se indica)

| Log_ID | Timestamp | Host | Event_ID | Detalle |
|---|---|---|---|---|
| `EVT-00174` | 09:02:00 | APP-SRV01 | 4625 | `CORP\admin`, `LogonType=10; RDP`, `Medium` |
| `EVT-00175` | 09:03:00 | APP-SRV01 | 4625 | idem |
| `EVT-00178` | 09:04:00 | APP-SRV01 | 4625 | idem |
| `EVT-00180` | 09:05:00 | APP-SRV01 | 4625 | idem |
| `EVT-00188` | 09:06:00 | APP-SRV01 | 4624 | `LogonType=10; RDP`, `High` |
| `EVT-00193` | 09:07:00 | APP-SRV01 | 4672 | Privilegios especiales, `Medium` |
| `EVT-00198` | 09:09:00 | APP-SRV01 | 4688 | `powershell.exe -NoProfile -EncodedCommand [REDACTED_SYNTHETIC]`, `parent=cmd.exe`, `High` |
| `EVT-00207` | 09:11:00 | APP-SRV01 | 4104 | `Get-LocalGroupMember Administrators; Get-SmbShare`, `High` |
| `EVT-00214` | 09:13:00 | APP-SRV01 | 4688 | `net.exe view \\FS-SRV01`, `parent=powershell.exe`, `Medium` |
| `EVT-00222` | 09:15:00 | FS-SRV01 | 4625 | `LogonType=3; source=APP-SRV01` |
| `EVT-00225` | 09:16:00 | FS-SRV01 | 4624 | `LogonType=3; source=APP-SRV01`, `High` |
| `EVT-00227` | 09:17:00 | FS-SRV01 | 5140 | `\\FS-SRV01\Finance`, `High` |
| `EVT-00231` | 09:18:00 | FS-SRV01 | 5145 | `Finance\Budget2027.xlsx`, `High` |
| `EVT-00232` | 09:20:00 | APP-SRV01 | 4688 | `tar.exe -a -c -f C:\Temp\finance.zip C:\Temp\reports`, `High` |
| `EVT-00235` | 09:21:00 | APP-SRV01 | 5156 | Salida permitida a `203.0.113.88:443`, `process=powershell.exe`, `High` |
| `EVT-00237` | 09:22:00 | APP-SRV01 | 4634 | Logoff de `CORP\admin` |

- Los 4 fallos RDP están separados por **exactamente 60 segundos**.
- La sesión completa dura **16 minutos** (`09:06` → `09:22`).
- `EVT-00235` tiene `Source_IP=10.10.2.15` pese a pertenecer a la sesión de `admin` (inconsistencia Q4/Q5).

**Indicadores sospechosos**

- RDP desde IP externa a un servidor de aplicaciones con cuenta privilegiada.
- Ejecución de PowerShell con `-EncodedCommand` (ofuscación).
- Reconocimiento explícito: grupos locales de administradores, shares, `net view`.
- Acceso a un recurso compartido financiero y a un archivo concreto (`Budget2027.xlsx`).
- Empaquetado con `tar` hacia `C:\Temp` (staging).
- Conexión saliente a IP externa usando `powershell.exe`.

**Hipótesis**

- H2.1: intrusión con credenciales de `CORP\admin` → reconocimiento → recolección → staging → exfiltración/C2.
- H2.2: actividad administrativa legítima de un administrador remoto (mantenimiento, inventario, backup manual).

**Por qué no se confirma:** no hay contenido del comando codificado, ni hashes, ni tamaño del archivo `finance.zip`, ni tráfico de salida medido en `EVT-00235` (no hay bytes), ni evidencia de que `203.0.113.88` sea un destino malicioso.

**Falsos positivos posibles:** tareas de administración legítimas, scripts de inventario, backup ad hoc, prueba autorizada.

---

### C3 — Lectura masiva de Finance y eliminación de shadow copies (cuenta `backupsvc`)

**Hechos observados**

| Log_ID | Timestamp | Host | Event_ID | Detalle |
|---|---|---|---|---|
| `EVT-00280` | 09:36:00 | WS-023 | 4688 | `powershell.exe -NoProfile -EncodedCommand <base64_redacted>`, `Warning` |
| `EVT-00284` | 09:37:00 | FS-SRV01 | 4663 | `Finance\FY2026\document_000.xlsx` |
| `EVT-00286` | 09:37:16 | FS-SRV01 | 4663 | `document_001.xlsx` |
| `EVT-00289` | 09:37:32 | FS-SRV01 | 4663 | `document_002.xlsx` |
| `EVT-00290` | 09:37:48 | FS-SRV01 | 4663 | `document_003.xlsx` |
| `EVT-00291` | 09:38:04 | FS-SRV01 | 4663 | `document_004.xlsx` |
| `EVT-00293` | 09:38:20 | FS-SRV01 | 4663 | `document_005.xlsx` |
| `EVT-00296` | 09:38:36 | FS-SRV01 | 4663 | `document_006.xlsx` |
| `EVT-00298` | 09:38:52 | FS-SRV01 | 4663 | `document_007.xlsx` |
| `EVT-00300` | 09:39:08 | FS-SRV01 | 4663 | `document_008.xlsx` |
| `EVT-00302` | 09:39:24 | FS-SRV01 | 4663 | `document_009.xlsx` |
| `EVT-00303` | 09:39:40 | FS-SRV01 | 4663 | `document_010.xlsx` |
| `EVT-00305` | 09:39:56 | FS-SRV01 | 4663 | `document_011.xlsx` |
| `EVT-00306` | 09:40:12 | FS-SRV01 | 4663 | `document_012.xlsx` |
| `EVT-00307` | 09:40:28 | FS-SRV01 | 4663 | `document_013.xlsx` |
| `EVT-00308` | 09:40:44 | FS-SRV01 | 4663 | `document_014.xlsx` |
| `EVT-00309` | 09:41:00 | FS-SRV01 | 4663 | `document_015.xlsx` |
| `EVT-00314` | 09:42:00 | WS-023 | 4688 | `vssadmin.exe delete shadows /all /quiet` |
| `EVT-00315` | 09:43:00 | FS-SRV01 | 5145 | Comprobación de acceso a `\\FS-SRV01\Finance` |

- Los 16 accesos a archivo ocurren cada **exactamente 16 segundos**, todos con `User=CORP\backupsvc`, `Hostname=FS-SRV01`, `Source_IP=10.10.1.44`, `Destination=\\FS-SRV01\Finance`, `Severity=Warning`.
- En el workbook se observaron 64 eventos `4663`. En el grupo `(User, Hostname, Destination)` indicado, los 16 valores de `Process_CommandLine` son strings no vacíos y literalmente distintos. Con R07/1.0, la ventana deslizante alcanza el umbral en el ancla `EVT-00302` (`09:39:24`): los primeros 10 accesos `EVT-00284`, `EVT-00286`, `EVT-00289`, `EVT-00290`, `EVT-00291`, `EVT-00293`, `EVT-00296`, `EVT-00298`, `EVT-00300` y `EVT-00302` están dentro de `(09:29:24, 09:39:24]`. Las ventanas calificadas posteriores se consolidan en una observación con las 16 evidencias de la secuencia, ordenadas por timestamp y `Log_ID`.
- `EVT-00280` y `EVT-00314` comparten usuario y `Source_IP` (`10.10.1.44`) pero ocurren en `WS-023`, no en `FS-SRV01`.

**Indicadores sospechosos**

- Secuencia automatizada de lectura de 16 archivos financieros en 4 minutos.
- `vssadmin delete shadows /all /quiet` es una técnica clásica de anti-recuperación / pre-ransomware.
- Uso de PowerShell codificado en la misma ventana temporal.

**Hipótesis**

- H3.1: compromiso de la cuenta de backup → recolección de datos financieros → destrucción de shadow copies para impedir recuperación.
- H3.2: tarea de backup legítima que lee archivos en lote; el `vssadmin` podría ser parte del ciclo normal de backup.

**Por qué no se confirma:** `backupsvc` es una cuenta de servicio con acceso amplio (76 eventos en 9 hosts) y 13 logons fallidos; leer archivos es *esperable* para un backup. No hay evidencia de cifrado, ni de exfiltración asociada a esta cuenta, ni de que `vssadmin` haya tenido efecto (no hay `7036` de parada de servicio en la ventana `09:40`–`09:45`).

**Falsos positivos posibles:** backup programado, indexación, antivirus, script de mantenimiento.

---

### C4 — Archivo comprimido y transferencia saliente masiva (WS-018)

**Hechos observados**

| Log_ID | Timestamp | Host | Event_ID | Detalle |
|---|---|---|---|---|
| `EVT-00419` | 10:40:00 | FS-SRV01 | 5140 | `CORP\rrojas` accede a `\\FS-SRV01\Legal`, `Source_IP=10.10.1.31` |
| `EVT-00428` | 10:42:00 | WS-018 | 4688 | `7z.exe a C:\Users\Public\archive.7z C:\Legal\*.docx`, `Severity=Informational` |
| `EVT-00430` | 10:43:00 | WS-018 | PROXY_ACCESS | `bytes_out=6737085 uri=/upload/session/1` → `198.51.100.88:443` |
| `EVT-00431` … `EVT-00461` | 10:43:18 → 10:49:18 | WS-018 | PROXY_ACCESS | 21 POST más, `/upload/session/2` … `/upload/session/22` |

- **22 POST HTTPS** a `198.51.100.88:443`, todos con `User=CORP\rrojas`, `Hostname=WS-018`, `Result=Allowed`, `Severity=Warning`.
- Cadencia **exactamente regular de 18 segundos**; duración total 6 min 18 s.
- Suma de `bytes_out`: **253.305.558 bytes ≈ 241,6 MiB**; mínimo 5.846.865 B, máximo 17.278.017 B.
- `Log_ID` completos: `EVT-00430, 00431, 00432, 00435, 00436, 00438, 00439, 00440, 00441, 00443, 00444, 00445, 00448, 00450, 00451, 00453, 00455, 00456, 00457, 00458, 00460, 00461`.
- Inconsistencia observada: el share accedido está en `FS-SRV01` (`\\FS-SRV01\Legal`) pero `7z` comprime una ruta local `C:\Legal\*.docx` en `WS-018`.

**Indicadores sospechosos**

- Compresión de documentos con herramienta de archivo hacia una ruta pública (`C:\Users\Public`).
- Transferencia saliente automatizada, volumétrica y sostenida a una única IP externa.
- Proximidad temporal (2 minutos) entre el acceso al share `Legal` y el archivado.

**Hipótesis**

- H4.1: recolección y exfiltración de documentos legales.
- H4.2: sincronización legítima a un servicio en la nube (el destino usa 443 y un endpoint `/upload/session/N`).

**Por qué no se confirma:** no hay hashes ni nombres de los archivos comprimidos, no se conoce el destino real de `198.51.100.88`, y la ruta archivada no coincide con el share accedido. El volumen (241,6 MiB) es un hecho, no una prueba de exfiltración.

**Falsos positivos posibles:** backup a la nube, envío legítimo de documentación, herramienta de sincronización corporativa.

---

### C5 — Persistencia en APP-SRV01 (tarea programada + servicio)

**Hechos observados**

| Log_ID | Timestamp | Host | Event_ID | Detalle |
|---|---|---|---|---|
| `EVT-00519` | 11:35:00 | APP-SRV01 | 4624 | `CORP\helpdesk` desde `10.10.3.18` |
| `EVT-00523` | 11:37:00 | APP-SRV01 | 4698 | `TaskName=\Microsoft\Windows\UpdateCheck; Action=powershell.exe -File C:\ProgramData\updatecheck.ps1` |
| `EVT-00524` | 11:38:00 | APP-SRV01 | 7045 | `ServiceName=WinUpdateHelper; ImagePath=C:\ProgramData\wuhelper.exe` |
| `EVT-00528` | 11:40:00 | APP-SRV01 | 4688 | `C:\ProgramData\wuhelper.exe` |
| `EVT-00542` | 11:46:00 | APP-SRV01 | 4688 | `C:\ProgramData\wuhelper.exe` |
| `EVT-00548` | 11:52:00 | APP-SRV01 | 4688 | `C:\ProgramData\wuhelper.exe` |
| `EVT-00559` | 11:58:00 | APP-SRV01 | 4688 | `C:\ProgramData\wuhelper.exe` |
| `EVT-00564` | 12:04:00 | APP-SRV01 | 4688 | `C:\ProgramData\wuhelper.exe` |

- Las 5 ejecuciones de `wuhelper.exe` ocurren cada **exactamente 6 minutos**.
- Nombres que imitan componentes legítimos de Windows (`UpdateCheck`, `WinUpdateHelper`) y binario en `C:\ProgramData`.

**Indicadores sospechosos**

- Mecanismo de persistencia doble (tarea programada + servicio).
- Ejecución periódica automatizada desde una ruta escribible por usuarios.
- *Masquerading* (nombres que aparentan ser de Windows Update).

**Hipótesis**

- H5.1: el actor de C2 (o un segundo actor) estableció persistencia en APP-SRV01 usando credenciales de `helpdesk`.
- H5.2: despliegue legítimo de software por parte de soporte técnico.

**Por qué no se confirma:** no hay hash ni firma de `wuhelper.exe`, no hay contenido de `updatecheck.ps1`, y `helpdesk` es una cuenta con actividad legítima esperable en soporte. No hay evidencia de que el binario sea malicioso.

**Falsos positivos posibles:** herramienta de actualización corporativa real, script de soporte, instalación autorizada.

---

### C6 — Enumeración web y ejecución de comandos en WEB-01

**Hechos observados**

| Log_ID | Timestamp | Ruta solicitada | HTTP |
|---|---|---|---|
| `EVT-00571` | 12:10:00 | `/uploads/test.aspx?cmd=whoami` | 200 |
| `EVT-00572` | 12:10:12 | `/login?user=admin` | 200 |
| `EVT-00573` | 12:10:24 | `/uploads/test.aspx?cmd=whoami` | 404 |
| `EVT-00574` | 12:10:36 | `/uploads/test.aspx?cmd=whoami` | 404 |
| `EVT-00576` | 12:10:48 | `/admin/` | 500 |
| `EVT-00577` | 12:11:00 | `/api/v1/export` | 200 |
| `EVT-00579` | 12:11:12 | `/login?user=admin` | 200 |
| `EVT-00581` | 12:11:24 | `/admin/` | 500 |
| `EVT-00582` | 12:11:36 | `/api/v1/export` | 404 |
| `EVT-00583` | 12:11:48 | `/admin/` | 500 |
| `EVT-00584` | 12:12:00 | `/admin/` | 500 |
| `EVT-00585` | 12:12:12 | `/admin/` | 404 |
| `EVT-00586` | 12:12:24 | `/login?user=admin` | 500 |
| `EVT-00588` | 12:12:36 | `/api/v1/export` | 404 |
| `EVT-00589` | 12:12:48 | `/login?user=admin` | 500 |
| `EVT-00590` | 12:13:00 | `/api/v1/export` | 500 |
| `EVT-00591` | 12:13:12 | `/login?user=admin` | 404 |
| `EVT-00592` | 12:13:24 | `/login?user=admin` | 200 |
| `EVT-00593` | 12:13:36 | `/login?user=admin` | 500 |
| `EVT-00595` | 12:13:48 | `/login?user=admin` | 500 |
| `EVT-00596` | 12:14:00 | `/api/v1/export` | 200 |
| `EVT-00599` | **12:15:00** | `cmd.exe /c whoami` (4688) | — |

- 21 peticiones HTTP desde `192.0.2.91`, cadencia **exactamente regular de 12 segundos**, entre `12:10:00` y `12:14:00`.
- `User = "-"` en todas las peticiones (no autenticado).
- Códigos: 200 ×6, 404 ×6, 500 ×9.
- 1 minuto después: `EVT-00599`, `4688` en `WEB-01`, usuario **`IIS APPPOOL\DefaultAppPool`**, comando `cmd.exe /c whoami`.

**Indicadores sospechosos**

- Sondeo automatizado de rutas sensibles (`/admin/`, `/login`, `/api/v1/export`).
- Intento explícito de ejecución de comandos vía parámetro (`?cmd=whoami`) y subida de un `.aspx`.
- Creación de proceso `cmd.exe` bajo la identidad del pool de aplicaciones (patrón típico de *web shell* / RCE).

**Hipótesis**

- H6.1: explotación de la aplicación web con ejecución remota de comandos y posible *web shell*.
- H6.2: escaneo automatizado de vulnerabilidades o prueba autorizada.

**Por qué no se confirma:** no hay evidencia de escritura del archivo `.aspx`, ni `4104`, ni conexiones salientes desde `WEB-01`, ni respuesta con contenido. El `200` inicial seguido de `404` es ambiguo (pudo existir el recurso y luego eliminarse, o ser una respuesta inconsistente del generador).

**Falsos positivos posibles:** escáner de vulnerabilidades corporativo, *health check* agresivo, prueba de QA.

---

## 7. Hechos, indicadores, hipótesis y datos insuficientes

| Elemento | Clasificación | Justificación |
|---|---|---|
| 33 `4625` en 10 min desde `203.0.113.74` contra 8 cuentas | **Hecho observado** | Registros presentes y contados |
| Cadencia exacta de 19 s | **Hecho observado** | 32 intervalos idénticos |
| `4624` de `mgarcia` desde la misma IP 3m52s después | **Hecho observado** | `EVT-00123` |
| `4672` en `WS-031` desde la misma IP | **Hecho observado** | `EVT-00126` |
| "El atacante obtuvo acceso" | **Hipótesis** | Falta evidencia de VPN/MFA/bloqueo de cuenta |
| RDP + PowerShell codificado + recon + Finance + `tar` + salida externa | **Hecho observado** (cada paso) | `EVT-00174`…`EVT-00237` |
| "Exfiltración de Finance" | **Hipótesis** | No hay bytes, ni destino del archivo, ni contenido del comando |
| 16 lecturas de Finance cada 16 s | **Hecho observado** | `EVT-00284`…`EVT-00309` |
| "Pre-ransomware" | **Hipótesis** | Solo hay `vssadmin`; no hay cifrado ni nota de rescate |
| 22 POST de 241,6 MiB a una IP externa | **Hecho observado** | `EVT-00430`…`EVT-00461` |
| "Exfiltración de documentos legales" | **Hipótesis** | La ruta archivada no coincide con el share |
| Tarea programada + servicio + 5 ejecuciones | **Hecho observado** | `EVT-00523`…`EVT-00564` |
| "Persistencia maliciosa" | **Hipótesis** | Sin hash/firma del binario |
| 21 peticiones web + `cmd.exe /c whoami` | **Hecho observado** | `EVT-00571`…`EVT-00599` |
| "Web shell / RCE exitoso" | **Hipótesis** | Sin evidencia de escritura ni de salida |
| Autoría común de C1–C6 | **Dato insuficiente** | IPs distintas, usuarios distintos, sin telemetría de red que los una |

---

## 8. Datos insuficientes (no se puede concluir)

| Pregunta | Por qué no se puede responder |
|---|---|
| ¿Los 6 escenarios están relacionados entre sí? | No hay logs de red, DNS, proxy completo ni EDR que conecten las IPs externas |
| ¿`203.0.113.74`, `198.51.100.77`, `192.0.2.91` son maliciosas? | Son rangos RFC 5737; sin threat intelligence ni DNS |
| ¿Qué ejecutaba el PowerShell codificado? | Payload redactado (`[REDACTED_SYNTHETIC]`, `<base64_redacted>`) |
| ¿Se exfiltraron datos? | No hay tamaño de `finance.zip`/`archive.7z` ni contenido de los POST |
| ¿Se cifraron archivos? | No hay eventos de cifrado ni de ransomware |
| ¿Hubo movimiento lateral real? | `Source_IP` no identifica hosts (Q4) y falta el `4624` que precede a `EVT-00126` |
| ¿`DC-01` y `DC01` son el mismo equipo? | Nombres distintos, ventanas temporales distintas, `DC01` sin `Destination` |
| ¿`backupsvc` y `svc_backup` son la misma identidad? | Nombres distintos y comportamiento distinto; no hay `4720`/`4738` que lo aclare |
| ¿Cuál es la línea base normal? | Solo 6 horas de un día, sin histórico |

---

## 9. Reglas de detección candidatas

> Cada regla se apoya en campos y eventos **realmente presentes**. La severidad propuesta es independiente del nivel de confianza.

### R01 — Rociado de credenciales (múltiples cuentas, mismo origen)

- **Objetivo:** detectar intentos de autenticación fallidos distribuidos entre varias cuentas desde un mismo origen.
- **Condición:** `Event_ID = 4625` agrupado por `Source_IP` en ventana de 10 min; alertar si `count >= 5` **y** `distinct(User) >= 3`.
- **Campos:** `Timestamp`, `Source_IP`, `User`, `Hostname`, `Result`.
- **Event_ID:** 4625.
- **Ventana:** 10 minutos.
- **Umbral justificado:** de los 102 `4625`, **61 son eventos aislados** (grupos de tamaño 1 sobre `(Hostname, User, Source_IP)`); la distribución de tamaños de grupo es `{1: 61, 2: 2, 4: 8, 5: 1}`. Los únicos grupos con ≥4 son los 8 de `203.0.113.74` y el de `CORP\admin` en `APP-SRV01` (4 en 3 min).
- **Evidencias esperadas:** lista de `Log_ID`, usuarios objetivo, primer/último intento, cadencia.
- **Severidad:** HIGH si `Source_IP` es externa; MEDIUM si es interna.
- **Falsos positivos:** usuario con contraseña vencida en varios equipos, servicio mal configurado, pruebas de autenticación.
- **Limitaciones:** sin `4740`/`4771` no se distingue *spraying* de errores legítimos; requiere identificar IPs externas (las internas no mapean a host, Q4).

### R02 — Logon exitoso posterior a fallos

- **Objetivo:** detectar acceso concedido después de una ráfaga de fallos.
- **Condición:** ≥3 `4625` para el mismo `(User, Hostname)` y luego un `4624` del mismo `(User, Hostname)` en ≤15 min.
- **Campos:** `Timestamp`, `User`, `Hostname`, `Source_IP`, `Event_Description` (para `LogonType`).
- **Event_ID:** 4625, 4624.
- **Ventana:** 15 minutos.
- **Evidencias esperadas:** `Log_ID` de fallos y del éxito, delta temporal, `LogonType`.
- **Severidad:** HIGH si el `4624` proviene de IP externa; MEDIUM en caso contrario.
- **Falsos positivos:** usuario que corrige la contraseña, `helpdesk` desbloqueando cuentas.
- **Limitaciones:** en el dataset, el éxito de `mgarcia` (`EVT-00123`) ocurre **3m52s** después del último fallo, pero no hay `4624` de `WS-031` que explique el `4672` (`EVT-00126`): la regla detectaría el caso de `DC-01`, no la cadena completa.

### R03 — Logon desde IP externa

- **Objetivo:** señalar autenticaciones desde fuera de los rangos internos.
- **Condición:** `Event_ID = 4624` y `Source_IP` fuera de `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- **Campos:** `Source_IP`, `User`, `Hostname`, `Timestamp`.
- **Event_ID:** 4624.
- **Ventana:** evento puntual (con contexto de ±10 min).
- **Evidencias esperadas:** `Log_ID`, usuario, host, IP, `LogonType`.
- **Severidad:** MEDIUM por defecto; HIGH si el usuario es privilegiado (`admin`) o si hay `4625` previos.
- **Falsos positivos:** VPN corporativa, teletrabajo, proveedores.
- **Limitaciones:** el dataset no distingue VPN de Internet; solo 2 eventos `4624` externos (`EVT-00123`, `EVT-00188`).

### R04 — RDP desde IP externa

- **Objetivo:** detectar escritorio remoto entrante desde fuera.
- **Condición:** `Event_ID = 4624` y `Event_Description` contiene `LogonType=10` y `Source_IP` externa.
- **Campos:** `Event_Description`, `Source_IP`, `User`, `Hostname`.
- **Event_ID:** 4624.
- **Ventana:** evento puntual.
- **Evidencias esperadas:** `EVT-00188`.
- **Severidad:** HIGH.
- **Falsos positivos:** administración remota legítima.
- **Limitaciones:** `LogonType` **no es una columna**: solo existe como texto dentro de `Event_Description` en 2 filas (`EVT-00188`, `EVT-00225`). La regla depende de parsear texto libre.

### R05 — PowerShell ofuscado

- **Objetivo:** detectar ejecución de PowerShell con codificación o perfil evadido.
- **Condición:** `Event_ID = 4688` y `Process_CommandLine` contiene `-EncodedCommand`, `-enc `, `-NoProfile` o `FromBase64String`.
- **Campos:** `Process_CommandLine`, `User`, `Hostname`.
- **Event_ID:** 4688 (complementario: 4104).
- **Ventana:** evento puntual.
- **Evidencias esperadas:** `EVT-00198`, `EVT-00280`.
- **Severidad:** HIGH.
- **Falsos positivos:** scripts de administración legítimos, herramientas de terceros.
- **Limitaciones:** el payload está redactado (Q10); no se puede evaluar el contenido.

### R06 — Comandos de reconocimiento

- **Objetivo:** detectar enumeración de grupos, shares y recursos.
- **Condición:** `Event_ID` en (4688, 4104) y el texto contiene `net view`, `Get-SmbShare`, `Get-LocalGroupMember`, `whoami`, `net group`.
- **Campos:** `Process_CommandLine`, `Event_Description`.
- **Event_ID:** 4688, 4104.
- **Ventana:** agrupar en 10 min por `(User, Hostname)`.
- **Evidencias esperadas:** `EVT-00207` (`Get-LocalGroupMember`, `Get-SmbShare`), `EVT-00214` (`net view \\FS-SRV01`), `EVT-00599` (`cmd.exe /c whoami`).
- **Severidad:** MEDIUM; HIGH si se combina con R05 o R02.
- **Falsos positivos:** inventario de TI, scripts de monitoreo, soporte.
- **Limitaciones:** solo 155 filas tienen `Process_CommandLine`.

### R07 — Lectura masiva de archivos en un share

- **Objetivo:** detectar recolección de archivos a escala.
- **Condición:** `Event_ID = 4663` agrupado por `(User, Hostname, Destination)`; alertar si `count(distinct Process_CommandLine) >= 10` en 10 min.
- **Campos:** `Timestamp`, `User`, `Hostname`, `Destination`, `Process_CommandLine`.
- **Event_ID:** 4663.
- **Ventana:** 10 minutos.
- **Umbral justificado:** fuera de la ráfaga, el máximo observado por `(usuario, host)` es **5** accesos `4663` (distribución `{1: 24, 2: 8, 3: 1, 5: 1}`); la ráfaga tiene **16** en 4 min.
- **Evidencias esperadas:** `EVT-00284`…`EVT-00309` (16 archivos).
- **Especificación R07/1.0:** ventana deslizante `(t - 10 minutos, t]`, por cada evento ancla; clave literal `(User, Hostname, Destination)`; al menos 10 valores literalmente distintos de `Process_CommandLine`. Los valores nulos, vacíos y solo con espacios no cuentan. Los duplicados idénticos por `Log_ID` cuentan una vez y todas las versiones de un ID conflictivo se excluyen. Ventanas calificadas de una clave se consolidan en una observación sin evidencias duplicadas.
- **Estado de implementación:** R07/1.0 está integrada en el pipeline. Para el workbook original, se observó una detección en la clave descrita, con las 16 evidencias enumeradas arriba. La severidad propuesta en análisis anteriores no está ratificada y no se asigna.
- **Falsos positivos:** backup, indexación, antivirus, migraciones.
- **Limitaciones:** `Process_CommandLine` se usa aquí como contenedor del nombre de archivo (`File access: ...`), no como línea de comandos real: **es una convención del dataset**, no un campo estándar de Windows.

### R08 — Herramienta de archivado hacia ruta temporal/pública

- **Especificación R08/1.0:** ver decisiones ratificadas en `PHASE4_DECISIONS.md`. La regla reconoce tokens exactos de `7z.exe`/`7z`, `rar.exe`/`rar`, `tar.exe`/`tar` y `Compress-Archive`; clasifica como `local_staging` las salidas explícitas en `C:\Temp`, `%TEMP%` o `C:\Users\Public`, y como `network_destination` las rutas UNC inequívocas. No expande `%TEMP%` ni interpreta una ruta local como destino público de Internet.
- **Correlación:** por cada evento `4688`, se asocian evidencias únicamente de findings R07 y/o R09 ya calificados, con `Hostname` y `User` idénticos y timestamp en `[t_R08 - 15 min, t_R08 + 15 min]`, extremos incluidos. OR basta; se conservan ambas relaciones si están presentes. La asociación no demuestra causalidad, transferencia exitosa, exfiltración ni impacto.
- **Parser:** `7z`/`rar` requiere operación `a` seguida inmediatamente por el archivo de salida; `tar` requiere modo creación `-c` y salida `-f`/`--file`; `Compress-Archive` requiere `-DestinationPath`. Formas no inequívocas o fuera de esta sintaxis se excluyen.
- **Resultado en el workbook original:** SHA-256 `0e5d5de56da596bf6b279a07f51e29498ad86782256cd842f42328543708a0c9`, 715 filas. `EVT-00232` (09:20, `APP-SRV01`, `CORP\admin`, `tar.exe` → `C:\Temp\finance.zip`) no tiene relación R07/R09 con identidad exacta dentro de ±15 minutos. `EVT-00428` (10:42, `WS-018`, `CORP\rrojas`, `7z.exe` → `C:\Users\Public\archive.7z`) se relaciona con R09: 22 evidencias proxy, desde `EVT-00430` (10:43) hasta `EVT-00461` (10:49:18), mismo host/usuario y dentro de la ventana. Resultado: una observación R08 con `EVT-00428` y esas 22 evidencias R09 ordenadas por timestamp y `Log_ID`.
- **Puntuación/severidad:** R08 no tiene cap de nivel ni confidence; `.7500` es referencia, no score forzado. E/K no evaluables mantiene score/confidence nulos. Severidad no ratificada y no asignada.
- **Limitaciones y falsos positivos:** no hay tamaño ni hash del archivo generado; una compresión y una transferencia próximas pueden ser actividad legítima o no guardar relación causal. La IP `198.51.100.88` está clasificada como `documentation`, no como destino público operativo.

### R09 — Transferencia saliente volumétrica

- **Alcance de esta sección:** perfil del patrón observado en el dataset.
  La especificación metodológica ratificada es [R09/1.0](./PHASE4_DECISIONS.md);
  esta descripción histórica no define criterios distintos.
- **Patrón observado:** 22 registros `PROXY_ACCESS` en el mismo grupo del dataset, con `bytes_out` incluido en `Process_CommandLine`; la suma observada se presenta como dato del workbook y no como prueba de exfiltración.
- **Criterio ratificado:** ventana deslizante de 15 minutos, anclada en cada evento elegible, intervalo `(t - 15 minutos, t]`, clave `(Hostname, User, Destination)`, eventos únicos por `Log_ID`, y `count >= 10 OR observed_bytes_out_sum >= 52,428,800`, con umbrales inclusivos. El detalle de duplicados, valores de bytes inválidos, claves incompletas y consolidación está en R09/1.0.
- **Campos:** `Timestamp`, `Hostname`, `User`, `Destination`, `Process_CommandLine` (parseo de `bytes_out=`).
- **Event_ID usado por R09:** `PROXY_ACCESS`; el campo `Log_Source` del workbook
  contiene `Proxy`, por lo que no se usa como selector.
- **Registros observados:** `EVT-00430`…`EVT-00461`.
- **Severidad:** la sugerencia HIGH de este análisis de dataset no constituye una decisión ratificada. Si una detección califica exclusivamente por bytes, `severity_eligible=false`.
- **Falsos positivos:** backup a nube, sincronización, actualizaciones, videollamadas.
- **Implementación:** R09/1.0 está integrada en el pipeline y produce una
  observación consolidada para los 22 registros del grupo de este patrón; las
  evidencias se limitan a registros participantes de ventanas calificadas.
- **Limitaciones:** `bytes_out` está **embebido en texto** dentro de `Process_CommandLine`; el dataset no tiene `bytes_in` ni dominio de destino. Los bytes observados no prueban transferencia exitosa, impacto ni intención maliciosa.

### R10 — Eliminación de shadow copies

- **Objetivo:** detectar anti-recuperación.
- **Condición:** `Event_ID = 4688` y `Process_CommandLine` contiene `vssadmin` + `delete` + `shadows`, o `wmic shadowcopy delete`, o `bcdedit` con `recoveryenabled no`.
- **Campos:** `Process_CommandLine`, `User`, `Hostname`.
- **Event_ID:** 4688.
- **Ventana:** evento puntual; correlacionar ±30 min con R07/R08.
- **Evidencias esperadas:** `EVT-00314`.
- **Severidad:** HIGH.
- **Falsos positivos:** mantenimiento de disco, scripts de backup que recrean shadow copies.
- **Limitaciones:** no hay evidencia de que el comando haya tenido éxito (solo su ejecución).

### R11 — Persistencia vía tarea programada o servicio

- **Objetivo:** detectar mecanismos de persistencia.
- **Condición:** `Event_ID = 4698` **o** `7045`, y el `Process_CommandLine` referencia rutas en `C:\ProgramData`, `C:\Temp`, `C:\Users\Public` o `%APPDATA%`.
- **Campos:** `Process_CommandLine`, `User`, `Hostname`, `Timestamp`.
- **Event_ID:** 4698, 7045.
- **Ventana:** agrupar por `(User, Hostname)` en 30 min.
- **Evidencias esperadas:** `EVT-00523` (tarea `UpdateCheck`), `EVT-00524` (servicio `WinUpdateHelper`), y las 5 ejecuciones `EVT-00528/00542/00548/00559/00564`.
- **Severidad:** HIGH si hay ambos mecanismos o ejecución periódica; MEDIUM si es uno solo.
- **Falsos positivos:** despliegue legítimo de software, agentes de TI.
- **Limitaciones:** sin hash/firma no se distingue software legítimo de malware; `4698`/`7045` son solo 1 evento cada uno en el dataset.

### R12 — Proceso hijo de un servicio web

- **Objetivo:** detectar ejecución de comandos desde el servidor web.
- **Condición:** `Event_ID = 4688` y `User` empieza con `IIS APPPOOL\` (o el padre es `w3wp.exe`) y el comando es `cmd.exe`, `powershell.exe`, `whoami`, `net.exe`.
- **Campos:** `User`, `Process_CommandLine`, `Event_Description` (padre).
- **Event_ID:** 4688.
- **Relación con R13:** independiente; no se correlaciona por proximidad temporal.
- **Evidencias esperadas:** `EVT-00599`.
- **Severidad:** pendiente de ratificación en Fase 4; R13 no la eleva.
- **Falsos positivos:** tareas legítimas de la aplicación, instaladores.
- **Limitaciones:** el dataset solo tiene 1 evento con identidad `IIS APPPOOL`; no hay `w3wp.exe` como proceso padre registrado.

### R13 — Enumeración web automatizada

- **Estado:** R13/1.0 implementada con criterios ratificados en `PHASE4_DECISIONS.md`.
- **Condición:** `Event_ID=HTTP_ACCESS`, agrupación por `Source_IP`, ventana deslizante `(t-5 min,t]`, `request_count >= 10` y (`error_rate >= 30%` o al menos una ruta sensible por segmento exacto).
- **Métricas:** `request_count` cuenta solicitudes únicas elegibles; `valid_result_count` cuenta códigos HTTP válidos 100–599; `error_count` cuenta 400–599; `error_rate=error_count/valid_result_count`. Resultados no interpretables no eliminan la solicitud del conteo y no entran en numerador/denominador. Si no hay resultado válido, la tasa es no calculable.
- **Rutas:** `/admin`, `/login`, `/api` y `/upload`; se ignora query/fragmento, se validan escapes y solo se comparan segmentos ASCII exactos sin distinguir mayúsculas. `/uploads` no coincide con `/upload`.
- **Integridad:** `Log_ID` textual no vacío; duplicados idénticos colapsados; todos los registros de un ID conflictivo excluidos. IP ausente/inválida y timestamp inválido no participan; las IP válidas de documentación se conservan como `documentation`, no como origen público operativo. Hostname y User no son requisitos.
- **Resultado observado:** el workbook original contiene 21 solicitudes HTTP, 21 IDs únicos, una IP `192.0.2.91` de categoría `documentation`, códigos 200 ×6, 404 ×6 y 500 ×9. La implementación emite una observación consolidada para esa IP, con 21 evidencias. La primera ventana calificante ancla en `EVT-00583`: 10 solicitudes, 10 resultados válidos, 6 errores (60%) y 7 solicitudes con ruta sensible. Esto describe solo registros observados; no confirma automatización, actividad maliciosa, éxito, impacto ni atribución.
- **R12:** regla independiente; no existe correlación ni elevación de severidad por proximidad temporal.
- **Severidad y puntuación:** severidad no ratificada. Score máximo 0.7500 y nivel máximo L1; score/confidence operativos siguen nulos mientras E/K no sean evaluables.
- **Limitaciones:** no hay User-Agent, método HTTP, tamaño de respuesta ni IP de destino real. El workbook no demuestra telemetría continua ni actividad fuera de su período observado. Escáner corporativo, monitoreo sintético y bots son posibles falsos positivos.

---

## 10. Reglas de la consigna que **no** se pueden implementar con este dataset

| Regla solicitada | Motivo de descarte |
|---|---|
| Creación de cuentas de usuario | No hay `4720` |
| Modificación de grupos privilegiados | No hay `4728`, `4732`, `4756` |
| Borrado de logs de seguridad | No hay `1102` |
| Transferencia de datos medida en bytes entrantes/salientes de red | Solo `PROXY_ACCESS` aporta `bytes_out`; `5156` no tiene bytes |
| Anomalía de red por volumen/puerto | `Destination` solo tiene 9 valores; sin puertos salvo `:443` |
| Acceso a archivos sensibles por nombre/ruta | Solo 16 eventos `4663` tienen nombre de archivo |
| Ejecución por proceso web (`w3wp.exe` → hijo) | No hay proceso padre estructurado; solo 1 evento con identidad de app pool |
| Correlación por IP interna → host | Imposible (Q4) |
| Detección de *beaconing* | Solo 67 eventos `5156`, sin periodicidad ni destino claro |

---

## 11. Evidencias necesarias para validar cada hipótesis

| Hipótesis | Evidencia adicional necesaria |
|---|---|
| H1.1 / H1.2 (spraying + acceso) | Logs de VPN/MFA de `mgarcia`; `4740` de bloqueo; `4771` Kerberos; geolocalización/horario laboral; confirmación de si `203.0.113.74` es un rango corporativo |
| H2.1 / H2.2 (RDP admin) | Contenido decodificado de `EVT-00198`; árbol de procesos EDR; `1149` (RDP); política de acceso remoto; hash de `finance.zip`; logs de DNS/proxy hacia `203.0.113.88` |
| H3.1 / H3.2 (backupsvc) | Ventana de backup programada; hash de los 16 archivos; estado de shadow copies (`vssadmin list shadows`); confirmación de si `backupsvc` debe leer `Finance` |
| H4.1 / H4.2 (exfiltración) | Nombre y tamaño de `archive.7z`; reputación de `198.51.100.88`; logs de proxy con dominio; política de subida a nube; si `C:\Legal` existe en `WS-018` |
| H5.1 / H5.2 (persistencia) | Hash y firma de `wuhelper.exe`; contenido de `updatecheck.ps1`; ticket de cambio de `helpdesk`; inventario de software autorizado |
| H6.1 / H6.2 (web) | Logs IIS con método, User-Agent y tamaño; contenido de `/uploads/test.aspx`; integridad del directorio de uploads; `4104` en `WEB-01`; conexiones salientes desde `WEB-01` |
| Autoría común | Logs de firewall perimetral, DNS, proxy completo y EDR con correlación temporal |

---

## 12. Falsos positivos a considerar por el motor

1. **Cuentas de servicio** (`backupsvc`, `svc_backup`) que leen muchos archivos por diseño.
2. **`helpdesk`** realizando tareas de soporte legítimas (tareas programadas, servicios, desbloqueos).
3. **`CORP\admin`** ejecutando herramientas administrativas legítimas.
4. **Usuarios con contraseña vencida** generando `4625` repetidos.
5. **Backups y sincronización a nube** produciendo tráfico saliente volumétrico.
6. **Escáneres de vulnerabilidades** generando `HTTP_ACCESS` con 404/500.
7. **`7036`** (servicio en ejecución) como ruido de fondo.
8. **Timestamps duplicados** que alteran el orden relativo de dos eventos en el mismo segundo.

---

## 13. Limitaciones del dataset (resumen)

1. **Ventana de 6 horas de un solo día**: no hay línea base histórica; los umbrales son heurísticos.
2. **`Source_IP` no identifica hosts internos**: impide correlación IP→host y limita el movimiento lateral.
3. **`Hostname` duplicado** (`DC-01`/`DC01`) y **cuentas casi homónimas** (`backupsvc`/`svc_backup`).
4. **`Severity` inconsistente**: no puede usarse como señal de detección.
5. **78,3 % de `Process_CommandLine` nulo** y **36,6 % de `Destination` nulo**.
6. **Payloads redactados**: no se puede analizar el contenido de los comandos ofuscados.
7. **Sin telemetría de red real** (sin bytes, sin DNS, sin puertos salvo 443).
8. **Sin hashes, PID, GUID ni árbol de procesos estructurado**.
9. **`Event_Description` es texto libre** que contiene datos clave no estructurados (`LogonType`, `parent`, nombre de archivo).
10. **Dataset sintético/anonimizado** (IPs RFC 5737): las conclusiones son válidas para el ejercicio, no para una red real.
11. **`Event_ID` de tipo mixto**: requiere normalización.
12. **Sin evidencia de éxito** de acciones destructivas (`vssadmin`): solo se registra la ejecución.

---

## 14. Conclusión

El dataset es **pequeño (715 filas), limpio en estructura y coherente en timestamps**, pero **limitado en telemetría**: no permite confirmar ningún incidente por sí solo. Contiene, sin embargo, **seis secuencias con indicadores fuertes y reproducibles**, todas construidas sobre `Log_ID` verificables:

| Secuencia | Ventana | Evidencia principal | Severidad propuesta | Confianza |
|---|---|---|---|---|
| C1 — Rociado de credenciales | 08:25:00–08:40:00 | `EVT-00057`…`EVT-00126` | HIGH | Media |
| C2 — RDP + recon + staging + salida | 09:02:00–09:22:00 | `EVT-00174`…`EVT-00237` | HIGH | Media-alta |
| C3 — Lectura Finance + `vssadmin` | 09:36:00–09:43:00 | `EVT-00280`…`EVT-00315` | HIGH | Media |
| C4 — Archivado + 241,6 MiB salientes | 10:40:00–10:49:18 | `EVT-00419`…`EVT-00461` | HIGH | Media |
| C5 — Persistencia (tarea + servicio) | 11:35:00–12:04:00 | `EVT-00519`…`EVT-00564` | HIGH | Media |
| C6 — Enumeración web + `cmd.exe` | 12:10:00–12:15:00 | `EVT-00571`…`EVT-00599` | HIGH | Media |

La **severidad** expresa impacto potencial; la **confianza** expresa cuán completa es la evidencia. Ninguna secuencia alcanza confianza alta porque faltan las fuentes externas listadas en la sección 11. Esta conclusión y la recomendación de Fase 3 que sigue corresponden a la evaluación del dataset fechada arriba; el estado actual del MVP se describe en [`PHASE4_DECISIONS.md`](./PHASE4_DECISIONS.md).

**Recomendación para la Fase 3:** implementar las reglas R01–R13 como funciones puras y deterministas sobre un `DataFrame` normalizado, con `Log_ID` como clave de trazabilidad, umbrales explícitos y tests que reproduzcan exactamente las secuencias C1–C6 y los falsos positivos de la sección 12.

---

## Anexo A — Distribución de severidad por `Event_ID`

| Event_ID | Informational | Warning | Medium | High |
|---|---:|---:|---:|---:|
| 7036 | 55 | 0 | 0 | 0 |
| 4625 | 64 | 33 | 5 | 0 |
| 4688 | 86 | 3 | 1 | 2 |
| 4634 | 94 | 0 | 0 | 0 |
| 4624 | 109 | 0 | 0 | 2 |
| 4663 | 48 | 16 | 0 | 0 |
| 5156 | 66 | 0 | 0 | 1 |
| 5140 | 73 | 0 | 0 | 1 |
| 4672 | 7 | 0 | 1 | 0 |
| 4104 | 0 | 0 | 0 | 1 |
| 5145 | 1 | 0 | 0 | 1 |
| PROXY_ACCESS | 0 | 22 | 0 | 0 |
| 4698 | 0 | 1 | 0 | 0 |
| 7045 | 0 | 1 | 0 | 0 |
| HTTP_ACCESS | 0 | 21 | 0 | 0 |

## Anexo B — Líneas de comando no triviales (todas las 155 no nulas, filtradas)

| Log_ID | Timestamp | Host | User | Comando |
|---|---|---|---|---|
| `EVT-00198` | 09:09:00 | APP-SRV01 | `CORP\admin` | `powershell.exe -NoProfile -EncodedCommand [REDACTED_SYNTHETIC]` |
| `EVT-00207` | 09:11:00 | APP-SRV01 | `CORP\admin` | `powershell.exe` (script block: `Get-LocalGroupMember Administrators; Get-SmbShare`) |
| `EVT-00214` | 09:13:00 | APP-SRV01 | `CORP\admin` | `net.exe view \\FS-SRV01` |
| `EVT-00232` | 09:20:00 | APP-SRV01 | `CORP\admin` | `tar.exe -a -c -f C:\Temp\finance.zip C:\Temp\reports` |
| `EVT-00280` | 09:36:00 | WS-023 | `CORP\backupsvc` | `powershell.exe -NoProfile -EncodedCommand <base64_redacted>` |
| `EVT-00314` | 09:42:00 | WS-023 | `CORP\backupsvc` | `vssadmin.exe delete shadows /all /quiet` |
| `EVT-00428` | 10:42:00 | WS-018 | `CORP\rrojas` | `7z.exe a C:\Users\Public\archive.7z C:\Legal\*.docx` |
| `EVT-00523` | 11:37:00 | APP-SRV01 | `CORP\helpdesk` | `TaskName=\Microsoft\Windows\UpdateCheck; Action=powershell.exe -File C:\ProgramData\updatecheck.ps1` |
| `EVT-00524` | 11:38:00 | APP-SRV01 | `CORP\helpdesk` | `ServiceName=WinUpdateHelper; ImagePath=C:\ProgramData\wuhelper.exe` |
| `EVT-00528` | 11:40:00 | APP-SRV01 | `CORP\helpdesk` | `C:\ProgramData\wuhelper.exe` |
| `EVT-00542` | 11:46:00 | APP-SRV01 | `CORP\helpdesk` | `C:\ProgramData\wuhelper.exe` |
| `EVT-00548` | 11:52:00 | APP-SRV01 | `CORP\helpdesk` | `C:\ProgramData\wuhelper.exe` |
| `EVT-00559` | 11:58:00 | APP-SRV01 | `CORP\helpdesk` | `C:\ProgramData\wuhelper.exe` |
| `EVT-00564` | 12:04:00 | APP-SRV01 | `CORP\helpdesk` | `C:\ProgramData\wuhelper.exe` |
| `EVT-00599` | 12:15:00 | WEB-01 | `IIS APPPOOL\DefaultAppPool` | `cmd.exe /c whoami` |
| `EVT-00284`…`EVT-00309` | 09:37–09:41 | FS-SRV01 | `CORP\backupsvc` | `File access: Finance\FY2026\document_000..015.xlsx` (16 eventos) |
| `EVT-00430`…`EVT-00461` | 10:43–10:49 | WS-018 | `CORP\rrojas` | `bytes_out=... uri=/upload/session/1..22` (22 eventos) |
| `EVT-00571`…`EVT-00596` | 12:10–12:14 | WEB-01 | `-` | URIs HTTP: `/uploads/test.aspx?cmd=whoami`, `/login?user=admin`, `/admin/`, `/api/v1/export` |

**Comandos de fondo considerados normales** (no listados): `explorer.exe` (64), `taskhostw.exe` (6), `notepad.exe` (6), `svchost.exe` (4).
