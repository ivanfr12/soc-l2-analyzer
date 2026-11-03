# SOC L2 Analyzer

Backend en Python para validar y analizar parcialmente el workbook SIEM del
desafío. `POST /analyze` devuelve `analysis-partial/1` y ejecuta únicamente
predicados deterministas que tienen condiciones suficientes; las reglas con
ventanas o correlaciones incompletas se marcan pendientes, sin afirmar
incidentes ni impacto. El contrato completo de `AnalysisResult`, los vectores
y serialización de `cj/1`, los catálogos E/K y los snapshots IANA aún no están
disponibles. El diagnóstico y los límites están en
[`docs/PHASE4_DECISIONS.md`](./docs/PHASE4_DECISIONS.md).

## Requisitos

- Windows
- Python 3.12 (validado con Python 3.12.3)
- Git
- PowerShell

## Obtener el repositorio

Clonar el repositorio si todavía no está disponible localmente:

```powershell
git clone https://github.com/ivanfr12/soc-l2-analyzer.git
Set-Location .\soc-l2-analyzer
```

Si ya está clonado, abrir una terminal PowerShell en la raíz del repositorio.

## Preparar el entorno e iniciar la API

Crear el entorno virtual si aún no existe e instalar las dependencias fijadas.
No hace falta activar el entorno:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Si `.venv` ya existe, no volver a ejecutar la creación. Uvicorn queda disponible
en `http://127.0.0.1:8000`. Para detenerlo, pulsar `Ctrl+C`.

## Comprobación de la API

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/health
Invoke-RestMethod -Uri http://127.0.0.1:8000/meta
```

También se pueden abrir estas URLs en el navegador:

- Health: <http://127.0.0.1:8000/health>
- Metadata: <http://127.0.0.1:8000/meta>
- Swagger UI: <http://127.0.0.1:8000/docs>

La respuesta de health es `{"status":"ok"}`. Metadata informa las versiones
de esquema/canonicalización, la hoja y columnas requeridas, el límite de carga
y `analysis_mode="partial"`.

## Analizar un workbook

1. Abrir `http://127.0.0.1:8000/docs` en el navegador mientras Uvicorn está
   ejecutándose.
2. Expandir `POST /analyze` y pulsar **Try it out**.
3. Seleccionar el Excel `.xlsx` en el campo `file` y pulsar **Execute**.

El endpoint también puede llamarse desde PowerShell:

```powershell
curl.exe -F "file=@D:\ruta\al\archivo.xlsx" http://127.0.0.1:8000/analyze
```

La carga valida firma ZIP, lectura con OpenPyXL, hoja `SIEM Export`, las 12
columnas esperadas y tamaño máximo de 10 MiB. Archivos inválidos reciben un
error HTTP controlado; el servidor no devuelve trazas internas.

### Interpretación de `analysis-partial/1`

- HTTP 200 para un archivo aceptado significa que se produjo una respuesta
  **parcial**, no que el workbook pasó por todas las reglas ni que exista un
  incidente confirmado.
- `completeness` informa filas vistas/evaluadas y conteos de reglas ejecutadas,
  parciales, pendientes o no evaluables.
- `rule_execution` ofrece estado, filas dentro del alcance por Event_ID,
  registros evaluados, coincidencias y motivo para cada regla.
- `observations` son coincidencias deterministas trazadas a `Log_ID`.
  `impact_demonstrated` e `incident_attribution` permanecen en `false`;
  severidad solo aparece cuando está ratificada.
- `score_1e4`, `confidence_basis_points` y `level` nulos significan no
  evaluables en el contrato parcial, no cero.
- `analysis_id` y `content_sha256` son nulos hasta poder implementar y verificar
  íntegramente `cj/1`. `file_sha256` sí es el hash de los bytes cargados.
- Cero observaciones significa que no hubo coincidencias en las condiciones
  implementadas; **no** significa que no hubiera actividad.

R02, R03, R04, R05, R10 y R12 se ejecutan con condiciones puntuales
documentadas. R06 y R11 solo evalúan coincidencias puntuales, sin afirmar
agrupación/periodicidad. R01, R07, R08, R09 y R13 están pendientes por
definiciones de ventanas/correlación. C1–C6 no se emiten porque falta la
membresía exacta de chains; C2 conserva `pending_reconciliation`.

La clasificación de IP es provisional: los bloques RFC 5737 se etiquetan
`documentation`, no IP pública operativa. Aún no se han incorporado los cuatro
snapshots XML IANA aprobados. No se asignan scores o confidence sin catálogos
E/K evaluables, ni se afirma canonicalización completa.

## Pruebas

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m compileall -q app tests
git diff --check
```

Para validar además el workbook original, sin copiarlo al repositorio:

```powershell
$env:SOC_L2_CHALLENGE_WORKBOOK = 'D:\Cursos\Soc 2- Comunidad Dojo\SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx'
.\.venv\Scripts\python.exe -m pytest -q
Remove-Item Env:SOC_L2_CHALLENGE_WORKBOOK -ErrorAction SilentlyContinue
```

No se deben guardar el workbook ni otros datasets del desafío en el
repositorio.

## Frontend local

La interfaz React/TypeScript está en [`frontend/`](./frontend/README.md).
Iniciá primero el backend y luego, en otra terminal PowerShell:

```powershell
Set-Location .\frontend
npm.cmd ci
npm.cmd run dev
```

Abrí <http://127.0.0.1:5173>. Vite redirige `/api/*` al backend local
`http://127.0.0.1:8000/*`; no requiere cambios de CORS en FastAPI.
