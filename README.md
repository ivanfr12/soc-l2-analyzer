# SOC L2 Analyzer

Aplicación local para analizar workbooks Excel (`.xlsx`) con registros SIEM
mediante un backend **FastAPI** en Python y una interfaz **React + TypeScript**
con Vite. El motor ejecuta reglas deterministas, entrega resultados parciales
con evidencia trazable y permite visualizar el dashboard y descargar informes
PDF ejecutivo y técnico.

El producto no es un SIEM completo ni una plataforma de respuesta automática.
Una observación no confirma por sí sola un incidente, impacto, causalidad,
atribución, exfiltración ni ejecución exitosa.

## Requisitos

- Windows, PowerShell y Git.
- Python 3.12 (validado con Python 3.12.3).
- Node.js 22.22.2+ o 24.15+ y npm para el frontend.

## Preparación

Desde PowerShell, clonar el repositorio si todavía no está disponible:

```powershell
git clone https://github.com/ivanfr12/soc-l2-analyzer.git
Set-Location .\soc-l2-analyzer
```

Crear el entorno virtual Python e instalar las dependencias fijadas:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Instalar las dependencias del frontend desde su lockfile:

```powershell
Set-Location .\frontend
npm.cmd ci
Set-Location ..
```

## Iniciar la aplicación

Abrir dos terminales PowerShell desde la raíz del repositorio.

Terminal 1 — backend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

La API local queda disponible en `http://127.0.0.1:8000`. La documentación
interactiva OpenAPI está en `http://127.0.0.1:8000/docs`.

Terminal 2 — frontend:

```powershell
Set-Location .\frontend
npm.cmd run dev
```

Abrir `http://127.0.0.1:5173`. El proxy de desarrollo reenvía `/api/*` a la API
local y quita ese prefijo; no hace falta habilitar CORS para este flujo.

## Analizar un workbook

1. Abrir la interfaz, seleccionar o arrastrar un archivo `.xlsx` y elegir
   **Analizar workbook**.
2. El dashboard muestra el estado parcial, la cobertura de reglas y las
   observaciones con referencias a `Log_ID`.
3. Si el análisis finaliza correctamente y su archivo sigue asociado, se pueden
   descargar el **informe ejecutivo** y el **informe técnico**.

La API también acepta el archivo desde `/docs`, mediante `POST /analyze`, o con
PowerShell:

```powershell
curl.exe -F "file=@.\archivo.xlsx" http://127.0.0.1:8000/analyze
```

La carga está limitada a 10 MiB. Se valida extensión, firma ZIP, lectura con
OpenPyXL, hoja `SIEM Export` y las 12 columnas requeridas. Los archivos vacíos,
corruptos, no XLSX o con estructura incompleta se rechazan con errores
controlados.

### Informes PDF

Después de un análisis exitoso, la interfaz permite descargar ambos informes.
`POST /reports/executive` y `POST /reports/technical` reciben el mismo archivo
analizado y su `expected_file_sha256`; el servidor valida el hash, vuelve a
ejecutar el análisis y genera el PDF sin conservar el workbook ni el informe.
Una discrepancia de hash se rechaza con HTTP 409. Las respuestas son
`application/pdf` y usan nombres de archivo fijos.

Los informes se generan con datos del análisis y de sus registros fuente.
Explican el alcance parcial y no convierten hallazgos observados en incidentes
confirmados ni generan scores, severidades o cadenas no evaluados.

## Reglas y clasificación IP

El pipeline contiene implementaciones deterministas de R01–R13 conforme a los
criterios ratificados disponibles. Cada resultado indica el estado de
ejecución y las observaciones incluyen evidencia enlazada a `Log_ID`. Las
reglas con condiciones pendientes o cobertura parcial no se presentan como
completamente evaluadas.

Los cuatro snapshots XML IANA están incorporados en `data/iana/`. El
`manifest.json` registra URL, fecha `updated`, formato, fecha de recuperación y
SHA-256 de cada archivo. El cargador verifica metadatos, contenido XML y hashes;
si un snapshot falta o no coincide, marca el conjunto `declared_unverified` y
aplica un comportamiento conservador sin consumir prefijos IANA no verificados.
Los rangos RFC 5737 se clasifican como `documentation`, no como IP públicas
operativas.

## Límites de `analysis-partial/1`

- Una respuesta HTTP 200 indica que se produjo un resultado **parcial**; no
  significa que todas las reglas hayan sido ejecutadas ni que exista un
  incidente confirmado.
- `completeness` y `rule_execution` describen registros vistos/evaluados y el
  alcance de cada regla. Cero coincidencias solo significa que no coincidieron
  los predicados implementados; no demuestra ausencia de actividad.
- Las observaciones deterministas conservan evidencia de origen. No se infieren
  causalidad, éxito de comandos, impacto, exfiltración ni atribución.
- `score_1e4`, `confidence_basis_points` y `level` nulos significan no
  evaluables, no cero. No se asigna score operativo cuando E/K no son
  evaluables; severidades no ratificadas permanecen sin definir.
- Las chains C1–C6 no se materializan porque faltan condiciones reproducibles
  de membresía y enlace. C2 conserva `pending_reconciliation`; C7 no está
  ratificada y no se activa. Ninguna se presenta como incidente confirmado.
- Los timestamps naive se conservan con `timezone_status="undefined"`.
  `analysis_id` y `content_sha256` siguen no evaluables hasta disponer de los
  vectores y la serialización completos de `cj/1`; `file_sha256` sí identifica
  los bytes recibidos.
- No hay base de datos, historial ni almacenamiento persistente de análisis;
  tampoco se integra IA/Ollama ni respuesta automática.

## Pruebas y verificaciones

Backend, desde la raíz:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m compileall -q app tests
git diff --check
```

Para incluir el workbook original en las pruebas, sin copiarlo al repositorio:

```powershell
$env:SOC_L2_CHALLENGE_WORKBOOK = (Resolve-Path '.\privado\challenge.xlsx').Path
.\.venv\Scripts\python.exe -m pytest -q
Remove-Item Env:SOC_L2_CHALLENGE_WORKBOOK
```

Frontend, desde `frontend`:

```powershell
npm.cmd test
npm.cmd run build
```

El workbook del desafío no se distribuye con el repositorio. Usá únicamente un
archivo al que tengas autorización de acceso y mantenelo fuera del control de
versiones.

## Documentación

- [Evaluación del dataset](./docs/DATA_ASSESSMENT.md): perfil y limitaciones de
  los registros del desafío.
- [Decisiones de Fase 4](./docs/PHASE4_DECISIONS.md): metodología ratificada,
  alcance implementado y aspectos pendientes.
- [Frontend](./frontend/README.md): instalación, uso, endpoints y verificación
  de la interfaz.
