# SOC L2 Analyzer — Frontend

Interfaz web React + TypeScript, construida con Vite, para analizar workbooks
Excel SIEM mediante la API FastAPI local. Muestra datos reales del contrato
parcial `analysis-partial/1`; no guarda historial ni resultados persistentes.

## Requisitos

- Node.js 22.22.2+ o 24.15+ y npm.
- Backend FastAPI disponible en `http://127.0.0.1:8000`.

## Instalar y ejecutar

Desde PowerShell, en la raíz del repositorio:

```powershell
Set-Location .\frontend
npm.cmd ci
npm.cmd run dev
```

Abrir <http://127.0.0.1:5173>. Para ejecutar ambos servicios, iniciar primero el
backend en una terminal desde la raíz:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Luego iniciar el frontend en una segunda terminal con los comandos anteriores.

## Carga y dashboard

El panel permite seleccionar o arrastrar un archivo `.xlsx`, validar en cliente
extensión y límite de tamaño informado por la API, y enviarlo mediante
`POST /analyze`. El dashboard presenta cobertura de reglas, observaciones y
evidencias asociadas por `Log_ID`; no muestra la respuesta como un incidente
confirmado. El archivo queda asociado en memoria al resultado actual para
habilitar las descargas. Al elegir otro archivo se limpian los resultados
anteriores; una exportación en curso se cancela cuando se desmonta el análisis
al que pertenecía.

## Informes PDF

Tras un análisis exitoso, se habilitan por separado **Descargar informe
ejecutivo** y **Descargar informe técnico**. Cada acción envía al backend el
mismo objeto `File` asociado al resultado y el `file_sha256` devuelto por la
API. El frontend muestra estados independientes de generación, descarga y
error, permite reintentar y no usa el nombre del archivo Excel como ruta.
Los PDFs se generan bajo demanda y no se almacenan permanentemente.

Endpoints del backend:

- `POST /reports/executive`
- `POST /reports/technical`

La API compara `expected_file_sha256` con el archivo recibido; si no coincide,
responde HTTP 409 y el frontend solicita volver a analizar el archivo.

## API y proxy de desarrollo

El frontend consulta:

- `GET /health` — conectividad del backend.
- `GET /meta` — versiones, hoja/columnas requeridas y máximo de carga.
- `POST /analyze` — análisis parcial del workbook.
- `POST /reports/executive` y `POST /reports/technical` — generación de PDF.

En desarrollo, Vite reenvía todas las rutas `/api/*` a
`http://127.0.0.1:8000/*` y elimina el prefijo `/api`. No es necesario habilitar
CORS para este flujo local. El proxy no configura un despliegue de producción.

## Pruebas y compilación

Desde `frontend`:

```powershell
npm.cmd test
npm.cmd run build
```

El script de build ejecuta TypeScript (`tsc --noEmit`) y luego genera el bundle
de producción con Vite.

## Limitaciones

- El dashboard refleja el resultado parcial de la API; las reglas pendientes no
  se muestran como ejecutadas y las observaciones no son incidentes
  confirmados.
- Score, nivel, confidence o severidad nulos/no disponibles no se reemplazan por
  valores inferidos.
- La API no devuelve todos los registros del workbook; la interfaz muestra
  resumen y evidencia incluidos en el resultado.
- No hay historial, persistencia, autenticación, gestión de incidentes,
  dashboards históricos, notificaciones funcionales ni respuesta automática.
- El proxy es exclusivo del servidor de desarrollo; la configuración de
  despliegue no está incluida.
