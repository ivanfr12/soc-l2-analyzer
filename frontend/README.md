# SOC L2 Analyzer — Frontend

Interfaz web en React, TypeScript y Vite para consumir la API local del SOC L2
Analyzer. Presenta respuestas reales del contrato parcial `analysis-partial/1`;
no incluye persistencia ni historial.

## Requisitos

- Node.js 22.22.2+ o 24.15+ (validado con Node.js 24.19.0).
- npm.
- Backend FastAPI iniciado en `http://127.0.0.1:8000`.

## Instalar y ejecutar

Desde PowerShell, en la raíz del repositorio:

```powershell
Set-Location .\frontend
npm.cmd ci
npm.cmd run dev
```

Abrir <http://127.0.0.1:5173>. Vite reenvía `/api/health`, `/api/meta` y
`/api/analyze` a FastAPI en `127.0.0.1:8000`, quitando el prefijo `/api`.
No es necesario habilitar CORS en el backend para este flujo de desarrollo.

Para iniciar ambos servicios, abrir dos terminales PowerShell:

```powershell
# Terminal 1, desde la raíz del repositorio
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

```powershell
# Terminal 2, desde la raíz del repositorio
Set-Location .\frontend
npm.cmd ci
npm.cmd run dev
```

## Funcionalidades

- Estado de conectividad consultando `/health`.
- Lectura de `/meta` para el límite de carga y versiones declaradas.
- Selección o arrastre de `.xlsx`, validación de extensión y tamaño, y envío
  manual mediante `POST /analyze`.
- Tarjetas de cobertura, tabla de estado de reglas y lista de observaciones.
- Detalle de evidencias con referencia a `Log_ID`.
- Estados de carga, error de red y errores de validación.

## Verificación

```powershell
npm.cmd test
npm.cmd run build
```

## Limitaciones

- La respuesta es parcial: las reglas pendientes no se presentan como
  ejecutadas y las observaciones no se tratan como incidentes confirmados.
- Scores, niveles, confidence o severidades ausentes/null se muestran como no
  evaluables o no disponibles.
- La API no devuelve el listado completo de registros; el frontend solo puede
  mostrar resumen y evidencia incluida en observaciones.
- No hay historial, almacenamiento, autenticación, vistas de incidentes,
  dashboards históricos ni notificaciones funcionales.
- El proxy de Vite es para desarrollo local; la integración de despliegue no
  está configurada en esta etapa.
