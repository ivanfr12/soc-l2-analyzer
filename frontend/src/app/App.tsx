import { useEffect, useState } from "react";
import { ArrowDownToLine, ShieldAlert, Sparkles } from "lucide-react";

import AppShell from "../components/AppShell";
import EmptyState from "../components/EmptyState";
import ErrorNotice, { type UiError } from "../components/ErrorNotice";
import LoadingState from "../components/LoadingState";
import type { ConnectionState } from "../components/ApiStatus";
import AnalysisDashboard from "../features/analysis/AnalysisDashboard";
import UploadPanel from "../features/upload/UploadPanel";
import { analyzeFile, ApiError, getHealth, getMetadata } from "../services/api";
import type { AnalysisResult, ApiMetadata } from "../types/analysis";

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

function toUiError(error: unknown): UiError {
  if (error instanceof ApiError) {
    if (error.kind === "network") {
      return {
        title: "No hay conexión con la API",
        message: error.message,
        kind: "connection",
      };
    }
    if ([413, 415, 422].includes(error.status ?? 0)) {
      return {
        title: "El archivo no pudo validarse",
        message: error.message,
        kind: "validation",
      };
    }
  }
  return {
    title: "No se pudo completar el análisis",
    message:
      error instanceof Error
        ? error.message
        : "Ocurrió un error inesperado. Revisá la conexión e intentá nuevamente.",
    kind: "unexpected",
  };
}

export default function App() {
  const [connection, setConnection] = useState<ConnectionState>("checking");
  const [metadata, setMetadata] = useState<ApiMetadata | null>(null);
  const [metadataWarning, setMetadataWarning] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [resultFile, setResultFile] = useState<File | null>(null);
  const [error, setError] = useState<UiError | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  useEffect(() => {
    let active = true;
    const refreshHealth = async () => {
      try {
        const health = await getHealth();
        if (active) setConnection(health.status === "ok" ? "online" : "offline");
      } catch {
        if (active) setConnection("offline");
      }
    };
    const refreshMetadata = async () => {
      try {
        const apiMetadata = await getMetadata();
        if (active) {
          setMetadata(apiMetadata);
          setMetadataWarning(null);
        }
      } catch {
        if (active) {
          setMetadataWarning(
            "No se pudo consultar /meta; se aplica el límite documentado de 10 MiB.",
          );
        }
      }
    };

    void refreshHealth();
    void refreshMetadata();
    const timer = window.setInterval(() => void refreshHealth(), 30_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  async function handleAnalyze(file: File) {
    setIsProcessing(true);
    setError(null);
    setResult(null);
    setResultFile(null);
    try {
      const analysis = await analyzeFile(file);
      setResult(analysis);
      setResultFile(file);
    } catch (caught) {
      setError(toUiError(caught));
    } finally {
      setIsProcessing(false);
    }
  }

  function navigate(section: "dashboard" | "upload") {
    const element = document.getElementById(
      section === "dashboard" ? "dashboard" : "new-analysis",
    );
    element?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return (
    <AppShell connection={connection} onNavigate={navigate}>
      <main className="workspace" id="dashboard">
        <section className="page-intro">
          <div className="page-intro__copy">
            <div className="breadcrumb">
              <span>Workspace</span>
              <span className="breadcrumb__slash">/</span>
              <strong>Dashboard</strong>
            </div>
            <h2>Panorama de seguridad</h2>
            <p>
              Analizá registros SIEM con reglas deterministas y evidencia trazable.
            </p>
          </div>
          <div className="scope-pill">
            <span className="scope-pill__dot" />
            <span>Alcance de análisis parcial</span>
          </div>
        </section>

        <div className="integrity-note">
          <ShieldAlert aria-hidden="true" size={17} />
          <span>
            Las observaciones no equivalen a incidentes confirmados. Las reglas
            pendientes no se ejecutan y no se conserva historial.
          </span>
        </div>

        {metadataWarning && (
          <ErrorNotice
            error={{
              title: "Metadata no disponible",
              message: metadataWarning,
              kind: "unexpected",
            }}
          />
        )}

        <div className="workspace-grid">
          <div className="workspace-grid__primary">
            <UploadPanel
              maxBytes={metadata?.max_upload_bytes ?? DEFAULT_MAX_BYTES}
              isProcessing={isProcessing}
              error={error}
              onAnalyze={handleAnalyze}
              onFileSelected={(file) => {
                setSelectedFile(file);
                setResult(null);
                setResultFile(null);
              }}
              onClearError={() => setError(null)}
            />
            {isProcessing && <LoadingState />}
            {result ? (
              <AnalysisDashboard
                result={result}
                reportFile={resultFile === selectedFile ? resultFile : null}
              />
            ) : (
              !isProcessing && <EmptyState onUpload={() => navigate("upload")} />
            )}
          </div>

          <aside className="context-rail">
            <section className="context-card context-card--contract">
              <div className="context-card__icon">
                <Sparkles aria-hidden="true" size={17} />
              </div>
              <span className="section-kicker">CONTRATO ACTIVO</span>
              <strong>analysis-partial/1</strong>
              <p>
                La respuesta refleja el alcance actualmente implementado por la API.
              </p>
              <div className="context-card__footer">
                <span>Schema</span>
                <b>{metadata?.analysis_schema_version ?? "No disponible"}</b>
                <span>Canon</span>
                <b>{metadata?.canon_version ?? "No disponible"}</b>
              </div>
            </section>

            <section className="context-card">
              <span className="section-kicker">GUÍA DE LECTURA</span>
              <h3>Qué muestra este panel</h3>
              <ul className="reading-guide">
                <li><i className="reading-guide__dot reading-guide__dot--cyan" /> Coincidencias en predicados implementados</li>
                <li><i className="reading-guide__dot reading-guide__dot--amber" /> Reglas con evaluación parcial o pendiente</li>
                <li><i className="reading-guide__dot reading-guide__dot--slate" /> Valores no evaluables como no disponibles</li>
              </ul>
            </section>

            <section className="context-card context-card--quiet">
              <div className="context-card__quiet-head">
                <ArrowDownToLine aria-hidden="true" size={16} />
                <span>Procesamiento local</span>
              </div>
              <p>
                El frontend comunica el archivo directamente al backend local.
                El archivo se procesa durante la solicitud. No se conserva
                historial ni almacenamiento persistente de los análisis. El
                procesamiento puede utilizar almacenamiento temporal.
              </p>
            </section>

            {result && (
              <section className="context-card context-card--hash">
                <span className="section-kicker">SHA-256 DEL ARCHIVO</span>
                <code>{result.file_sha256}</code>
              </section>
            )}
          </aside>
        </div>

        <footer className="workspace-footer">
          <span>SOC L2 Analyzer</span>
          <span>Observabilidad determinista · alcance parcial</span>
        </footer>
      </main>
    </AppShell>
  );
}
