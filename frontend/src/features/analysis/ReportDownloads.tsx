import { useEffect, useRef, useState } from "react";
import { Check, Download, LoaderCircle } from "lucide-react";

import {
  ApiError,
  requestExecutiveReport,
  requestTechnicalReport,
} from "../../services/api";
import type { ReportType } from "../../services/api";

type ExportStatus = "available" | "generating" | "downloaded" | "error";

interface ReportState {
  status: ExportStatus;
  message: string | null;
}

interface ReportDownloadsProps {
  file: File;
  expectedFileSha256: string;
}

const REPORTS: Array<{
  type: ReportType;
  label: string;
}> = [
  {
    type: "executive",
    label: "Descargar informe ejecutivo",
  },
  {
    type: "technical",
    label: "Descargar informe técnico",
  },
];

function fallbackFilename(reportType: ReportType): string {
  return reportType === "executive"
    ? "SOC_L2_Informe_Ejecutivo.pdf"
    : "SOC_L2_Informe_Tecnico.pdf";
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError && error.code === "file_hash_mismatch") {
    return "El archivo no coincide con el análisis actual. Volvé a analizarlo antes de generar el informe.";
  }
  return error instanceof Error
    ? error.message
    : "No se pudo generar el informe. Intentá nuevamente.";
}

export default function ReportDownloads({
  file,
  expectedFileSha256,
}: ReportDownloadsProps) {
  const [states, setStates] = useState<Record<ReportType, ReportState>>({
    executive: { status: "available", message: null },
    technical: { status: "available", message: null },
  });
  const inFlight = useRef(new Set<ReportType>());
  const controllers = useRef(new Map<ReportType, AbortController>());

  useEffect(
    () => () => {
      for (const controller of controllers.current.values()) {
        controller.abort();
      }
      controllers.current.clear();
    },
    [file, expectedFileSha256],
  );

  async function download(reportType: ReportType) {
    if (inFlight.current.has(reportType)) return;
    inFlight.current.add(reportType);
    const controller = new AbortController();
    controllers.current.set(reportType, controller);
    setStates((current) => ({
      ...current,
      [reportType]: { status: "generating", message: null },
    }));

    try {
      const report =
        reportType === "executive"
          ? await requestExecutiveReport(
              file,
              expectedFileSha256,
              controller.signal,
            )
          : await requestTechnicalReport(
              file,
              expectedFileSha256,
              controller.signal,
            );
      if (controller.signal.aborted) return;

      const objectUrl = URL.createObjectURL(report.blob);
      try {
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = report.filename || fallbackFilename(reportType);
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
      } finally {
        window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      }
      setStates((current) => ({
        ...current,
        [reportType]: { status: "downloaded", message: null },
      }));
    } catch (error) {
      if (controller.signal.aborted) return;
      setStates((current) => ({
        ...current,
        [reportType]: { status: "error", message: errorMessage(error) },
      }));
    } finally {
      inFlight.current.delete(reportType);
      if (controllers.current.get(reportType) === controller) {
        controllers.current.delete(reportType);
      }
    }
  }

  return (
    <section className="report-downloads panel" aria-label="Descarga de informes">
      <div className="panel-heading">
        <div>
          <span className="section-kicker">INFORMES PDF</span>
          <h2>Exportar este análisis</h2>
          <p>Los informes se generan desde el mismo archivo y SHA-256 del análisis visible.</p>
        </div>
      </div>
      <div className="report-downloads__actions">
        {REPORTS.map(({ type, label }) => {
          const state = states[type];
          return (
            <div className="report-downloads__action" key={type}>
              <button
                type="button"
                className="button button--secondary"
                onClick={() => void download(type)}
                disabled={state.status === "generating"}
                aria-busy={state.status === "generating"}
              >
                {state.status === "generating" ? (
                  <LoaderCircle aria-hidden="true" className="spin" size={15} />
                ) : state.status === "downloaded" ? (
                  <Check aria-hidden="true" size={15} />
                ) : (
                  <Download aria-hidden="true" size={15} />
                )}
                {state.status === "generating"
                  ? `Generando ${type === "executive" ? "informe ejecutivo" : "informe técnico"}…`
                  : state.status === "downloaded"
                    ? `${label} · descargado`
                    : label}
              </button>
              {state.status === "error" && state.message && (
                <p className="report-downloads__error" role="alert">
                  {state.message}
                </p>
              )}
              {state.status === "downloaded" && (
                <span className="report-downloads__success" role="status">
                  Informe descargado correctamente.
                </span>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
