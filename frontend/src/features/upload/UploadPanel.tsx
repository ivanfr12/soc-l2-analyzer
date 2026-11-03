import { useRef, useState, type FormEvent } from "react";
import {
  Check,
  FileSpreadsheet,
  HardDriveUpload,
  LoaderCircle,
  Trash2,
  Upload,
} from "lucide-react";

import type { UiError } from "../../components/ErrorNotice";

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

interface UploadPanelProps {
  maxBytes?: number;
  isProcessing: boolean;
  error: UiError | null;
  onAnalyze: (file: File) => Promise<void>;
  onClearError: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toLocaleString("es-ES", { maximumFractionDigits: 0 })} KiB`;
  }
  return `${(bytes / (1024 * 1024)).toLocaleString("es-ES", {
    maximumFractionDigits: 2,
  })} MiB`;
}

export default function UploadPanel({
  maxBytes = DEFAULT_MAX_BYTES,
  isProcessing,
  error,
  onAnalyze,
  onClearError,
}: UploadPanelProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  function chooseFile(candidate?: File) {
    setFileError(null);
    onClearError();
    if (!candidate) return;

    if (!candidate.name.toLowerCase().endsWith(".xlsx")) {
      setFile(null);
      setFileError("El formato no es compatible. Seleccioná un archivo .xlsx.");
      return;
    }
    if (candidate.size === 0) {
      setFile(null);
      setFileError("El archivo está vacío. Elegí un workbook con datos.");
      return;
    }
    if (candidate.size > maxBytes) {
      setFile(null);
      setFileError(
        `El archivo supera el límite de ${formatBytes(maxBytes)} configurado por la API.`,
      );
      return;
    }
    setFile(candidate);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || isProcessing) return;
    await onAnalyze(file);
  }

  return (
    <section className="upload-panel panel" id="new-analysis">
      <div className="panel-heading">
        <div>
          <span className="section-kicker">INGESTA SEGURA</span>
          <h2>Nuevo análisis</h2>
          <p>Seleccioná un workbook SIEM para iniciar una evaluación parcial.</p>
        </div>
        <span className="upload-panel__limit">
          <HardDriveUpload aria-hidden="true" size={15} />
          Máximo {formatBytes(maxBytes)}
        </span>
      </div>

      <form onSubmit={submit}>
        <input
          ref={inputRef}
          className="visually-hidden"
          type="file"
          accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
          aria-label="Seleccionar archivo Excel XLSX"
          onChange={(event) => {
            chooseFile(event.currentTarget.files?.[0]);
            event.currentTarget.value = "";
          }}
        />
        <div
          className={`drop-zone${isDragging ? " drop-zone--dragging" : ""}${file ? " drop-zone--selected" : ""}`}
          onDragOver={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
              setIsDragging(false);
            }
          }}
          onDrop={(event) => {
            event.preventDefault();
            setIsDragging(false);
            chooseFile(event.dataTransfer.files[0]);
          }}
        >
          {file ? (
            <div className="selected-file">
              <span className="selected-file__icon">
                <FileSpreadsheet aria-hidden="true" size={22} />
              </span>
              <div className="selected-file__details">
                <strong title={file.name}>{file.name}</strong>
                <span>{formatBytes(file.size)} · XLSX seleccionado</span>
              </div>
              <span className="selected-file__check" aria-label="Archivo válido">
                <Check aria-hidden="true" size={16} />
              </span>
              <button
                type="button"
                className="icon-button selected-file__remove"
                onClick={() => {
                  setFile(null);
                  setFileError(null);
                  onClearError();
                }}
                aria-label="Quitar archivo seleccionado"
                disabled={isProcessing}
              >
                <Trash2 aria-hidden="true" size={17} />
              </button>
            </div>
          ) : (
            <div className="drop-zone__content">
              <span className="drop-zone__icon">
                <Upload aria-hidden="true" size={21} />
              </span>
              <div>
                <strong>Arrastrá tu archivo acá</strong>
                <span>o elegilo desde tu equipo · solo .xlsx</span>
              </div>
              <button
                type="button"
                className="button button--secondary"
                onClick={() => inputRef.current?.click()}
                disabled={isProcessing}
              >
                Explorar archivos
              </button>
            </div>
          )}
        </div>

        {(fileError || error) && (
          <div className="upload-error" role="alert">
            <strong>{fileError ? "No se pudo seleccionar" : error?.title}</strong>
            <span>{fileError ?? error?.message}</span>
            {error && (
              <button type="button" onClick={onClearError}>
                Cerrar
              </button>
            )}
          </div>
        )}

        <div className="upload-panel__footer">
          <p>
            <span className="privacy-dot" />
            Se procesa durante la solicitud; puede utilizar almacenamiento temporal.
          </p>
          <button
            type="submit"
            className="button button--primary"
            disabled={!file || isProcessing}
          >
            {isProcessing ? (
              <>
                <LoaderCircle aria-hidden="true" className="spin" size={16} />
                Analizando…
              </>
            ) : (
              <>
                <FileSpreadsheet aria-hidden="true" size={16} />
                Analizar workbook
              </>
            )}
          </button>
        </div>
      </form>
    </section>
  );
}
