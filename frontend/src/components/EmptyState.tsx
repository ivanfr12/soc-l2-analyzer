import { FileSearch, Upload } from "lucide-react";

interface EmptyStateProps {
  onUpload: () => void;
}

export default function EmptyState({ onUpload }: EmptyStateProps) {
  return (
    <section className="empty-state panel">
      <div className="empty-state__visual">
        <span className="empty-state__ring empty-state__ring--outer" />
        <span className="empty-state__ring empty-state__ring--inner" />
        <FileSearch aria-hidden="true" size={31} strokeWidth={1.5} />
      </div>
      <span className="section-kicker">LISTO PARA ANALIZAR</span>
      <h2>Sin análisis en esta sesión</h2>
      <p>
        Cargá un workbook SIEM para iniciar una evaluación determinista. No se
        conserva historial al cerrar o recargar esta página.
      </p>
      <button className="button button--primary" onClick={onUpload}>
        <Upload aria-hidden="true" size={16} />
        Seleccionar workbook
      </button>
    </section>
  );
}
