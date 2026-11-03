import { useEffect } from "react";
import { Clock3, ExternalLink, X } from "lucide-react";

import type { Observation } from "../../types/analysis";

interface EvidenceDetailsProps {
  observation: Observation;
  onClose: () => void;
}

function EvidenceValue({ value }: { value: string | null }) {
  return <span>{value?.trim() || "No disponible"}</span>;
}

export default function EvidenceDetails({
  observation,
  onClose,
}: EvidenceDetailsProps) {
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  return (
    <div className="dialog-backdrop" onMouseDown={onClose}>
      <section
        className="evidence-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="evidence-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="evidence-dialog__header">
          <div>
            <span className="section-kicker">EVIDENCIA TRAZABLE</span>
            <h2 id="evidence-title">{observation.rule_id} · {observation.rule_name}</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Cerrar detalle">
            <X aria-hidden="true" size={19} />
          </button>
        </header>
        <p className="evidence-dialog__description">{observation.description}</p>
        <div className="evidence-disclaimer">
          <ExternalLink aria-hidden="true" size={15} />
          <span>
            Observación determinista; no confirma incidente, atribución ni impacto.
          </span>
        </div>
        <div className="evidence-list">
          {observation.evidence.map((event, index) => (
            <article
              className="evidence-card"
              key={`${event.Log_ID ?? "event"}-${index}`}
            >
              <div className="evidence-card__top">
                <span className="evidence-card__log-id">
                  {event.Log_ID ?? "Log_ID no disponible"}
                </span>
                <span className="evidence-card__time">
                  <Clock3 aria-hidden="true" size={13} />
                  <EvidenceValue value={event.Timestamp} />
                </span>
              </div>
              <dl className="evidence-fields">
                <div>
                  <dt>Hostname</dt>
                  <dd><EvidenceValue value={event.Hostname} /></dd>
                </div>
                <div>
                  <dt>Event_ID</dt>
                  <dd><EvidenceValue value={event.Event_ID} /></dd>
                </div>
                <div>
                  <dt>User</dt>
                  <dd><EvidenceValue value={event.User} /></dd>
                </div>
                <div>
                  <dt>Source_IP</dt>
                  <dd><EvidenceValue value={event.Source_IP} /></dd>
                </div>
                <div>
                  <dt>Categoría IP</dt>
                  <dd>{event.source_ip_category || "No disponible"}</dd>
                </div>
              </dl>
            </article>
          ))}
          {observation.evidence.length === 0 && (
            <p className="table-empty">Esta observación no contiene evidencia.</p>
          )}
        </div>
      </section>
    </div>
  );
}
