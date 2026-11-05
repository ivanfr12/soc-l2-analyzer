import { Link2 } from "lucide-react";

import type { ChainDetail, ChainExecutionResult } from "../../types/analysis";

interface ChainDetailsProps {
  result: ChainExecutionResult | null;
  loading: boolean;
  error: string | null;
}

const STATUS_LABEL: Record<string, string> = {
  executed: "Ejecutada",
  not_evaluable: "No evaluable",
  pending_reconciliation: "Pendiente de conciliación",
};

function statusClass(status: string): string {
  if (status === "executed") return "chain-status--executed";
  if (status === "pending_reconciliation") return "chain-status--pending";
  return "chain-status--not-evaluable";
}

function ChainCard({ chain }: { chain: ChainDetail }) {
  return (
    <article className="chain-card">
      <header className="chain-card__header">
        <div>
          <span className="section-kicker">{chain.chain_id}</span>
          <h3>{chain.name}</h3>
        </div>
        <span className={`chain-status ${statusClass(chain.status)}`}>
          {STATUS_LABEL[chain.status] ?? chain.status}
        </span>
      </header>

      <p className="chain-card__semantics">
        Semántica: <strong>{chain.semantics}</strong> (secuencia observada
        candidata, no incidente confirmado).
      </p>

      <dl className="chain-card__meta">
        <div>
          <dt>Nivel</dt>
          <dd>{chain.level === null ? "No definido" : `L${chain.level}`}</dd>
        </div>
        <div>
          <dt>Severidad</dt>
          <dd>{chain.severity ?? "No definida"}</dd>
        </div>
        <div>
          <dt>Score de referencia</dt>
          <dd>
            {chain.reference_score_1e4 === null
              ? "No evaluable"
              : (chain.reference_score_1e4 / 10000).toFixed(4)}
          </dd>
        </div>
        <div>
          <dt>Ratificada</dt>
          <dd>{chain.ratified ? "Sí" : "No"}</dd>
        </div>
      </dl>

      <p className="chain-card__reason">{chain.reason}</p>

      {chain.nodes.length > 0 && (
        <div className="chain-card__block">
          <h4>Nodos</h4>
          <ul className="chain-node-list">
            {chain.nodes.map((node, index) => (
              <li key={`${node.rule_id}-${index}`}>
                <strong>{node.rule_id}</strong>
                <span>
                  {node.log_ids.length} Log_ID · {node.hostnames.join(", ") || "—"} ·{" "}
                  {node.users.join(", ") || "—"} · {node.source_ips.join(", ") || "—"}
                </span>
                <code className="chain-node__ids">
                  {node.log_ids.join(", ")}
                </code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {chain.links.length > 0 && (
        <div className="chain-card__block">
          <h4>Enlaces</h4>
          <ul className="chain-link-list">
            {chain.links.map((link, index) => (
              <li key={index}>
                <Link2 aria-hidden="true" size={14} />
                <span>
                  {link.from_rule} → {link.to_rule} · {link.delta_seconds}s /{" "}
                  {link.window_seconds}s · {link.basis.join(", ")}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {chain.evidence.length > 0 && (
        <div className="chain-card__block">
          <h4>Evidencia principal</h4>
          <p className="chain-card__ids">{chain.evidence.join(", ")}</p>
        </div>
      )}

      {chain.contextual_evidence.length > 0 && (
        <div className="chain-card__block chain-card__block--context">
          <h4>Evidencia contextual (no membership)</h4>
          <ul className="chain-context-list">
            {chain.contextual_evidence.map((item, index) => (
              <li key={index}>
                <strong>{item.rule_id}</strong>
                <span>{item.log_ids.join(", ")}</span>
                {item.note && <p>{item.note}</p>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}

export default function ChainDetails({
  result,
  loading,
  error,
}: ChainDetailsProps) {
  return (
    <section className="panel result-panel" aria-label="Cadenas de correlación">
      <div className="panel-heading panel-heading--row">
        <div>
          <span className="section-kicker">CADENAS DE CORRELACIÓN</span>
          <h2>Secuencias observadas candidatas</h2>
          <p>
            Las cadenas son asociaciones deterministas de observaciones; no
            equivalen a incidentes confirmados ni prueban causalidad, identidad
            de sesión, compromiso, exfiltración ni impacto.
          </p>
        </div>
      </div>

      {loading && <p className="chain-details__status">Consultando cadenas…</p>}
      {error && (
        <div className="chain-details__error" role="alert">
          {error}
        </div>
      )}
      {result && (
        <div className="chain-grid">
          {Object.values(result.chains).map((chain) => (
            <ChainCard key={chain.chain_id} chain={chain} />
          ))}
        </div>
      )}
      {!loading && !error && !result && (
        <p className="chain-details__status">
          Sin datos de cadenas. Ejecutá un análisis para consultarlas.
        </p>
      )}
    </section>
  );
}