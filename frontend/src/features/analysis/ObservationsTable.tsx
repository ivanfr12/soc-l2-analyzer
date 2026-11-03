import { ArrowUpRight, CircleAlert } from "lucide-react";

import type { Observation } from "../../types/analysis";

interface ObservationsTableProps {
  observations: Observation[];
  onSelect: (observation: Observation) => void;
}

function formatConfidence(value: number | null): string {
  return value === null
    ? "No evaluable"
    : `${(value / 100).toLocaleString("es-ES", { maximumFractionDigits: 2 })}%`;
}

export default function ObservationsTable({
  observations,
  onSelect,
}: ObservationsTableProps) {
  return (
    <div className="table-scroll">
      <table className="data-table observations-table">
        <thead>
          <tr>
            <th>Regla</th>
            <th>Tipo de observación</th>
            <th>Descripción</th>
            <th>Severidad</th>
            <th>Nivel</th>
            <th>Confidence</th>
            <th>Evidencia</th>
          </tr>
        </thead>
        <tbody>
          {observations.map((observation, index) => (
            <tr key={`${observation.rule_id}-${observation.evidence[0]?.Log_ID ?? index}-${index}`}>
              <td>
                <span className="rule-id">{observation.rule_id}</span>
                <span className="rule-name">{observation.rule_name}</span>
              </td>
              <td>
                <span className="observation-type">
                  <CircleAlert aria-hidden="true" size={14} />
                  {observation.observation_type}
                </span>
              </td>
              <td className="observation-description">{observation.description}</td>
              <td>
                {observation.severity === null ? (
                  <span className="not-available">No disponible</span>
                ) : (
                  <span className={`severity severity--${observation.severity.toLowerCase()}`}>
                    <span />
                    {observation.severity}
                  </span>
                )}
              </td>
              <td>
                {observation.level === null ? (
                  <span className="not-available">No evaluable</span>
                ) : (
                  <span className="level-pill">L{observation.level}</span>
                )}
              </td>
              <td>
                {observation.confidence_basis_points === null ? (
                  <span className="not-available">No evaluable</span>
                ) : (
                  <span className="confidence-value">
                    {formatConfidence(observation.confidence_basis_points)}
                  </span>
                )}
              </td>
              <td>
                <button
                  className="evidence-link"
                  onClick={() => onSelect(observation)}
                  aria-label={`Ver evidencias de ${observation.rule_id}`}
                >
                  {observation.evidence.length}{" "}
                  {observation.evidence.length === 1 ? "registro" : "registros"}
                  <ArrowUpRight aria-hidden="true" size={14} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {observations.length === 0 && (
        <div className="observations-empty">
          <CircleAlert aria-hidden="true" size={18} />
          <div>
            <strong>No hubo coincidencias en las condiciones implementadas</strong>
            <span>Esto no significa ausencia de actividad o de amenazas.</span>
          </div>
        </div>
      )}
    </div>
  );
}
