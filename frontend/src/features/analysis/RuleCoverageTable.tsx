import {
  CircleHelp,
  CirclePause,
  CirclePlay,
  CircleX,
  type LucideIcon,
} from "lucide-react";

import type { RuleExecution, RuleStatus } from "../../types/analysis";

const statusDetails = new Map<
  string,
  { label: string; className: string; icon: LucideIcon }
>([
  ["executed", { label: "Ejecutada", className: "executed", icon: CirclePlay }],
  ["partially_executed", { label: "Parcial", className: "partial", icon: CirclePause }],
  ["pending", { label: "Pendiente", className: "pending", icon: CircleHelp }],
  ["not_evaluable", { label: "No evaluable", className: "unevaluable", icon: CircleX }],
]);

function RuleStatusBadge({ status }: { status: RuleStatus }) {
  const detail = statusDetails.get(status);
  if (!detail) {
    return (
      <span className="status-badge status-badge--unknown">
        <CircleHelp aria-hidden="true" size={13} />
        {status || "Estado no disponible"}
      </span>
    );
  }
  const Icon = detail.icon;
  return (
    <span className={`status-badge status-badge--${detail.className}`}>
      <Icon aria-hidden="true" size={13} />
      {detail.label}
    </span>
  );
}

interface RuleCoverageTableProps {
  rules: Record<string, RuleExecution>;
}

export default function RuleCoverageTable({ rules }: RuleCoverageTableProps) {
  const entries = Object.entries(rules).sort(([first], [second]) =>
    first.localeCompare(second, undefined, { numeric: true }),
  );

  return (
    <div className="table-scroll">
      <table className="data-table rule-table">
        <thead>
          <tr>
            <th>Regla</th>
            <th>Estado</th>
            <th>En alcance</th>
            <th>Evaluados</th>
            <th>Coincidencias</th>
            <th>Alcance / limitación</th>
          </tr>
        </thead>
        <tbody>
          {entries.map(([ruleId, rule]) => (
            <tr key={ruleId}>
              <td>
                <span className="rule-id">{ruleId}</span>
                <span className="rule-name">{rule.name}</span>
              </td>
              <td>
                <RuleStatusBadge status={rule.status} />
              </td>
              <td className="table-number">{rule.records_in_scope.toLocaleString("es-ES")}</td>
              <td className="table-number">{rule.records_evaluated.toLocaleString("es-ES")}</td>
              <td className="table-number table-number--accent">
                {rule.matched_observation_count.toLocaleString("es-ES")}
              </td>
              <td className="rule-reason">
                {rule.reason ?? "No informado"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {entries.length === 0 && (
        <p className="table-empty">La respuesta no incluye cobertura de reglas.</p>
      )}
    </div>
  );
}
