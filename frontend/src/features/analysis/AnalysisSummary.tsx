import {
  Activity,
  CircleCheck,
  CirclePause,
  FileStack,
  ScanSearch,
  ShieldAlert,
} from "lucide-react";

import StatCard from "../../components/StatCard";
import type { AnalysisResult } from "../../types/analysis";

interface AnalysisSummaryProps {
  result: AnalysisResult;
}

export default function AnalysisSummary({ result }: AnalysisSummaryProps) {
  const { completeness, activity_summary: activity } = result;

  return (
    <div className="summary-grid">
      <StatCard
        label="Registros vistos"
        value={completeness.records_seen}
        description="Filas de datos no vacías"
        icon={FileStack}
        accent="blue"
      />
      <StatCard
        label="Registros evaluados"
        value={completeness.records_evaluated}
        description="Normalizados para las reglas"
        icon={CircleCheck}
        accent="green"
      />
      <StatCard
        label="No evaluables"
        value={completeness.records_not_evaluable}
        description="Filas excluidas por datos inválidos"
        icon={CirclePause}
        accent="amber"
      />
      <StatCard
        label="Observaciones"
        value={activity.observations_emitted}
        description="Coincidencias deterministas"
        icon={ShieldAlert}
        accent="cyan"
      />
      <StatCard
        label="Reglas ejecutadas"
        value={completeness.rules_executed}
        description={`${completeness.rules_partially_executed} parcialmente ejecutadas`}
        icon={Activity}
        accent="violet"
      />
      <StatCard
        label="Reglas pendientes"
        value={completeness.rules_pending}
        description={`${completeness.rules_total} reglas en el catálogo`}
        icon={ScanSearch}
        accent="muted"
      />
    </div>
  );
}
