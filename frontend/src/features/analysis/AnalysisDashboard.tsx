import { useState } from "react";
import { AlertTriangle, Fingerprint, Info } from "lucide-react";

import type { AnalysisResult, Observation } from "../../types/analysis";
import AnalysisSummary from "./AnalysisSummary";
import EvidenceDetails from "./EvidenceDetails";
import ObservationsTable from "./ObservationsTable";
import ReportDownloads from "./ReportDownloads";
import RuleCoverageTable from "./RuleCoverageTable";

interface AnalysisDashboardProps {
  result: AnalysisResult;
  reportFile?: File | null;
}

export default function AnalysisDashboard({
  result,
  reportFile = null,
}: AnalysisDashboardProps) {
  const [selectedObservation, setSelectedObservation] =
    useState<Observation | null>(null);

  return (
    <>
      <section className="analysis-result" aria-label="Resultado del análisis">
        <div className="result-banner">
          <div className="result-banner__icon">
            <Info aria-hidden="true" size={19} />
          </div>
          <div className="result-banner__copy">
            <strong>Resultado parcial · evidencia observable, no incidente confirmado</strong>
            <p>
              Se procesaron {result.completeness.records_evaluated.toLocaleString("es-ES")} de{" "}
              {result.completeness.records_seen.toLocaleString("es-ES")} registros. Las reglas
              pendientes no se ejecutaron y las observaciones no prueban impacto ni atribución.
            </p>
          </div>
          <span className="result-banner__contract">analysis-partial/1</span>
        </div>

        {result.timezone_status === "undefined" && (
          <div className="integrity-note" role="note">
            <Info aria-hidden="true" size={17} />
            <span>
              Zona horaria no definida. Se muestran los timestamps originales sin
              conversión horaria.
            </span>
          </div>
        )}

        <AnalysisSummary result={result} />
        {reportFile && (
          <ReportDownloads
            file={reportFile}
            expectedFileSha256={result.file_sha256}
          />
        )}

        <section className="panel result-panel">
          <div className="panel-heading panel-heading--row">
            <div>
              <span className="section-kicker">COBERTURA DE DETECCIÓN</span>
              <h2>Estado de reglas</h2>
              <p>La cobertura y los conteos provienen de la respuesta de la API.</p>
            </div>
            <div className="coverage-legend">
              <span className="legend-item"><i className="legend-dot legend-dot--active" /> Ejecutadas</span>
              <span className="legend-item"><i className="legend-dot legend-dot--pending" /> Pendientes</span>
            </div>
          </div>
          <RuleCoverageTable rules={result.rule_execution} />
        </section>

        <section className="panel result-panel">
          <div className="panel-heading panel-heading--row">
            <div>
              <span className="section-kicker">OBSERVACIONES TRAZABLES</span>
              <h2>Coincidencias de reglas</h2>
              <p>
                Cada observación enlaza con los registros fuente mediante su Log_ID.
              </p>
            </div>
            <span className="observation-count">
              {result.observations.length.toLocaleString("es-ES")} observaciones
            </span>
          </div>
          <ObservationsTable
            observations={result.observations}
            onSelect={setSelectedObservation}
          />
        </section>

        <section className="analysis-footnotes">
          <div className="footnote-card">
            <Fingerprint aria-hidden="true" size={17} />
            <div>
              <strong>Identidad del análisis</strong>
              <span>
                {result.analysis_id === null
                  ? `No evaluable: ${result.analysis_id_reason}`
                  : result.analysis_id}
              </span>
            </div>
          </div>
          {result.completeness.records_not_evaluable > 0 && (
            <div className="footnote-card footnote-card--warning">
              <AlertTriangle aria-hidden="true" size={17} />
              <div>
                <strong>Registros no evaluables</strong>
                <span>
                  {result.completeness.records_not_evaluable.toLocaleString("es-ES")} filas
                  omitidas. Revisá la evidencia y códigos devueltos por la API.
                </span>
              </div>
            </div>
          )}
        </section>
      </section>

      {selectedObservation && (
        <EvidenceDetails
          observation={selectedObservation}
          onClose={() => setSelectedObservation(null)}
        />
      )}
    </>
  );
}
