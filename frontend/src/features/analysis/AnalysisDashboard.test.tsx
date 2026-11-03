import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import AnalysisDashboard from "./AnalysisDashboard";
import type { AnalysisResult } from "../../types/analysis";

function makeResult(timezoneStatus: string): AnalysisResult {
  return {
    contract: "analysis-partial/1",
    schema_version: "1.0",
    canon_version: "cj/1",
    analysis_id: null,
    analysis_id_status: "not_evaluable",
    analysis_id_reason: "No evaluable",
    file_sha256: "abc123",
    content_sha256: null,
    content_sha256_status: "not_evaluable",
    status: "partial",
    completion_status: "partial",
    timezone_status: timezoneStatus,
    completeness: {
      records_seen: 0,
      records_evaluated: 0,
      records_not_evaluable: 0,
      records_with_non_evaluable_ip: 0,
      rules_total: 0,
      rules_executed: 0,
      rules_partially_executed: 0,
      rules_pending: 0,
      rules_not_evaluable: 0,
      chains_not_evaluable: 0,
      chains_pending_reconciliation: 0,
      chains_not_ratified: 0,
    },
    rule_execution: {},
    chain_execution: {},
    non_evaluable_records: [],
    ip_classification_status: "provisional",
    observations: [],
    activity_summary: {
      records_loaded: 0,
      observations_emitted: 0,
      no_observations_means_no_rule_match_not_no_activity: true,
    },
  };
}

describe("AnalysisDashboard timestamp notice", () => {
  it("explains that original timestamps are shown without timezone conversion", () => {
    render(<AnalysisDashboard result={makeResult("undefined")} />);

    expect(
      screen.getByText(
        "Zona horaria no definida. Se muestran los timestamps originales sin conversión horaria.",
      ),
    ).toBeInTheDocument();
  });

  it("does not show an undefined-timezone warning for another status", () => {
    render(<AnalysisDashboard result={makeResult("defined")} />);

    expect(screen.queryByText(/Zona horaria no definida/)).not.toBeInTheDocument();
  });
});
