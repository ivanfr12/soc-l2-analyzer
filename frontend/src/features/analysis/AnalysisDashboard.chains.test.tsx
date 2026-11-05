import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AnalysisDashboard from "./AnalysisDashboard";
import type { AnalysisResult } from "../../types/analysis";

const mocks = vi.hoisted(() => ({
  getChains: vi.fn(),
}));

vi.mock("../../services/api", () => ({
  ApiError: class ApiError extends Error {},
  getChains: mocks.getChains,
}));

function makeResult(fileSha: string): AnalysisResult {
  return {
    contract: "analysis-partial/1",
    schema_version: "1.0",
    canon_version: "cj/1",
    analysis_id: null,
    analysis_id_status: "not_evaluable",
    analysis_id_reason: "No evaluable",
    file_sha256: fileSha,
    content_sha256: null,
    content_sha256_status: "not_evaluable",
    status: "partial",
    completion_status: "partial",
    timezone_status: "undefined",
    completeness: {
      records_seen: 1,
      records_evaluated: 1,
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
    ip_classification_status: "verified",
    observations: [],
    activity_summary: {
      records_loaded: 1,
      observations_emitted: 0,
      no_observations_means_no_rule_match_not_no_activity: true,
    },
  };
}

describe("AnalysisDashboard chains integration", () => {
  beforeEach(() => {
    mocks.getChains.mockReset();
  });
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("shows chains after a successful query", async () => {
    mocks.getChains.mockResolvedValue({
      contract: "chain-execution/1",
      file_sha256: "a".repeat(64),
      analysis_id: null,
      analysis_id_status: "provisional_unratified_vectors",
      canon_version: "cj/1",
      semantics: "observed_sequence_candidate",
      chains: {
        C1: {
          chain_id: "C1",
          name: "C1",
          status: "executed",
          ratified: true,
          reason: "ok",
          semantics: "observed_sequence_candidate",
          level: 2,
          severity: "Medium",
          severity_status: "ratified",
          score_1e4: null,
          score_status: "not_evaluable_without_E_K_catalogs",
          reference_score_1e4: 4500,
          evidence: [],
          nodes: [],
          links: [],
          contextual_evidence: [],
        },
      },
    });
    const file = new File(["workbook"], "events.xlsx");
    render(<AnalysisDashboard result={makeResult("a".repeat(64))} reportFile={file} />);
    await waitFor(() => expect(screen.getByText("C1", { selector: ".section-kicker" })).toBeInTheDocument());
  });

  it("keeps the analysis visible when /chains fails", async () => {
    mocks.getChains.mockRejectedValue(new Error("network"));
    const file = new File(["workbook"], "events.xlsx");
    render(<AnalysisDashboard result={makeResult("a".repeat(64))} reportFile={file} />);
    await waitFor(() =>
      expect(screen.getByText(/No se pudieron consultar las cadenas/)).toBeInTheDocument(),
    );
    expect(screen.getByText("analysis-partial/1")).toBeInTheDocument();
  });

  it("ignores a stale chains response", async () => {
    let resolveFirst: (value: unknown) => void = () => {};
    const first = new Promise((resolve) => {
      resolveFirst = resolve;
    });
    const second = Promise.resolve({
      contract: "chain-execution/1",
      file_sha256: "b".repeat(64),
      analysis_id: null,
      analysis_id_status: "provisional_unratified_vectors",
      canon_version: "cj/1",
      semantics: "observed_sequence_candidate",
      chains: {
        C1: {
          chain_id: "C1",
          name: "NEW",
          status: "executed",
          ratified: true,
          reason: "new",
          semantics: "observed_sequence_candidate",
          level: 2,
          severity: "Medium",
          severity_status: "ratified",
          score_1e4: null,
          score_status: "not_evaluable_without_E_K_catalogs",
          reference_score_1e4: 4500,
          evidence: [],
          nodes: [],
          links: [],
          contextual_evidence: [],
        },
      },
    });
    mocks.getChains.mockReturnValueOnce(first).mockReturnValueOnce(second);

    const file = new File(["workbook"], "events.xlsx");
    const { rerender } = render(
      <AnalysisDashboard result={makeResult("a".repeat(64))} reportFile={file} />,
    );
    rerender(<AnalysisDashboard result={makeResult("b".repeat(64))} reportFile={file} />);

    resolveFirst({
      contract: "chain-execution/1",
      file_sha256: "a".repeat(64),
      analysis_id: null,
      analysis_id_status: "provisional_unratified_vectors",
      canon_version: "cj/1",
      semantics: "observed_sequence_candidate",
      chains: {
        C1: {
          chain_id: "C1",
          name: "OLD",
          status: "executed",
          ratified: true,
          reason: "old",
          semantics: "observed_sequence_candidate",
          level: 2,
          severity: "Medium",
          severity_status: "ratified",
          score_1e4: null,
          score_status: "not_evaluable_without_E_K_catalogs",
          reference_score_1e4: 4500,
          evidence: [],
          nodes: [],
          links: [],
          contextual_evidence: [],
        },
      },
    });

    await waitFor(() => expect(screen.getByText("NEW")).toBeInTheDocument());
    expect(screen.queryByText("OLD")).not.toBeInTheDocument();
  });
});