import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AnalysisResult } from "../types/analysis";
import App from "./App";

const mocks = vi.hoisted(() => ({
  analyzeFile: vi.fn(),
  getHealth: vi.fn(),
  getMetadata: vi.fn(),
}));

vi.mock("../services/api", () => ({
  ApiError: class ApiError extends Error {},
  analyzeFile: mocks.analyzeFile,
  getChains: vi.fn().mockResolvedValue(null),
  getHealth: mocks.getHealth,
  getMetadata: mocks.getMetadata,
  requestExecutiveReport: vi.fn(),
  requestTechnicalReport: vi.fn(),
}));

function makeResult(): AnalysisResult {
  return {
    contract: "analysis-partial/1",
    schema_version: "1.0",
    canon_version: "cj/1",
    analysis_id: null,
    analysis_id_status: "not_evaluable",
    analysis_id_reason: "No evaluable",
    file_sha256: "a".repeat(64),
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
      rules_total: 13,
      rules_executed: 0,
      rules_partially_executed: 0,
      rules_pending: 13,
      rules_not_evaluable: 0,
      chains_not_evaluable: 5,
      chains_pending_reconciliation: 1,
      chains_not_ratified: 1,
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

beforeEach(() => {
  mocks.getHealth.mockResolvedValue({ status: "ok" });
  mocks.getMetadata.mockResolvedValue({
    analysis_schema_version: "1.0",
    canon_version: "cj/1",
    max_upload_bytes: 10 * 1024 * 1024,
    required_sheet: "SIEM Export",
    required_columns: ["Log_ID"],
    analysis_available: true,
    analysis_mode: "partial",
  });
  mocks.analyzeFile.mockResolvedValue(makeResult());
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("App report association", () => {
  it("removes the previous result and report actions when a new workbook is selected", async () => {
    render(<App />);
    const input = screen.getByLabelText("Seleccionar archivo Excel XLSX");
    const firstFile = new File(["first"], "first.xlsx");
    fireEvent.change(input, { target: { files: [firstFile] } });
    fireEvent.click(screen.getByRole("button", { name: "Analizar workbook" }));

    await screen.findByRole("button", {
      name: "Descargar informe ejecutivo",
    });
    expect(mocks.analyzeFile).toHaveBeenCalledWith(firstFile);

    fireEvent.change(input, {
      target: { files: [new File(["second"], "second.xlsx")] },
    });

    await waitFor(() => {
      expect(
        screen.queryByRole("button", { name: /Descargar informe/ }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByRole("region", { name: "Resultado del análisis" }),
      ).not.toBeInTheDocument();
    });
  });
});
