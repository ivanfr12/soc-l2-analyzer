import { afterEach, describe, expect, it, vi } from "vitest";

import {
  analyzeFile,
  ApiError,
  getChains,
  getHealth,
  getMetadata,
  requestExecutiveReport,
  requestTechnicalReport,
} from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("API client", () => {
  it("uses health and metadata endpoints and validates their payloads", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ status: "ok" }), { status: 200 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            analysis_schema_version: "1.0",
            canon_version: "cj/1",
            max_upload_bytes: 10 * 1024 * 1024,
            required_sheet: "SIEM Export",
            required_columns: ["Log_ID"],
            analysis_available: true,
            analysis_mode: "partial",
          }),
          { status: 200 },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    await expect(getHealth()).resolves.toEqual({ status: "ok" });
    await expect(getMetadata()).resolves.toMatchObject({
      canon_version: "cj/1",
      analysis_mode: "partial",
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/health",
      "/api/meta",
    ]);
  });

  it("uploads multipart data without setting Content-Type and validates the contract", async () => {
    const payload = {
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
      timezone_status: "undefined",
      completeness: {
        records_seen: 1,
        records_evaluated: 1,
        records_not_evaluable: 0,
        records_with_non_evaluable_ip: 0,
        rules_total: 13,
        rules_executed: 6,
        rules_partially_executed: 2,
        rules_pending: 5,
        rules_not_evaluable: 0,
        chains_not_evaluable: 5,
        chains_pending_reconciliation: 1,
        chains_not_ratified: 1,
      },
      rule_execution: {
        R03: {
          name: "Logon desde IP externa",
          status: "executed",
          matched_observation_count: 0,
          records_in_scope: 1,
          records_evaluated: 1,
          reason: null,
        },
      },
      chain_execution: {},
      non_evaluable_records: [],
      ip_classification_status: "provisional_without_iana_snapshots",
      observations: [],
      activity_summary: {
        records_loaded: 1,
        observations_emitted: 0,
        no_observations_means_no_rule_match_not_no_activity: true,
      },
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(payload), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const file = new File(["workbook"], "events.xlsx", {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    });
    await expect(analyzeFile(file)).resolves.toMatchObject({
      contract: "analysis-partial/1",
      completeness: { records_seen: 1 },
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/analyze");
    expect(init.method).toBe("POST");
    expect(init.body).toBeInstanceOf(FormData);
    expect((init.body as FormData).get("file")).toBe(file);
    expect(init.headers).toBeUndefined();
  });

  it("surfaces API validation errors and rejects unexpected contracts", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              detail: { code: "missing_sheet", message: "Falta la hoja SIEM Export." },
            }),
            { status: 422 },
          ),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ contract: "other/1" }), { status: 200 }),
        ),
    );
    const file = new File(["data"], "events.xlsx");

    await expect(analyzeFile(file)).rejects.toMatchObject({
      status: 422,
      code: "missing_sheet",
      message: "Falta la hoja SIEM Export.",
    });
    await expect(analyzeFile(file)).rejects.toBeInstanceOf(ApiError);
  });

  it.each([
    ["executive", requestExecutiveReport, "/api/reports/executive"],
    ["technical", requestTechnicalReport, "/api/reports/technical"],
  ] as const)(
    "requests the %s report with the analyzed file and expected hash",
    async (_type, requestReport, endpoint) => {
      const fetchMock = vi.fn().mockResolvedValue(
        new Response("%PDF-1.4 test", {
          status: 200,
          headers: {
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="safe-report.pdf"',
          },
        }),
      );
      vi.stubGlobal("fetch", fetchMock);
      const file = new File(["workbook"], "events.xlsx");

      const report = await requestReport(file, "a".repeat(64));

      expect(report.blob).toBeInstanceOf(Blob);
      expect(await report.blob.slice(0, 5).text()).toBe("%PDF-");
      expect(report.filename).toBe("safe-report.pdf");
      const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(endpoint);
      expect(init.method).toBe("POST");
      expect(init.body).toBeInstanceOf(FormData);
      expect((init.body as FormData).get("file")).toBe(file);
      expect((init.body as FormData).get("expected_file_sha256")).toBe(
        "a".repeat(64),
      );
      expect(init.headers).toBeUndefined();
    },
  );

  it("uses a safe fallback name for an unsafe Content-Disposition filename", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("%PDF-1.4 test", {
          status: 200,
          headers: {
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="../private.pdf"',
          },
        }),
      ),
    );

    const report = await requestExecutiveReport(
      new File(["workbook"], "events.xlsx"),
      "a".repeat(64),
    );

    expect(report.filename).toBe("SOC_L2_Informe_Ejecutivo.pdf");
  });

  it("validates a chain-execution/1 response", async () => {
    const payload = {
      contract: "chain-execution/1",
      file_sha256: "a".repeat(64),
      analysis_id: "A-" + "b".repeat(32),
      analysis_id_status: "provisional_unratified_vectors",
      canon_version: "cj/1",
      semantics: "observed_sequence_candidate",
      chains: {
        C1: {
          chain_id: "C1",
          name: "Cadena 1",
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
          evidence: ["EVT-1"],
          nodes: [
            {
              rule_id: "R01",
              log_ids: ["EVT-1"],
              hostnames: ["DC-01"],
              users: ["CORP\\u"],
              source_ips: ["203.0.113.74"],
              first_timestamp: "2026-10-23T08:25:00",
              last_timestamp: "2026-10-23T08:35:08",
            },
          ],
          links: [
            {
              from_rule: "R01",
              to_rule: "R02",
              basis: ["same_source_ip"],
              delta_seconds: 232,
              window_seconds: 900,
            },
          ],
          contextual_evidence: [
            {
              rule_id: "4672",
              log_ids: ["EVT-2"],
              basis: ["same_user"],
              delta_seconds: 60,
              window_seconds: 3600,
              note: "contexto",
            },
          ],
        },
      },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(payload), { status: 200 }),
      ),
    );
    const file = new File(["workbook"], "events.xlsx");
    await expect(getChains(file, "a".repeat(64))).resolves.toMatchObject({
      contract: "chain-execution/1",
      chains: { C1: { status: "executed" } },
    });
  });

  it("rejects an invalid chain-execution contract", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ contract: "other/1" }), { status: 200 }),
      ),
    );
    const file = new File(["workbook"], "events.xlsx");
    await expect(getChains(file, "a".repeat(64))).rejects.toBeInstanceOf(
      ApiError,
    );
  });

  it("surfaces 409 analysis_not_cached", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            detail: { code: "analysis_not_cached", message: "No hay análisis." },
          }),
          { status: 409 },
        ),
      ),
    );
    const file = new File(["workbook"], "events.xlsx");
    await expect(getChains(file, "a".repeat(64))).rejects.toMatchObject({
      status: 409,
      code: "analysis_not_cached",
    });
  });

  it("surfaces 409 file_hash_mismatch", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            detail: { code: "file_hash_mismatch", message: "Hash incorrecto." },
          }),
          { status: 409 },
        ),
      ),
    );
    const file = new File(["workbook"], "events.xlsx");
    await expect(getChains(file, "a".repeat(64))).rejects.toMatchObject({
      status: 409,
      code: "file_hash_mismatch",
    });
  });

  it("surfaces network errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("boom")));
    const file = new File(["workbook"], "events.xlsx");
    await expect(getChains(file, "a".repeat(64))).rejects.toBeInstanceOf(
      ApiError,
    );
  });
  it("parses JSON report errors instead of treating them as PDFs", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            detail: {
              code: "file_hash_mismatch",
              message: "El archivo no coincide con el análisis actual.",
            },
          }),
          { status: 409, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );

    await expect(
      requestTechnicalReport(
        new File(["workbook"], "events.xlsx"),
        "a".repeat(64),
      ),
    ).rejects.toMatchObject({
      status: 409,
      code: "file_hash_mismatch",
      message: "El archivo no coincide con el análisis actual.",
    });
  });

  it("rejects a successful HTTP response that is not a PDF", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "not a pdf" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(
      requestExecutiveReport(
        new File(["workbook"], "events.xlsx"),
        "a".repeat(64),
      ),
    ).rejects.toThrow("no devolvió un documento PDF");
  });
});
