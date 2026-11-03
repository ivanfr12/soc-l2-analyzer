import { afterEach, describe, expect, it, vi } from "vitest";

import { analyzeFile, ApiError, getHealth, getMetadata } from "./api";

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
});
