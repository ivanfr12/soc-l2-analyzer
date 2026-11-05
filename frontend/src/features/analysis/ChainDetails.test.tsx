import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import ChainDetails from "./ChainDetails";
import type { ChainDetail, ChainExecutionResult } from "../../types/analysis";

function makeChain(overrides: Partial<ChainDetail> = {}): ChainDetail {
  return {
    chain_id: "C1",
    name: "Cadena 1",
    status: "executed",
    ratified: true,
    reason: "motivo",
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
        note: "contexto opcional",
      },
    ],
    ...overrides,
  };
}

function makeResult(chains: Record<string, ChainDetail>): ChainExecutionResult {
  return {
    contract: "chain-execution/1",
    file_sha256: "a".repeat(64),
    analysis_id: null,
    analysis_id_status: "provisional_unratified_vectors",
    canon_version: "cj/1",
    semantics: "observed_sequence_candidate",
    chains,
  };
}

describe("ChainDetails", () => {
  it("renders C1-C6, C2 pending and C7 not ratified", () => {
    const chains: Record<string, ChainDetail> = {};
    for (const id of ["C1", "C2", "C3", "C4", "C5", "C6"]) {
      chains[id] = makeChain({
        chain_id: id,
        name: `Cadena ${id}`,
        status: id === "C2" ? "pending_reconciliation" : "executed",
      });
    }
    chains.C7 = makeChain({
      chain_id: "C7",
      name: "C7",
      status: "not_evaluable",
      ratified: false,
      severity: null,
      level: null,
      reference_score_1e4: null,
    });

    render(<ChainDetails result={makeResult(chains)} loading={false} error={null} />);

    expect(screen.getByText("C1", { selector: ".section-kicker" })).toBeInTheDocument();
    expect(screen.getByText("C2", { selector: ".section-kicker" })).toBeInTheDocument();
    expect(screen.getByText("C7", { selector: ".section-kicker" })).toBeInTheDocument();
    expect(screen.getByText("Pendiente de conciliación")).toBeInTheDocument();
    expect(screen.getAllByText("No").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/secuencia observada candidata/i).length).toBeGreaterThanOrEqual(1);
  });

  it("shows contextual evidence differentiated from primary evidence", () => {
    const chains = { C1: makeChain({}) };
    render(<ChainDetails result={makeResult(chains)} loading={false} error={null} />);
    expect(screen.getByText("Evidencia contextual (no membership)")).toBeInTheDocument();
    expect(screen.getByText("contexto opcional")).toBeInTheDocument();
    expect(screen.getByText("Evidencia principal")).toBeInTheDocument();
  });

  it("shows loading and error states", () => {
    const { rerender } = render(
      <ChainDetails result={null} loading={true} error={null} />,
    );
    expect(screen.getByText("Consultando cadenas…")).toBeInTheDocument();

    rerender(<ChainDetails result={null} loading={false} error="boom" />);
    expect(screen.getByText("boom")).toBeInTheDocument();
  });
});