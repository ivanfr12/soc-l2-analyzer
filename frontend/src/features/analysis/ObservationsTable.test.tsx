import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import ObservationsTable from "./ObservationsTable";
import type { Observation } from "../../types/analysis";

const observation: Observation = {
  rule_id: "R05",
  rule_name: "PowerShell ofuscado",
  observation_type: "deterministic_rule_match",
  description: "Predicado documentado coincidente.",
  evidence: [],
  impact_demonstrated: false,
  incident_attribution: false,
  severity: null,
  severity_status: "not_defined",
  level: null,
  level_status: "not_evaluable_in_partial_contract",
  score_1e4: null,
  confidence_basis_points: null,
  confidence_status: "not_evaluable_without_E_K_catalogs",
};

describe("ObservationsTable", () => {
  it("renders nullable severity, level, and confidence as unavailable", () => {
    render(<ObservationsTable observations={[observation]} onSelect={() => {}} />);

    expect(screen.getByText("No disponible")).toBeInTheDocument();
    expect(screen.getAllByText("No evaluable")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Ver evidencias de R05" })).toHaveTextContent(
      "0 registros",
    );
  });

  it("does not describe an empty match list as no activity", () => {
    render(<ObservationsTable observations={[]} onSelect={() => {}} />);

    expect(
      screen.getByText("No hubo coincidencias en las condiciones implementadas"),
    ).toBeInTheDocument();
    expect(screen.getByText("Esto no significa ausencia de actividad o de amenazas.")).toBeInTheDocument();
  });
});
