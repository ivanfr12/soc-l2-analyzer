import type {
  AnalysisResult,
  ApiHealth,
  ApiMetadata,
} from "../types/analysis";

export class ApiError extends Error {
  readonly status: number | null;
  readonly code: string | null;
  readonly kind: "http" | "network" | "unexpected";

  constructor(
    message: string,
    status: number | null = null,
    code: string | null = null,
    kind: "http" | "network" | "unexpected" = "unexpected",
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.kind = kind;
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isStringOrNull = (value: unknown): value is string | null =>
  value === null || typeof value === "string";

const isNumberOrNull = (value: unknown): value is number | null =>
  value === null || typeof value === "number";

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === "string");

function isEvidenceRecord(value: unknown): boolean {
  return (
    isRecord(value) &&
    isStringOrNull(value.Log_ID) &&
    isStringOrNull(value.Timestamp) &&
    isStringOrNull(value.Hostname) &&
    isStringOrNull(value.Event_ID) &&
    isStringOrNull(value.User) &&
    isStringOrNull(value.Source_IP) &&
    typeof value.source_ip_category === "string" &&
    typeof value.ip_classification_source === "string" &&
    typeof value.ip_registry_validation_status === "string"
  );
}

function isObservation(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.rule_id === "string" &&
    typeof value.rule_name === "string" &&
    typeof value.observation_type === "string" &&
    typeof value.description === "string" &&
    Array.isArray(value.evidence) &&
    value.evidence.every(isEvidenceRecord) &&
    typeof value.impact_demonstrated === "boolean" &&
    typeof value.incident_attribution === "boolean" &&
    isStringOrNull(value.severity) &&
    typeof value.severity_status === "string" &&
    isNumberOrNull(value.level) &&
    typeof value.level_status === "string" &&
    isNumberOrNull(value.score_1e4) &&
    isNumberOrNull(value.confidence_basis_points) &&
    typeof value.confidence_status === "string"
  );
}

function isRuleExecution(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.name === "string" &&
    typeof value.status === "string" &&
    typeof value.matched_observation_count === "number" &&
    typeof value.records_in_scope === "number" &&
    typeof value.records_evaluated === "number" &&
    isStringOrNull(value.reason)
  );
}

function isCompleteness(value: unknown): boolean {
  const numericFields = [
    "records_seen",
    "records_evaluated",
    "records_not_evaluable",
    "records_with_non_evaluable_ip",
    "rules_total",
    "rules_executed",
    "rules_partially_executed",
    "rules_pending",
    "rules_not_evaluable",
    "chains_not_evaluable",
    "chains_pending_reconciliation",
    "chains_not_ratified",
  ];
  return (
    isRecord(value) &&
    numericFields.every((field) => typeof value[field] === "number")
  );
}

function isAnalysisResult(value: unknown): value is AnalysisResult {
  if (!isRecord(value) || value.contract !== "analysis-partial/1") {
    return false;
  }

  const rules = value.rule_execution;
  const chains = value.chain_execution;
  const activity = value.activity_summary;
  return (
    typeof value.schema_version === "string" &&
    typeof value.canon_version === "string" &&
    isStringOrNull(value.analysis_id) &&
    typeof value.analysis_id_status === "string" &&
    typeof value.analysis_id_reason === "string" &&
    typeof value.file_sha256 === "string" &&
    isStringOrNull(value.content_sha256) &&
    typeof value.content_sha256_status === "string" &&
    typeof value.status === "string" &&
    typeof value.completion_status === "string" &&
    typeof value.timezone_status === "string" &&
    isCompleteness(value.completeness) &&
    isRecord(rules) &&
    Object.values(rules).every(isRuleExecution) &&
    isRecord(chains) &&
    Object.values(chains).every(
      (chain) =>
        isRecord(chain) &&
        typeof chain.status === "string" &&
        typeof chain.ratified === "boolean" &&
        typeof chain.reason === "string",
    ) &&
    Array.isArray(value.non_evaluable_records) &&
    value.non_evaluable_records.every(
      (record) =>
        isRecord(record) &&
        isStringOrNull(record.log_id) &&
        typeof record.code === "string",
    ) &&
    typeof value.ip_classification_status === "string" &&
    Array.isArray(value.observations) &&
    value.observations.every(isObservation) &&
    isRecord(activity) &&
    typeof activity.records_loaded === "number" &&
    typeof activity.observations_emitted === "number" &&
    typeof activity.no_observations_means_no_rule_match_not_no_activity === "boolean"
  );
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new ApiError(
      "La API devolvió una respuesta que no se pudo interpretar.",
      response.status,
      null,
      "unexpected",
    );
  }
}

async function requestJson(path: string, init?: RequestInit): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new ApiError(
      "No se pudo conectar con la API. Verificá que el backend esté iniciado.",
      null,
      null,
      "network",
    );
  }

  const payload = await readJson(response);
  if (!response.ok) {
    const detail =
      isRecord(payload) && isRecord(payload.detail) ? payload.detail : null;
    const message =
      detail && typeof detail.message === "string"
        ? detail.message
        : "La API rechazó la solicitud.";
    const code = detail && typeof detail.code === "string" ? detail.code : null;
    throw new ApiError(message, response.status, code, "http");
  }
  return payload;
}

export async function getHealth(): Promise<ApiHealth> {
  const payload = await requestJson("/api/health");
  if (!isRecord(payload) || typeof payload.status !== "string") {
    throw new ApiError("La respuesta de health no tiene el formato esperado.");
  }
  return { status: payload.status };
}

export async function getMetadata(): Promise<ApiMetadata> {
  const payload = await requestJson("/api/meta");
  if (
    !isRecord(payload) ||
    typeof payload.max_upload_bytes !== "number" ||
    typeof payload.analysis_schema_version !== "string" ||
    typeof payload.canon_version !== "string" ||
    typeof payload.required_sheet !== "string" ||
    !isStringArray(payload.required_columns) ||
    typeof payload.analysis_available !== "boolean" ||
    typeof payload.analysis_mode !== "string"
  ) {
    throw new ApiError("La metadata de la API tiene un formato inesperado.");
  }
  return {
    analysis_schema_version: payload.analysis_schema_version,
    canon_version: payload.canon_version,
    max_upload_bytes: payload.max_upload_bytes,
    required_sheet: payload.required_sheet,
    required_columns: payload.required_columns,
    analysis_available: payload.analysis_available,
    analysis_mode: payload.analysis_mode,
  };
}

export async function analyzeFile(file: File): Promise<AnalysisResult> {
  const formData = new FormData();
  formData.append("file", file);

  const payload = await requestJson("/api/analyze", {
    method: "POST",
    body: formData,
  });
  if (!isAnalysisResult(payload)) {
    throw new ApiError(
      "La API respondió, pero el contrato no coincide con analysis-partial/1.",
    );
  }
  return payload;
}
