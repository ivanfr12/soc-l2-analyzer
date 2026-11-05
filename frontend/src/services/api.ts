import type {
  AnalysisResult,
  ApiHealth,
  ApiMetadata,
  ChainExecutionResult,
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

export interface ReportDownload {
  blob: Blob;
  filename: string;
}

export type ReportType = "executive" | "technical";

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

function isChainNode(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.rule_id === "string" &&
    isStringArray(value.log_ids) &&
    isStringArray(value.hostnames) &&
    isStringArray(value.users) &&
    isStringArray(value.source_ips) &&
    isStringOrNull(value.first_timestamp) &&
    isStringOrNull(value.last_timestamp)
  );
}

function isChainLink(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.from_rule === "string" &&
    typeof value.to_rule === "string" &&
    isStringArray(value.basis) &&
    typeof value.delta_seconds === "number" &&
    typeof value.window_seconds === "number"
  );
}

function isContextualEvidence(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.rule_id === "string" &&
    isStringArray(value.log_ids) &&
    (value.basis === undefined || isStringArray(value.basis)) &&
    (value.delta_seconds === undefined ||
      typeof value.delta_seconds === "number") &&
    (value.window_seconds === undefined ||
      typeof value.window_seconds === "number") &&
    (value.note === undefined || typeof value.note === "string")
  );
}

function isChainDetail(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.chain_id === "string" &&
    typeof value.name === "string" &&
    typeof value.status === "string" &&
    typeof value.ratified === "boolean" &&
    typeof value.reason === "string" &&
    typeof value.semantics === "string" &&
    isNumberOrNull(value.level) &&
    isStringOrNull(value.severity) &&
    typeof value.severity_status === "string" &&
    isNumberOrNull(value.score_1e4) &&
    typeof value.score_status === "string" &&
    isNumberOrNull(value.reference_score_1e4) &&
    isStringArray(value.evidence) &&
    Array.isArray(value.nodes) &&
    value.nodes.every(isChainNode) &&
    Array.isArray(value.links) &&
    value.links.every(isChainLink) &&
    Array.isArray(value.contextual_evidence) &&
    value.contextual_evidence.every(isContextualEvidence)
  );
}

function isChainExecutionResult(value: unknown): value is ChainExecutionResult {
  if (!isRecord(value) || value.contract !== "chain-execution/1") {
    return false;
  }
  if (
    typeof value.file_sha256 !== "string" ||
    !isStringOrNull(value.analysis_id) ||
    typeof value.analysis_id_status !== "string" ||
    typeof value.canon_version !== "string" ||
    typeof value.semantics !== "string" ||
    !isRecord(value.chains)
  ) {
    return false;
  }
  return Object.values(value.chains).every(isChainDetail);
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

export async function getChains(
  file: File,
  expectedFileSha256: string,
): Promise<ChainExecutionResult> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("expected_file_sha256", expectedFileSha256);

  const payload = await requestJson("/api/chains", {
    method: "POST",
    body: formData,
  });
  if (!isChainExecutionResult(payload)) {
    throw new ApiError(
      "La API respondió, pero el contrato no coincide con chain-execution/1.",
    );
  }
  return payload;
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

function reportFilename(
  contentDisposition: string | null,
  reportType: ReportType,
): string {
  const fallback =
    reportType === "executive"
      ? "SOC_L2_Informe_Ejecutivo.pdf"
      : "SOC_L2_Informe_Tecnico.pdf";
  if (!contentDisposition) return fallback;

  const encoded = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const plain = contentDisposition.match(/filename="?([^";]+)"?/i)?.[1];
  let candidate = encoded ? decodeFilename(encoded) : plain;
  if (
    !candidate ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*\.pdf$/i.test(candidate) ||
    candidate.includes("..")
  ) {
    return fallback;
  }
  return candidate;
}

function decodeFilename(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

async function reportError(response: Response): Promise<ApiError> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return new ApiError(
      "La API rechazó la solicitud de informe.",
      response.status,
      null,
      "http",
    );
  }

  const detail = isRecord(payload) ? payload.detail : null;
  const message =
    isRecord(detail) && typeof detail.message === "string"
      ? detail.message
      : "La API rechazó la solicitud de informe.";
  const code =
    isRecord(detail) && typeof detail.code === "string" ? detail.code : null;
  return new ApiError(message, response.status, code, "http");
}

async function requestReport(
  reportType: ReportType,
  file: File,
  expectedFileSha256: string,
  signal?: AbortSignal,
): Promise<ReportDownload> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("expected_file_sha256", expectedFileSha256);

  let response: Response;
  try {
    response = await fetch(`/api/reports/${reportType}`, {
      method: "POST",
      body: formData,
      signal,
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new ApiError(
      "No se pudo conectar con la API para generar el informe.",
      null,
      null,
      "network",
    );
  }

  if (!response.ok) throw await reportError(response);
  if (
    !response.headers
      .get("content-type")
      ?.toLowerCase()
      .includes("application/pdf")
  ) {
    throw new ApiError("La API no devolvió un documento PDF válido.");
  }

  const blob = await response.blob();
  if (blob.size < 5 || (await blob.slice(0, 5).text()) !== "%PDF-") {
    throw new ApiError("La API devolvió un contenido que no es un PDF válido.");
  }
  return {
    blob,
    filename: reportFilename(
      response.headers.get("content-disposition"),
      reportType,
    ),
  };
}

export function requestExecutiveReport(
  file: File,
  expectedFileSha256: string,
  signal?: AbortSignal,
): Promise<ReportDownload> {
  return requestReport("executive", file, expectedFileSha256, signal);
}

export function requestTechnicalReport(
  file: File,
  expectedFileSha256: string,
  signal?: AbortSignal,
): Promise<ReportDownload> {
  return requestReport("technical", file, expectedFileSha256, signal);
}
