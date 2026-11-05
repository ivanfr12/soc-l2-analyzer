export type RuleStatus =
  | "executed"
  | "partially_executed"
  | "pending"
  | "not_evaluable"
  | string;

export interface ApiHealth {
  status: string;
}

export interface ApiMetadata {
  analysis_schema_version: string;
  canon_version: string;
  max_upload_bytes: number;
  required_sheet: string;
  required_columns: string[];
  analysis_available: boolean;
  analysis_mode: string;
}

export interface Completeness {
  records_seen: number;
  records_evaluated: number;
  records_not_evaluable: number;
  records_with_non_evaluable_ip: number;
  rules_total: number;
  rules_executed: number;
  rules_partially_executed: number;
  rules_pending: number;
  rules_not_evaluable: number;
  chains_not_evaluable: number;
  chains_pending_reconciliation: number;
  chains_not_ratified: number;
}

export interface RuleExecution {
  name: string;
  status: RuleStatus;
  matched_observation_count: number;
  records_in_scope: number;
  records_evaluated: number;
  reason: string | null;
}

export interface ChainExecution {
  status: string;
  ratified: boolean;
  reason: string;
}

export interface NonEvaluableRecord {
  log_id: string | null;
  code: string;
}

export interface EvidenceRecord {
  Log_ID: string | null;
  Timestamp: string | null;
  Hostname: string | null;
  Event_ID: string | null;
  User: string | null;
  Source_IP: string | null;
  source_ip_category: string;
  ip_classification_source: string;
  ip_registry_validation_status: string;
}

export interface Observation {
  rule_id: string;
  rule_name: string;
  observation_type: string;
  description: string;
  evidence: EvidenceRecord[];
  impact_demonstrated: boolean;
  incident_attribution: boolean;
  severity: string | null;
  severity_status: string;
  level: number | null;
  level_status: string;
  score_1e4: number | null;
  confidence_basis_points: number | null;
  confidence_status: string;
}

export interface ChainNode {
  rule_id: string;
  log_ids: string[];
  hostnames: string[];
  users: string[];
  source_ips: string[];
  first_timestamp: string | null;
  last_timestamp: string | null;
}

export interface ChainLink {
  from_rule: string;
  to_rule: string;
  basis: string[];
  delta_seconds: number;
  window_seconds: number;
}

export interface ContextualEvidence {
  rule_id: string;
  log_ids: string[];
  basis?: string[];
  delta_seconds?: number;
  window_seconds?: number;
  note?: string;
}

export interface ChainDetail {
  chain_id: string;
  name: string;
  status: string;
  ratified: boolean;
  reason: string;
  semantics: string;
  level: number | null;
  severity: string | null;
  severity_status: string;
  score_1e4: number | null;
  score_status: string;
  reference_score_1e4: number | null;
  evidence: string[];
  nodes: ChainNode[];
  links: ChainLink[];
  contextual_evidence: ContextualEvidence[];
}

export interface ChainExecutionResult {
  contract: "chain-execution/1";
  file_sha256: string;
  analysis_id: string | null;
  analysis_id_status: string;
  canon_version: string;
  semantics: string;
  chains: Record<string, ChainDetail>;
}
export interface AnalysisResult {
  contract: "analysis-partial/1";
  schema_version: string;
  canon_version: string;
  analysis_id: string | null;
  analysis_id_status: string;
  analysis_id_reason: string;
  file_sha256: string;
  content_sha256: string | null;
  content_sha256_status: string;
  status: string;
  completion_status: string;
  timezone_status: string;
  completeness: Completeness;
  rule_execution: Record<string, RuleExecution>;
  chain_execution: Record<string, ChainExecution>;
  non_evaluable_records: NonEvaluableRecord[];
  ip_classification_status: string;
  observations: Observation[];
  activity_summary: {
    records_loaded: number;
    observations_emitted: number;
    no_observations_means_no_rule_match_not_no_activity: boolean;
  };
}
