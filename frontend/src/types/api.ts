/**
 * Type definitions matching backend specs/API_CONTRACT.md and specs/DATA_SCHEMA.md.
 */

export type ServiceStatus = 'ok' | 'degraded' | 'unavailable';

export type DependencyStatus = 'connected' | 'degraded' | 'unavailable' | 'not_configured';

export interface DependencyHealth {
  status: DependencyStatus;
  message: string;
  latency_ms?: number;
}

export interface HealthLiveResponse {
  status: string;
}

export interface HealthReadyResponse {
  status: ServiceStatus;
  dependencies: {
    wazuh_api: DependencyHealth;
    opensearch: DependencyHealth;
    ollama: DependencyHealth;
  };
  retrieved_at: string;
  request_id: string;
}

export interface EncryptionKeyStatus {
  key_file_path: string;
  key_file_exists: boolean;
  dpapi_available: boolean;
  key_usable: boolean;
  recovery_strategy: string;
}

export interface BackupOperationalStatusResponse {
  status: 'OK' | 'DEGRADED' | 'UNAVAILABLE';
  scheduler_enabled: boolean;
  scheduler_active: boolean;
  is_backup_in_progress: boolean;
  backup_interval_minutes: number;
  last_backup_attempt_at: string | null;
  last_successful_backup_at: string | null;
  last_backup_duration_seconds: number | null;
  last_backup_verification_status: 'VERIFIED' | 'FAILED' | 'UNVERIFIED' | 'CANCELLED';
  last_backup_error: string | null;
  last_backup_error_category: string | null;
  last_backup_encrypted: boolean | null;
  encryption_key_status: EncryptionKeyStatus;
  last_recovery_drill_at: string | null;
  last_recovery_drill_status: 'VERIFIED' | 'FAILED' | 'NEVER_RUN';
  last_audit_verification_at?: string | null;
  last_audit_verification_status?: 'VERIFIED' | 'FAILED' | 'UNVERIFIED';
  last_audit_events_verified?: number | null;
  last_audit_error?: string | null;
  retrieved_at: string;
}

export interface AuditVerificationStatusResponse {
  status: 'VERIFIED' | 'FAILED' | 'UNVERIFIED';
  verified_events_count: number;
  active_checkpoint_sequence: number | null;
  error: string | null;
  verified_at: string;
}

export interface ApiErrorDetail {
  code: string;
  message: string;
  request_id: string;
  details?: unknown;
}

export interface ApiErrorResponse {
  error: ApiErrorDetail;
}

// ==========================================
// Alert Data Models (specs/DATA_SCHEMA.md)
// ==========================================

export type DataStatus = 'fresh' | 'stale' | 'partial' | 'unavailable';

export interface NormalizedAlert {
  alert_id: string;
  source_system: string;
  source_index: string;
  timestamp: string; // ISO 8601 UTC
  retrieved_at: string; // ISO 8601 UTC
  rule_id: string;
  rule_description: string;
  rule_level?: number | null;
  agent_id?: string | null;
  agent_name?: string | null;
  host_name?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;
  event_type?: string | null;
  location?: string | null;
  decoder_name?: string | null;
  raw_evidence_ref: string;
  normalization_warnings: string[];
}

export interface QueryWindow {
  start_time: string;
  end_time: string;
}

export interface PaginationMetadata {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
  has_more: boolean;
}

export interface AlertListResponse {
  items: NormalizedAlert[];
  pagination: PaginationMetadata;
  query_window: QueryWindow;
  retrieved_at: string;
  data_status: DataStatus;
  request_id?: string;
}

export interface AlertQueryParams {
  start_time?: string;
  end_time?: string;
  severity_min?: number;
  rule_id?: string;
  host_name?: string;
  source_ip?: string;
  username?: string;
  page?: number;
  page_size?: number;
  sort_order?: 'asc' | 'desc';
}

// ==========================================
// Investigation AI Models (specs/AI_SAFETY_RULES.md & specs/DATA_SCHEMA.md)
// ==========================================

export type ConfidenceLabel = 'high' | 'medium' | 'low' | 'unverified';
export type UncertaintyLevel = 'low' | 'medium' | 'high';
export type PriorityLevel = 'low' | 'medium' | 'high';
export type InvestigationStatus = 'pending' | 'valid' | 'invalid' | 'unavailable' | 'timed_out' | 'failed';

export interface ObservedFact {
  fact_id: string;
  statement: string;
  cited_evidence_ids: string[];
}

export interface Hypothesis {
  hypothesis_id: string;
  statement: string;
  cited_evidence_ids: string[];
  uncertainty: UncertaintyLevel;
}

export interface RecommendedCheck {
  check_id: string;
  description: string;
  rationale: string;
  priority: PriorityLevel;
  is_read_only: boolean;
}

export interface RelatedEventsSummary {
  correlation_status: string;
  retrieved_count: number;
  included_count: number;
  truncated_count: number;
  window_minutes: number;
  anchor_timestamp?: string | null;
  unsupported_signals?: string[] | null;
}

export interface EvidenceItem {
  evidence_id: string;
  source_record_id: string;
  event_timestamp: string;
  rule_id: string;
  rule_level?: number | null;
  rule_description: string;
  agent_name?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;
  location?: string | null;
  raw_evidence_ref: string;
  is_primary: boolean;
  correlation_reason?: string | null;
  correlation_qualifier?: string | null;
  sanitized_event_data?: Record<string, unknown>;
}

export interface InvestigationResult {
  investigation_id: string;
  alert_id: string;
  status: InvestigationStatus;
  generated_at: string;
  model_name: string;
  model_tag: string;
  prompt_version: string;
  schema_version: string;
  summary: string;
  observed_facts: ObservedFact[];
  hypotheses: Hypothesis[];
  recommended_checks: RecommendedCheck[];
  limitations: string[];
  confidence_label: ConfidenceLabel;
  unsupported_citation_warnings: string[];
  disclaimer: string;
  correlation_status?: string | null;
  related_events_summary?: RelatedEventsSummary | null;
  evidence_items?: EvidenceItem[] | null;
}

export interface InvestigationRequest {
  alert_id?: string;
  include_related_events?: boolean;
  correlation_window_minutes?: number;
  max_related_events?: number;
  max_evidence_items?: number;
}

// ==========================================
// Investigation History Models (Phase 7.3 / specs/PHASE_7_API_CONTRACT.md)
// ==========================================

export interface InvestigationSummaryItem {
  investigation_id: string;
  alert_id: string;
  run_sequence: number;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  primary_rule_id: string;
  primary_rule_level?: number | null;
  primary_agent_name?: string | null;
  model_name?: string | null;
  model_tag?: string | null;
  confidence_label?: ConfidenceLabel | null;
  correlation_status?: string | null;
  evidence_count: number;
  execution_duration_ms?: number | null;
  error_code?: string | null;
  error_message?: string | null;
  created_at: string;
  updated_at: string;
  actor_id: string;
  analyst_rating?: 'helpful' | 'incorrect' | 'incomplete' | null;
  analyst_notes?: string | null;
  feedback_submitted_at?: string | null;
}


export interface InvestigationPagination {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface InvestigationListResponse {
  items: InvestigationSummaryItem[];
  pagination: InvestigationPagination;
  request_id: string;
}

export interface InvestigationQueryParams {
  alert_id?: string;
  status?: string;
  rule_id?: string;
  agent_name?: string;
  confidence_label?: string;
  start_time?: string;
  end_time?: string;
  page?: number;
  page_size?: number;
  sort_order?: 'asc' | 'desc';
}

export interface EvidenceSnapshotItem {
  evidence_id: string;
  source_record_id: string;
  event_timestamp: string;
  is_primary: boolean;
  rule_id: string;
  rule_level?: number | null;
  rule_description?: string | null;
  agent_name?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;
  correlation_reason?: string | null;
  correlation_qualifier?: string | null;
  raw_evidence_ref: string;
}

export interface InvestigationDetailResult {
  model_name: string;
  model_tag: string;
  prompt_version: string;
  summary: string;
  confidence_label: ConfidenceLabel;
  disclaimer: string;
  observed_facts: ObservedFact[];
  hypotheses: Hypothesis[];
  recommended_checks: RecommendedCheck[];
  limitations: string[];
  unsupported_citation_warnings: string[];
  correlation_status?: string | null;
}

export interface InvestigationDetailResponse {
  investigation_id: string;
  alert_id: string;
  run_sequence: number;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  primary_rule_id: string;
  primary_rule_level?: number | null;
  primary_agent_name?: string | null;
  query_window_minutes: number;
  max_evidence_items: number;
  error_code?: string | null;
  error_message?: string | null;
  execution_duration_ms?: number | null;
  created_at: string;
  updated_at: string;
  actor_id: string;
  analyst_rating?: 'helpful' | 'incorrect' | 'incomplete' | null;
  analyst_notes?: string | null;
  feedback_submitted_at?: string | null;
  result?: InvestigationDetailResult | null;
  evidence_items: EvidenceSnapshotItem[];
  request_id: string;
}

// ==========================================
// Case Management Models
// ==========================================

export type CaseStatus = 'open' | 'in_progress' | 'resolved' | 'closed';
export type CasePriority = 'low' | 'medium' | 'high' | 'critical';

export interface Case {
  case_id: string;
  title: string;
  description?: string | null;
  status: CaseStatus;
  priority: CasePriority;
  assignee?: string | null;
  alert_id?: string | null;
  investigation_id?: string | null;
  analyst_notes?: string | null;
  created_at: string;
  updated_at: string;
  closed_at?: string | null;
}

export interface CaseCreateInput {
  title: string;
  description?: string | null;
  priority?: CasePriority;
  assignee?: string | null;
  alert_id?: string | null;
  investigation_id?: string | null;
  analyst_notes?: string | null;
}

export interface CaseUpdateInput {
  title?: string;
  description?: string | null;
  status?: CaseStatus;
  priority?: CasePriority;
  assignee?: string | null;
  analyst_notes?: string | null;
}

export interface CasePagination {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface CaseListResponse {
  items: Case[];
  pagination: CasePagination;
  request_id: string;
}

export interface CaseFilters {
  status?: CaseStatus;
  priority?: CasePriority;
  assignee?: string;
  alert_id?: string;
  page?: number;
  page_size?: number;
  sort_order?: 'asc' | 'desc';
}

export interface AgentOSInfo {
  name?: string | null;
  version?: string | null;
  platform?: string | null;
  arch?: string | null;
  uname?: string | null;
}

export interface AgentItem {
  id: string;
  name: string;
  ip?: string | null;
  status: 'active' | 'disconnected' | 'never_connected' | 'pending' | string;
  version?: string | null;
  node_name?: string | null;
  date_add?: string | null;
  last_keep_alive?: string | null;
  os?: AgentOSInfo | null;
}

export interface AgentSummary {
  total: number;
  active: number;
  disconnected: number;
  never_connected: number;
  pending: number;
}

export interface AgentListResponse {
  items: AgentItem[];
  summary: AgentSummary;
  total_items: number;
  retrieved_at: string;
}

export interface NotificationTestResponse {
  status: 'delivered' | 'failed' | 'disabled';
  message: string;
  target_masked?: string | null;
  dispatched_at: string;
}

export type ContainmentActionType = 'BLOCK_IP' | 'ISOLATE_HOST' | 'KILL_PROCESS' | 'DISABLE_USER';

export type ContainmentPlatform =
  | 'LINUX_IPTABLES'
  | 'LINUX_NFTABLES'
  | 'WINDOWS_NETSH'
  | 'WAZUH_ACTIVE_RESPONSE';

export interface GeneratedCommand {
  platform: ContainmentPlatform;
  command: string;
  description: string;
}

export interface ProposedContainmentAction {
  action_type: ContainmentActionType;
  target: string;
  rationale: string;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
  commands: GeneratedCommand[];
}

export interface ContainmentProposalResponse {
  proposed_actions: ProposedContainmentAction[];
  generated_at: string;
}

export interface ContainmentExecutionRequest {
  action_type: ContainmentActionType;
  target: string;
  rationale: string;
  analyst_id: string;
  analyst_approval: boolean;
  alert_id?: string;
  investigation_id?: string;
}

export interface ContainmentExecutionResponse {
  execution_id: string;
  action_type: ContainmentActionType;
  target: string;
  status: string;
  generated_commands: GeneratedCommand[];
  audit_id: string;
  approved_at: string;
  analyst_id: string;
  message: string;
}

export interface ContainmentHistoryRecord {
  audit_id: string;
  timestamp: string;
  actor_id: string;
  action: string;
  resource_id: string;
  outcome: string;
  event_hash: string;
  target?: string;
  action_type?: string;
  rationale?: string;
  alert_id?: string;
}



