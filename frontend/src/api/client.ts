/**
 * Typed API Client for backend communication strictly adhering to API_CONTRACT.md.
 * Communicates ONLY with the authenticated backend, NEVER directly with Wazuh, OpenSearch, or Ollama.
 */

import type {
  AlertListResponse,
  AlertQueryParams,
  AuditVerificationStatusResponse,
  BackupOperationalStatusResponse,
  Case,
  CaseCreateInput,
  CaseFilters,
  CaseListResponse,
  CaseUpdateInput,
  HealthLiveResponse,
  HealthReadyResponse,
  InvestigationDetailResponse,
  InvestigationListResponse,
  InvestigationQueryParams,
  NormalizedAlert,
  AgentListResponse,
  NotificationTestResponse,
} from '../types/api';



class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = '/api/v1') {
    this.baseUrl = baseUrl;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = new Headers(options.headers);
    if (!headers.has('Accept')) {
      headers.set('Accept', 'application/json');
    }

    try {
      const response = await fetch(url, { ...options, headers });
      const contentType = response.headers.get('content-type');
      const isJson = contentType && contentType.includes('application/json');

      if (!response.ok) {
        if (isJson) {
          const errorData = (await response.json()) as Record<string, unknown>;
          // Specialized case for 503 from /health/ready or /health/backup which still returns a valid telemetry payload
          if (
            response.status === 503 &&
            ((endpoint.includes('/health/ready') && 'dependencies' in errorData) ||
             (endpoint.includes('/health/backup') && 'encryption_key_status' in errorData))
          ) {
            return errorData as unknown as T;
          }
          const errDetail = errorData.error as { message?: string } | undefined;
          throw new Error(errDetail?.message || `API error ${response.status}: ${response.statusText}`);
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return (await response.json()) as T;
    } catch (err: unknown) {
      if (err instanceof Error) {
        throw err;
      }
      throw new Error(String(err));
    }
  }

  /**
   * Probe backend process liveness.
   */
  async getHealthLive(signal?: AbortSignal): Promise<HealthLiveResponse> {
    return this.request<HealthLiveResponse>('/health/live', { signal });
  }

  /**
   * Probe upstream dependency readiness.
   */
  async getHealthReady(signal?: AbortSignal): Promise<HealthReadyResponse> {
    return this.request<HealthReadyResponse>('/health/ready', { signal });
  }

  /**
   * Query normalized security alerts within a bounded time window and pagination limit.
   */
  async getAlerts(params?: AlertQueryParams, signal?: AbortSignal): Promise<AlertListResponse> {
    const searchParams = new URLSearchParams();
    if (params) {
      if (params.start_time) searchParams.set('start_time', params.start_time);
      if (params.end_time) searchParams.set('end_time', params.end_time);
      if (params.severity_min !== undefined && params.severity_min !== null && params.severity_min > 0) {
        searchParams.set('severity_min', String(params.severity_min));
      }
      if (params.rule_id?.trim()) searchParams.set('rule_id', params.rule_id.trim());
      if (params.host_name?.trim()) searchParams.set('host_name', params.host_name.trim());
      if (params.source_ip?.trim()) searchParams.set('source_ip', params.source_ip.trim());
      if (params.username?.trim()) searchParams.set('username', params.username.trim());
      if (params.page !== undefined && params.page > 0) {
        searchParams.set('page', String(params.page));
      }
      if (params.page_size !== undefined && params.page_size > 0) {
        // Enforce max boundary of 100 on client side
        const clampedSize = Math.min(Math.max(1, params.page_size), 100);
        searchParams.set('page_size', String(clampedSize));
      }
      if (params.sort_order) searchParams.set('sort_order', params.sort_order);
    }
    const queryStr = searchParams.toString();
    const endpoint = queryStr ? `/alerts?${queryStr}` : '/alerts';
    return this.request<AlertListResponse>(endpoint, { signal });
  }

  /**
   * Fetch a single normalized alert by stable source ID.
   */
  async getAlertById(alertId: string, signal?: AbortSignal): Promise<NormalizedAlert> {
    const cleanId = encodeURIComponent(alertId.trim());
    return this.request<NormalizedAlert>(`/alerts/${cleanId}`, { signal });
  }

  /**
   * Request evidence-grounded AI investigation for an alert.
   */
  async investigateAlert(
    alertId: string,
    options?: {
      include_related_events?: boolean;
      correlation_window_minutes?: number;
      max_related_events?: number;
      max_evidence_items?: number;
    },
    signal?: AbortSignal,
  ): Promise<import('../types/api').InvestigationResult> {
    const cleanId = encodeURIComponent(alertId.trim());
    const payload: Record<string, unknown> = {
      include_related_events: options?.include_related_events ?? false,
      max_evidence_items: options?.max_evidence_items ?? 10,
    };
    if (options?.correlation_window_minutes !== undefined) {
      payload.correlation_window_minutes = Math.min(Math.max(5, options.correlation_window_minutes), 60);
    }
    if (options?.max_related_events !== undefined) {
      payload.max_related_events = Math.min(Math.max(1, options.max_related_events), 20);
    }

    return this.request<import('../types/api').InvestigationResult>(`/alerts/${cleanId}/investigate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      signal,
    });
  }

  /**
   * Query historical investigations with bounded filtering and pagination.
   */
  async getInvestigations(
    params?: InvestigationQueryParams,
    signal?: AbortSignal,
  ): Promise<InvestigationListResponse> {
    const searchParams = new URLSearchParams();
    if (params) {
      if (params.alert_id?.trim()) searchParams.set('alert_id', params.alert_id.trim());
      if (params.status?.trim()) searchParams.set('status', params.status.trim());
      if (params.rule_id?.trim()) searchParams.set('rule_id', params.rule_id.trim());
      if (params.agent_name?.trim()) searchParams.set('agent_name', params.agent_name.trim());
      if (params.confidence_label?.trim()) searchParams.set('confidence_label', params.confidence_label.trim());
      if (params.start_time?.trim()) searchParams.set('start_time', params.start_time.trim());
      if (params.end_time?.trim()) searchParams.set('end_time', params.end_time.trim());
      if (params.page !== undefined && params.page > 0) {
        searchParams.set('page', String(params.page));
      }
      if (params.page_size !== undefined && params.page_size > 0) {
        const clamped = Math.min(Math.max(1, params.page_size), 100);
        searchParams.set('page_size', String(clamped));
      }
      if (params.sort_order) {
        searchParams.set('sort_order', params.sort_order);
      }
    }
    const queryStr = searchParams.toString();
    const endpoint = queryStr ? `/investigations?${queryStr}` : '/investigations';
    return this.request<InvestigationListResponse>(endpoint, { signal });
  }

  /**
   * Retrieve full investigation detail by ID including facts, hypotheses, checks, and evidence snapshots.
   */
  async getInvestigationById(
    investigationId: string,
    signal?: AbortSignal,
  ): Promise<InvestigationDetailResponse> {
    const cleanId = encodeURIComponent(investigationId.trim());
    return this.request<InvestigationDetailResponse>(`/investigations/${cleanId}`, { signal });
  }

  /**
   * Fetch truthful operational telemetry for backups, encryption key, and scheduler.
   */
  async getHealthBackup(signal?: AbortSignal): Promise<BackupOperationalStatusResponse> {
    return this.request<BackupOperationalStatusResponse>('/health/backup', { signal });
  }

  /**
   * Fetch latest recorded cryptographic audit chain verification state.
   */
  async getHealthAudit(signal?: AbortSignal): Promise<AuditVerificationStatusResponse> {
    return this.request<AuditVerificationStatusResponse>('/health/audit', { signal });
  }

  /**
   * Trigger on-demand cryptographic verification of the audit chain.
   */
  async verifyHealthAudit(signal?: AbortSignal): Promise<AuditVerificationStatusResponse> {
    return this.request<AuditVerificationStatusResponse>('/health/audit/verify', {
      method: 'POST',
      signal,
    });
  }

  /**
   * Submit analyst feedback on an AI investigation findings.
   */
  async submitInvestigationFeedback(
    investigationId: string,
    rating: 'helpful' | 'incorrect' | 'incomplete',
    notes?: string,
    signal?: AbortSignal
  ): Promise<InvestigationDetailResponse> {
    const cleanId = encodeURIComponent(investigationId.trim());
    return this.request<InvestigationDetailResponse>(`/investigations/${cleanId}/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rating, notes: notes?.trim() || null }),
      signal,
    });
  }

  /**
   * Export normalized alerts matching filters as CSV or JSON Blob.
   */
  async exportAlerts(
    params?: AlertQueryParams,
    format: 'csv' | 'json' = 'csv',
    signal?: AbortSignal
  ): Promise<Blob> {
    const searchParams = new URLSearchParams();
    searchParams.set('format', format);
    if (params) {
      if (params.start_time) searchParams.set('start_time', params.start_time);
      if (params.end_time) searchParams.set('end_time', params.end_time);
      if (params.severity_min !== undefined && params.severity_min !== null && params.severity_min > 0) {
        searchParams.set('severity_min', String(params.severity_min));
      }
      if (params.rule_id?.trim()) searchParams.set('rule_id', params.rule_id.trim());
      if (params.host_name?.trim()) searchParams.set('host_name', params.host_name.trim());
      if (params.source_ip?.trim()) searchParams.set('source_ip', params.source_ip.trim());
      if (params.username?.trim()) searchParams.set('username', params.username.trim());
      if (params.sort_order) searchParams.set('sort_order', params.sort_order);
    }
    const queryStr = searchParams.toString();
    const url = `${this.baseUrl}/alerts/export?${queryStr}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: format === 'json' ? 'application/json' : 'text/csv',
      },
      signal,
    });
    if (!response.ok) {
      throw new Error(`Alert export failed: HTTP ${response.status}`);
    }
    return await response.blob();
  }

  /**
   * Export investigation report as sanitized Markdown, JSON, or CSV Blob.
   */
  async exportInvestigationReport(
    investigationId: string,
    format: 'markdown' | 'json' | 'csv' = 'markdown',
    signal?: AbortSignal
  ): Promise<Blob> {
    const cleanId = encodeURIComponent(investigationId.trim());
    const url = `${this.baseUrl}/investigations/${cleanId}/export?format=${format}`;
    const acceptHeader = format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'text/markdown';
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: acceptHeader,
      },
      signal,
    });
    if (!response.ok) {
      throw new Error(`Export failed: HTTP ${response.status}`);
    }
    return await response.blob();
  }

  /**
   * Export cases matching filters as CSV or JSON Blob.
   */
  async exportCases(
    params?: CaseFilters,
    format: 'csv' | 'json' = 'csv',
    signal?: AbortSignal
  ): Promise<Blob> {
    const searchParams = new URLSearchParams();
    searchParams.set('format', format);
    if (params) {
      if (params.status?.trim()) searchParams.set('status', params.status.trim());
      if (params.priority?.trim()) searchParams.set('priority', params.priority.trim());
      if (params.assignee?.trim()) searchParams.set('assignee', params.assignee.trim());
      if (params.alert_id?.trim()) searchParams.set('alert_id', params.alert_id.trim());
      if (params.sort_order) searchParams.set('sort_order', params.sort_order);
    }
    const queryStr = searchParams.toString();
    const url = `${this.baseUrl}/cases/export?${queryStr}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: format === 'json' ? 'application/json' : 'text/csv',
      },
      signal,
    });
    if (!response.ok) {
      throw new Error(`Cases export failed: HTTP ${response.status}`);
    }
    return await response.blob();
  }

  /**
   * Query paginated cases with status, priority, and assignee filters.
   */
  async getCases(params?: CaseFilters, signal?: AbortSignal): Promise<CaseListResponse> {
    const searchParams = new URLSearchParams();
    if (params) {
      if (params.status?.trim()) searchParams.set('status', params.status.trim());
      if (params.priority?.trim()) searchParams.set('priority', params.priority.trim());
      if (params.assignee?.trim()) searchParams.set('assignee', params.assignee.trim());
      if (params.alert_id?.trim()) searchParams.set('alert_id', params.alert_id.trim());
      if (params.page !== undefined && params.page > 0) searchParams.set('page', String(params.page));
      if (params.page_size !== undefined && params.page_size > 0) {
        const clamped = Math.min(Math.max(1, params.page_size), 100);
        searchParams.set('page_size', String(clamped));
      }
      if (params.sort_order) searchParams.set('sort_order', params.sort_order);
    }
    const queryStr = searchParams.toString();
    const endpoint = queryStr ? `/cases?${queryStr}` : '/cases';
    return this.request<CaseListResponse>(endpoint, { signal });
  }

  /**
   * Retrieve case details by ID.
   */
  async getCaseById(caseId: string, signal?: AbortSignal): Promise<Case> {
    const cleanId = encodeURIComponent(caseId.trim());
    return this.request<Case>(`/cases/${cleanId}`, { signal });
  }

  /**
   * Create a new investigation case.
   */
  async createCase(input: CaseCreateInput, signal?: AbortSignal): Promise<Case> {
    return this.request<Case>('/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
      signal,
    });
  }

  /**
   * Update an existing case.
   */
  async updateCase(caseId: string, input: CaseUpdateInput, signal?: AbortSignal): Promise<Case> {
    const cleanId = encodeURIComponent(caseId.trim());
    return this.request<Case>(`/cases/${cleanId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
      signal,
    });
  }

  /**
   * Soft-delete a case.
   */
  async deleteCase(caseId: string, signal?: AbortSignal): Promise<{ message: string; case_id: string }> {
    const cleanId = encodeURIComponent(caseId.trim());
    return this.request<{ message: string; case_id: string }>(`/cases/${cleanId}`, {
      method: 'DELETE',
      signal,
    });
  }

  /**
   * Retrieve monitored Wazuh agent fleet with status and OS details.
   */
  async getAgents(
    limit: number = 20,
    offset: number = 0,
    status?: string,
    signal?: AbortSignal
  ): Promise<AgentListResponse> {
    const searchParams = new URLSearchParams();
    searchParams.set('limit', String(Math.min(Math.max(1, limit), 100)));
    searchParams.set('offset', String(Math.max(0, offset)));
    if (status && status !== 'all') {
      searchParams.set('status', status.trim());
    }
    const queryStr = searchParams.toString();
    return this.request<AgentListResponse>(`/agents?${queryStr}`, { signal });
  }

  /**
   * Dispatch a test security notification to the configured or override webhook.
   */
  async testNotificationWebhook(
    webhookUrl?: string,
    signal?: AbortSignal
  ): Promise<NotificationTestResponse> {
    return this.request<NotificationTestResponse>('/notifications/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ webhook_url: webhookUrl || null }),
      signal,
    });
  }
}


export const apiClient = new ApiClient();

