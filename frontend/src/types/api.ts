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

export interface ApiErrorDetail {
  code: string;
  message: string;
  request_id: string;
  details?: unknown;
}

export interface ApiErrorResponse {
  error: ApiErrorDetail;
}
