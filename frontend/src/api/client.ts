/**
 * Typed API Client for backend communication strictly adhering to API_CONTRACT.md.
 * Communicates ONLY with the authenticated backend, NEVER directly with Wazuh, OpenSearch, or Ollama.
 */

import type { ApiErrorResponse, HealthLiveResponse, HealthReadyResponse } from '../types/api';

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
          const errorData = (await response.json()) as ApiErrorResponse;
          // Specialized case for 503 from /health/ready which still returns a valid HealthReadyResponse payload
          if (response.status === 503 && endpoint.includes('/health/ready') && 'dependencies' in errorData) {
            return errorData as unknown as T;
          }
          throw new Error(errorData.error?.message || `API error ${response.status}: ${response.statusText}`);
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
  async getHealthLive(): Promise<HealthLiveResponse> {
    return this.request<HealthLiveResponse>('/health/live');
  }

  /**
   * Probe upstream dependency readiness.
   */
  async getHealthReady(): Promise<HealthReadyResponse> {
    return this.request<HealthReadyResponse>('/health/ready');
  }
}

export const apiClient = new ApiClient();
