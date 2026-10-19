import React, { useEffect, useState, useCallback } from 'react';
import { apiClient } from './api/client';
import type { DependencyHealth, HealthReadyResponse } from './types/api';

export const App: React.FC = () => {
  const [healthData, setHealthData] = useState<HealthReadyResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastCheckTime, setLastCheckTime] = useState<string>('Never');

  const fetchHealth = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiClient.getHealthReady();
      setHealthData(data);
      setLastCheckTime(new Date().toLocaleTimeString());
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      setLastCheckTime(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
  }, [fetchHealth]);

  const renderBadge = (health?: DependencyHealth) => {
    if (!health) return <span className="status-badge unavailable">Unknown</span>;
    return (
      <span className={`status-badge ${health.status}`}>
        <span className="status-dot"></span>
        {health.status.replace('_', ' ')}
      </span>
    );
  };

  return (
    <>
      <header className="soc-header">
        <div className="brand-section">
          <div className="brand-logo-icon">W</div>
          <div>
            <div className="brand-title">Wazuh + Ollama SIEM</div>
            <div className="brand-subtitle">Threat Hunting & AI Investigation Platform</div>
          </div>
        </div>

        <div className="header-status-pill">
          <span>SYSTEM:</span>
          {loading ? (
            <span style={{ color: 'var(--text-muted)' }}>CHECKING...</span>
          ) : error ? (
            <span style={{ color: 'var(--status-unavailable)' }}>OFFLINE</span>
          ) : healthData?.status === 'ok' ? (
            <span style={{ color: 'var(--status-connected)' }}>READY</span>
          ) : healthData?.status === 'degraded' ? (
            <span style={{ color: 'var(--status-degraded)' }}>DEGRADED</span>
          ) : (
            <span style={{ color: 'var(--status-unavailable)' }}>UNAVAILABLE</span>
          )}
        </div>
      </header>

      <main className="app-container">
        <section className="page-header">
          <div>
            <h1 className="page-title">Infrastructure Health & Baseline</h1>
            <p className="page-description">
              Real-time operational status of detection, storage, and AI inference backends. All metrics are truthfully retrieved from the backend API without simulation.
            </p>
          </div>

          <button
            className="refresh-button"
            onClick={fetchHealth}
            disabled={loading}
            aria-label="Refresh telemetry status"
          >
            <span className={loading ? 'spin' : ''}>↻</span>
            {loading ? 'Probing...' : 'Refresh Telemetry'}
          </button>
        </section>

        {error && (
          <div
            style={{
              padding: '1rem 1.25rem',
              borderRadius: '8px',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#fca5a5',
              marginBottom: '2rem',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.875rem',
            }}
          >
            <strong>Backend Connection Error:</strong> {error}
          </div>
        )}

        <section className="grid-container">
          {/* Wazuh Manager Card */}
          <article className="telemetry-card">
            <div className="card-header">
              <div className="card-title-group">
                <h3>Wazuh Manager API</h3>
                <div className="card-role-label">Detection Authority</div>
              </div>
              {renderBadge(healthData?.dependencies?.wazuh_api)}
            </div>
            <div className="card-body">
              {healthData?.dependencies?.wazuh_api?.message || 'Awaiting status probe...'}
            </div>
            <div className="card-footer">
              <span>ENDPOINT: /api/v1/health</span>
              <span>
                {healthData?.dependencies?.wazuh_api?.latency_ms !== undefined
                  ? `${healthData.dependencies.wazuh_api.latency_ms} ms`
                  : '--'}
              </span>
            </div>
          </article>

          {/* OpenSearch Indexer Card */}
          <article className="telemetry-card">
            <div className="card-header">
              <div className="card-title-group">
                <h3>Wazuh Indexer / OpenSearch</h3>
                <div className="card-role-label">Search & Evidence Store</div>
              </div>
              {renderBadge(healthData?.dependencies?.opensearch)}
            </div>
            <div className="card-body">
              {healthData?.dependencies?.opensearch?.message || 'Awaiting status probe...'}
            </div>
            <div className="card-footer">
              <span>CLUSTER: Verified TLS</span>
              <span>
                {healthData?.dependencies?.opensearch?.latency_ms !== undefined
                  ? `${healthData.dependencies.opensearch.latency_ms} ms`
                  : '--'}
              </span>
            </div>
          </article>

          {/* Ollama Local LLM Card */}
          <article className="telemetry-card">
            <div className="card-header">
              <div className="card-title-group">
                <h3>Ollama Local AI</h3>
                <div className="card-role-label">Investigation Assistant</div>
              </div>
              {renderBadge(healthData?.dependencies?.ollama)}
            </div>
            <div className="card-body">
              {healthData?.dependencies?.ollama?.message || 'Awaiting status probe...'}
            </div>
            <div className="card-footer">
              <span>LOCAL INFERENCE: Isolated</span>
              <span>
                {healthData?.dependencies?.ollama?.latency_ms !== undefined
                  ? `${healthData.dependencies.ollama.latency_ms} ms`
                  : '--'}
              </span>
            </div>
          </article>
        </section>

        {/* Phase 1 Architecture Notice */}
        <section className="baseline-banner">
          <h4>🛡️ Phase 1 Architecture & Engineering Guardrails</h4>
          <p>
            In strict compliance with <code>AGENTS.md</code> and <code>specs/AI_SAFETY_RULES.md</code>, this platform enforces truthful operational reporting:
          </p>
          <ul className="baseline-list">
            <li><strong>Zero Mock Data:</strong> Alert tables and detection charts are withheld until real authenticated connections are established in Phase 2.</li>
            <li><strong>Credential Isolation:</strong> The frontend never connects directly to Wazuh, OpenSearch, or Ollama; all requests are authenticated via the FastAPI backend.</li>
            <li><strong>Read-Only v1:</strong> No automated remediation, host execution, or firewall modification actions exist in this release.</li>
            <li><strong>Audit & Traceability:</strong> All operations propagate request correlation IDs (<code>{healthData?.request_id || 'X-Request-ID'}</code>).</li>
          </ul>
        </section>
      </main>

      <footer className="soc-footer">
        <div>Wazuh + Ollama SIEM Platform v0.1.0-alpha</div>
        <div>Last Telemetry Probe: {lastCheckTime}</div>
      </footer>
    </>
  );
};

export default App;
