import React from 'react';
import type { NormalizedAlert, PaginationMetadata } from '../types/api';

interface AlertsTableProps {
  alerts: NormalizedAlert[];
  loading: boolean;
  error: string | null;
  pagination: PaginationMetadata | null;
  onPageChange: (newPage: number) => void;
  onSelectAlert: (alert: NormalizedAlert) => void;
  onInvestigateAlert?: (alert: NormalizedAlert) => void;
  onRetry: () => void;
}

export const AlertsTable: React.FC<AlertsTableProps> = ({
  alerts,
  loading,
  error,
  pagination,
  onPageChange,
  onSelectAlert,
  onInvestigateAlert,
  onRetry,
}) => {
  const getSeverityBadge = (level?: number | null) => {
    if (level === undefined || level === null) {
      return <span className="severity-badge unknown">LVL ?</span>;
    }
    let cat = 'low';
    if (level >= 12) cat = 'critical';
    else if (level >= 8) cat = 'high';
    else if (level >= 4) cat = 'medium';

    return <span className={`severity-badge ${cat}`}>LVL {level}</span>;
  };

  const formatTimestamp = (raw: string) => {
    try {
      const d = new Date(raw);
      if (isNaN(d.getTime())) return raw;
      return (
        <div className="time-cell">
          <span className="time-primary">{d.toLocaleTimeString()}</span>
          <span className="time-secondary">{d.toISOString().slice(0, 10)}</span>
        </div>
      );
    } catch {
      return raw;
    }
  };

  // Render Error State
  if (error) {
    return (
      <section className="table-card">
        <div className="state-container error">
          <div className="state-icon">⚠️</div>
          <h4 className="state-title">Failed to Retrieve Alerts</h4>
          <p className="state-description">{error}</p>
          <button type="button" className="refresh-button" onClick={onRetry}>
            ↻ Retry Query
          </button>
        </div>
      </section>
    );
  }

  // Render Empty State
  if (!loading && alerts.length === 0) {
    return (
      <section className="table-card">
        <div className="state-container empty">
          <div className="state-icon">🛡️</div>
          <h4 className="state-title">No Security Alerts Detected</h4>
          <p className="state-description">
            There are currently no alerts recorded in OpenSearch matching your time range and filter parameters.
            All metrics reflect truthful telemetry directly from Wazuh Indexer.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="table-card">
      <div className="table-responsive">
        <table className="soc-table" aria-label="Security alerts list">
          <thead>
            <tr>
              <th scope="col" style={{ width: '90px' }}>Severity</th>
              <th scope="col" style={{ width: '130px' }}>Timestamp</th>
              <th scope="col" style={{ width: '90px' }}>Rule ID</th>
              <th scope="col">Rule Description</th>
              <th scope="col" style={{ width: '160px' }}>Host / Agent</th>
              <th scope="col" style={{ width: '140px' }}>Source IP</th>
              <th scope="col" style={{ width: '150px', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              // Skeleton loading rows
              Array.from({ length: 5 }).map((_, idx) => (
                <tr key={`skeleton-${idx}`} className="skeleton-row">
                  <td><div className="skeleton-pill"></div></td>
                  <td><div className="skeleton-text short"></div></td>
                  <td><div className="skeleton-text short"></div></td>
                  <td><div className="skeleton-text long"></div></td>
                  <td><div className="skeleton-text medium"></div></td>
                  <td><div className="skeleton-text medium"></div></td>
                  <td><div className="skeleton-btn"></div></td>
                </tr>
              ))
            ) : (
              alerts.map((alert) => (
                <tr
                  key={alert.alert_id}
                  className="table-row-clickable"
                  onClick={() => onSelectAlert(alert)}
                >
                  <td>{getSeverityBadge(alert.rule_level)}</td>
                  <td>{formatTimestamp(alert.timestamp)}</td>
                  <td>
                    <span className="mono-subtle">{alert.rule_id}</span>
                  </td>
                  <td>
                    {/* Rendered as plain text */}
                    <div className="rule-desc-cell" title={alert.rule_description}>
                      {alert.rule_description || 'No description provided'}
                    </div>
                  </td>
                  <td>
                    <div className="host-cell">
                      <span className="host-name">{alert.agent_name || alert.host_name || 'N/A'}</span>
                      {alert.agent_id && <span className="agent-id">ID: {alert.agent_id}</span>}
                    </div>
                  </td>
                  <td>
                    {alert.source_ip ? (
                      <span className="mono ip-tag">{alert.source_ip}</span>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div className="table-actions-cell">
                      <button
                        type="button"
                        className="btn-inspect"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert);
                        }}
                        aria-label={`View details for alert ${alert.alert_id}`}
                      >
                        View
                      </button>
                      {onInvestigateAlert && (
                        <button
                          type="button"
                          className="btn-ai-action"
                          onClick={(e) => {
                            e.stopPropagation();
                            onInvestigateAlert(alert);
                          }}
                          aria-label={`Run AI investigation on alert ${alert.alert_id}`}
                          title="Run evidence-grounded AI investigation"
                        >
                          🤖 AI
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Bar */}
      {pagination && (
        <div className="pagination-bar">
          <div className="pagination-info">
            {pagination.total_items > 0 ? (
              <span>
                Showing{' '}
                <strong>{(pagination.page - 1) * pagination.page_size + 1}</strong>
                {' '}-{' '}
                <strong>
                  {Math.min(pagination.page * pagination.page_size, pagination.total_items)}
                </strong>
                {' '}of{' '}
                <strong>{pagination.total_items}</strong> alerts
              </span>
            ) : (
              <span>0 alerts</span>
            )}
          </div>

          <div className="pagination-controls">
            <button
              type="button"
              className="btn-page"
              onClick={() => onPageChange(pagination.page - 1)}
              disabled={pagination.page <= 1 || loading}
              aria-label="Previous page"
            >
              ← Prev
            </button>

            <span className="page-indicator">
              Page {pagination.page} of {Math.max(1, pagination.total_pages)}
            </span>

            <button
              type="button"
              className="btn-page"
              onClick={() => onPageChange(pagination.page + 1)}
              disabled={!pagination.has_more || pagination.page >= pagination.total_pages || loading}
              aria-label="Next page"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </section>
  );
};
