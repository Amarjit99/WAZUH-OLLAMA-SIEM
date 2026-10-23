import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiClient } from '../api/client';
import type {
  ConfidenceLabel,
  InvestigationPagination,
  InvestigationQueryParams,
  InvestigationSummaryItem,
} from '../types/api';

interface InvestigationHistoryTableProps {
  onSelectInvestigation: (investigationId: string) => void;
}

export const InvestigationHistoryTable: React.FC<InvestigationHistoryTableProps> = ({
  onSelectInvestigation,
}) => {
  const [items, setItems] = useState<InvestigationSummaryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPagination] = useState<InvestigationPagination | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [alertIdFilter, setAlertIdFilter] = useState<string>('');
  const [ruleIdFilter, setRuleIdFilter] = useState<string>('');
  const [agentNameFilter, setAgentNameFilter] = useState<string>('');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(25);

  const abortControllerRef = useRef<AbortController | null>(null);

  const fetchHistory = useCallback(async () => {
    // Abort previous in-flight request to prevent race conditions
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    setLoading(true);
    setError(null);

    const params: InvestigationQueryParams = {
      page,
      page_size: pageSize,
      sort_order: 'desc',
    };

    if (statusFilter.trim()) params.status = statusFilter.trim();
    if (alertIdFilter.trim()) params.alert_id = alertIdFilter.trim();
    if (ruleIdFilter.trim()) params.rule_id = ruleIdFilter.trim();
    if (agentNameFilter.trim()) params.agent_name = agentNameFilter.trim();
    if (confidenceFilter.trim()) params.confidence_label = confidenceFilter.trim();

    try {
      const resp = await apiClient.getInvestigations(params, abortController.signal);
      if (!abortController.signal.aborted) {
        setItems(resp.items);
        setPagination(resp.pagination);
        setLoading(false);
      }
    } catch (err: unknown) {
      if (abortController.signal.aborted) return;
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      setLoading(false);
    }
  }, [page, pageSize, statusFilter, alertIdFilter, ruleIdFilter, agentNameFilter, confidenceFilter]);

  useEffect(() => {
    fetchHistory();
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [fetchHistory]);

  const handleResetFilters = () => {
    setStatusFilter('');
    setAlertIdFilter('');
    setRuleIdFilter('');
    setAgentNameFilter('');
    setConfidenceFilter('');
    setPage(1);
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return <span className="inv-history-status-badge completed">COMPLETED</span>;
      case 'running':
        return <span className="inv-history-status-badge running">RUNNING</span>;
      case 'failed':
        return <span className="inv-history-status-badge failed">FAILED</span>;
      case 'cancelled':
        return <span className="inv-history-status-badge cancelled">CANCELLED</span>;
      default:
        return <span className="inv-history-status-badge queued">{status.toUpperCase()}</span>;
    }
  };

  const getConfidenceBadge = (confidence?: ConfidenceLabel | null) => {
    if (!confidence) return <span className="confidence-pill none">--</span>;
    switch (confidence.toLowerCase()) {
      case 'high':
        return <span className="confidence-pill high">HIGH</span>;
      case 'medium':
        return <span className="confidence-pill medium">MEDIUM</span>;
      case 'low':
        return <span className="confidence-pill low">LOW</span>;
      default:
        return <span className="confidence-pill unverified">{confidence.toUpperCase()}</span>;
    }
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

  return (
    <div className="investigation-history-container">
      {/* Top Filter Bar */}
      <section className="filter-card">
        <div className="filter-header-row">
          <div className="filter-title-group">
            <span className="filter-icon">📜</span>
            <h3 className="filter-heading">Investigation History Query & Audit Records</h3>
          </div>
          <div className="filter-actions">
            <button
              type="button"
              className="filter-reset-btn"
              onClick={handleResetFilters}
              disabled={loading}
            >
              Reset Filters
            </button>
            <button
              type="button"
              className="refresh-button"
              onClick={() => { setPage(1); fetchHistory(); }}
              disabled={loading}
              title="Refresh investigation history"
            >
              ↻ Refresh
            </button>
          </div>
        </div>

        <div className="filter-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
          {/* Status Filter */}
          <div className="filter-field">
            <label htmlFor="filter-status" className="filter-label">Status</label>
            <select
              id="filter-status"
              className="filter-select"
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
            >
              <option value="">All Statuses</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>

          {/* Alert ID Filter */}
          <div className="filter-field">
            <label htmlFor="filter-alert-id" className="filter-label">Alert ID</label>
            <input
              id="filter-alert-id"
              type="text"
              className="filter-input mono"
              placeholder="Filter by Wazuh Alert ID..."
              value={alertIdFilter}
              onChange={(e) => { setAlertIdFilter(e.target.value); setPage(1); }}
            />
          </div>

          {/* Rule ID Filter */}
          <div className="filter-field">
            <label htmlFor="filter-rule-id" className="filter-label">Rule ID</label>
            <input
              id="filter-rule-id"
              type="text"
              className="filter-input mono"
              placeholder="e.g. 5710"
              value={ruleIdFilter}
              onChange={(e) => { setRuleIdFilter(e.target.value); setPage(1); }}
            />
          </div>

          {/* Agent Filter */}
          <div className="filter-field">
            <label htmlFor="filter-agent" className="filter-label">Agent Hostname</label>
            <input
              id="filter-agent"
              type="text"
              className="filter-input"
              placeholder="e.g. web-server-prod"
              value={agentNameFilter}
              onChange={(e) => { setAgentNameFilter(e.target.value); setPage(1); }}
            />
          </div>

          {/* Confidence Filter */}
          <div className="filter-field">
            <label htmlFor="filter-confidence" className="filter-label">Confidence</label>
            <select
              id="filter-confidence"
              className="filter-select"
              value={confidenceFilter}
              onChange={(e) => { setConfidenceFilter(e.target.value); setPage(1); }}
            >
              <option value="">All Confidences</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="unverified">Unverified</option>
            </select>
          </div>
        </div>
      </section>

      {/* Main Table Card */}
      <section className="table-card">
        {/* Error State */}
        {error && (
          <div className="state-container error">
            <div className="state-icon">⚠️</div>
            <h4 className="state-title">Failed to Retrieve History</h4>
            <p className="state-description">{error}</p>
            <button
              type="button"
              className="refresh-button"
              onClick={fetchHistory}
            >
              ↻ Retry Query
            </button>
          </div>
        )}

        {/* Loading State */}
        {loading && !error && (
          <div className="state-container loading">
            <div className="spinner" />
            <h4 className="state-title">Querying Investigation Persistence...</h4>
            <p className="state-description">Retrieving immutable audit records and analysis snapshots from local database.</p>
          </div>
        )}

        {/* Empty State */}
        {!loading && !error && items.length === 0 && (
          <div className="state-container empty">
            <div className="state-icon">📋</div>
            <h4 className="state-title">No Investigation Records Found</h4>
            <p className="state-description">
              No historical investigations match your selected criteria. Investigations triggered from the Live Alerts tab are durably stored here.
            </p>
          </div>
        )}

        {/* Populated Table */}
        {!loading && !error && items.length > 0 && (
          <>
            <div className="table-container">
              <table className="alerts-data-table" aria-label="Investigation History Table">
                <thead>
                  <tr>
                    <th scope="col" style={{ width: '130px' }}>STATUS</th>
                    <th scope="col" style={{ width: '70px' }}>RUN</th>
                    <th scope="col">ALERT ID</th>
                    <th scope="col">PRIMARY RULE</th>
                    <th scope="col">AGENT</th>
                    <th scope="col">CONFIDENCE</th>
                    <th scope="col" style={{ width: '80px' }}>EVID</th>
                    <th scope="col" style={{ width: '90px' }}>DURATION</th>
                    <th scope="col">CREATED (UTC)</th>
                    <th scope="col" style={{ width: '120px', textAlign: 'center' }}>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr
                      key={item.investigation_id}
                      className="alert-row"
                      onClick={() => onSelectInvestigation(item.investigation_id)}
                      tabIndex={0}
                      role="button"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          onSelectInvestigation(item.investigation_id);
                        }
                      }}
                      title={`Open investigation ${item.investigation_id}`}
                    >
                      <td>{getStatusBadge(item.status)}</td>
                      <td>
                        <span className="run-seq-pill" title={`Sequential execution #${item.run_sequence} for this alert`}>
                          #{item.run_sequence}
                        </span>
                      </td>
                      <td className="mono font-bold" style={{ color: 'var(--accent-cyan)' }}>
                        {item.alert_id}
                      </td>
                      <td>
                        <span className="mono">Rule {item.primary_rule_id}</span>
                        {item.primary_rule_level !== null && item.primary_rule_level !== undefined && (
                          <span className="severity-badge-mini" style={{ marginLeft: '6px' }}>
                            LVL {item.primary_rule_level}
                          </span>
                        )}
                      </td>
                      <td>{item.primary_agent_name || <span className="text-muted">Unavailable</span>}</td>
                      <td>{getConfidenceBadge(item.confidence_label)}</td>
                      <td>
                        <span className="evidence-count-pill">
                          {item.evidence_count} {item.evidence_count === 1 ? 'item' : 'items'}
                        </span>
                      </td>
                      <td>
                        {item.execution_duration_ms !== null && item.execution_duration_ms !== undefined ? (
                          <span className="mono">{item.execution_duration_ms} ms</span>
                        ) : (
                          <span className="text-muted">--</span>
                        )}
                      </td>
                      <td>{formatTimestamp(item.created_at)}</td>
                      <td style={{ textAlign: 'center' }}>
                        <button
                          type="button"
                          className="view-details-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectInvestigation(item.investigation_id);
                          }}
                          aria-label={`View full details of investigation ${item.investigation_id}`}
                        >
                          Inspect ➔
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {pagination && (
              <div className="table-pagination">
                <div className="pagination-info">
                  Showing <strong>{(pagination.page - 1) * pagination.page_size + 1}</strong> to{' '}
                  <strong>{Math.min(pagination.page * pagination.page_size, pagination.total_items)}</strong> of{' '}
                  <strong>{pagination.total_items}</strong> investigations
                </div>
                <div className="pagination-controls">
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={!pagination.has_prev}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    aria-label="Previous page"
                  >
                    ◀ Prev
                  </button>
                  <span className="page-indicator">
                    Page <strong>{pagination.page}</strong> of <strong>{Math.max(1, pagination.total_pages)}</strong>
                  </span>
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={!pagination.has_next}
                    onClick={() => setPage((p) => p + 1)}
                    aria-label="Next page"
                  >
                    Next ▶
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
};
