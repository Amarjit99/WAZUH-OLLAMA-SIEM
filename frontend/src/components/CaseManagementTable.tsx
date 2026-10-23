import React, { useEffect, useState, useCallback, useRef } from 'react';
import { apiClient } from '../api/client';
import type { Case, CaseFilters, CasePagination, CasePriority, CaseStatus } from '../types/api';

interface CaseManagementTableProps {
  onOpenCase: (caseItem: Case) => void;
  onCreateCase: () => void;
  onOpenInvestigation?: (investigationId: string) => void;
  refreshTrigger?: number;
}

export const CaseManagementTable: React.FC<CaseManagementTableProps> = ({
  onOpenCase,
  onCreateCase,
  onOpenInvestigation,
  refreshTrigger,
}) => {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPagination] = useState<CasePagination | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [priorityFilter, setPriorityFilter] = useState<string>('');
  const [assigneeFilter, setAssigneeFilter] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [exportingCsv, setExportingCsv] = useState<boolean>(false);
  const pageSize = 25;

  const abortControllerRef = useRef<AbortController | null>(null);

  const fetchCases = useCallback(async () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setLoading(true);
    setError(null);

    const query: CaseFilters = {
      page,
      page_size: pageSize,
      sort_order: 'desc',
    };
    if (statusFilter) query.status = statusFilter as CaseStatus;
    if (priorityFilter) query.priority = priorityFilter as CasePriority;
    if (assigneeFilter.trim()) query.assignee = assigneeFilter.trim();

    try {
      const resp = await apiClient.getCases(query, controller.signal);
      if (!controller.signal.aborted) {
        setCases(resp.items);
        setPagination(resp.pagination);
        setLoading(false);
      }
    } catch (err: unknown) {
      if (controller.signal.aborted) return;
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      setLoading(false);
    }
  }, [page, statusFilter, priorityFilter, assigneeFilter]);

  useEffect(() => {
    fetchCases();
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [fetchCases, refreshTrigger]);

  const handleResetFilters = () => {
    setStatusFilter('');
    setPriorityFilter('');
    setAssigneeFilter('');
    setPage(1);
  };

  const handleExportCsv = async () => {
    setExportingCsv(true);
    try {
      const query: CaseFilters = {};
      if (statusFilter) query.status = statusFilter as CaseStatus;
      if (priorityFilter) query.priority = priorityFilter as CasePriority;
      if (assigneeFilter.trim()) query.assignee = assigneeFilter.trim();
      const blob = await apiClient.exportCases(query, 'csv');
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cases_export_${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export cases:', err);
    } finally {
      setExportingCsv(false);
    }
  };

  const getPriorityBadgeStyle = (priority: CasePriority) => {
    switch (priority) {
      case 'critical':
        return { background: 'rgba(239, 68, 68, 0.2)', border: '1px solid #ef4444', color: '#ef4444' };
      case 'high':
        return { background: 'rgba(249, 115, 22, 0.2)', border: '1px solid #f97316', color: '#f97316' };
      case 'medium':
        return { background: 'rgba(234, 179, 8, 0.2)', border: '1px solid #eab308', color: '#eab308' };
      case 'low':
      default:
        return { background: 'rgba(59, 130, 246, 0.2)', border: '1px solid #3b82f6', color: '#60a5fa' };
    }
  };

  const getStatusBadgeStyle = (status: CaseStatus) => {
    switch (status) {
      case 'open':
        return { background: 'rgba(6, 182, 212, 0.2)', border: '1px solid #06b6d4', color: '#22d3ee' };
      case 'in_progress':
        return { background: 'rgba(245, 158, 11, 0.2)', border: '1px solid #f59e0b', color: '#fbbf24' };
      case 'resolved':
        return { background: 'rgba(16, 185, 129, 0.2)', border: '1px solid #10b981', color: '#34d399' };
      case 'closed':
      default:
        return { background: 'rgba(100, 116, 139, 0.2)', border: '1px solid #64748b', color: '#94a3b8' };
    }
  };

  return (
    <div className="case-management-container">
      {/* Filters & Action Bar */}
      <div
        className="filter-panel"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
          padding: '1rem',
          background: 'var(--bg-card)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          marginBottom: '1.25rem',
        }}
      >
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <div>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              aria-label="Filter by case status"
              style={{
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)',
                padding: '0.5rem 0.75rem',
                borderRadius: '6px',
                fontSize: '0.85rem',
              }}
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
            </select>
          </div>

          <div>
            <select
              value={priorityFilter}
              onChange={(e) => {
                setPriorityFilter(e.target.value);
                setPage(1);
              }}
              aria-label="Filter by case priority"
              style={{
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)',
                padding: '0.5rem 0.75rem',
                borderRadius: '6px',
                fontSize: '0.85rem',
              }}
            >
              <option value="">All Priorities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div>
            <input
              type="text"
              value={assigneeFilter}
              onChange={(e) => {
                setAssigneeFilter(e.target.value);
                setPage(1);
              }}
              placeholder="Filter by assignee..."
              style={{
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)',
                padding: '0.5rem 0.75rem',
                borderRadius: '6px',
                fontSize: '0.85rem',
              }}
            />
          </div>

          {(statusFilter || priorityFilter || assigneeFilter) && (
            <button
              type="button"
              className="btn-secondary"
              onClick={handleResetFilters}
              style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem' }}
            >
              Reset Filters
            </button>
          )}

          <button
            type="button"
            className="btn-secondary"
            onClick={fetchCases}
            disabled={loading}
            style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem' }}
          >
            ↻ Refresh
          </button>

          <button
            type="button"
            className="btn-secondary"
            onClick={handleExportCsv}
            disabled={loading || exportingCsv}
            style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem' }}
            title="Export filtered cases to sanitized CSV"
          >
            {exportingCsv ? '↻ Exporting...' : '📥 Export CSV'}
          </button>
        </div>

        <button
          type="button"
          onClick={onCreateCase}
          style={{
            background: 'linear-gradient(135deg, #0284c7, #06b6d4)',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            padding: '0.55rem 1.25rem',
            fontWeight: 600,
            fontSize: '0.875rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            boxShadow: '0 0 12px rgba(6, 182, 212, 0.3)',
          }}
        >
          <span>+</span> Open New Case
        </button>
      </div>

      {/* Loading state */}
      {loading && cases.length === 0 && (
        <div className="state-container loading" style={{ padding: '4rem 1rem' }}>
          <div className="spinner" />
          <h4 className="state-title">Loading Security Incident Cases...</h4>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="state-container error" style={{ padding: '3rem 1rem' }}>
          <div className="state-icon">⚠️</div>
          <h4 className="state-title">Error Loading Cases</h4>
          <p className="state-description">{error}</p>
          <button type="button" className="refresh-button" onClick={fetchCases}>
            ↻ Retry
          </button>
        </div>
      )}

      {/* Cases Table */}
      {!loading && !error && cases.length === 0 && (
        <div className="state-container empty" style={{ padding: '4rem 1rem' }}>
          <div className="state-icon">📁</div>
          <h4 className="state-title">No Incident Cases Found</h4>
          <p className="state-description">
            {statusFilter || priorityFilter || assigneeFilter
              ? 'No cases match your active filters. Try clearing filters.'
              : 'No incident investigation cases have been opened yet.'}
          </p>
          <button
            type="button"
            onClick={onCreateCase}
            style={{
              marginTop: '1rem',
              padding: '0.5rem 1.25rem',
              background: 'var(--accent-blue)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
            }}
          >
            + Create First Case
          </button>
        </div>
      )}

      {cases.length > 0 && (
        <div className="table-responsive" style={{ overflowX: 'auto' }}>
          <table className="alerts-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ width: '160px' }}>Case ID</th>
                <th style={{ width: '90px' }}>Priority</th>
                <th>Title & Overview</th>
                <th style={{ width: '120px' }}>Status</th>
                <th style={{ width: '130px' }}>Assignee</th>
                <th style={{ width: '150px' }}>Linked Assets</th>
                <th style={{ width: '170px' }}>Created</th>
                <th style={{ width: '90px', textAlign: 'center' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr
                  key={c.case_id}
                  onClick={() => onOpenCase(c)}
                  style={{ cursor: 'pointer' }}
                  className="table-row-hover"
                >
                  <td className="mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                    {c.case_id}
                  </td>
                  <td>
                    <span
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        ...getPriorityBadgeStyle(c.priority),
                      }}
                    >
                      {c.priority}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{c.title}</div>
                    {c.description && (
                      <div
                        style={{
                          fontSize: '0.8rem',
                          color: 'var(--text-muted)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          maxWidth: '380px',
                        }}
                      >
                        {c.description}
                      </div>
                    )}
                  </td>
                  <td>
                    <span
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        ...getStatusBadgeStyle(c.status),
                      }}
                    >
                      {c.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.85rem' }}>
                    {c.assignee ? (
                      <span>👤 {c.assignee}</span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>Unassigned</span>
                    )}
                  </td>
                  <td style={{ fontSize: '0.8rem' }}>
                    {c.alert_id && (
                      <div className="mono" title={`Alert ID: ${c.alert_id}`}>
                        🚨 {c.alert_id.slice(0, 12)}...
                      </div>
                    )}
                    {c.investigation_id && (
                      <div
                        className="mono"
                        style={{ color: 'var(--accent-cyan)', cursor: 'pointer' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          if (onOpenInvestigation) onOpenInvestigation(c.investigation_id!);
                        }}
                        title="Click to view linked investigation"
                      >
                        🔎 Inv: {c.investigation_id.slice(0, 8)}...
                      </div>
                    )}
                    {!c.alert_id && !c.investigation_id && (
                      <span style={{ color: 'var(--text-muted)' }}>None</span>
                    )}
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {new Date(c.created_at).toLocaleString()}
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={(e) => {
                        e.stopPropagation();
                        onOpenCase(c);
                      }}
                      style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination Footer */}
      {pagination && pagination.total_pages > 1 && (
        <div
          className="pagination-controls"
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginTop: '1.25rem',
            padding: '0.75rem 0',
          }}
        >
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Showing page {pagination.page} of {pagination.total_pages} ({pagination.total_items} total cases)
          </span>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn-secondary"
              disabled={!pagination.has_prev || loading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              style={{ padding: '0.4rem 0.8rem' }}
            >
              ← Previous
            </button>
            <button
              type="button"
              className="btn-secondary"
              disabled={!pagination.has_next || loading}
              onClick={() => setPage((p) => p + 1)}
              style={{ padding: '0.4rem 0.8rem' }}
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
