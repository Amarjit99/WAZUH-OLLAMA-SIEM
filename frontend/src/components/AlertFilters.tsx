import React from 'react';
import type { DataStatus } from '../types/api';

export interface FilterState {
  timeWindowHours: number; // 1, 6, 12, 24 (capped at 24)
  severityMin: number; // 0 = all, 3 = low+, 5 = med+, 8 = high+, 12 = crit+
  ruleId: string;
  hostName: string;
  sourceIp: string;
  sortOrder: 'desc' | 'asc';
  pageSize: number;
  autoRefreshInterval: number; // 0 = off, 15 = 15s, 30 = 30s, 60 = 60s
}

interface AlertFiltersProps {
  filters: FilterState;
  onChange: (updated: Partial<FilterState>) => void;
  onRefresh: () => void;
  onReset: () => void;
  loading: boolean;
  dataStatus?: DataStatus;
  totalAlerts?: number;
  onExportCsv?: () => void;
  exportingCsv?: boolean;
}

export const AlertFilters: React.FC<AlertFiltersProps> = ({
  filters,
  onChange,
  onRefresh,
  onReset,
  loading,
  dataStatus = 'fresh',
  totalAlerts = 0,
  onExportCsv,
  exportingCsv = false,
}) => {
  return (
    <section className="filters-card">
      <div className="filters-top-bar">
        <div className="filters-title-group">
          <h3 className="filters-title">Alert Stream Telemetry</h3>
          <div className="status-indicators">
            <span className={`status-badge ${dataStatus}`}>
              <span className="status-dot"></span>
              DATA: {dataStatus}
            </span>
            <span className="count-badge">
              {loading ? 'Scanning...' : `${totalAlerts} Total Alerts`}
            </span>
          </div>
        </div>

        <div className="filters-action-group">
          {/* Auto Refresh Select */}
          <div className="control-group">
            <label htmlFor="auto-refresh-select" className="control-label">
              AUTO-POLL
            </label>
            <select
              id="auto-refresh-select"
              className="soc-select"
              value={filters.autoRefreshInterval}
              onChange={(e) => onChange({ autoRefreshInterval: Number(e.target.value) })}
            >
              <option value={0}>Off</option>
              <option value={15}>15s</option>
              <option value={30}>30s</option>
              <option value={60}>60s</option>
            </select>
          </div>

          {/* Manual Refresh Button */}
          <button
            type="button"
            className="refresh-button"
            onClick={onRefresh}
            disabled={loading}
            aria-label="Refresh alerts table"
          >
            <span className={loading ? 'spin' : ''}>↻</span>
            {loading ? 'Loading...' : 'Refresh Alerts'}
          </button>
        </div>
      </div>

      <div className="filters-controls-grid">
        {/* Time Window Select (bounded to 24h max) */}
        <div className="filter-field">
          <label htmlFor="time-window-select" className="filter-label">
            Time Range
          </label>
          <select
            id="time-window-select"
            className="soc-select"
            value={filters.timeWindowHours}
            onChange={(e) => onChange({ timeWindowHours: Number(e.target.value) })}
          >
            <option value={1}>Past 1 Hour</option>
            <option value={6}>Past 6 Hours</option>
            <option value={12}>Past 12 Hours</option>
            <option value={24}>Past 24 Hours (Max)</option>
          </select>
        </div>

        {/* Severity Minimum Filter */}
        <div className="filter-field">
          <label htmlFor="severity-min-select" className="filter-label">
            Min Severity
          </label>
          <select
            id="severity-min-select"
            className="soc-select"
            value={filters.severityMin}
            onChange={(e) => onChange({ severityMin: Number(e.target.value) })}
          >
            <option value={0}>All Levels (1-16)</option>
            <option value={3}>Level 3+ (Low+)</option>
            <option value={5}>Level 5+ (Medium+)</option>
            <option value={8}>Level 8+ (High+)</option>
            <option value={12}>Level 12+ (Critical+)</option>
          </select>
        </div>

        {/* Rule ID Input */}
        <div className="filter-field">
          <label htmlFor="rule-id-input" className="filter-label">
            Rule ID
          </label>
          <input
            id="rule-id-input"
            type="text"
            className="soc-input"
            placeholder="e.g. 5710"
            value={filters.ruleId}
            onChange={(e) => onChange({ ruleId: e.target.value })}
          />
        </div>

        {/* Host / Agent Input */}
        <div className="filter-field">
          <label htmlFor="host-name-input" className="filter-label">
            Host / Agent
          </label>
          <input
            id="host-name-input"
            type="text"
            className="soc-input"
            placeholder="e.g. wazuh-manager"
            value={filters.hostName}
            onChange={(e) => onChange({ hostName: e.target.value })}
          />
        </div>

        {/* Source IP Input */}
        <div className="filter-field">
          <label htmlFor="source-ip-input" className="filter-label">
            Source IP
          </label>
          <input
            id="source-ip-input"
            type="text"
            className="soc-input"
            placeholder="e.g. 192.168.1.100"
            value={filters.sourceIp}
            onChange={(e) => onChange({ sourceIp: e.target.value })}
          />
        </div>

        {/* Sort Order */}
        <div className="filter-field">
          <label htmlFor="sort-order-select" className="filter-label">
            Order
          </label>
          <select
            id="sort-order-select"
            className="soc-select"
            value={filters.sortOrder}
            onChange={(e) => onChange({ sortOrder: e.target.value as 'asc' | 'desc' })}
          >
            <option value="desc">Newest First</option>
            <option value="asc">Oldest First</option>
          </select>
        </div>

        {/* Page Size Select */}
        <div className="filter-field">
          <label htmlFor="page-size-select" className="filter-label">
            Page Size
          </label>
          <select
            id="page-size-select"
            className="soc-select"
            value={filters.pageSize}
            onChange={(e) => onChange({ pageSize: Number(e.target.value) })}
          >
            <option value={10}>10 / page</option>
            <option value={25}>25 / page</option>
            <option value={50}>50 / page</option>
            <option value={100}>100 / page</option>
          </select>
        </div>

        {/* Actions */}
        <div className="filter-field-actions" style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end' }}>
          <button type="button" className="btn-secondary" onClick={onReset} title="Reset all filters">
            Reset Filters
          </button>
          {onExportCsv && (
            <button
              type="button"
              className="btn-secondary"
              onClick={onExportCsv}
              disabled={exportingCsv || loading}
              title="Export filtered alerts to sanitized CSV"
            >
              {exportingCsv ? '↻ Exporting...' : '📥 Export CSV'}
            </button>
          )}
        </div>
      </div>
    </section>
  );
};
