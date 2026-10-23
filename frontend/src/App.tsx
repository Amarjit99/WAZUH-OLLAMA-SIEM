import React, { useEffect, useState, useCallback, useRef } from 'react';
import { apiClient } from './api/client';
import { AlertDetailModal } from './components/AlertDetailModal';
import { AlertFilters, type FilterState } from './components/AlertFilters';
import { AlertsTable } from './components/AlertsTable';
import { CaseManagementTable } from './components/CaseManagementTable';
import { CaseModal } from './components/CaseModal';
import { InvestigationDetailModal } from './components/InvestigationDetailModal';
import { InvestigationHistoryTable } from './components/InvestigationHistoryTable';
import { InvestigationModal } from './components/InvestigationModal';
import { AgentFleetTable } from './components/AgentFleetTable';
import type {
  AlertQueryParams,
  AuditVerificationStatusResponse,
  BackupOperationalStatusResponse,
  Case,
  DataStatus,
  DependencyHealth,
  HealthReadyResponse,
  InvestigationResult,
  NormalizedAlert,
  PaginationMetadata,
} from './types/api';


interface OperationalAlert {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  desc: string;
  hint: string;
}

const formatTimestamp = (ts?: string | null): string => {
  if (!ts) return 'Never';
  try {
    const d = new Date(ts);
    return isNaN(d.getTime()) ? ts : d.toLocaleString();
  } catch {
    return ts;
  }
};

const DEFAULT_FILTERS: FilterState = {
  timeWindowHours: 24, // Default to past 24h to capture single-node alerts
  severityMin: 0,
  ruleId: '',
  hostName: '',
  sourceIp: '',
  sortOrder: 'desc',
  pageSize: 25,
  autoRefreshInterval: 0, // Default manual
};

export const App: React.FC = () => {
  // Telemetry Health State
  const [healthData, setHealthData] = useState<HealthReadyResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [lastCheckTime, setLastCheckTime] = useState<string>('Never');

  // Operational Backup & Audit Telemetry State
  const [backupHealth, setBackupHealth] = useState<BackupOperationalStatusResponse | null>(null);
  const [auditHealth, setAuditHealth] = useState<AuditVerificationStatusResponse | null>(null);
  const [auditVerifying, setAuditVerifying] = useState<boolean>(false);
  const [auditVerifyError, setAuditVerifyError] = useState<string | null>(null);
  const [dismissedAlerts, setDismissedAlerts] = useState<Record<string, boolean>>({});
  const [lastProbeTimestamp, setLastProbeTimestamp] = useState<number>(0);
  const [isStale, setIsStale] = useState<boolean>(false);

  // Alerts State
  const [alerts, setAlerts] = useState<NormalizedAlert[]>([]);
  const [alertsLoading, setAlertsLoading] = useState<boolean>(true);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [pagination, setPagination] = useState<PaginationMetadata | null>(null);
  const [dataStatus, setDataStatus] = useState<DataStatus>('fresh');
  const [selectedAlert, setSelectedAlert] = useState<NormalizedAlert | null>(null);

  // AI Investigation State
  const [investigatingAlert, setInvestigatingAlert] = useState<NormalizedAlert | null>(null);
  const [investigationResult, setInvestigationResult] = useState<InvestigationResult | null>(null);
  const [investigationLoading, setInvestigationLoading] = useState<boolean>(false);
  const [investigationError, setInvestigationError] = useState<string | null>(null);
  const investigationAbortRef = useRef<AbortController | null>(null);

  // Tab View State: live_alerts | history | cases | fleet
  const [activeTab, setActiveTab] = useState<'live_alerts' | 'history' | 'cases' | 'fleet'>('live_alerts');
  const [selectedHistoryInvestigationId, setSelectedHistoryInvestigationId] = useState<string | null>(null);

  // Case Management State
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);
  const [isCaseModalOpen, setIsCaseModalOpen] = useState<boolean>(false);
  const [caseInitialValues, setCaseInitialValues] = useState<{ alertId?: string; investigationId?: string; title?: string } | undefined>(undefined);
  const [caseRefreshTrigger, setCaseRefreshTrigger] = useState<number>(0);

  const handleOpenCreateCase = (alertId?: string, investigationId?: string, title?: string) => {
    setSelectedCase(null);
    setCaseInitialValues({ alertId, investigationId, title });
    setIsCaseModalOpen(true);
  };

  const handleOpenEditCase = (caseItem: Case) => {
    setSelectedCase(caseItem);
    setCaseInitialValues(undefined);
    setIsCaseModalOpen(true);
  };

  const handleCaseSaved = () => {
    setCaseRefreshTrigger((prev) => prev + 1);
  };

  const handleCaseDeleted = () => {
    setCaseRefreshTrigger((prev) => prev + 1);
  };


  // Filters & Pagination State
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);
  const [page, setPage] = useState<number>(1);
  const [alertsExporting, setAlertsExporting] = useState<boolean>(false);

  const handleExportAlertsCsv = async () => {
    setAlertsExporting(true);
    try {
      const now = new Date();
      const startTime = new Date(now.getTime() - filters.timeWindowHours * 60 * 60 * 1000);
      const params: AlertQueryParams = {
        start_time: startTime.toISOString(),
        end_time: now.toISOString(),
        sort_order: filters.sortOrder,
      };
      if (filters.severityMin > 0) params.severity_min = filters.severityMin;
      if (filters.ruleId.trim()) params.rule_id = filters.ruleId.trim();
      if (filters.hostName.trim()) params.host_name = filters.hostName.trim();
      if (filters.sourceIp.trim()) params.source_ip = filters.sourceIp.trim();

      const blob = await apiClient.exportAlerts(params, 'csv');
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `alerts_export_${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export alerts CSV:', err);
    } finally {
      setAlertsExporting(false);
    }
  };

  // Concurrency and Abort Controllers
  const abortControllerRef = useRef<AbortController | null>(null);
  const latestRequestTimestampRef = useRef<number>(0);

  // 1. Truthful Telemetry Probing (Wazuh, OpenSearch, Ollama, Backup, Audit)
  const refreshTelemetry = useCallback(async () => {
    setHealthLoading(true);
    setHealthError(null);
    try {
      const [readyRes, backupRes, auditRes] = await Promise.allSettled([
        apiClient.getHealthReady(),
        apiClient.getHealthBackup(),
        apiClient.getHealthAudit(),
      ]);

      if (readyRes.status === 'fulfilled') {
        setHealthData(readyRes.value);
      } else {
        const msg = readyRes.reason instanceof Error ? readyRes.reason.message : String(readyRes.reason);
        setHealthError(msg);
      }

      if (backupRes.status === 'fulfilled') {
        setBackupHealth(backupRes.value);
      }

      if (auditRes.status === 'fulfilled') {
        setAuditHealth(auditRes.value);
      }

      setLastCheckTime(new Date().toLocaleTimeString());
      setLastProbeTimestamp(Date.now());
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setHealthError(msg);
      setLastCheckTime(new Date().toLocaleTimeString());
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    let isCancelled = false;

    const loadInitialHealth = async () => {
      try {
        const [readyRes, backupRes, auditRes] = await Promise.allSettled([
          apiClient.getHealthReady(),
          apiClient.getHealthBackup(),
          apiClient.getHealthAudit(),
        ]);
        if (!isCancelled) {
          if (readyRes.status === 'fulfilled') {
            setHealthData(readyRes.value);
            setHealthError(null);
          } else {
            const msg = readyRes.reason instanceof Error ? readyRes.reason.message : String(readyRes.reason);
            setHealthError(msg);
          }

          if (backupRes.status === 'fulfilled') {
            setBackupHealth(backupRes.value);
          }

          if (auditRes.status === 'fulfilled') {
            setAuditHealth(auditRes.value);
          }

          setLastCheckTime(new Date().toLocaleTimeString());
          setLastProbeTimestamp(Date.now());
          setHealthLoading(false);
        }
      } catch (err: unknown) {
        if (!isCancelled) {
          const msg = err instanceof Error ? err.message : String(err);
          setHealthError(msg);
          setLastCheckTime(new Date().toLocaleTimeString());
          setHealthLoading(false);
        }
      }
    };

    loadInitialHealth();
    const intervalId = setInterval(loadInitialHealth, 30000);

    return () => {
      isCancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  // Monitor Telemetry Staleness (90s threshold)
  useEffect(() => {
    if (lastProbeTimestamp <= 0) return;
    const checkTimer = setInterval(() => {
      if (Date.now() - lastProbeTimestamp > 90000) {
        setIsStale(true);
      }
    }, 15000);
    return () => clearInterval(checkTimer);
  }, [lastProbeTimestamp]);

  // On-demand Cryptographic Audit Verification Handler
  const handleVerifyAuditChain = async () => {
    setAuditVerifying(true);
    setAuditVerifyError(null);
    try {
      const res = await apiClient.verifyHealthAudit();
      setAuditHealth(res);
      // Synchronize backup operational status as well
      const updatedBackup = await apiClient.getHealthBackup().catch(() => null);
      if (updatedBackup) setBackupHealth(updatedBackup);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setAuditVerifyError(msg);
    } finally {
      setAuditVerifying(false);
    }
  };

  const handleDismissAlert = (id: string) => {
    setDismissedAlerts((prev) => ({ ...prev, [id]: true }));
  };

  // Trigger key for manual and periodic re-fetches
  const [refreshKey, setRefreshKey] = useState<number>(0);

  // 2. Alert Query Execution Effect
  useEffect(() => {
    let isCancelled = false;
    const controller = new AbortController();
    abortControllerRef.current = controller;
    const requestTimestamp = Date.now();
    latestRequestTimestampRef.current = requestTimestamp;

    const executeFetch = async () => {
      try {
        const now = new Date();
        const startTime = new Date(now.getTime() - filters.timeWindowHours * 60 * 60 * 1000);

        const params: AlertQueryParams = {
          start_time: startTime.toISOString(),
          end_time: now.toISOString(),
          page,
          page_size: filters.pageSize,
          sort_order: filters.sortOrder,
        };

        if (filters.severityMin > 0) {
          params.severity_min = filters.severityMin;
        }
        if (filters.ruleId.trim()) {
          params.rule_id = filters.ruleId.trim();
        }
        if (filters.hostName.trim()) {
          params.host_name = filters.hostName.trim();
        }
        if (filters.sourceIp.trim()) {
          params.source_ip = filters.sourceIp.trim();
        }

        const response = await apiClient.getAlerts(params, controller.signal);

        if (!isCancelled && latestRequestTimestampRef.current === requestTimestamp) {
          setAlerts(response.items);
          setPagination(response.pagination);
          setDataStatus(response.data_status);
          setAlertsError(null);
          setAlertsLoading(false);
        }
      } catch (err: unknown) {
        if (err instanceof DOMException && err.name === 'AbortError') {
          return;
        }
        if (!isCancelled && latestRequestTimestampRef.current === requestTimestamp) {
          const msg = err instanceof Error ? err.message : String(err);
          setAlertsError(msg);
          setAlertsLoading(false);
        }
      }
    };

    executeFetch();

    return () => {
      isCancelled = true;
      controller.abort();
    };
  }, [page, filters, refreshKey]);

  // Auto-refresh timer for alerts
  useEffect(() => {
    if (filters.autoRefreshInterval <= 0) return;

    const timer = setInterval(() => {
      setAlertsLoading(true);
      setRefreshKey((k) => k + 1);
    }, filters.autoRefreshInterval * 1000);

    return () => clearInterval(timer);
  }, [filters.autoRefreshInterval]);

  // Handlers
  const handleFilterChange = (updated: Partial<FilterState>) => {
    setAlertsLoading(true);
    setFilters((prev) => ({ ...prev, ...updated }));
    setPage(1);
  };

  const handleResetFilters = () => {
    setAlertsLoading(true);
    setFilters(DEFAULT_FILTERS);
    setPage(1);
  };

  const handlePageChange = (newPage: number) => {
    setAlertsLoading(true);
    setPage(newPage);
  };

  const handleManualRefreshAlerts = () => {
    setAlertsLoading(true);
    setRefreshKey((k) => k + 1);
  };

  // AI Investigation Handlers
  const handleStartInvestigation = useCallback(async (alert: NormalizedAlert) => {
    if (investigationAbortRef.current) {
      investigationAbortRef.current.abort();
    }
    const controller = new AbortController();
    investigationAbortRef.current = controller;

    setInvestigatingAlert(alert);
    setInvestigationResult(null);
    setInvestigationLoading(true);
    setInvestigationError(null);

    try {
      const result = await apiClient.investigateAlert(
        alert.alert_id,
        {
          include_related_events: true,
          correlation_window_minutes: 30,
          max_related_events: 10,
          max_evidence_items: 15,
        },
        controller.signal
      );
      setInvestigationResult(result);
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') {
        return;
      }
      const msg = err instanceof Error ? err.message : String(err);
      setInvestigationError(msg);
    } finally {
      setInvestigationLoading(false);
    }
  }, []);

  const handleRetryInvestigation = useCallback(() => {
    if (investigatingAlert) {
      handleStartInvestigation(investigatingAlert);
    }
  }, [investigatingAlert, handleStartInvestigation]);

  const handleCancelInvestigation = useCallback(() => {
    if (investigationAbortRef.current) {
      investigationAbortRef.current.abort();
    }
    setInvestigationLoading(false);
    setInvestigationError('Investigation cancelled by analyst.');
  }, []);

  const handleCloseInvestigation = useCallback(() => {
    if (investigationAbortRef.current) {
      investigationAbortRef.current.abort();
    }
    setInvestigatingAlert(null);
    setInvestigationResult(null);
    setInvestigationLoading(false);
    setInvestigationError(null);
  }, []);

  const renderBadge = (health?: DependencyHealth) => {
    if (!health) return <span className="status-badge unavailable">Unknown</span>;
    return (
      <span className={`status-badge ${health.status}`}>
        <span className="status-dot"></span>
        {health.status.replace('_', ' ')}
      </span>
    );
  };

  // Derive Truthful Operational Alerts
  const activeAlerts: OperationalAlert[] = [];

  if (isStale) {
    activeAlerts.push({
      id: 'stale-telemetry',
      severity: 'warning',
      title: 'Stale Operational Telemetry',
      desc: 'No telemetry update received in the last 90 seconds.',
      hint: 'Backend might be experiencing network congestion. Click "Refresh Health" to probe.',
    });
  }

  if (healthData?.dependencies?.wazuh_api?.status === 'unavailable') {
    activeAlerts.push({
      id: 'wazuh-unavailable',
      severity: 'critical',
      title: 'Wazuh Manager API Unavailable',
      desc: healthData.dependencies.wazuh_api.message || 'Cannot reach Wazuh API endpoint.',
      hint: 'Check if Wazuh manager daemon is running and TLS certificate is valid.',
    });
  }

  if (healthData?.dependencies?.opensearch?.status === 'unavailable') {
    activeAlerts.push({
      id: 'opensearch-unavailable',
      severity: 'critical',
      title: 'Wazuh Indexer / OpenSearch Unavailable',
      desc: healthData.dependencies.opensearch.message || 'Cannot connect to OpenSearch cluster.',
      hint: 'Verify OpenSearch docker container health and network connectivity.',
    });
  }

  if (healthData?.dependencies?.ollama?.status === 'unavailable') {
    activeAlerts.push({
      id: 'ollama-unavailable',
      severity: 'warning',
      title: 'Ollama AI Service Unavailable',
      desc: healthData.dependencies.ollama.message || 'Cannot connect to Ollama service endpoint.',
      hint: 'Ensure `ollama serve` is running and `llama3.2:3b` model is loaded locally.',
    });
  }

  if (backupHealth) {
    if (backupHealth.status === 'UNAVAILABLE' || (backupHealth.last_backup_error_category && backupHealth.last_backup_error_category !== 'None')) {
      activeAlerts.push({
        id: `backup-fail-${backupHealth.last_backup_error_category || backupHealth.status}`,
        severity: 'critical',
        title: 'Backup Subsystem Failure / Degraded',
        desc: `Backup subsystem reported status: ${backupHealth.status}. Error category: ${backupHealth.last_backup_error_category || 'None'}.`,
        hint: 'Inspect backup directory permissions, available disk space, and SQLite busy timeout.',
      });
    }

    if (!backupHealth.encryption_key_status?.key_usable || !backupHealth.encryption_key_status?.key_file_exists) {
      activeAlerts.push({
        id: 'encryption-key-unavailable',
        severity: 'critical',
        title: 'Encryption Key Unavailable',
        desc: `Encryption key usable: ${backupHealth.encryption_key_status?.key_usable ? 'YES' : 'NO'}. DPAPI available: ${backupHealth.encryption_key_status?.dpapi_available ? 'YES' : 'NO'}.`,
        hint: 'Ensure DPAPI user master key or explicit encryption key is configured.',
      });
    }

    if (backupHealth.scheduler_enabled && !backupHealth.scheduler_active) {
      activeAlerts.push({
        id: 'scheduler-not-running',
        severity: 'warning',
        title: 'Backup Scheduler Enabled But Inactive',
        desc: 'Scheduler is marked enabled in configuration but background execution thread is not running.',
        hint: 'Verify process lifespan startup tasks and scheduler lifecycle configuration.',
      });
    }

    if (backupHealth.last_backup_verification_status === 'FAILED') {
      activeAlerts.push({
        id: 'backup-verification-failed',
        severity: 'critical',
        title: 'Backup Verification Failure',
        desc: 'The most recent backup verification failed integrity/signature checks.',
        hint: 'Do not rely on this archive. Perform an isolated disaster recovery drill.',
      });
    }
  }

  if (auditHealth && auditHealth.status === 'FAILED') {
    activeAlerts.push({
      id: 'audit-verification-failed',
      severity: 'critical',
      title: 'Cryptographic Audit Chain Integrity Failure',
      desc: `Audit log verification detected a hash chain break: ${auditHealth.error || 'Mismatched checksums'}.`,
      hint: 'Audit log integrity is fail-closed. Investigate database audit records for unauthorized tampering.',
    });
  }

  const unDismissedAlerts = activeAlerts.filter((a) => !dismissedAlerts[a.id]);

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
          {healthLoading ? (
            <span style={{ color: 'var(--text-muted)' }}>CHECKING...</span>
          ) : healthError ? (
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
        {/* Page Top Section */}
        <section className="page-header">
          <div>
            <h1 className="page-title">SOC Operations & Telemetry</h1>
            <p className="page-description">
              Real-time operational status and security alert stream. All detections are retrieved through
              authenticated, read-only APIs without simulation or mock fabrication.
            </p>
          </div>

          <button
            type="button"
            className="refresh-button"
            onClick={refreshTelemetry}
            disabled={healthLoading}
            aria-label="Refresh telemetry status"
          >
            <span className={healthLoading ? 'spin' : ''}>↻</span>
            {healthLoading ? 'Probing...' : 'Refresh Health'}
          </button>
        </section>

        {/* Global Connection Error Banner */}
        {healthError && (
          <div className="error-banner">
            <strong>Backend Connection Error:</strong> {healthError}
          </div>
        )}

        {/* Operational Alerts Banner */}
        {unDismissedAlerts.length > 0 && (
          <div className="operational-alerts-container" role="region" aria-label="Operational Alerts">
            {unDismissedAlerts.map((alert) => (
              <div key={alert.id} className={`operational-alert-card ${alert.severity}`}>
                <div className="operational-alert-content">
                  <div className="operational-alert-title">
                    <span>{alert.severity === 'critical' ? '⚠️' : 'ℹ️'}</span>
                    <span>{alert.title}</span>
                  </div>
                  <div className="operational-alert-desc">{alert.desc}</div>
                  <div className="operational-alert-hint">Recovery Hint: {alert.hint}</div>
                </div>
                <button
                  type="button"
                  className="operational-alert-dismiss"
                  onClick={() => handleDismissAlert(alert.id)}
                  aria-label={`Dismiss alert ${alert.title}`}
                >
                  Dismiss
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Telemetry Grid */}
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
              <span>TRANSPORT: HTTPS</span>
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
              <span>INDEX: wazuh-alerts-*</span>
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
              <span>ISOLATION: Read-Only v1</span>
              <span>
                {healthData?.dependencies?.ollama?.latency_ms !== undefined
                  ? `${healthData.dependencies.ollama.latency_ms} ms`
                  : '--'}
              </span>
            </div>
          </article>

          {/* Encrypted Backup & Key Operations Card */}
          <article className="telemetry-card">
            <div className="card-header">
              <div className="card-title-group">
                <h3>Encrypted Backup & Storage</h3>
                <div className="card-role-label">Disaster Recovery & DPAPI</div>
              </div>
              <span className={`status-badge ${backupHealth?.status === 'OK' ? 'healthy' : backupHealth?.status === 'DEGRADED' ? 'degraded' : backupHealth?.status === 'UNAVAILABLE' ? 'failed' : 'unavailable'}`}>
                <span className="status-dot"></span>
                {backupHealth?.status || 'UNKNOWN'}
              </span>
            </div>
            <div className="card-body">
              <div className="telemetry-row">
                <span className="telemetry-label">SCHEDULER:</span>
                <span className="telemetry-val">
                  {backupHealth?.scheduler_enabled
                    ? (backupHealth.scheduler_active ? 'ENABLED (RUNNING)' : 'ENABLED (STOPPED)')
                    : 'DISABLED (BY DEFAULT)'}
                </span>
              </div>
              <div className="telemetry-row">
                <span className="telemetry-label">ENCRYPTION KEY:</span>
                <span className="telemetry-val">
                  {backupHealth?.encryption_key_status?.key_usable ? 'USABLE (DPAPI)' : 'NOT USABLE'} ({backupHealth?.encryption_key_status?.recovery_strategy || 'AES-256-GCM'})
                </span>
              </div>
              <div className="telemetry-row">
                <span className="telemetry-label">LAST ATTEMPT:</span>
                <span className="telemetry-val">{formatTimestamp(backupHealth?.last_backup_attempt_at)}</span>
              </div>
              <div className="telemetry-row">
                <span className="telemetry-label">LAST SUCCESS:</span>
                <span className="telemetry-val">{formatTimestamp(backupHealth?.last_successful_backup_at)}</span>
              </div>
              <div className="telemetry-row">
                <span className="telemetry-label">BACKUP VERIFY:</span>
                <span className="telemetry-val">
                  {backupHealth?.last_backup_verification_status || 'UNVERIFIED'}
                </span>
              </div>
              <div className="telemetry-row">
                <span className="telemetry-label">RECOVERY DRILL:</span>
                <span className="telemetry-val">
                  {backupHealth?.last_recovery_drill_status || 'NEVER_RUN'}
                </span>
              </div>
              <div className="telemetry-row">
                <span className="telemetry-label">ERROR CATEGORY:</span>
                <span className="telemetry-val">
                  {backupHealth?.last_backup_error_category || 'None'}
                </span>
              </div>
            </div>
            <div className="card-footer">
              <span>INTERVAL: {backupHealth?.backup_interval_minutes ?? 60}m</span>
              <span>ISOLATION: AES-GCM</span>
            </div>
          </article>

          {/* Cryptographic Audit Log & Chain Card */}
          <article className="telemetry-card">
            <div className="card-header">
              <div className="card-title-group">
                <h3>Tamper-Evident Audit Chain</h3>
                <div className="card-role-label">Cryptographic Log Integrity</div>
              </div>
              <span className={`status-badge ${auditHealth?.status === 'VERIFIED' ? 'verified' : auditHealth?.status === 'FAILED' ? 'failed' : 'unverified'}`}>
                <span className="status-dot"></span>
                {auditHealth?.status || 'UNVERIFIED'}
              </span>
            </div>
            <div className="card-body">
              <div className="telemetry-row">
                <span className="telemetry-label">CHAIN STATUS:</span>
                <span className="telemetry-val">
                  {auditHealth?.status === 'VERIFIED' ? 'VALID HASH CHAIN' : auditHealth?.status === 'FAILED' ? 'INTEGRITY BREAK' : 'UNVERIFIED'}
                </span>
              </div>
              <div className="telemetry-row">
                <span className="telemetry-label">EVENTS VERIFIED:</span>
                <span className="telemetry-val">
                  {auditHealth?.verified_events_count !== undefined && auditHealth.status === 'VERIFIED'
                    ? `${auditHealth.verified_events_count} Contiguous Records`
                    : 'Unverified'}
                </span>
              </div>
              <div className="telemetry-row">
                <span className="telemetry-label">LAST VERIFIED:</span>
                <span className="telemetry-val">{formatTimestamp(auditHealth?.verified_at)}</span>
              </div>
              {auditHealth?.error && (
                <div className="telemetry-row">
                  <span className="telemetry-label">ERROR:</span>
                  <span className="telemetry-val" style={{ color: 'var(--status-unavailable)' }}>{auditHealth.error}</span>
                </div>
              )}
              {auditVerifyError && (
                <div className="telemetry-row">
                  <span className="telemetry-label">VERIFY ERR:</span>
                  <span className="telemetry-val" style={{ color: 'var(--status-unavailable)' }}>{auditVerifyError}</span>
                </div>
              )}

              <button
                type="button"
                className="telemetry-action-btn"
                onClick={handleVerifyAuditChain}
                disabled={auditVerifying}
                aria-label="Verify audit log hash chain integrity"
              >
                <span className={auditVerifying ? 'spin' : ''}>{auditVerifying ? '↻' : '🔒'}</span>
                {auditVerifying ? 'Verifying Hashes...' : 'Verify Audit Chain'}
              </button>
            </div>
            <div className="card-footer">
              <span>ALGORITHM: SHA-256</span>
              <span>PRUNING: HARD-BLOCKED</span>
            </div>
          </article>
        </section>

        {/* View Switcher Tabs: Live Alerts vs. Investigation History */}
        <nav className="view-tabs-container" aria-label="Investigation Workspace Navigation">
          <button
            type="button"
            className={`view-tab-btn ${activeTab === 'live_alerts' ? 'active' : ''}`}
            onClick={() => setActiveTab('live_alerts')}
            aria-current={activeTab === 'live_alerts' ? 'page' : undefined}
          >
            <span>🚨 Live Alerts Stream</span>
            {pagination?.total_items !== undefined && (
              <span className="view-tab-badge">{pagination.total_items}</span>
            )}
          </button>
          <button
            type="button"
            className={`view-tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
            aria-current={activeTab === 'history' ? 'page' : undefined}
          >
            <span>📜 Investigation History & Audits</span>
          </button>
          <button
            type="button"
            className={`view-tab-btn ${activeTab === 'cases' ? 'active' : ''}`}
            onClick={() => setActiveTab('cases')}
            aria-current={activeTab === 'cases' ? 'page' : undefined}
          >
            <span>📁 Cases & Incident Management</span>
          </button>
          <button
            type="button"
            className={`view-tab-btn ${activeTab === 'fleet' ? 'active' : ''}`}
            onClick={() => setActiveTab('fleet')}
            aria-current={activeTab === 'fleet' ? 'page' : undefined}
          >
            <span>🛡️ Endpoint Fleet & Webhooks</span>
          </button>
        </nav>

        {/* View Content */}
        {activeTab === 'live_alerts' && (
          <section className="alerts-section">
            <AlertFilters
              filters={filters}
              onChange={handleFilterChange}
              onRefresh={handleManualRefreshAlerts}
              onReset={handleResetFilters}
              loading={alertsLoading}
              dataStatus={dataStatus}
              totalAlerts={pagination?.total_items ?? 0}
              onExportCsv={handleExportAlertsCsv}
              exportingCsv={alertsExporting}
            />

            <AlertsTable
              alerts={alerts}
              loading={alertsLoading}
              error={alertsError}
              pagination={pagination}
              onPageChange={handlePageChange}
              onSelectAlert={(alert) => setSelectedAlert(alert)}
              onInvestigateAlert={handleStartInvestigation}
              onRetry={handleManualRefreshAlerts}
            />
          </section>
        )}

        {activeTab === 'history' && (
          <section className="history-section">
            <InvestigationHistoryTable
              onSelectInvestigation={(id) => setSelectedHistoryInvestigationId(id)}
            />
          </section>
        )}

        {activeTab === 'cases' && (
          <section className="cases-section">
            <CaseManagementTable
              onOpenCase={handleOpenEditCase}
              onCreateCase={() => handleOpenCreateCase()}
              onOpenInvestigation={(id) => setSelectedHistoryInvestigationId(id)}
              refreshTrigger={caseRefreshTrigger}
            />
          </section>
        )}

        {activeTab === 'fleet' && (
          <section className="fleet-section">
            <AgentFleetTable />
          </section>
        )}


        {/* Phase Architecture Notice */}
        <section className="baseline-banner">
          <h4>🛡️ Active Guardrails & Data Authenticity Notice</h4>
          <p>
            In accordance with <code>AGENTS.md</code> and <code>specs/AI_SAFETY_RULES.md</code>:
          </p>
          <ul className="baseline-list">
            <li><strong>Live Telemetry:</strong> All alerts above are retrieved directly from the live Wazuh Indexer without fabrication or simulated metrics.</li>
            <li><strong>Privileged Isolation:</strong> The frontend communicates strictly with FastAPI; no direct connections to Wazuh Manager or OpenSearch occur.</li>
            <li><strong>Strictly Read-Only:</strong> Remediation, firewall blocking, account locking, and mutation endpoints are disabled.</li>
            <li><strong>Audit Correlation:</strong> Backend trace ID: <code>{healthData?.request_id || 'X-Request-ID'}</code>.</li>
          </ul>
        </section>
      </main>

      {/* Alert Detail Inspection Modal */}
      <AlertDetailModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onInvestigate={handleStartInvestigation}
        onCreateCase={(alt) =>
          handleOpenCreateCase(alt.alert_id, undefined, `Case: ${alt.rule_description} (${alt.alert_id})`)
        }
      />

      {/* AI Investigation Advisory Modal */}
      <InvestigationModal
        alert={investigatingAlert}
        result={investigationResult}
        loading={investigationLoading}
        error={investigationError}
        onClose={handleCloseInvestigation}
        onRetry={handleRetryInvestigation}
        onCancel={handleCancelInvestigation}
        onCreateCase={handleOpenCreateCase}
      />

      {/* Persisted Investigation Detail Modal */}
      <InvestigationDetailModal
        investigationId={selectedHistoryInvestigationId}
        onClose={() => setSelectedHistoryInvestigationId(null)}
        onCreateCase={handleOpenCreateCase}
      />

      {/* Case Management Modal (Create / Inspect / Edit) */}
      <CaseModal
        caseItem={selectedCase}
        initialValues={caseInitialValues}
        isOpen={isCaseModalOpen}
        onClose={() => setIsCaseModalOpen(false)}
        onSaved={handleCaseSaved}
        onDeleted={handleCaseDeleted}
        onOpenInvestigation={(id) => {
          setIsCaseModalOpen(false);
          setSelectedHistoryInvestigationId(id);
        }}
      />


      <footer className="soc-footer">
        <div>Wazuh + Ollama SIEM Platform v0.1.0 (Phase 7.3 Active)</div>
        <div>Last Telemetry Probe: {lastCheckTime}</div>
      </footer>
    </>
  );
};

export default App;
