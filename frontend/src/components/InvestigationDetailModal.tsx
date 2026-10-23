import React, { useEffect, useState, useCallback, useRef } from 'react';
import { apiClient } from '../api/client';
import type {
  ConfidenceLabel,
  InvestigationDetailResponse,
  PriorityLevel,
  UncertaintyLevel,
} from '../types/api';

interface InvestigationDetailModalProps {
  investigationId: string | null;
  onClose: () => void;
  onCreateCase?: (alertId?: string, investigationId?: string, title?: string) => void;
}

export const InvestigationDetailModal: React.FC<InvestigationDetailModalProps> = ({
  investigationId,
  onClose,
  onCreateCase,
}) => {
  const [data, setData] = useState<InvestigationDetailResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeEvidenceId, setActiveEvidenceId] = useState<string | null>(null);
  const [copiedSummary, setCopiedSummary] = useState<boolean>(false);
  const [exportingFormat, setExportingFormat] = useState<'markdown' | 'json' | 'csv' | null>(null);

  // Feedback State
  const [feedbackRating, setFeedbackRating] = useState<'helpful' | 'incorrect' | 'incomplete' | null>(null);
  const [feedbackNotes, setFeedbackNotes] = useState<string>('');
  const [feedbackSubmitting, setFeedbackSubmitting] = useState<boolean>(false);
  const [feedbackSuccess, setFeedbackSuccess] = useState<string | null>(null);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);

  const abortControllerRef = useRef<AbortController | null>(null);

  const fetchDetail = useCallback(async (id: string) => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setLoading(true);
    setError(null);
    setData(null);

    try {
      const resp = await apiClient.getInvestigationById(id, controller.signal);
      if (!controller.signal.aborted) {
        setData(resp);
        if (resp.analyst_rating) {
          setFeedbackRating(resp.analyst_rating as 'helpful' | 'incorrect' | 'incomplete');
        }
        if (resp.analyst_notes) {
          setFeedbackNotes(resp.analyst_notes);
        }
        setLoading(false);
      }
    } catch (err: unknown) {
      if (controller.signal.aborted) return;
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (investigationId) {
      fetchDetail(investigationId);
    } else {
      setData(null);
      setError(null);
      setLoading(false);
    }
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [investigationId, fetchDetail]);

  const handleExport = async (format: 'markdown' | 'json' | 'csv') => {
    if (!data) return;
    setExportingFormat(format);
    try {
      const blob = await apiClient.exportInvestigationReport(data.investigation_id, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = format === 'json' ? 'json' : format === 'csv' ? 'csv' : 'md';
      a.download = `investigation_${data.investigation_id}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed:', err);
    } finally {
      setExportingFormat(null);
    }
  };

  const handleSubmitFeedback = async () => {
    if (!data || !feedbackRating) return;
    setFeedbackSubmitting(true);
    setFeedbackError(null);
    setFeedbackSuccess(null);
    try {
      const updated = await apiClient.submitInvestigationFeedback(
        data.investigation_id,
        feedbackRating,
        feedbackNotes
      );
      setData(updated);
      setFeedbackSuccess('Feedback submitted and recorded to the audit trail.');
      setTimeout(() => setFeedbackSuccess(null), 4000);
    } catch (err) {
      setFeedbackError(err instanceof Error ? err.message : String(err));
    } finally {
      setFeedbackSubmitting(false);
    }
  };


  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!investigationId) return null;

  const scrollToEvidence = (evidenceId: string) => {
    setActiveEvidenceId(evidenceId);
    const element = document.getElementById(`persisted-ev-card-${evidenceId}`);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const handleCopyReport = async () => {
    if (!data) return;
    const res = data.result;
    const reportText =
      `[PERSISTED SIEM INVESTIGATION RECORD]\n` +
      `Investigation ID: ${data.investigation_id}\n` +
      `Target Alert: ${data.alert_id} (Run #${data.run_sequence})\n` +
      `Status: ${data.status.toUpperCase()}\n` +
      `Rule ID: ${data.primary_rule_id} | Agent: ${data.primary_agent_name || 'N/A'}\n` +
      (res ? `Confidence: ${res.confidence_label.toUpperCase()}\nModel: ${res.model_name}:${res.model_tag}\n\n` : '\n') +
      (res ? `SUMMARY:\n${res.summary}\n\n` : '') +
      (res && res.observed_facts.length > 0
        ? `OBSERVED FACTS:\n` + res.observed_facts.map((f) => `- [${f.cited_evidence_ids.join(', ')}] ${f.statement}`).join('\n') + '\n\n'
        : '') +
      (res && res.hypotheses.length > 0
        ? `HYPOTHESES:\n` + res.hypotheses.map((h) => `- (${h.uncertainty.toUpperCase()} uncertainty) [${h.cited_evidence_ids.join(', ')}] ${h.statement}`).join('\n') + '\n\n'
        : '') +
      (res && res.recommended_checks.length > 0
        ? `RECOMMENDED CHECKS:\n` + res.recommended_checks.map((c) => `- [Priority: ${c.priority.toUpperCase()}] ${c.description} (Rationale: ${c.rationale})`).join('\n') + '\n\n'
        : '') +
      (res ? `DISCLAIMER:\n${res.disclaimer}\n` : '') +
      (data.error_message ? `ERROR DETAILS: [${data.error_code}] ${data.error_message}\n` : '') +
      `Created: ${data.created_at} (Actor: ${data.actor_id})`;

    try {
      await navigator.clipboard.writeText(reportText);
      setCopiedSummary(true);
      setTimeout(() => setCopiedSummary(false), 2000);
    } catch {
      // Ignore clipboard write restrictions
    }
  };

  const getConfidenceBadgeClass = (conf: ConfidenceLabel) => {
    switch (conf) {
      case 'high':
        return 'confidence-badge high';
      case 'medium':
        return 'confidence-badge medium';
      case 'low':
        return 'confidence-badge low';
      default:
        return 'confidence-badge unverified';
    }
  };

  const getUncertaintyBadgeClass = (unc: UncertaintyLevel) => {
    switch (unc) {
      case 'low':
        return 'uncertainty-badge low';
      case 'medium':
        return 'uncertainty-badge medium';
      case 'high':
        return 'uncertainty-badge high';
      default:
        return 'uncertainty-badge';
    }
  };

  const getPriorityBadgeClass = (pri: PriorityLevel) => {
    switch (pri) {
      case 'high':
        return 'priority-badge high';
      case 'medium':
        return 'priority-badge medium';
      case 'low':
        return 'priority-badge low';
      default:
        return 'priority-badge';
    }
  };

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-investigation-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-container investigation-modal-container">
        {/* Header */}
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="modal-title-icon">🔎</span>
            <div>
              <div className="modal-category">PERSISTED INVESTIGATION AUDIT RECORD</div>
              <h3 id="modal-investigation-title" className="modal-title">
                Investigation <span className="mono font-bold">{investigationId}</span>
              </h3>
            </div>
          </div>
          <div className="modal-header-actions" style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
            {data && (
              <>
                <button
                  type="button"
                  className="action-btn-copy"
                  onClick={handleCopyReport}
                  title="Copy complete investigation record to clipboard"
                >
                  {copiedSummary ? '✓ Copied' : '📋 Copy'}
                </button>

                <button
                  type="button"
                  className="action-btn-copy"
                  onClick={() => handleExport('markdown')}
                  disabled={exportingFormat !== null}
                  title="Download sanitized Markdown report with formula injection mitigation"
                >
                  {exportingFormat === 'markdown' ? '↻ Exporting...' : '📥 Markdown'}
                </button>

                <button
                  type="button"
                  className="action-btn-copy"
                  onClick={() => handleExport('json')}
                  disabled={exportingFormat !== null}
                  title="Download structured JSON report"
                >
                  {exportingFormat === 'json' ? '↻ Exporting...' : '📥 JSON'}
                </button>

                <button
                  type="button"
                  className="action-btn-copy"
                  onClick={() => handleExport('csv')}
                  disabled={exportingFormat !== null}
                  title="Download structured CSV report with formula injection mitigation"
                >
                  {exportingFormat === 'csv' ? '↻ Exporting...' : '📥 CSV'}
                </button>

                {onCreateCase && (
                  <button
                    type="button"
                    className="action-btn-copy"
                    style={{ borderColor: 'var(--accent-blue)', color: 'var(--accent-cyan)' }}
                    onClick={() => onCreateCase(data.alert_id, data.investigation_id, `Case for Alert ${data.alert_id} (Rule ${data.primary_rule_id})`)}
                    title="Open Case Management with this investigation linked"
                  >
                    📁 Create Case
                  </button>
                )}
              </>
            )}
            <button
              type="button"
              className="modal-close-btn"
              onClick={onClose}
              aria-label="Close detail modal"
            >
              ✕
            </button>
          </div>

        </div>

        {/* Modal Body */}
        <div className="modal-body">
          {/* Loading */}
          {loading && (
            <div className="state-container loading" style={{ padding: '3rem 1rem' }}>
              <div className="spinner" />
              <h4 className="state-title">Loading Investigation Record...</h4>
              <p className="state-description">Fetching structured findings, facts, and evidence snapshots from persistence.</p>
            </div>
          )}

          {/* Error */}
          {error && !loading && (
            <div className="state-container error" style={{ padding: '3rem 1rem' }}>
              <div className="state-icon">⚠️</div>
              <h4 className="state-title">Unable to Retrieve Investigation</h4>
              <p className="state-description">{error}</p>
              <button
                type="button"
                className="refresh-button"
                onClick={() => fetchDetail(investigationId)}
              >
                ↻ Retry
              </button>
            </div>
          )}

          {/* Data Presentation */}
          {data && !loading && !error && (
            <div className="inv-content">
              {/* Section 1: Overview & Lifecycle Banner */}
              <div className="inv-target-card">
                <div className="target-card-header">
                  <div className="target-title-wrap">
                    <span className="target-label">LIFECYCLE STATUS:</span>
                    <span className={`inv-history-status-badge ${data.status.toLowerCase()}`}>
                      {data.status.toUpperCase()}
                    </span>
                    <span className="run-seq-pill" title={`Sequential execution #${data.run_sequence} for this alert`}>
                      Run #{data.run_sequence}
                    </span>
                  </div>
                  <span className="target-time mono">
                    Created: {new Date(data.created_at).toLocaleString()}
                  </span>
                </div>
                <div className="target-meta-grid">
                  <div className="meta-item">
                    <span className="meta-label">Anchor Alert ID:</span>
                    <span className="meta-val mono" style={{ color: 'var(--accent-cyan)' }}>
                      {data.alert_id}
                    </span>
                  </div>
                  <div className="meta-item">
                    <span className="meta-label">Primary Rule:</span>
                    <span className="meta-val mono">
                      Rule {data.primary_rule_id}
                      {data.primary_rule_level !== null && data.primary_rule_level !== undefined && (
                        <span className="severity-badge-mini" style={{ marginLeft: '6px' }}>
                          LVL {data.primary_rule_level}
                        </span>
                      )}
                    </span>
                  </div>
                  <div className="meta-item">
                    <span className="meta-label">Monitored Agent:</span>
                    <span className="meta-val">{data.primary_agent_name || 'Unavailable'}</span>
                  </div>
                  <div className="meta-item">
                    <span className="meta-label">Execution Duration:</span>
                    <span className="meta-val mono">
                      {data.execution_duration_ms !== null && data.execution_duration_ms !== undefined
                        ? `${data.execution_duration_ms} ms`
                        : '--'}
                    </span>
                  </div>
                  <div className="meta-item">
                    <span className="meta-label">Correlation Window:</span>
                    <span className="meta-val mono">±{Math.floor(data.query_window_minutes / 2)}m ({data.query_window_minutes}m total)</span>
                  </div>
                  <div className="meta-item">
                    <span className="meta-label">Audit Actor ID:</span>
                    <span className="meta-val mono">{data.actor_id}</span>
                  </div>
                </div>
              </div>

              {/* Safe Failure Block if Failed */}
              {data.status.toLowerCase() === 'failed' && (
                <div className="inv-error-card" style={{ marginTop: '1rem' }}>
                  <div className="error-title">⚠️ Investigation Failed During Inference</div>
                  <div className="error-message">
                    <strong>Error Code:</strong> {data.error_code || 'INFERENCE_FAILURE'}
                    <br />
                    <strong>Details:</strong> {data.error_message || 'A safe failure was recorded by the persistence service.'}
                  </div>
                </div>
              )}

              {/* Running Status Notice */}
              {data.status.toLowerCase() === 'running' && (
                <div className="state-container loading" style={{ margin: '1rem 0', background: 'var(--bg-card)' }}>
                  <div className="spinner" />
                  <h4 className="state-title">Investigation Currently In Progress</h4>
                  <p className="state-description">Local Ollama LLM inference is currently active for this alert anchor.</p>
                </div>
              )}

              {/* Cancelled Notice */}
              {data.status.toLowerCase() === 'cancelled' && (
                <div className="advisory-banner" style={{ borderLeftColor: '#64748b', marginTop: '1rem' }}>
                  <span className="advisory-icon">⏹️</span>
                  <div className="advisory-text">
                    <strong>INVESTIGATION CANCELLED:</strong> This execution was cancelled by the analyst prior to completion.
                    {data.error_message && <div><em>Reason: {data.error_message}</em></div>}
                  </div>
                </div>
              )}

              {/* Section 2: AI Findings (when result is present) */}
              {data.result && (
                <>
                  {/* Advisory Disclaimer */}
                  <div className="advisory-banner" role="alert" style={{ marginTop: '1rem' }}>
                    <span className="advisory-icon">🛡️</span>
                    <div className="advisory-text">
                      <strong>ADVISORY AI ANALYSIS:</strong> {data.result.disclaimer}{' '}
                      <em>Wazuh alert logs remain the authoritative detection and forensic record.</em>
                    </div>
                  </div>

                  {/* Summary */}
                  <section className="inv-section">
                    <div className="section-header-row">
                      <h4 className="section-heading">Executive Findings Summary</h4>
                      <span className={getConfidenceBadgeClass(data.result.confidence_label)}>
                        CONFIDENCE: {data.result.confidence_label.toUpperCase()}
                      </span>
                    </div>
                    <div className="inv-summary-card">
                      <p className="inv-summary-text">{data.result.summary}</p>
                    </div>
                  </section>

                  {/* Observed Facts */}
                  <section className="inv-section">
                    <h4 className="section-heading">
                      Observed Facts ({data.result.observed_facts.length})
                    </h4>
                    <p className="section-subtext">
                      Factual statements grounded directly in evaluated evidence records. Click any evidence pill to jump to its snapshot.
                    </p>
                    {data.result.observed_facts.length === 0 ? (
                      <div className="empty-sub-card">No discrete observed facts recorded.</div>
                    ) : (
                      <div className="facts-list">
                        {data.result.observed_facts.map((fact) => (
                          <div key={fact.fact_id} className="fact-item">
                            <div className="fact-header">
                              <span className="item-id-tag">{fact.fact_id}</span>
                              <div className="citations-group">
                                <span className="citations-label">Source Evidence:</span>
                                {fact.cited_evidence_ids.map((id) => (
                                  <button
                                    key={id}
                                    type="button"
                                    className={`evidence-pill-btn ${activeEvidenceId === id ? 'active' : ''}`}
                                    onClick={() => scrollToEvidence(id)}
                                    title={`Jump to evidence record ${id}`}
                                  >
                                    {id}
                                  </button>
                                ))}
                              </div>
                            </div>
                            <div className="fact-statement">{fact.statement}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>

                  {/* Hypotheses */}
                  <section className="inv-section">
                    <h4 className="section-heading">
                      Investigative Hypotheses ({data.result.hypotheses.length})
                    </h4>
                    <p className="section-subtext">
                      Plausible inferences with calibrated uncertainty levels.
                    </p>
                    {data.result.hypotheses.length === 0 ? (
                      <div className="empty-sub-card">No investigative hypotheses recorded.</div>
                    ) : (
                      <div className="hypotheses-list">
                        {data.result.hypotheses.map((hyp) => (
                          <div key={hyp.hypothesis_id} className="hypothesis-item">
                            <div className="hyp-header">
                              <span className="item-id-tag">{hyp.hypothesis_id}</span>
                              <span className={getUncertaintyBadgeClass(hyp.uncertainty)}>
                                {hyp.uncertainty.toUpperCase()} UNCERTAINTY
                              </span>
                              {hyp.cited_evidence_ids.length > 0 && (
                                <div className="citations-group">
                                  <span className="citations-label">Cited:</span>
                                  {hyp.cited_evidence_ids.map((id) => (
                                    <button
                                      key={id}
                                      type="button"
                                      className={`evidence-pill-btn ${activeEvidenceId === id ? 'active' : ''}`}
                                      onClick={() => scrollToEvidence(id)}
                                      title={`Jump to cited evidence record ${id}`}
                                    >
                                      {id}
                                    </button>
                                  ))}
                                </div>
                              )}
                            </div>
                            <div className="hyp-statement">{hyp.statement}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>

                  {/* Recommended Read-Only Checks */}
                  <section className="inv-section">
                    <h4 className="section-heading">
                      Recommended Read-Only Defensive Checks ({data.result.recommended_checks.length})
                    </h4>
                    <p className="section-subtext">
                      Non-destructive verification steps strictly confined to read-only diagnostic actions.
                    </p>
                    {data.result.recommended_checks.length === 0 ? (
                      <div className="empty-sub-card">No specific defensive checks recommended.</div>
                    ) : (
                      <div className="checks-list">
                        {data.result.recommended_checks.map((check) => (
                          <div key={check.check_id} className="check-item">
                            <div className="check-header">
                              <span className="item-id-tag">{check.check_id}</span>
                              <span className={getPriorityBadgeClass(check.priority)}>
                                {check.priority.toUpperCase()} PRIORITY
                              </span>
                              <span className="readonly-badge">READ-ONLY DEFENSIVE</span>
                            </div>
                            <div className="check-desc">{check.description}</div>
                            {check.rationale && (
                              <div className="check-rationale">
                                <strong>Rationale:</strong> {check.rationale}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </section>
                </>
              )}

              {/* Analyst AI Evaluation & Feedback */}
              <section
                className="inv-section feedback-section"
                style={{
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '1.25rem',
                  marginTop: '1.5rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <h4 className="section-heading" style={{ margin: 0 }}>
                    🎯 Analyst AI Evaluation & Feedback
                  </h4>
                  {data.analyst_rating && (
                    <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      Recorded: {data.feedback_submitted_at || 'Saved'}
                    </span>
                  )}
                </div>
                <p className="section-subtext" style={{ marginBottom: '1rem' }}>
                  Provide feedback on the AI assistant's findings accuracy, reasoning, and completeness to evaluate performance over time.
                </p>

                <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    onClick={() => setFeedbackRating('helpful')}
                    style={{
                      padding: '0.5rem 1rem',
                      borderRadius: '6px',
                      border: feedbackRating === 'helpful' ? '1px solid #10b981' : '1px solid var(--border-subtle)',
                      background: feedbackRating === 'helpful' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                      color: feedbackRating === 'helpful' ? '#10b981' : 'var(--text-primary)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                    }}
                  >
                    👍 Helpful & Accurate
                  </button>

                  <button
                    type="button"
                    onClick={() => setFeedbackRating('incomplete')}
                    style={{
                      padding: '0.5rem 1rem',
                      borderRadius: '6px',
                      border: feedbackRating === 'incomplete' ? '1px solid #f59e0b' : '1px solid var(--border-subtle)',
                      background: feedbackRating === 'incomplete' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                      color: feedbackRating === 'incomplete' ? '#f59e0b' : 'var(--text-primary)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                    }}
                  >
                    ⚠️ Incomplete Context
                  </button>

                  <button
                    type="button"
                    onClick={() => setFeedbackRating('incorrect')}
                    style={{
                      padding: '0.5rem 1rem',
                      borderRadius: '6px',
                      border: feedbackRating === 'incorrect' ? '1px solid #ef4444' : '1px solid var(--border-subtle)',
                      background: feedbackRating === 'incorrect' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                      color: feedbackRating === 'incorrect' ? '#ef4444' : 'var(--text-primary)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                    }}
                  >
                    ❌ Incorrect / Hallucination
                  </button>
                </div>

                <div style={{ marginBottom: '1rem' }}>
                  <label htmlFor="feedback-notes" style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                    Analyst Commentary / Correction Notes:
                  </label>
                  <textarea
                    id="feedback-notes"
                    value={feedbackNotes}
                    onChange={(e) => setFeedbackNotes(e.target.value)}
                    placeholder="Enter investigative context, false positive notes, or correction rationale..."
                    rows={3}
                    style={{
                      width: '100%',
                      background: 'rgba(0, 0, 0, 0.3)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      color: 'var(--text-primary)',
                      padding: '0.6rem 0.75rem',
                      fontFamily: 'inherit',
                      fontSize: '0.875rem',
                      resize: 'vertical',
                      boxSizing: 'border-box',
                    }}
                  />
                </div>

                {feedbackSuccess && (
                  <div style={{ color: '#10b981', fontSize: '0.85rem', marginBottom: '0.75rem' }}>
                    ✓ {feedbackSuccess}
                  </div>
                )}
                {feedbackError && (
                  <div style={{ color: '#ef4444', fontSize: '0.85rem', marginBottom: '0.75rem' }}>
                    ⚠️ {feedbackError}
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    onClick={handleSubmitFeedback}
                    disabled={!feedbackRating || feedbackSubmitting}
                    style={{
                      padding: '0.5rem 1.25rem',
                      borderRadius: '6px',
                      border: 'none',
                      background: 'var(--accent-blue)',
                      color: '#ffffff',
                      fontWeight: 600,
                      cursor: (!feedbackRating || feedbackSubmitting) ? 'not-allowed' : 'pointer',
                      opacity: (!feedbackRating || feedbackSubmitting) ? 0.5 : 1,
                    }}
                  >
                    {feedbackSubmitting ? 'Recording Feedback...' : 'Save Feedback & Audit'}
                  </button>
                </div>
              </section>

              {/* Section 3: Minimized Forensic Evidence Snapshots */}
              <section className="inv-section">

                <h4 className="section-heading">
                  Forensic Evidence Snapshots ({data.evidence_items.length})
                </h4>
                <p className="section-subtext">
                  Minimized, sanitized evidence packages captured during investigation inference.
                </p>
                {data.evidence_items.length === 0 ? (
                  <div className="empty-sub-card">No evidence snapshots recorded for this investigation.</div>
                ) : (
                  <div className="evidence-cards-list">
                    {data.evidence_items.map((ev) => (
                      <div
                        key={ev.evidence_id}
                        id={`persisted-ev-card-${ev.evidence_id}`}
                        className={`evidence-card ${ev.is_primary ? 'is-primary-card' : ''} ${
                          activeEvidenceId === ev.evidence_id ? 'active-highlight' : ''
                        }`}
                      >
                        <div className="evidence-card-header">
                          <div className="evidence-id-tags">
                            <span className="evidence-badge-tag">{ev.evidence_id}</span>
                            {ev.is_primary ? (
                              <span className="role-pill primary">PRIMARY ALERT</span>
                            ) : (
                              <span className="role-pill related">RELATED EVENT</span>
                            )}
                          </div>
                          <span className="evidence-timestamp mono">{ev.event_timestamp}</span>
                        </div>
                        <div className="evidence-card-body">
                          <div className="evidence-rule-row">
                            <span className="evidence-rule-id mono">Rule {ev.rule_id}</span>
                            {ev.rule_level !== null && ev.rule_level !== undefined && (
                              <span className="severity-badge-mini">LVL {ev.rule_level}</span>
                            )}
                            <span className="evidence-rule-desc">
                              {ev.rule_description || 'No description provided'}
                            </span>
                          </div>
                          <div className="evidence-meta-grid">
                            <div className="meta-cell">
                              <span className="meta-label">Agent / Host:</span>
                              <span className="meta-val mono">{ev.agent_name || 'Unavailable'}</span>
                            </div>
                            <div className="meta-cell">
                              <span className="meta-label">Source IP:</span>
                              <span className="meta-val mono">{ev.source_ip || 'None'}</span>
                            </div>
                            <div className="meta-cell">
                              <span className="meta-label">Dest IP:</span>
                              <span className="meta-val mono">{ev.destination_ip || 'None'}</span>
                            </div>
                            <div className="meta-cell">
                              <span className="meta-label">User / Account:</span>
                              <span className="meta-val mono">{ev.username || 'None'}</span>
                            </div>
                          </div>
                          {ev.correlation_reason && (
                            <div className="evidence-correlation-row">
                              <span className="meta-label">Correlation Signal:</span>
                              <span className="correlation-reason-tag">{ev.correlation_reason}</span>
                            </div>
                          )}
                          {ev.correlation_qualifier && (
                            <div className="evidence-qualifier-banner">
                              ℹ️ <strong>Context Qualifier:</strong> {ev.correlation_qualifier}
                            </div>
                          )}
                          <div className="raw-ref-row">
                            <span className="meta-label">Index Reference:</span>
                            <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                              {ev.raw_evidence_ref}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {/* Audit Trail Note */}
              <div className="correlation-disclaimer" style={{ marginTop: '1.5rem', textAlign: 'center' }}>
                🔒 <em>Viewing this record is registered in the cryptographic hash-chained audit ledger. (Actor: {data.actor_id})</em>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer">
          <div className="modal-footer-left">
            {data && (
              <span className="text-muted mono" style={{ fontSize: '0.75rem' }}>
                Correlation ID: {data.request_id}
              </span>
            )}
          </div>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
