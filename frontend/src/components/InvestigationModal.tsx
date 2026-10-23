import React, { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import type { InvestigationResult, NormalizedAlert } from '../types/api';

interface InvestigationModalProps {
  alert: NormalizedAlert | null;
  result: InvestigationResult | null;
  loading: boolean;
  error: string | null;
  onClose: () => void;
  onRetry: () => void;
  onCancel?: () => void;
  onCreateCase?: (alertId?: string, investigationId?: string, title?: string) => void;
}

export const InvestigationModal: React.FC<InvestigationModalProps> = ({
  alert,
  result,
  loading,
  error,
  onClose,
  onRetry,
  onCancel,
  onCreateCase,
}) => {
  const [copiedSummary, setCopiedSummary] = useState(false);
  const [copiedMarkdown, setCopiedMarkdown] = useState(false);
  const [activeEvidenceId, setActiveEvidenceId] = useState<string | null>(null);
  const [exportingFormat, setExportingFormat] = useState<'markdown' | 'json' | null>(null);


  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!alert) return null;

  const scrollToEvidence = (evidenceId: string) => {
    setActiveEvidenceId(evidenceId);
    const element = document.getElementById(`evidence-card-${evidenceId}`);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const handleCopySummary = async () => {
    if (!result) return;
    const reportText = `[AI INVESTIGATION ADVISORY - ${result.investigation_id}]\n` +
      `Target Alert: ${result.alert_id}\n` +
      `Model: ${result.model_name}:${result.model_tag}\n` +
      `Status: ${result.status}\n` +
      `Confidence: ${result.confidence_label}\n\n` +
      `SUMMARY:\n${result.summary}\n\n` +
      `OBSERVED FACTS:\n` +
      result.observed_facts.map(f => `- [${f.cited_evidence_ids.join(', ')}] ${f.statement}`).join('\n') +
      `\n\nHYPOTHESES:\n` +
      result.hypotheses.map(h => `- (${h.uncertainty.toUpperCase()} uncertainty) [${h.cited_evidence_ids.join(', ')}] ${h.statement}`).join('\n') +
      `\n\nRECOMMENDED READ-ONLY CHECKS:\n` +
      result.recommended_checks.map(c => `- [Priority: ${c.priority.toUpperCase()}] ${c.description} (Rationale: ${c.rationale})`).join('\n') +
      `\n\nDISCLAIMER:\n${result.disclaimer}`;

    try {
      await navigator.clipboard.writeText(reportText);
      setCopiedSummary(true);
      setTimeout(() => setCopiedSummary(false), 2000);
    } catch {
      // Ignore if clipboard denied
    }
  };

  const handleExport = async (format: 'markdown' | 'json') => {
    if (!result) return;
    setExportingFormat(format);
    try {
      const blob = await apiClient.exportInvestigationReport(result.investigation_id, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `investigation_${result.investigation_id}.${format === 'json' ? 'json' : 'md'}`;
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


  const handleCopyMarkdown = async () => {
    if (!result) return;
    const factsMarkdown = result.observed_facts.length > 0
      ? result.observed_facts.map(f => `- **[${f.cited_evidence_ids.join(', ')}]** ${f.statement}`).join('\n')
      : '_No discrete observed facts extracted._';

    const hypothesesMarkdown = result.hypotheses.length > 0
      ? result.hypotheses.map(h => `- **[${h.cited_evidence_ids.join(', ')}]** (${h.uncertainty.toUpperCase()} Uncertainty): ${h.statement}`).join('\n')
      : '_No investigative hypotheses provided._';

    const checksMarkdown = result.recommended_checks.length > 0
      ? result.recommended_checks.map(c => `- [ ] **[Priority: ${c.priority.toUpperCase()}]** ${c.description} — _Rationale: ${c.rationale}_`).join('\n')
      : '_No additional checks recommended._';

    const limitationsMarkdown = result.limitations.length > 0
      ? result.limitations.map(l => `- ${l}`).join('\n')
      : '_No explicit limitations noted._';

    let evidenceMarkdown = '_No evidence records included in package._';
    if (result.evidence_items && result.evidence_items.length > 0) {
      evidenceMarkdown = '| Evidence ID | Role | Timestamp (UTC) | Rule ID & Title | Agent / Host | Network & User | Correlation Signal |\n' +
        '| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n' +
        result.evidence_items.map(ev => {
          const role = ev.is_primary ? 'PRIMARY' : 'RELATED';
          const network = `Src: ${ev.source_ip || '-'} | Dst: ${ev.destination_ip || '-'} | User: ${ev.username || '-'}`;
          const signal = ev.correlation_reason ? `${ev.correlation_reason} (${ev.correlation_qualifier || 'standard'})` : 'Primary Anchor';
          return `| ${ev.evidence_id} | ${role} | ${ev.event_timestamp} | ${ev.rule_id}: ${ev.rule_description.replace(/\|/g, '-')} | ${ev.agent_name || '-'} | ${network} | ${signal} |`;
        }).join('\n');
    }

    const fullMarkdown = `# Wazuh + Ollama SIEM — AI Investigation Report\n\n` +
      `**Investigation ID:** \`${result.investigation_id}\`  \n` +
      `**Target Alert ID:** \`${result.alert_id}\`  \n` +
      `**Generated At:** ${result.generated_at} (UTC)  \n` +
      `**Inference Model:** \`${result.model_name}:${result.model_tag}\`  \n` +
      `**Validation Status:** **${result.status.toUpperCase()}**  \n` +
      `**Assigned Confidence:** **${result.confidence_label.toUpperCase()}**  \n\n` +
      `---\n\n` +
      `> 🛡️ **ADVISORY NOTICE:** ${result.disclaimer}\n` +
      `> _Wazuh alert logs remain the authoritative detection and forensic record. AI output is advisory analysis._\n\n` +
      `---\n\n` +
      `## 1. Executive Findings Summary\n\n${result.summary}\n\n` +
      `## 2. Observed Facts\n\n${factsMarkdown}\n\n` +
      `## 3. Investigative Hypotheses\n\n${hypothesesMarkdown}\n\n` +
      `## 4. Authoritative Evidence Package (Provenance)\n\n${evidenceMarkdown}\n\n` +
      `## 5. Recommended Read-Only Investigative Checks\n\n${checksMarkdown}\n\n` +
      `## 6. Investigation Bounds & Telemetry Gaps\n\n${limitationsMarkdown}\n`;

    try {
      await navigator.clipboard.writeText(fullMarkdown);
      setCopiedMarkdown(true);
      setTimeout(() => setCopiedMarkdown(false), 2000);
    } catch {
      // Ignore if clipboard denied
    }
  };

  const getConfidenceBadgeClass = (conf?: string) => {
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

  const getUncertaintyBadgeClass = (level?: string) => {
    switch (level) {
      case 'low':
        return 'uncertainty-badge low';
      case 'medium':
        return 'uncertainty-badge medium';
      case 'high':
        return 'uncertainty-badge high';
      default:
        return 'uncertainty-badge medium';
    }
  };

  const getPriorityBadgeClass = (p?: string) => {
    switch (p) {
      case 'high':
        return 'priority-badge high';
      case 'medium':
        return 'priority-badge medium';
      default:
        return 'priority-badge low';
    }
  };

  return (
    <div
      className="modal-backdrop"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="investigation-modal-title"
    >
      <div className="modal-container investigation-modal" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="modal-header">
          <div className="modal-title-group">
            <div className="inv-header-meta">
              <span className="detection-authority-tag">DETECTION OF RECORD: WAZUH / OPENSEARCH</span>
              <span className="ai-advisor-tag">🤖 ADVISORY AI INVESTIGATION</span>
              {result && (
                <span className={`status-pill ${result.status === 'valid' ? 'pill-valid' : 'pill-warning'}`}>
                  {result.status.toUpperCase()}
                </span>
              )}
            </div>
            <h2 id="investigation-modal-title" className="modal-title">
              Alert Investigation Report
            </h2>
            <div className="modal-id-row">
              <span className="mono-subtle">Target Alert: {alert.alert_id}</span>
              {result && (
                <span className="mono-subtle" style={{ marginLeft: '12px' }}>
                  Model: {result.model_name}:{result.model_tag}
                </span>
              )}
            </div>
          </div>
          <button type="button" className="btn-modal-close" onClick={onClose} aria-label="Close modal">
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body">
          {/* Loading State */}
          {loading && (
            <div className="inv-state-box loading">
              <div className="spinner" role="status" aria-label="Loading investigation"></div>
              <h3 className="inv-state-title">Running Evidence-Grounded AI Investigation</h3>
              <p className="inv-state-desc">
                Retrieving and sanitizing Wazuh security logs, compiling bounded evidence context, and performing local
                Ollama analysis with schema validation...
              </p>
              {onCancel && (
                <button type="button" className="btn-cancel-inference" onClick={onCancel}>
                  Cancel Request
                </button>
              )}
            </div>
          )}

          {/* Error State */}
          {!loading && error && (
            <div className="inv-state-box error">
              <div className="state-icon">⚠️</div>
              <h3 className="inv-state-title">Investigation Request Failed</h3>
              <div className="inv-error-message">{error}</div>
              <p className="inv-state-desc">
                {error.includes('unavailable') || error.includes('offline')
                  ? 'Local Ollama service or the target AI model is currently offline. Existing alert browsing remains fully functional.'
                  : 'The backend encountered an error executing inference or validating the response structure.'}
              </p>
              <div className="inv-error-actions">
                <button type="button" className="btn-retry-inference" onClick={onRetry}>
                  ↻ Retry Investigation
                </button>
                <button type="button" className="btn-modal-dismiss" onClick={onClose}>
                  Dismiss
                </button>
              </div>
            </div>
          )}

          {/* Success Result State */}
          {!loading && !error && result && (
            <div className="inv-content">
              {/* Mandatory Advisory Notice */}
              <div className="advisory-banner" role="alert">
                <span className="advisory-icon">🛡️</span>
                <div className="advisory-text">
                  <strong>ADVISORY AI ANALYSIS:</strong> {result.disclaimer}{' '}
                  <em>Wazuh alert logs remain the authoritative detection and forensic record.</em>
                </div>
              </div>

              {/* Related Events Context & Correlation Metadata */}
              {result.related_events_summary && (
                <div className="correlation-context-card">
                  <div className="correlation-header">
                    <span className="correlation-title">🔗 RELATED-EVENT CONTEXT ENRICHMENT</span>
                    <span className={`correlation-pill status-${result.related_events_summary.correlation_status}`}>
                      {result.related_events_summary.correlation_status === 'enriched' && 'ENRICHED'}
                      {result.related_events_summary.correlation_status === 'partial' && 'PARTIAL (TRUNCATED / WEAK)'}
                      {result.related_events_summary.correlation_status === 'no_related_events_found' && 'NO RELATED EVENTS FOUND'}
                      {result.related_events_summary.correlation_status === 'no_matches' && 'NO MATCHES'}
                      {result.related_events_summary.correlation_status === 'failed_fallback_single_alert' && 'SINGLE-ALERT FALLBACK'}
                      {result.related_events_summary.correlation_status === 'skipped_not_requested' && 'NOT REQUESTED'}
                    </span>
                  </div>
                  <div className="correlation-stats-row">
                    <span className="stat-item">
                      <strong>Window:</strong> ±{Math.floor(result.related_events_summary.window_minutes / 2)}m ({result.related_events_summary.window_minutes}m total)
                    </span>
                    <span className="stat-item">
                      <strong>Retrieved:</strong> {result.related_events_summary.retrieved_count}
                    </span>
                    <span className="stat-item">
                      <strong>Included:</strong> {result.related_events_summary.included_count}
                    </span>
                    {result.related_events_summary.truncated_count > 0 && (
                      <span className="stat-item truncation-highlight">
                        ⚠️ <strong>Truncated:</strong> {result.related_events_summary.truncated_count} events
                      </span>
                    )}
                  </div>
                  {result.related_events_summary.unsupported_signals && result.related_events_summary.unsupported_signals.length > 0 && (
                    <div className="correlation-unsupported-note" style={{ fontSize: '0.75rem', color: '#f59e0b', marginTop: '6px' }}>
                      ⚠️ <strong>Telemetry Notice:</strong> [{result.related_events_summary.unsupported_signals.join(', ')}] are not represented in the normalized alert evidence package for this investigation (process correlation is not available in this evidence view).
                    </div>
                  )}
                  <div className="correlation-disclaimer" style={{ marginTop: '6px' }}>
                    ℹ️ <em>Correlation context provides observational proximity. Correlation does not prove causation, attacker progression, or compromise.</em>
                  </div>
                </div>
              )}

              {/* High-level Narrative Summary */}
              <section className="inv-section">
                <div className="section-header-row">
                  <h4 className="section-heading">Executive Findings Summary</h4>
                  <span className={getConfidenceBadgeClass(result.confidence_label)}>
                    CONFIDENCE: {result.confidence_label.toUpperCase()}
                  </span>
                </div>
                <div className="inv-summary-card">
                  <p className="inv-summary-text">{result.summary}</p>
                </div>
              </section>

              {/* Observed Facts */}
              <section className="inv-section">
                <h4 className="section-heading">
                  Observed Facts ({result.observed_facts.length})
                </h4>
                <p className="section-subtext">
                  Factual statements directly corroborating one or more supplied evidence records. Click any evidence pill to jump to its source record.
                </p>
                {result.observed_facts.length === 0 ? (
                  <div className="empty-sub-card">No discrete observed facts extracted.</div>
                ) : (
                  <div className="facts-list">
                    {result.observed_facts.map((fact) => (
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
                                title={`Jump to supporting evidence record ${id}`}
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
                  Investigative Hypotheses ({result.hypotheses.length})
                </h4>
                <p className="section-subtext">
                  Plausible inferences and interpretations with explicit uncertainty rankings. Click any evidence pill to jump to its source record.
                </p>
                {result.hypotheses.length === 0 ? (
                  <div className="empty-sub-card">No investigative hypotheses provided.</div>
                ) : (
                  <div className="hypotheses-list">
                    {result.hypotheses.map((hyp) => (
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

              {/* Authoritative Evidence Provenance Package */}
              {result.evidence_items && result.evidence_items.length > 0 && (
                <section className="inv-section" id="evidence-provenance-section">
                  <div className="section-header-row">
                    <h4 className="section-heading">
                      Authoritative Evidence Package ({result.evidence_items.length} Records)
                    </h4>
                    <span className="footer-read-only-pill">STABLE PROVENANCE</span>
                  </div>
                  <p className="section-subtext">
                    Authoritative SIEM evidence evaluated during this investigation. Primary alert remains EV-01.
                  </p>
                  <div className="evidence-provenance-list">
                    {result.evidence_items.map((ev) => (
                      <div
                        key={ev.evidence_id}
                        id={`evidence-card-${ev.evidence_id}`}
                        className={`evidence-provenance-card ${ev.is_primary ? 'is-primary' : 'is-related'} ${
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
                            <span className="evidence-rule-desc">{ev.rule_description || 'No description provided'}</span>
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
                              {ev.correlation_qualifier === 'network_association_subject_to_nat_dhcp_or_shared_egress' && (
                                <span>⚠️ <strong>Network Attribute:</strong> Shared IP address is subject to NAT, DHCP pools, or proxies; does not prove a shared host or attacker.</span>
                              )}
                              {ev.correlation_qualifier === 'generic_account_name_unverified_identity' && (
                                <span>⚠️ <strong>Generic Account:</strong> Matching generic username across hosts does not verify human identity or lateral movement.</span>
                              )}
                              {ev.correlation_qualifier === 'temporal_proximity_only_non_causal' && (
                                <span>ℹ️ <strong>Temporal Signal:</strong> Temporal proximity only; non-causal association.</span>
                              )}
                              {ev.correlation_qualifier === 'reporting_endpoint_context_only' && (
                                <span>ℹ️ <strong>Endpoint Context:</strong> Activity co-located on the same monitored endpoint.</span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {/* Recommended Read-Only Checks */}
              <section className="inv-section">
                <h4 className="section-heading">
                  Recommended Investigative Checks ({result.recommended_checks.length})
                </h4>
                <p className="section-subtext">
                  Read-only actions intended for a human analyst to verify or rule out activity.
                </p>
                {result.recommended_checks.length === 0 ? (
                  <div className="empty-sub-card">No additional checks recommended.</div>
                ) : (
                  <div className="checks-list">
                    {result.recommended_checks.map((check) => (
                      <div key={check.check_id} className="check-item">
                        <div className="check-header">
                          <span className="item-id-tag">{check.check_id}</span>
                          <span className="read-only-check-pill">READ-ONLY CHECK</span>
                          <span className={getPriorityBadgeClass(check.priority)}>
                            PRIORITY: {check.priority.toUpperCase()}
                          </span>
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

              {/* Limitations & Unsupported Warnings */}
              <section className="inv-section">
                <h4 className="section-heading">Investigation Bounds & Context Gaps</h4>
                {result.unsupported_citation_warnings && result.unsupported_citation_warnings.length > 0 && (
                  <div className="warning-box">
                    <strong>⚠️ Grounding &amp; Citation Warnings:</strong>
                    <ul className="modal-warnings-list" style={{ marginTop: '6px' }}>
                      {result.unsupported_citation_warnings.map((w, idx) => (
                        <li key={idx}>{w}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.limitations.length > 0 ? (
                  <ul className="limitations-list">
                    {result.limitations.map((lim, idx) => (
                      <li key={idx}>{lim}</li>
                    ))}
                  </ul>
                ) : (
                  <div className="empty-sub-card">No explicit limitations noted.</div>
                )}
              </section>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="modal-footer">
          {result && (
            <div className="modal-footer-actions" style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn-copy-markdown"
                onClick={handleCopyMarkdown}
                title="Copy complete structured Markdown investigation report"
              >
                {copiedMarkdown ? '✓ Copied MD' : '📄 Copy Report'}
              </button>
              <button
                type="button"
                className="btn-copy-summary"
                onClick={handleCopySummary}
                title="Copy narrative summary to clipboard"
              >
                {copiedSummary ? '✓ Copied Summary' : '📋 Copy Summary'}
              </button>
              <button
                type="button"
                className="btn-copy-summary"
                onClick={() => handleExport('markdown')}
                disabled={exportingFormat !== null}
                title="Download sanitized Markdown report"
              >

                {exportingFormat === 'markdown' ? '↻ Exporting...' : '📥 Markdown'}
              </button>
              <button
                type="button"
                className="btn-copy-summary"
                onClick={() => handleExport('json')}
                disabled={exportingFormat !== null}
                title="Download structured JSON report"
              >
                {exportingFormat === 'json' ? '↻ Exporting...' : '📥 JSON'}
              </button>
              {onCreateCase && (
                <button
                  type="button"
                  className="btn-copy-summary"
                  style={{ borderColor: 'var(--accent-blue)', color: 'var(--accent-cyan)' }}
                  onClick={() => {
                    onClose();
                    onCreateCase(alert.alert_id, result.investigation_id, `Case for Alert ${alert.alert_id} (Rule ${alert.rule_id})`);
                  }}
                  title="Open a tracked incident case for this alert"
                >
                  📁 Open Case
                </button>
              )}
            </div>
          )}
          <button type="button" className="btn-modal-dismiss" onClick={onClose}>
            Close
          </button>

        </div>
      </div>
    </div>
  );
};
