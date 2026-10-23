import React, { useEffect, useState } from 'react';
import type { NormalizedAlert } from '../types/api';

interface AlertDetailModalProps {
  alert: NormalizedAlert | null;
  onClose: () => void;
  onInvestigate?: (alert: NormalizedAlert) => void;
  onCreateCase?: (alert: NormalizedAlert) => void;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({
  alert,
  onClose,
  onInvestigate,
  onCreateCase,
}) => {

  const [copied, setCopied] = useState(false);

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

  const handleCopyId = async () => {
    try {
      await navigator.clipboard.writeText(alert.alert_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback ignore if clipboard denied
    }
  };

  const getSeverityLabel = (level?: number | null) => {
    if (level === undefined || level === null) return 'UNKNOWN';
    if (level >= 12) return 'CRITICAL';
    if (level >= 8) return 'HIGH';
    if (level >= 4) return 'MEDIUM';
    return 'LOW';
  };

  const getSeverityClass = (level?: number | null) => {
    if (level === undefined || level === null) return 'unknown';
    if (level >= 12) return 'critical';
    if (level >= 8) return 'high';
    if (level >= 4) return 'medium';
    return 'low';
  };

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className="modal-container" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <span className={`severity-badge ${getSeverityClass(alert.rule_level)}`}>
              LEVEL {alert.rule_level ?? '?'}: {getSeverityLabel(alert.rule_level)}
            </span>
            <h2 id="modal-title" className="modal-title">
              Alert Details
            </h2>
            <div className="modal-id-row">
              <span className="mono-subtle">{alert.alert_id}</span>
              <button
                type="button"
                className="btn-copy-id"
                onClick={handleCopyId}
                title="Copy unique Alert ID"
                aria-label="Copy alert ID"
              >
                {copied ? '✓ Copied' : 'Copy ID'}
              </button>
            </div>
          </div>
          <button type="button" className="btn-modal-close" onClick={onClose} aria-label="Close modal">
            ✕
          </button>
        </div>

        <div className="modal-body">
          {/* Rule Description Section */}
          <section className="modal-section">
            <h4 className="section-heading">Rule Description</h4>
            <div className="modal-description-box">
              {/* Strictly rendered as plain text to prevent XSS */}
              {alert.rule_description || 'No rule description provided.'}
            </div>
          </section>

          {/* Core Properties Grid */}
          <section className="modal-section">
            <h4 className="section-heading">Telemetry & Detection Metadata</h4>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="detail-label">Rule ID</span>
                <span className="detail-value mono">{alert.rule_id}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Source Authority</span>
                <span className="detail-value">{alert.source_system}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Event Timestamp (UTC)</span>
                <span className="detail-value mono">{alert.timestamp}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Retrieved At (UTC)</span>
                <span className="detail-value mono">{alert.retrieved_at}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Agent ID / Name</span>
                <span className="detail-value mono">
                  {alert.agent_name ? `${alert.agent_name} (${alert.agent_id ?? 'n/a'})` : (alert.agent_id ?? 'None')}
                </span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Manager Host</span>
                <span className="detail-value mono">{alert.host_name ?? 'None'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Source IP</span>
                <span className="detail-value mono">{alert.source_ip ?? 'None'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Destination IP</span>
                <span className="detail-value mono">{alert.destination_ip ?? 'None'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Account / Username</span>
                <span className="detail-value mono">{alert.username ?? 'None'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Event Classification</span>
                <span className="detail-value mono">{alert.event_type ?? 'None'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Decoder</span>
                <span className="detail-value mono">{alert.decoder_name ?? 'None'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Log Location</span>
                <span className="detail-value mono">{alert.location ?? 'None'}</span>
              </div>
            </div>
          </section>

          {/* Evidence Reference */}
          <section className="modal-section">
            <h4 className="section-heading">Evidence Reference</h4>
            <div className="evidence-ref-box">
              <code>{alert.raw_evidence_ref}</code>
            </div>
          </section>

          {/* Normalization Warnings */}
          {alert.normalization_warnings && alert.normalization_warnings.length > 0 && (
            <section className="modal-section">
              <h4 className="section-heading" style={{ color: 'var(--status-degraded)' }}>
                Normalization Notes
              </h4>
              <ul className="modal-warnings-list">
                {alert.normalization_warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <div className="modal-footer">
          <span className="footer-read-only-pill">READ-ONLY EVIDENCE RECORD</span>
          <div className="footer-actions-group">
            {onInvestigate && (
              <button
                type="button"
                className="btn-modal-investigate"
                onClick={() => {
                  onClose();
                  onInvestigate(alert);
                }}
                title="Run local AI investigation on this alert"
              >
                🤖 Investigate with AI
              </button>
            )}
            {onCreateCase && (

              <button
                type="button"
                className="btn-modal-dismiss"
                style={{ borderColor: 'var(--accent-blue)', color: 'var(--accent-cyan)' }}
                onClick={() => {
                  onClose();
                  onCreateCase(alert);
                }}
                title="Open a tracked incident case for this alert"
              >
                📁 Open Case
              </button>
            )}
            <button type="button" className="btn-modal-dismiss" onClick={onClose}>
              Close
            </button>
          </div>

        </div>
      </div>
    </div>
  );
};
