import React, { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import type { Case, CasePriority, CaseStatus } from '../types/api';

interface CaseModalProps {
  caseItem: Case | null;
  initialValues?: { alertId?: string; investigationId?: string; title?: string };
  isOpen: boolean;
  onClose: () => void;
  onSaved: (caseItem: Case) => void;
  onDeleted?: (caseId: string) => void;
  onOpenInvestigation?: (investigationId: string) => void;
}

export const CaseModal: React.FC<CaseModalProps> = ({
  caseItem,
  initialValues,
  isOpen,
  onClose,
  onSaved,
  onDeleted,
  onOpenInvestigation,
}) => {
  const isCreate = !caseItem;

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [status, setStatus] = useState<CaseStatus>('open');
  const [priority, setPriority] = useState<CasePriority>('medium');
  const [assignee, setAssignee] = useState('');
  const [alertId, setAlertId] = useState('');
  const [investigationId, setInvestigationId] = useState('');
  const [analystNotes, setAnalystNotes] = useState('');

  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (caseItem) {
      setTitle(caseItem.title || '');
      setDescription(caseItem.description || '');
      setStatus(caseItem.status);
      setPriority(caseItem.priority);
      setAssignee(caseItem.assignee || '');
      setAlertId(caseItem.alert_id || '');
      setInvestigationId(caseItem.investigation_id || '');
      setAnalystNotes(caseItem.analyst_notes || '');
    } else {
      setTitle(initialValues?.title || '');
      setDescription('');
      setStatus('open');
      setPriority('medium');
      setAssignee('');
      setAlertId(initialValues?.alertId || '');
      setInvestigationId(initialValues?.investigationId || '');
      setAnalystNotes('');
    }
    setError(null);
  }, [caseItem, initialValues, isOpen]);

  if (!isOpen) return null;

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      setError('Case title is required.');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      if (isCreate) {
        const created = await apiClient.createCase({
          title: title.trim(),
          description: description.trim() || null,
          priority,
          assignee: assignee.trim() || null,
          alert_id: alertId.trim() || null,
          investigation_id: investigationId.trim() || null,
          analyst_notes: analystNotes.trim() || null,
        });
        onSaved(created);
      } else {
        const updated = await apiClient.updateCase(caseItem.case_id, {
          title: title.trim(),
          description: description.trim() || null,
          status,
          priority,
          assignee: assignee.trim() || null,
          analyst_notes: analystNotes.trim() || null,
        });
        onSaved(updated);
      }
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!caseItem) return;
    if (!window.confirm(`Are you sure you want to delete case ${caseItem.case_id}?`)) {
      return;
    }

    setDeleting(true);
    setError(null);
    try {
      await apiClient.deleteCase(caseItem.case_id);
      if (onDeleted) onDeleted(caseItem.case_id);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="case-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-container" style={{ maxWidth: '720px' }}>
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="modal-title-icon">📁</span>
            <div>
              <div className="modal-category">
                {isCreate ? 'NEW INVESTIGATION CASE' : 'CASE DETAILS & WORKFLOW'}
              </div>
              <h3 id="case-modal-title" className="modal-title">
                {isCreate ? 'Open Security Incident Case' : caseItem.case_id}
              </h3>
            </div>
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose}>
            ✕
          </button>
        </div>

        <form onSubmit={handleSave}>
          <div className="modal-body" style={{ maxHeight: 'calc(80vh - 120px)', overflowY: 'auto' }}>
            {error && (
              <div
                style={{
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid #ef4444',
                  color: '#ef4444',
                  padding: '0.75rem',
                  borderRadius: '6px',
                  marginBottom: '1rem',
                  fontSize: '0.875rem',
                }}
              >
                ⚠️ {error}
              </div>
            )}

            <div style={{ marginBottom: '1rem' }}>
              <label
                htmlFor="case-title"
                style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}
              >
                Case Title *
              </label>
              <input
                id="case-title"
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Credential stuffing activity targeting agent-01"
                required
                style={{
                  width: '100%',
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  padding: '0.6rem 0.75rem',
                  fontSize: '0.9rem',
                  boxSizing: 'border-box',
                }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
              <div>
                <label
                  htmlFor="case-status"
                  style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}
                >
                  Status
                </label>
                <select
                  id="case-status"
                  value={status}
                  onChange={(e) => setStatus(e.target.value as CaseStatus)}
                  disabled={isCreate}
                  style={{
                    width: '100%',
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    color: 'var(--text-primary)',
                    padding: '0.6rem 0.75rem',
                    fontSize: '0.9rem',
                    boxSizing: 'border-box',
                  }}
                >
                  <option value="open">Open</option>
                  <option value="in_progress">In Progress</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                </select>
              </div>

              <div>
                <label
                  htmlFor="case-priority"
                  style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}
                >
                  Priority
                </label>
                <select
                  id="case-priority"
                  value={priority}
                  onChange={(e) => setPriority(e.target.value as CasePriority)}
                  style={{
                    width: '100%',
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    color: 'var(--text-primary)',
                    padding: '0.6rem 0.75rem',
                    fontSize: '0.9rem',
                    boxSizing: 'border-box',
                  }}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
              <div>
                <label
                  htmlFor="case-assignee"
                  style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}
                >
                  Assignee
                </label>
                <input
                  id="case-assignee"
                  type="text"
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  placeholder="e.g. secops_lead, analyst_1"
                  style={{
                    width: '100%',
                    background: 'rgba(0, 0, 0, 0.3)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    color: 'var(--text-primary)',
                    padding: '0.6rem 0.75rem',
                    fontSize: '0.9rem',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              <div>
                <label
                  htmlFor="case-alert-id"
                  style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}
                >
                  Linked Wazuh Alert ID
                </label>
                <input
                  id="case-alert-id"
                  type="text"
                  value={alertId}
                  onChange={(e) => setAlertId(e.target.value)}
                  placeholder="Optional alert ID"
                  disabled={!isCreate}
                  className="mono"
                  style={{
                    width: '100%',
                    background: 'rgba(0, 0, 0, 0.3)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    color: 'var(--text-primary)',
                    padding: '0.6rem 0.75rem',
                    fontSize: '0.85rem',
                    boxSizing: 'border-box',
                  }}
                />
              </div>
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                <label
                  htmlFor="case-inv-id"
                  style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}
                >
                  Linked Investigation ID
                </label>
                {investigationId && onOpenInvestigation && (
                  <button
                    type="button"
                    onClick={() => onOpenInvestigation(investigationId)}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--accent-cyan)',
                      fontSize: '0.8rem',
                      cursor: 'pointer',
                      textDecoration: 'underline',
                    }}
                  >
                    View Investigation Findings ↗
                  </button>
                )}
              </div>
              <input
                id="case-inv-id"
                type="text"
                value={investigationId}
                onChange={(e) => setInvestigationId(e.target.value)}
                placeholder="Optional investigation UUID"
                disabled={!isCreate}
                className="mono"
                style={{
                  width: '100%',
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  padding: '0.6rem 0.75rem',
                  fontSize: '0.85rem',
                  boxSizing: 'border-box',
                }}
              />
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label
                htmlFor="case-desc"
                style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}
              >
                Case Description
              </label>
              <textarea
                id="case-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Incident summary, affected assets, scope of compromise..."
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

            <div style={{ marginBottom: '1rem' }}>
              <label
                htmlFor="case-notes"
                style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}
              >
                Analyst Investigation Notes & Timeline
              </label>
              <textarea
                id="case-notes"
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                placeholder="Track investigation progress, evidence verified, manual containment steps..."
                rows={4}
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

            {!isCreate && (
              <div
                style={{
                  display: 'flex',
                  gap: '1.5rem',
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)',
                  borderTop: '1px solid var(--border-subtle)',
                  paddingTop: '0.75rem',
                }}
              >
                <span>Created: {new Date(caseItem.created_at).toLocaleString()}</span>
                <span>Updated: {new Date(caseItem.updated_at).toLocaleString()}</span>
                {caseItem.closed_at && (
                  <span style={{ color: '#10b981' }}>
                    Closed: {new Date(caseItem.closed_at).toLocaleString()}
                  </span>
                )}
              </div>
            )}
          </div>

          <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
            <div>
              {!isCreate && onDeleted && (
                <button
                  type="button"
                  onClick={handleDelete}
                  disabled={deleting || saving}
                  style={{
                    padding: '0.5rem 1rem',
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid #ef4444',
                    color: '#ef4444',
                    borderRadius: '6px',
                    cursor: deleting ? 'not-allowed' : 'pointer',
                  }}
                >
                  {deleting ? 'Deleting...' : 'Delete Case'}
                </button>
              )}
            </div>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button type="button" className="btn-secondary" onClick={onClose} disabled={saving}>
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                style={{
                  padding: '0.5rem 1.25rem',
                  background: 'var(--accent-blue)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  fontWeight: 600,
                  cursor: saving ? 'not-allowed' : 'pointer',
                }}
              >
                {saving ? 'Saving...' : isCreate ? 'Create Case' : 'Save Changes'}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
