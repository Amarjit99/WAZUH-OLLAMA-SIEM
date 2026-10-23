import React, { useState, useEffect, useCallback } from 'react';
import { apiClient } from '../api/client';
import type {
  ContainmentExecutionResponse,
  ProposedContainmentAction,
} from '../types/api';

interface ContainmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetInfo?: {
    sourceIp?: string;
    agentName?: string;
    agentId?: string;
    alertId?: string;
    investigationId?: string;
  };
}

export const ContainmentModal: React.FC<ContainmentModalProps> = ({
  isOpen,
  onClose,
  targetInfo,
}) => {
  const [loading, setLoading] = useState<boolean>(false);
  const [proposedActions, setProposedActions] = useState<ProposedContainmentAction[]>([]);
  const [selectedActionIndex, setSelectedActionIndex] = useState<number>(0);
  const [analystId, setAnalystId] = useState<string>('soc-analyst');
  const [rationale, setRationale] = useState<string>('');
  const [analystApproval, setAnalystApproval] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [executionResult, setExecutionResult] = useState<ContainmentExecutionResponse | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const fetchProposals = useCallback(async () => {
    if (!targetInfo) return;
    setLoading(true);
    setError(null);
    setExecutionResult(null);
    setAnalystApproval(false);
    try {
      const res = await apiClient.proposeContainment({
        source_ip: targetInfo.sourceIp,
        agent_name: targetInfo.agentName,
        agent_id: targetInfo.agentId,
        alert_id: targetInfo.alertId,
        investigation_id: targetInfo.investigationId,
      });
      setProposedActions(res.proposed_actions || []);
      setSelectedActionIndex(0);
      if (res.proposed_actions && res.proposed_actions.length > 0) {
        setRationale(res.proposed_actions[0].rationale || '');
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to generate containment playbooks');
    } finally {
      setLoading(false);
    }
  }, [targetInfo]);

  useEffect(() => {
    if (isOpen) {
      fetchProposals();
    }
  }, [isOpen, fetchProposals]);

  if (!isOpen) return null;

  const currentAction = proposedActions[selectedActionIndex] || null;

  const handleCopyCommand = (cmd: string, idx: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleAuthorize = async () => {
    if (!currentAction) return;
    if (!analystApproval) {
      setError('You must check the authorization confirmation box.');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const res = await apiClient.executeContainment({
        action_type: currentAction.action_type,
        target: currentAction.target,
        rationale: rationale.trim() || currentAction.rationale,
        analyst_id: analystId.trim() || 'soc-analyst',
        analyst_approval: true,
        alert_id: targetInfo?.alertId,
        investigation_id: targetInfo?.investigationId,
      });
      setExecutionResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Containment authorization failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-2">
            <span className="text-xl">🛡️</span>
            <div>
              <h2 className="text-base font-bold text-white">Analyst Active Response & Containment</h2>
              <p className="text-xs text-slate-400">Human-in-the-Loop Mitigation Gate</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition p-1 text-lg leading-none"
            aria-label="Close containment dialog"
          >
            ✕
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-5 flex-1">
          {loading ? (
            <div className="py-12 text-center text-slate-400 text-sm">
              Formulating platform containment playbooks...
            </div>
          ) : proposedActions.length === 0 ? (
            <div className="py-8 text-center text-slate-400 text-sm space-y-2">
              <div>No automated containment targets identified from this event.</div>
              <div className="text-xs text-slate-500">
                Ensure a valid external source IP or agent identifier is associated with the alert.
              </div>
            </div>
          ) : (
            <>
              {/* Proposal selector tabs if multiple */}
              {proposedActions.length > 1 && (
                <div className="flex gap-2 border-b border-slate-800 pb-2">
                  {proposedActions.map((act, idx) => (
                    <button
                      key={idx}
                      onClick={() => {
                        setSelectedActionIndex(idx);
                        setRationale(act.rationale);
                      }}
                      className={`px-3 py-1.5 text-xs font-semibold rounded transition ${
                        selectedActionIndex === idx
                          ? 'bg-cyan-600 text-white'
                          : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                      }`}
                    >
                      {act.action_type.replace('_', ' ')}: {act.target}
                    </button>
                  ))}
                </div>
              )}

              {currentAction && (
                <div className="space-y-4">
                  {/* Action Overview Card */}
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono uppercase text-cyan-400 font-bold">
                        {currentAction.action_type}
                      </span>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          currentAction.risk_level === 'LOW'
                            ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                            : currentAction.risk_level === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-400 border-amber-800'
                            : 'bg-rose-950 text-rose-400 border-rose-800'
                        }`}
                      >
                        RISK: {currentAction.risk_level}
                      </span>
                    </div>
                    <div className="text-sm font-semibold text-white">
                      Target Entity: <span className="font-mono text-cyan-300">{currentAction.target}</span>
                    </div>
                    <div className="text-xs text-slate-400">{currentAction.rationale}</div>
                  </div>

                  {/* Generated Commands by Platform */}
                  <div className="space-y-2">
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Generated Defense Commands & Rules
                    </div>
                    <div className="space-y-2">
                      {currentAction.commands.map((cmd, idx) => (
                        <div
                          key={idx}
                          className="bg-slate-950 p-3 rounded border border-slate-800 text-xs space-y-1.5"
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-mono text-slate-400 font-bold uppercase">
                              {cmd.platform.replace('_', ' ')}
                            </span>
                            <button
                              onClick={() => handleCopyCommand(cmd.command, idx)}
                              className="text-[11px] text-cyan-400 hover:text-cyan-300 font-medium transition"
                            >
                              {copiedIndex === idx ? '✓ Copied!' : 'Copy Rule'}
                            </button>
                          </div>
                          <div className="font-mono text-slate-200 bg-slate-900/90 p-2 rounded overflow-x-auto select-all">
                            {cmd.command}
                          </div>
                          <div className="text-[11px] text-slate-500">{cmd.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Analyst Input & Approval Box */}
                  <div className="space-y-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs font-medium text-slate-300 mb-1">
                          Approving Analyst ID
                        </label>
                        <input
                          type="text"
                          value={analystId}
                          onChange={(e) => setAnalystId(e.target.value)}
                          className="w-full px-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-slate-300 mb-1">
                          Containment Rationale
                        </label>
                        <input
                          type="text"
                          value={rationale}
                          onChange={(e) => setRationale(e.target.value)}
                          placeholder="Reason for authorizing containment..."
                          className="w-full px-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
                        />
                      </div>
                    </div>

                    <label className="flex items-start gap-2.5 cursor-pointer pt-1">
                      <input
                        type="checkbox"
                        checked={analystApproval}
                        onChange={(e) => setAnalystApproval(e.target.checked)}
                        className="mt-0.5 rounded border-slate-700 text-cyan-600 focus:ring-0"
                      />
                      <span className="text-xs text-slate-300 font-medium">
                        I explicitly authorize and approve this active containment response. I acknowledge this decision will be permanently committed to the SHA-256 tamper-evident audit trail.
                      </span>
                    </label>
                  </div>
                </div>
              )}
            </>
          )}

          {/* Feedback & Result Banner */}
          {error && (
            <div className="p-3 rounded bg-rose-950/50 border border-rose-800 text-xs text-rose-300">
              {error}
            </div>
          )}

          {executionResult && (
            <div className="p-4 rounded-lg bg-emerald-950/60 border border-emerald-800 text-xs text-emerald-200 space-y-1.5">
              <div className="font-bold flex items-center gap-1.5 text-emerald-400">
                <span>✓</span>
                <span>Containment Action Authorized & Audited</span>
              </div>
              <div>{executionResult.message}</div>
              <div className="font-mono text-[10px] text-slate-400">
                Audit Event ID: {executionResult.audit_id}
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition"
          >
            Close
          </button>

          {currentAction && !executionResult && (
            <button
              onClick={handleAuthorize}
              disabled={!analystApproval || submitting}
              className="px-5 py-1.5 text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white rounded transition disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {submitting ? 'Committing to Audit Trail...' : 'Approve & Commit to Audit Trail'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
