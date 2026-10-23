import React, { useState, useEffect, useCallback } from 'react';
import { apiClient } from '../api/client';
import { ContainmentModal } from './ContainmentModal';
import type { AgentItem, AgentSummary, NotificationTestResponse } from '../types/api';

export const AgentFleetTable: React.FC = () => {
  const [agents, setAgents] = useState<AgentItem[]>([]);
  const [summary, setSummary] = useState<AgentSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAgentForContainment, setSelectedAgentForContainment] = useState<AgentItem | null>(null);
  
  // Webhook Test State
  const [testUrl, setTestUrl] = useState<string>('');
  const [testResult, setTestResult] = useState<NotificationTestResponse | null>(null);
  const [testingWebhook, setTestingWebhook] = useState<boolean>(false);

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.getAgents(50, 0, statusFilter);
      setAgents(response.items || []);
      setSummary(response.summary || null);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to retrieve agent fleet telemetry';
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 30000); // 30s auto-refresh
    return () => clearInterval(interval);
  }, [fetchAgents]);

  const handleTestWebhook = async () => {
    setTestingWebhook(true);
    setTestResult(null);
    try {
      const res = await apiClient.testNotificationWebhook(testUrl.trim() || undefined);
      setTestResult(res);
    } catch (err: unknown) {
      setTestResult({
        status: 'failed',
        message: err instanceof Error ? err.message : 'Network error testing webhook',
        dispatched_at: new Date().toISOString(),
      });
    } finally {
      setTestingWebhook(false);
    }
  };

  const filteredAgents = agents.filter((a) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      a.id.toLowerCase().includes(q) ||
      a.name.toLowerCase().includes(q) ||
      (a.ip && a.ip.toLowerCase().includes(q)) ||
      (a.os?.name && a.os.name.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      {/* Top Stat Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-xs uppercase tracking-wider text-slate-400 font-medium">Total Monitored Endpoints</div>
          <div className="text-2xl font-bold text-white mt-1">{summary?.total ?? 0}</div>
          <div className="text-xs text-slate-500 mt-1">Enrolled in Wazuh Manager</div>
        </div>

        <div className="bg-slate-900 border border-emerald-950/60 rounded-lg p-4">
          <div className="text-xs uppercase tracking-wider text-emerald-400 font-medium flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            Active / Reporting
          </div>
          <div className="text-2xl font-bold text-emerald-300 mt-1">{summary?.active ?? 0}</div>
          <div className="text-xs text-slate-500 mt-1">Sending keep-alive heartbeats</div>
        </div>

        <div className="bg-slate-900 border border-rose-950/60 rounded-lg p-4">
          <div className="text-xs uppercase tracking-wider text-rose-400 font-medium flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            Disconnected / Offline
          </div>
          <div className="text-2xl font-bold text-rose-300 mt-1">{summary?.disconnected ?? 0}</div>
          <div className="text-xs text-slate-500 mt-1">Endpoint agent unreachable</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-xs uppercase tracking-wider text-slate-400 font-medium">Never Connected</div>
          <div className="text-2xl font-bold text-slate-300 mt-1">{summary?.never_connected ?? 0}</div>
          <div className="text-xs text-slate-500 mt-1">Key registered, pending sync</div>
        </div>
      </div>

      {/* Control bar: Search, Filter, Refresh */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/80 p-3 rounded-lg border border-slate-800">
        <div className="flex items-center gap-3 flex-1">
          <input
            type="text"
            placeholder="Search agents by ID, hostname, IP, or OS..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full max-w-sm px-3 py-1.5 text-sm bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 text-sm bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active Only</option>
            <option value="disconnected">Disconnected Only</option>
          </select>
        </div>

        <button
          onClick={fetchAgents}
          disabled={loading}
          className="px-4 py-1.5 text-sm bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition flex items-center justify-center gap-2 disabled:opacity-50"
        >
          {loading ? (
            <svg className="animate-spin h-4 w-4 text-cyan-400" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
            </svg>
          ) : (
            <span>↻ Refresh Fleet</span>
          )}
        </button>
      </div>

      {/* Agents Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {error && (
          <div className="p-4 bg-rose-950/40 border-b border-rose-900 text-rose-300 text-sm flex items-center gap-2">
            <span>⚠ Error:</span>
            <span>{error}</span>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Agent ID</th>
                <th className="px-4 py-3">Hostname</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">IP Address</th>
                <th className="px-4 py-3">Operating System</th>
                <th className="px-4 py-3">Agent Version</th>
                <th className="px-4 py-3">Node / Cluster</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {loading && agents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                    Querying Wazuh Manager agent registry...
                  </td>
                </tr>
              ) : filteredAgents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                    No agents matched the criteria.
                  </td>
                </tr>
              ) : (
                filteredAgents.map((agent) => (
                  <tr key={agent.id} className="hover:bg-slate-800/40 transition">
                    <td className="px-4 py-3 font-mono font-semibold text-cyan-400">
                      {agent.id}
                    </td>
                    <td className="px-4 py-3 font-medium text-white flex items-center gap-2">
                      {agent.id === '000' && (
                        <span className="text-[10px] bg-cyan-950 text-cyan-400 border border-cyan-800 px-1.5 py-0.5 rounded font-mono">
                          MANAGER
                        </span>
                      )}
                      {agent.name}
                    </td>
                    <td className="px-4 py-3">
                      {agent.status === 'active' ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                          ACTIVE
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-rose-950/80 text-rose-400 border border-rose-800">
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
                          {agent.status.toUpperCase()}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-300">
                      {agent.ip || '—'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-slate-200">
                        {agent.os?.name ? `${agent.os.name} ${agent.os.version || ''}` : 'Unknown'}
                      </div>
                      {agent.os?.arch && (
                        <div className="text-[11px] text-slate-500 font-mono">{agent.os.arch}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                      {agent.version || '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {agent.node_name || 'node01'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => setSelectedAgentForContainment(agent)}
                        className="px-2.5 py-1 text-xs font-semibold bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800 rounded transition inline-flex items-center gap-1"
                        title="Open Human-in-the-Loop Active Response Containment"
                      >
                        <span>🛡️ Contain</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Automated Webhook Notification Testing Panel */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <span className="text-base">🔔</span>
            <h3 className="font-semibold text-white text-sm">Automated SOC Webhook Notification Dispatcher</h3>
          </div>
          <span className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">
            Slack / Discord / Generic JSON
          </span>
        </div>
        <p className="text-xs text-slate-400 mb-4">
          When high-severity alerts (Level &ge; 10) or kernel rootkits occur, the SIEM automatically posts formatted alerts to the configured webhook. Test connectivity below.
        </p>

        <div className="flex flex-col sm:flex-row gap-2">
          <input
            type="url"
            placeholder="https://discord.com/api/webhooks/... or https://hooks.slack.com/... (Leave empty for .env default)"
            value={testUrl}
            onChange={(e) => setTestUrl(e.target.value)}
            className="flex-1 px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button
            onClick={handleTestWebhook}
            disabled={testingWebhook}
            className="px-4 py-1.5 text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded transition disabled:opacity-50 whitespace-nowrap"
          >
            {testingWebhook ? 'Dispatching...' : 'Dispatch Test Alert'}
          </button>
        </div>

        {testResult && (
          <div
            className={`mt-3 p-3 rounded text-xs border ${
              testResult.status === 'delivered'
                ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                : testResult.status === 'disabled'
                ? 'bg-amber-950/40 border-amber-800 text-amber-300'
                : 'bg-rose-950/40 border-rose-800 text-rose-300'
            }`}
          >
            <div className="font-semibold uppercase tracking-wider text-[11px] mb-1">
              Status: {testResult.status}
            </div>
            <div>{testResult.message}</div>
            {testResult.target_masked && (
              <div className="font-mono text-[10px] text-slate-400 mt-1">
                Target: {testResult.target_masked}
              </div>
            )}
          </div>
        )}
      </div>

      {selectedAgentForContainment && (
        <ContainmentModal
          isOpen={!!selectedAgentForContainment}
          onClose={() => setSelectedAgentForContainment(null)}
          targetInfo={{
            agentId: selectedAgentForContainment.id,
            agentName: selectedAgentForContainment.name,
            sourceIp:
              selectedAgentForContainment.ip && selectedAgentForContainment.ip !== 'any'
                ? selectedAgentForContainment.ip
                : undefined,
          }}
        />
      )}
    </div>
  );
};
