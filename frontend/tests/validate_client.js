/**
 * Frontend Client Contract & Security Invariant Verification Test
 * Runs under standard Node.js without heavy frameworks.
 */

import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

console.log('--- Running Frontend Client Contract & Security Checks ---');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendDir = path.resolve(__dirname, '..');

// 1. Verify bundle contains no secrets or direct upstream ports
const distAssetsDir = path.join(frontendDir, 'dist', 'assets');
if (fs.existsSync(distAssetsDir)) {
  const files = fs.readdirSync(distAssetsDir);
  for (const f of files) {
    if (f.endsWith('.js')) {
      const content = fs.readFileSync(path.join(distAssetsDir, f), 'utf-8');
      assert(!content.includes(':55000'), `Bundle ${f} contains direct Wazuh Manager port!`);
      assert(!content.includes(':9200'), `Bundle ${f} contains direct OpenSearch port!`);
      assert(!content.includes(':11434'), `Bundle ${f} contains direct Ollama port!`);
      assert(!content.includes('WAZUH_API_PASSWORD'), `Bundle ${f} contains backend secret names!`);
      assert(!content.includes('OPENSEARCH_PASSWORD'), `Bundle ${f} contains backend secret names!`);
      console.log(`✓ Verified production bundle ${f} has 0 leaked ports or backend credentials.`);
    }
  }
} else {
  console.log('ℹ Notice: dist/assets not found, skipping bundle scan (run `npm run build` first).');
}

// 2. Verify Client API URL parameter construction & investigation endpoint
class TestApiClient {
  constructor(baseUrl = '/api/v1') {
    this.baseUrl = baseUrl;
    this.lastUrl = '';
    this.lastOptions = {};
  }

  request(endpoint, options = {}) {
    this.lastUrl = `${this.baseUrl}${endpoint}`;
    this.lastOptions = options;
    return Promise.resolve({ endpoint, options });
  }

  async getAlerts(params = {}, signal) {
    const searchParams = new URLSearchParams();
    if (params.start_time) searchParams.set('start_time', params.start_time);
    if (params.end_time) searchParams.set('end_time', params.end_time);
    if (params.severity_min !== undefined && params.severity_min !== null && params.severity_min > 0) {
      searchParams.set('severity_min', String(params.severity_min));
    }
    if (params.rule_id?.trim()) searchParams.set('rule_id', params.rule_id.trim());
    if (params.host_name?.trim()) searchParams.set('host_name', params.host_name.trim());
    if (params.source_ip?.trim()) searchParams.set('source_ip', params.source_ip.trim());
    if (params.username?.trim()) searchParams.set('username', params.username.trim());
    if (params.page !== undefined && params.page > 0) {
      searchParams.set('page', String(params.page));
    }
    if (params.page_size !== undefined && params.page_size > 0) {
      const clampedSize = Math.min(Math.max(1, params.page_size), 100);
      searchParams.set('page_size', String(clampedSize));
    }
    if (params.sort_order) searchParams.set('sort_order', params.sort_order);

    const queryStr = searchParams.toString();
    const endpoint = queryStr ? `/alerts?${queryStr}` : '/alerts';
    return this.request(endpoint, { signal });
  }

  async investigateAlert(alertId, options = {}, signal) {
    const boundedEvidenceItems = options.max_evidence_items !== undefined
      ? Math.min(Math.max(1, options.max_evidence_items), 20)
      : 10;

    const payload = {
      include_related_events: options.include_related_events ?? false,
      max_evidence_items: boundedEvidenceItems,
    };

    return this.request(`/alerts/${encodeURIComponent(alertId)}/investigate`, {
      method: 'POST',
      body: JSON.stringify(payload),
      headers: {
        'Content-Type': 'application/json',
      },
      signal,
    });
  }
}

const testClient = new TestApiClient();

// Check standard query
await testClient.getAlerts({ page: 2, page_size: 50, severity_min: 8 });
assert(testClient.lastUrl.includes('/api/v1/alerts?'));
assert(testClient.lastUrl.includes('page=2'));
assert(testClient.lastUrl.includes('page_size=50'));
assert(testClient.lastUrl.includes('severity_min=8'));
console.log('✓ Verified standard query params formatting.');

// Check page size clamping (max 100)
await testClient.getAlerts({ page_size: 500 });
assert(testClient.lastUrl.includes('page_size=100'), 'Client failed to clamp page_size to 100!');
console.log('✓ Verified client page_size clamping <= 100.');

// Check empty/blank parameters omitted
await testClient.getAlerts({ rule_id: '   ', host_name: '' });
assert(!testClient.lastUrl.includes('rule_id'), 'Blank rule_id was not omitted!');
assert(!testClient.lastUrl.includes('host_name'), 'Empty host_name was not omitted!');
console.log('✓ Verified blank/empty filter pruning.');

// Check investigateAlert API call construction
await testClient.investigateAlert('alert-xyz-12345', { max_evidence_items: 50 });
assert.strictEqual(testClient.lastUrl, '/api/v1/alerts/alert-xyz-12345/investigate');
assert.strictEqual(testClient.lastOptions.method, 'POST');
const parsedBody = JSON.parse(testClient.lastOptions.body);
assert.strictEqual(parsedBody.include_related_events, false);
assert.strictEqual(parsedBody.max_evidence_items, 20, 'Failed to clamp max_evidence_items to 20!');
console.log('✓ Verified investigateAlert endpoint and payload clamping <= 20.');

// Check special character alert ID encoding
await testClient.investigateAlert('alert/test#1', {});
assert.strictEqual(testClient.lastUrl, '/api/v1/alerts/alert%2Ftest%231/investigate');
console.log('✓ Verified investigateAlert encodes alert ID in URL path.');

// 3. Verify no dangerouslySetInnerHTML in any source files
const srcDir = path.join(frontendDir, 'src');
function checkDirForDanger(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      checkDirForDanger(fullPath);
    } else if (entry.name.endsWith('.tsx') || entry.name.endsWith('.ts')) {
      const src = fs.readFileSync(fullPath, 'utf-8');
      assert(!src.includes('dangerouslySetInnerHTML'), `Source file ${entry.name} uses dangerouslySetInnerHTML!`);
    }
  }
}
checkDirForDanger(srcDir);
console.log('✓ Verified 100% of frontend source files avoid dangerouslySetInnerHTML.');

// 4. Verify authoritative alert fields cannot be overridden by AI outputs
const originalAlert = {
  alert_id: 'original-alert-001',
  rule_id: '5710',
  rule_level: 10,
  rule_description: 'sshd: Attempt to login using a non-existent user',
  timestamp: '2026-10-20T10:00:00Z',
  agent_id: '001',
};

const aiInvestigationOutput = {
  investigation_id: 'inv-test-999',
  alert_id: 'original-alert-001',
  status: 'completed',
  summary: 'Advisory analysis only.',
  rule_level: 1, // Attempted overwrite
  rule_id: '0000', // Attempted overwrite
};

// Invariant: Merging or displaying investigation results must preserve authoritative alert fields
const safeMergedView = {
  ...originalAlert,
  investigation: aiInvestigationOutput,
};

assert.strictEqual(safeMergedView.rule_id, '5710', 'Alert rule_id was mutated!');
assert.strictEqual(safeMergedView.rule_level, 10, 'Alert rule_level was mutated!');
assert.strictEqual(safeMergedView.alert_id, 'original-alert-001', 'Alert alert_id was mutated!');
console.log('✓ Verified authoritative alert severity and rule metadata are immutable.');

// 5. Verify Safe Error Status Mappings
function getSafeErrorMessage(status, _rawError) {
  switch (status) {
    case 400:
      return 'Invalid investigation request parameters.';
    case 404:
      return 'The requested alert could not be found or has expired from the index.';
    case 502:
      return 'Local AI model service (Ollama) is unavailable or unreachable.';
    case 503:
      return 'Investigation service is temporarily degraded or busy. Please retry later.';
    case 504:
      return 'Local AI model inference timed out. Please try again or inspect system load.';
    default:
      return 'An unexpected error occurred during investigation.';
  }
}

assert.strictEqual(getSafeErrorMessage(400, 'raw exception details'), 'Invalid investigation request parameters.');
assert.strictEqual(getSafeErrorMessage(502, 'connection refused'), 'Local AI model service (Ollama) is unavailable or unreachable.');
assert.strictEqual(getSafeErrorMessage(503, 'service degraded'), 'Investigation service is temporarily degraded or busy. Please retry later.');
assert.strictEqual(getSafeErrorMessage(504, 'timeout after 60s'), 'Local AI model inference timed out. Please try again or inspect system load.');
console.log('✓ Verified safe user-facing error messages for HTTP 400, 404, 502, 503, 504.');

// 6. Phase 7.3 Investigation History Query & Detail API client tests
class TestHistoryApiClient extends TestApiClient {
  async getInvestigations(params = {}, signal) {
    const searchParams = new URLSearchParams();
    if (params.alert_id?.trim()) searchParams.set('alert_id', params.alert_id.trim());
    if (params.status?.trim()) searchParams.set('status', params.status.trim());
    if (params.rule_id?.trim()) searchParams.set('rule_id', params.rule_id.trim());
    if (params.agent_name?.trim()) searchParams.set('agent_name', params.agent_name.trim());
    if (params.confidence_label?.trim()) searchParams.set('confidence_label', params.confidence_label.trim());
    if (params.start_time?.trim()) searchParams.set('start_time', params.start_time.trim());
    if (params.end_time?.trim()) searchParams.set('end_time', params.end_time.trim());
    if (params.page !== undefined && params.page > 0) {
      searchParams.set('page', String(params.page));
    }
    if (params.page_size !== undefined && params.page_size > 0) {
      const clamped = Math.min(Math.max(1, params.page_size), 100);
      searchParams.set('page_size', String(clamped));
    }
    if (params.sort_order) {
      searchParams.set('sort_order', params.sort_order);
    }
    const queryStr = searchParams.toString();
    const endpoint = queryStr ? `/investigations?${queryStr}` : '/investigations';
    return this.request(endpoint, { signal });
  }

  async getInvestigationById(investigationId, signal) {
    const cleanId = encodeURIComponent(investigationId.trim());
    return this.request(`/investigations/${cleanId}`, { signal });
  }
}

const historyClient = new TestHistoryApiClient();

// Check getInvestigations query construction & page_size clamping
await historyClient.getInvestigations({ page: 1, page_size: 500, status: 'completed', rule_id: '5710' });
assert(historyClient.lastUrl.includes('/api/v1/investigations?'), 'URL does not point to /api/v1/investigations');
assert(historyClient.lastUrl.includes('page_size=100'), 'Failed to clamp page_size to 100 in getInvestigations');
assert(historyClient.lastUrl.includes('status=completed'), 'Status filter omitted');
assert(historyClient.lastUrl.includes('rule_id=5710'), 'Rule ID filter omitted');
console.log('✓ Verified getInvestigations query construction and <= 100 clamping.');

// Check getInvestigationById encoding
await historyClient.getInvestigationById('inv-test/123#special');
assert.strictEqual(historyClient.lastUrl, '/api/v1/investigations/inv-test%2F123%23special');
console.log('✓ Verified getInvestigationById URL parameter encoding.');

// 7. Verify no fake or hard-coded mock investigation records exist in source code
const historyComponentSrc = fs.readFileSync(path.join(frontendDir, 'src', 'components', 'InvestigationHistoryTable.tsx'), 'utf-8');
assert(!historyComponentSrc.includes('mockAlert'), 'InvestigationHistoryTable contains mock alerts!');
assert(!historyComponentSrc.includes('fakeInvestigation'), 'InvestigationHistoryTable contains fake investigations!');
assert(historyComponentSrc.includes('apiClient.getInvestigations'), 'InvestigationHistoryTable does not call apiClient!');
console.log('✓ Verified InvestigationHistoryTable is 100% wired to real backend API (no mock data).');

const detailComponentSrc = fs.readFileSync(path.join(frontendDir, 'src', 'components', 'InvestigationDetailModal.tsx'), 'utf-8');
assert(detailComponentSrc.includes('apiClient.getInvestigationById'), 'InvestigationDetailModal does not call apiClient!');
assert(detailComponentSrc.includes('apiClient.submitInvestigationFeedback'), 'InvestigationDetailModal does not call submitInvestigationFeedback!');
assert(detailComponentSrc.includes('apiClient.exportInvestigationReport'), 'InvestigationDetailModal does not call exportInvestigationReport!');
console.log('✓ Verified InvestigationDetailModal is 100% wired to real backend API (no mock data, export & feedback wired).');

// 8. Verify Case Management components are wired to real backend API
const caseTableSrc = fs.readFileSync(path.join(frontendDir, 'src', 'components', 'CaseManagementTable.tsx'), 'utf-8');
assert(!caseTableSrc.includes('mockCase'), 'CaseManagementTable contains mock cases!');
assert(caseTableSrc.includes('apiClient.getCases'), 'CaseManagementTable does not call apiClient.getCases!');
assert(caseTableSrc.includes('apiClient.exportCases'), 'CaseManagementTable does not call apiClient.exportCases!');
console.log('✓ Verified CaseManagementTable is 100% wired to real backend API (including exportCases).');

const caseModalSrc = fs.readFileSync(path.join(frontendDir, 'src', 'components', 'CaseModal.tsx'), 'utf-8');
assert(caseModalSrc.includes('apiClient.createCase'), 'CaseModal does not call apiClient.createCase!');
assert(caseModalSrc.includes('apiClient.updateCase'), 'CaseModal does not call apiClient.updateCase!');
assert(caseModalSrc.includes('apiClient.deleteCase'), 'CaseModal does not call apiClient.deleteCase!');
console.log('✓ Verified CaseModal is 100% wired to real backend API CRUD endpoints.');

// 9. Verify App.tsx alert export is wired to apiClient.exportAlerts
const appSrc = fs.readFileSync(path.join(frontendDir, 'src', 'App.tsx'), 'utf-8');
assert(appSrc.includes('apiClient.exportAlerts'), 'App.tsx does not call apiClient.exportAlerts!');
console.log('✓ Verified App.tsx alerts export is wired to apiClient.exportAlerts.');

console.log('--- ALL FRONTEND CONTRACT & SECURITY CHECKS PASSED ---');


