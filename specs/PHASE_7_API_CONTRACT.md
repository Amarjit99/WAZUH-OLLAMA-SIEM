# API Contract Specification — Phase 7: Secure Investigation History & Audit Persistence

**Document ID:** `specs/PHASE_7_API_CONTRACT.md`  
**Status:** PROPOSED ARCHITECTURAL SPECIFICATION  
**Scope:** RESTful Endpoints, Request/Response Schemas, Error Envelopes & Audit Events  
**Base Path:** `/api/v1/investigations`  
**Security Boundary:** Authenticated via `verify_api_auth` (Bearer Token), Loopback Confinement (`127.0.0.1`)  
**Authors:** SOC API Engineering & Antigravity Security Agent  
**Last Updated:** October 20, 2026  

---

## 1. General API Conventions

1. **Format:** Strict JSON request and response payloads, encoded in UTF-8.
2. **Timestamps:** ISO 8601 UTC strings (`YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS.mmmmmm+00:00`).
3. **Authentication:** All endpoints require an `Authorization: Bearer <API_KEY>` header. Missing or invalid keys return HTTP 401 with standard error envelopes.
4. **Correlation Tracking:** Every request echoes or generates a `X-Correlation-ID` header, returned in response bodies under `request_id`.
5. **Pagination Bounds:** Default `page_size=25`, maximum `page_size=100`. Offset or page must be $\ge 1$.
6. **No Secret Leakage:** Responses never contain database connection strings, passwords, JWTs, or raw system prompts.

---

## 2. Endpoint Specifications

### 2.1 List Investigation History
- **Method & Path:** `GET /api/v1/investigations`
- **Summary:** List past investigations with bounded filtering and pagination.
- **Authentication:** Required (`verify_api_auth`).
- **Query Parameters:**
  - `alert_id` (`string`, optional, max 128 chars): Filter by specific Wazuh alert document ID.
  - `status` (`string`, optional): Filter by `queued`, `running`, `completed`, `failed`, `cancelled`.
  - `rule_id` (`string`, optional, max 64 chars): Filter by primary alert rule ID.
  - `agent_name` (`string`, optional, max 255 chars): Filter by agent/host name.
  - `confidence_label` (`string`, optional): Filter by `low`, `medium`, `high`.
  - `start_time` (`datetime`, optional, ISO 8601 UTC): Lower bound on `created_at`.
  - `end_time` (`datetime`, optional, ISO 8601 UTC): Upper bound on `created_at`. Window cannot exceed 90 days.
  - `page` (`integer`, optional, default 1, min 1): 1-indexed page.
  - `page_size` (`integer`, optional, default 25, min 1, max 100): Page limit.
  - `sort_order` (`string`, optional, default `desc`, enum `asc`, `desc`): Sort by `created_at`.
- **Response Model (HTTP 200 OK):**
  ```json
  {
    "items": [
      {
        "investigation_id": "inv-9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
        "alert_id": "8Vb3NpEBR5hQ2Yw1Zz9x",
        "run_sequence": 1,
        "status": "completed",
        "primary_rule_id": "5710",
        "primary_rule_level": 5,
        "primary_agent_name": "production-auth-01",
        "model_name": "ollama",
        "model_tag": "llama3.2:3b",
        "confidence_label": "medium",
        "correlation_status": "enriched",
        "evidence_count": 8,
        "execution_duration_ms": 11420,
        "created_at": "2026-10-20T18:32:00.123456Z",
        "actor_id": "local_analyst"
      }
    ],
    "pagination": {
      "page": 1,
      "page_size": 25,
      "total_items": 42,
      "total_pages": 2,
      "has_next": true,
      "has_prev": false
    },
    "request_id": "req-12345"
  }
  ```
- **Audit Event Generated:** `INVESTIGATION_LIST_QUERIED` (if enabled in audit policy)

---

### 2.2 Retrieve Investigation Detail
- **Method & Path:** `GET /api/v1/investigations/{investigation_id}`
- **Summary:** Retrieve full structured investigation results, facts, hypotheses, checks, and evidence snapshots.
- **Authentication:** Required (`verify_api_auth`).
- **Path Parameters:**
  - `investigation_id` (`string`, required, UUIDv4 format).
- **Response Model (HTTP 200 OK):**
  ```json
  {
    "investigation_id": "inv-9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "alert_id": "8Vb3NpEBR5hQ2Yw1Zz9x",
    "run_sequence": 1,
    "status": "completed",
    "created_at": "2026-10-20T18:32:00.123456Z",
    "updated_at": "2026-10-20T18:32:11.543456Z",
    "execution_duration_ms": 11420,
    "actor_id": "local_analyst",
    "result": {
      "model_name": "ollama",
      "model_tag": "llama3.2:3b",
      "summary": "Observed repeated failed authentication attempts followed by successful administrative login.",
      "confidence_label": "medium",
      "disclaimer": "Advisory AI analysis only. Wazuh alert logs remain the authoritative detection and forensic record.",
      "observed_facts": [
        {
          "fact_id": "F-1",
          "statement": "Multiple SSH authentication failures recorded from source IP 192.168.1.50.",
          "cited_evidence_ids": ["EV-01", "EV-02"]
        }
      ],
      "hypotheses": [
        {
          "hypothesis_id": "H-1",
          "statement": "Activity is consistent with external credential spraying.",
          "uncertainty": "medium",
          "cited_evidence_ids": ["EV-01", "EV-02"]
        }
      ],
      "recommended_checks": [
        {
          "check_id": "C-1",
          "description": "Verify external firewall drop logs for 192.168.1.50.",
          "rationale": "Confirm if attacker targeted additional endpoints.",
          "priority": "high",
          "is_read_only": true
        }
      ],
      "limitations": [
        "Network packet captures not available."
      ],
      "unsupported_citation_warnings": []
    },
    "evidence_items": [
      {
        "evidence_id": "EV-01",
        "source_record_id": "8Vb3NpEBR5hQ2Yw1Zz9x",
        "event_timestamp": "2026-10-20T18:30:00.000000Z",
        "is_primary": true,
        "rule_id": "5710",
        "rule_level": 5,
        "rule_description": "sshd: Attempt to login using a non-existent user",
        "agent_name": "production-auth-01",
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.15",
        "username": "admin",
        "correlation_reason": "primary_investigation_target",
        "correlation_qualifier": "reporting_endpoint_context_only",
        "raw_evidence_ref": "wazuh-alerts-4.x-2026.10.20/8Vb3NpEBR5hQ2Yw1Zz9x"
      }
    ],
    "request_id": "req-12345"
  }
  ```
- **Error Responses:**
  - `404 NOT_FOUND`: When `investigation_id` does not exist or has been deleted.
  - `400 VALIDATION_ERROR`: Malformed UUID format.
- **Audit Event Generated:** `INVESTIGATION_VIEWED`

---

### 2.3 Export Investigation Report
- **Method & Path:** `GET /api/v1/investigations/{investigation_id}/export`
- **Summary:** Export sanitized investigation report formatted for SOC casework.
- **Authentication:** Required (`verify_api_auth`).
- **Query Parameters:**
  - `format` (`string`, required, enum `markdown`, `json`).
- **Response:**
  - If `format=markdown`: Content-Type `text/markdown; charset=utf-8`. Returns standard, beautifully formatted report with advisory disclaimers and sanitization headers.
  - If `format=json`: Content-Type `application/json`. Returns full sanitized schema.
- **Audit Event Generated:** `INVESTIGATION_EXPORTED` (records requested format and user context).

---

### 2.4 Soft-Delete Investigation
- **Method & Path:** `DELETE /api/v1/investigations/{investigation_id}`
- **Summary:** Mark an investigation as soft-deleted (`deleted_at` set) or purge per policy.
- **Authentication:** Required (`verify_api_auth`).
- **Response Model (HTTP 200 OK):**
  ```json
  {
    "status": "deleted",
    "investigation_id": "inv-9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "deleted_at": "2026-10-20T19:00:00.000000Z",
    "request_id": "req-12345"
  }
  ```
- **Audit Event Generated:** `INVESTIGATION_DELETED` (immutable audit record written with deletion timestamp).

---

## 3. Idempotency & Duplicate Submission Behavior

When an analyst triggers an investigation via `/api/v1/alerts/{alert_id}/investigate`:
1. **In-Flight Conflict (HTTP 409):** If an investigation is currently in `status='running'` for that exact `alert_id`, the backend rejects duplicate concurrent triggers with HTTP 409 (`CONFLICT`), returning:
   ```json
   {
     "error": {
       "code": "CONCURRENT_INVESTIGATION_RUNNING",
       "message": "An investigation is already in progress for this alert.",
       "investigation_id": "inv-9a8b7c6d-...",
       "request_id": "req-12345"
     }
   }
   ```
2. **Sequential Re-Runs:** If prior investigations for that alert are already `completed` or `failed`, the backend increments `run_sequence` (e.g. Run #2) and launches a new investigation without overwriting prior records.

---

## 4. Standard Error Envelope Contract

All persistence endpoints return the project's standard error envelope:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Detailed safe error description without credentials or stack traces",
    "request_id": "req-12345"
  }
}
```
Standard codes: `VALIDATION_ERROR`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `INSUFFICIENT_STORAGE`, `DEPENDENCY_UNAVAILABLE`, `INTERNAL_ERROR`.
