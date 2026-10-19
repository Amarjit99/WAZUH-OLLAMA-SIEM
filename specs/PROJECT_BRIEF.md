# Project Brief

## Name
Wazuh + Ollama Local AI SIEM and Threat Hunting Assistant

## One-sentence description
An internally hosted security investigation platform that uses Wazuh for authoritative detection, OpenSearch/Wazuh Indexer for evidence retrieval, Python for orchestration, and Ollama for evidence-grounded local summaries.

## Problem
Security analysts must manually review many alerts and correlated events. This project aims to reduce repetitive investigation effort without replacing SIEM detection or analyst judgment.

## Target users
- Security analyst: searches alerts, opens investigations, reviews evidence and exports reports.
- Security administrator: configures integrations, reviews health, manages approved settings.
- Auditor/reviewer: views permitted case history and audit events.

Role definitions and permissions must be enforced server-side.

## Goals
1. Connect to a real configured Wazuh environment.
2. Retrieve alerts through documented authenticated APIs.
3. Search relevant indexed evidence using bounded queries.
4. Generate local AI summaries from evidence already retrieved and authorized.
5. Show source records and AI claims separately.
6. Offer filters, investigation history, exports, health status, and auditability.
7. Measure latency, reliability, and AI factuality.

## Non-goals for v1
- Replacing Wazuh rules or claiming the LLM is a detection engine.
- Automatic response actions.
- Unrestricted shell/endpoint execution.
- Unrestricted external threat-intelligence calls.
- Reading arbitrary indexer data outside approved indexes.
- Claiming that a connection to an AI website proves prompt content was uploaded.
- Guaranteeing complete detection coverage.

## Primary user journey
1. Analyst opens the authenticated dashboard.
2. Backend confirms dependency health and data freshness.
3. Analyst filters alerts by time, host, source IP, severity, rule, or source.
4. Analyst opens an alert and inspects the original evidence.
5. Analyst requests an AI-assisted investigation.
6. Backend retrieves bounded related evidence and sends a minimized package to Ollama.
7. The response is schema-validated and evidence references are checked.
8. Analyst reviews facts, hypotheses, missing evidence, and recommended read-only checks.
9. Analyst saves notes/case status and exports an authorized report.

## First milestone
A controlled Linux authentication event produces a verified Wazuh alert. The backend retrieves the actual alert from the configured environment, submits selected evidence to local Ollama, validates the returned analysis, and presents both the source evidence and the analysis.

## Success measures
- The end-to-end first milestone passes in a documented test environment.
- No fabricated production alerts or metrics.
- All AI evidence references resolve to retrieved records.
- The service remains usable when Ollama is unavailable; Wazuh detection is unaffected.
- Unauthorized requests are denied.
- Latency and factuality are measured rather than guessed.


## Known questions to resolve before production
- What operating system and hardware will host Wazuh and Ollama?
- Which Wazuh version and topology are deployed?
- Which endpoints and log sources are in scope for the first release?
- Is strict offline operation required, including notifications and model downloads?
- How many endpoints/events per second and how many days of retention are expected?
- Which user authentication method and roles are required?
- Is the application single-user lab software or a multi-user SOC application?
