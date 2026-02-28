# Integration Platform: Master Action List

## 1. Domain: PF-Jira (Engine Maturity & UI)
- [x] **UI Consolidation:** Deprecate the standalone `/pf-jira/sync` page and embed the Manual Sync trigger into the Routing Rules dashboard.
- [x] **Edge Cases (DLQ):** Implement a persistent Dead-Letter Queue (DLQ) visualization in the UI for tasks that fail API constraints.
- [x] **Routing Matrix:** Refactored mapping tables into a unified `RoutingRule` Firewall model for multi-variate conditional dispatch.
- [x] **Ghost Record Recovery:** Implemented 404 HTTP intercepts to self-heal orphaned SQLite state records during upstream deletions.
- [x] **Firewall Deny Rules:** Extend `RoutingRule` with an `action` enum (`SYNC`, `DROP`). Update the worker to yield early on `DROP`.
- [x] **Dynamic Field Injection (Pivot):** Rejected hardcoded columns (e.g., `target_assignee`). Implemented `RuleFieldMapping` relation to support `STATIC` and `PF_PAYLOAD` (JSONPath) injection across all Jira fields.
- [x] **Proactive Circuit Breaking:** Implemented an asynchronous Nightly Sync (`validate_routing_rules_task`) that shadow-maps rules against live Jira `createmeta`, autonomously disabling rules that violate upstream schema constraints.
- [x] **Reactive Cache Invalidation (The 400 Trap):** Wrapped issue mutation in an HTTP 400 interceptor to surgically purge stale Redis `createmeta` cache keys and trigger self-healing ARQ retries.
- [x] **Rule Editing:** Implement a Bulma modal containing an HTMX-powered form to edit existing rules without deletion/recreation.

- [x] **UI Enhancement:** Upgrade the "Select Jira Board" HTML `<select>` into a live-filterable searchable dropdown. *(Note: Custom Vanilla JS wrapper rejected. Evaluate robust, dependency-light alternatives like Tom Select or a native Bulma extension).*

## 2. Platform Architecture (Dynamic State & Plugin Pivot)
- [x] **Configuration Data Model:** Create a `DomainConfig` SQLite table to hold the Master Switch, Polling Interval, and Fallback Projects, isolating mutable state from `settings.py`.
- [x] **Tick/Yield Worker Refactor:** Modify the ARQ polling worker to run continuously but yield dynamically based on the intervals and master switches defined in `DomainConfig`.
- [x] **Settings UI:** Build the `/admin/settings` dashboard to manage the `DomainConfig` table via HTMX.
- [ ] **Decoupling:** Refactor `src/domain/` to support a dynamic plugin loader. Extract `pf_jira` into an isolated module that registers its own routers, workers, and menu items at startup.
- [ ] **Stubs:** Outline and scaffold the file structures for future integrations: `plugins/telegram`, `plugins/slack`, `plugins/pipedrive`.
- [x] **Alerting Service:** Implement a unified internal service to push critical fault notifications (e.g., worker death, network timeouts) to a dedicated Slack/Telegram webhook.
- [x] **Beeaytify Logs:** Get rid of all ugly log records like `<built-in method rollback of sqlite3.Connection object at 0x000001CC9D4924D0>` - async / await noise, turn them to beautiful meaningful strings

## 3. Testing & CI/CD
- [x] **Firewall Matrix Testing:** Write unittests for the new `evaluate_routing_rules` linear evaluation logic to guarantee priority sorting and default fallbacks.
- [x] **Ghost Record Testing:** Mock `httpx.HTTPStatusError` with a 404 status code to verify the SQLite state purging logic in the ARQ workers.
- [ ] **Coverage Expansion:** Systematically increase `unittest` coverage across the core gateway, focusing on database rollback scenarios, HTTP 429 rate-limiting, and RBAC middleware.

## 4. Documentation & Developer Experience
- [x] **Architectural Decision Records (ADR):** Created `03-STATE_SYNC_MECHANICS.md`, `04-IPAAS_REJECTION.md`, and `05-FRONTEND_STRATEGY.md`.
- [x] **Architectural Decision Records (ADR):** Created `06-ROUTING_AND_RECOVERY.md` detailing the Firewall Model and 404 Ghost Record handlers.
- [ ] **In-App Documentation:** Implement a Markdown-rendering route (`/admin/help/{topic}`) pulling from `src/static/user_guides/` to serve contextual help natively within the Bulma layout.
- [ ] **UI Tooltips:** Inject lightweight CSS-only Bulma tooltips across the rules and settings dashboards for immediate contextual assistance.
- [ ] **Agent Directives:** Revise and update `AGENTS.md` to establish exact plugin scaffolding instructions, enforcing the new `DomainConfig` and `Tick/Yield` execution patterns.
- [x] **Architectural Decision Records (ADR):** Created `07-OBSERVABILITY_AND_CIRCUIT_BREAKING.md` detailing the proactive schema validation, the 400 Trap, and the Notification Matrix.

## 5. Configuration Maturity & De-Hardcoding
- [x] **Externalize Integration Lineage:** Expand `DomainConfig` to own integration-specific identifiers (e.g., `jira_tracking_label`, `jira_entity_property_key`), removing hardcoded "PeopleForce" magic strings from the ARQ workers and JQL reverse-vector sweeps.
- [x] **String Templating Engine (PF-Variables):** Introduce `MappingSourceType.TEMPLATE` to `RuleFieldMapping`. Implement regex-based JSONPath interpolation (e.g., `{{ path.to.variable }}`) in the `FieldDataResolver` to construct dynamic Jira text fields (Summary, Description) without Python-level hardcoding.

## 6.  UI Latency Strategy (High Priority)
- [x] **Phase 0:** Audit all admin routes; strip blocking external I/O (Jira/Redis/ARQ) and implement deferred hydration. *(Resolved via `HTTPClientManager` and connection pooling).*
- [x] **Phase 1 & 9:** Implement deterministic UI state. *(Resolved via global HTMX `is-loading` event listeners in `base.html`).*
- [x] **Phase 3 & 6:** Implement Stale-While-Revalidate caching layer and predictive prewarming. *(Resolved via `CacheManager` and ARQ cron job).*
- [x] **Phase 8:** Develop diagnostic panel for cache metrics and purge/refresh controls. *(Resolved via HTMX injections in `/admin/settings`).*
- [ ] **Phase 5:** Decouple rule persistence from schema validation; implement status badge (Validating/Invalid) state machine.
- [ ] **Phase 7:** Implement SSE stream for real-time validation status updates.
- [ ] **Phase 10:** Integrate latency instrumentation (p50/p95 tracking) for modal opens and save operations.
- [ ] **Phase 11:** Evaluate migration to [`SAQ`](https://saq-py.readthedocs.io/en/latest/) for worker queue performance and latency reduction.

## 7. Phase: API Infrastructure & Authorization

- [ ] **Core API Architecture & Refactoring**
    - [ ] Initialize `/api` route namespace in a dedicated module (`routes/api.py`).
    - [ ] Refactor business logic (Rule CRUD, Settings, Sync Toggles) into a shared `Service Layer` to ensure parity between Web and API interfaces.
    - [ ] Implement Pydantic models for request/response serialization and strict schema validation.
    - [ ] Decouple current session-based web routes from core logic to allow dual-entry points.

- [ ] **Hybrid Security & Auth Implementation**
    - [ ] **HMAC Engine:**
        - [ ] Implement SHA-256 signature verification middleware.
        - [ ] Canonicalization string: `Method + Path + RawBody + Timestamp`.
        - [ ] Implement ± 60s timestamp window check to mitigate clock drift issues.
    - [ ] **Hybrid Auth Router:**
        - [ ] Develop middleware to check for `X-Signature` (HMAC) or `Authorization: Bearer` headers.
        - [ ] Implement IP-CIDR whitelisting decorator specifically for Bearer token usage.
    - [ ] **Replay Protection:** Integrate Redis-backed nonce/Request-ID tracking for HMAC requests.

- [ ] **Credential Management (UI & Logic)**
    - [ ] Extend DB schema for `api_credentials`:
        - `client_id`, `secret_hash`, `type` (HMAC/Bearer), `allowed_ips` (JSON/CIDR list), `scopes`, `status`, `last_used_at`.
    - [ ] **Admin Dashboard Update:**
        - [ ] Create view for generating/revoking API credentials.
        - [ ] Implement "Secret Reveal" logic (one-time view) and secret hashing (PBKDF2/Argon2) for storage.
        - [ ] Support for secondary secrets to facilitate zero-downtime rotation.

- [ ] **Automation & Developer Experience (DX)**
    - [ ] **`api-curl.sh` Helper Script:**
        - [ ] Create a POSIX-compliant wrapper for `curl` that automates signing.
        - [ ] Requirements: OpenSSL for HMAC, environment variable support for secrets.
    - [ ] **Documentation:**
        - [ ] Add "API Reference" section to internal docs.
        - [ ] Provide copy-pasteable examples for Bash (via helper) and Python (signing class).
    - [ ] Implement an authenticated `/api/v1/debug/whoami` endpoint for credential verification."""
## 8. Configuration & Technical Debt
- [ ] **De-Hardcode Tenant Constants:** Strip all hardcoded tenant-specific strings (`todapay.com`, `todapay.atlassian.net`, `admin@todapay.com`) from the entire codebase, including Jinja templates (`src/templates/`) and the `tests/` directory. Replace with dynamic configuration variables (e.g., `settings.JIRA_BASE_URL`, `settings.TENANT_DOMAIN`).