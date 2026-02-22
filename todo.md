# Integration Platform: Master Action List

## 1. Domain: PF-Jira (Engine Maturity & UI)
- [x] **UI Consolidation:** Deprecate the standalone `/pf-jira/sync` page and embed the Manual Sync trigger into the Routing Rules dashboard.
- [x] **Edge Cases (DLQ):** Implement a persistent Dead-Letter Queue (DLQ) visualization in the UI for tasks that fail API constraints.
- [x] **Routing Matrix:** Refactored mapping tables into a unified `RoutingRule` Firewall model for multi-variate conditional dispatch.
- [x] **Ghost Record Recovery:** Implemented 404 HTTP intercepts to self-heal orphaned SQLite state records during upstream deletions.
- [x] **Firewall Deny Rules:** Extend `RoutingRule` with an `action` enum (`SYNC`, `DROP`). Update the worker to yield early on `DROP`.
- [x] **Assignee/Reporter Overrides:** Add `target_assignee_email` and `target_reporter_email` to the `RoutingRule` table to override default behavior.
- [x] **Rule Editing:** Implement a Bulma modal containing an HTMX-powered form to edit existing rules without deletion/recreation.
- [x] **Rule Validation Endpoint:** Implement an asynchronous bulk validation endpoint that evaluates all unique Jira target projects and identities against the Atlassian API.
- [x] **UI Enhancement:** Upgrade the "Select Jira Board" HTML `<select>` into a live-filterable searchable dropdown. *(Note: Custom Vanilla JS wrapper rejected. Evaluate robust, dependency-light alternatives like Tom Select or a native Bulma extension).*

## 2. Platform Architecture (Dynamic State & Plugin Pivot)
- [ ] **Configuration Data Model:** Create a `DomainConfig` SQLite table to hold the Master Switch, Polling Interval, and Fallback Projects, isolating mutable state from `settings.py`.
- [ ] **Tick/Yield Worker Refactor:** Modify the ARQ polling worker to run continuously but yield dynamically based on the intervals and master switches defined in `DomainConfig`.
- [ ] **Settings UI:** Build the `/admin/settings` dashboard to manage the `DomainConfig` table via HTMX.
- [ ] **Decoupling:** Refactor `src/domain/` to support a dynamic plugin loader. Extract `pf_jira` into an isolated module that registers its own routers, workers, and menu items at startup.
- [ ] **Stubs:** Outline and scaffold the file structures for future integrations: `plugins/telegram`, `plugins/slack`, `plugins/pipedrive`.
- [ ] **Alerting Service:** Implement a unified internal service to push critical fault notifications (e.g., worker death, network timeouts) to a dedicated Slack/Telegram webhook.

## 3. Testing & CI/CD
- [ ] **Firewall Matrix Testing:** Write unittests for the new `evaluate_routing_rules` linear evaluation logic to guarantee priority sorting and default fallbacks.
- [ ] **Ghost Record Testing:** Mock `httpx.HTTPStatusError` with a 404 status code to verify the SQLite state purging logic in the ARQ workers.
- [ ] **Coverage Expansion:** Systematically increase `unittest` coverage across the core gateway, focusing on database rollback scenarios, HTTP 429 rate-limiting, and RBAC middleware.

## 4. Documentation & Developer Experience
- [x] **Architectural Decision Records (ADR):** Created `03-STATE_SYNC_MECHANICS.md`, `04-IPAAS_REJECTION.md`, and `05-FRONTEND_STRATEGY.md`.
- [x] **Architectural Decision Records (ADR):** Created `06-ROUTING_AND_RECOVERY.md` detailing the Firewall Model and 404 Ghost Record handlers.
- [ ] **In-App Documentation:** Implement a Markdown-rendering route (`/admin/help/{topic}`) pulling from `src/static/user_guides/` to serve contextual help natively within the Bulma layout.
- [ ] **UI Tooltips:** Inject lightweight CSS-only Bulma tooltips across the rules and settings dashboards for immediate contextual assistance.
- [ ] **Agent Directives:** Revise and update `AGENTS.md` to establish exact plugin scaffolding instructions, enforcing the new `DomainConfig` and `Tick/Yield` execution patterns.