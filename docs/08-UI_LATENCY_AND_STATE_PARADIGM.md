# Architectural Decision Record 08: UI Latency & Interaction Paradigm

> **"Render instantly. Mutate asynchronously. Cache ruthlessly."**

This document defines the strict UI architecture for the Integration Gateway. Because the Gateway acts as a configuration firewall for disparate, high-latency SaaS platforms (Jira, PeopleForce), the Admin UI must protect the user from underlying network volatility.

The UI must behave as if Jira is local, workers are idle, and network latency does not exist.

## 1. The Zero-I/O Synchronous Mandate
FastAPI route handlers serving Jinja2 HTML templates must never execute synchronous, blocking network calls to external APIs.

* **The TLS Handshake Penalty:** Instantiating `httpx.AsyncClient` requires ~350ms to parse the OS SSL trust store. To prevent this from blocking the Event Loop during UI rendering, all external clients must utilize the `HTTPClientManager` to share a persistent, thread-safe connection pool.
* **The Atlassian Latency Trap:** Querying Jira for metadata (Projects, Issue Types, `createmeta` schemas) takes 300ms–1200ms. These calls are strictly forbidden within the UI request-response cycle.

## 2. Stale-While-Revalidate (SWR) Metadata Caching
Instead of implementing complex "Lazy Hydration" (where a modal opens empty and populates via secondary AJAX calls), the Gateway utilizes an aggressive SWR caching strategy to guarantee `<50ms` UI rendering.

1. **O(1) Redis Reads:** FastAPI routes query Redis (`jira:projects`, `jira:createmeta:...`). If the key exists, it is parsed and rendered instantly.
2. **Predictive Prewarming:** An ARQ background cron job fetches global metadata every 24 hours, guaranteeing the UI rarely encounters a cache miss.
3. **The Cold-Start Fallback:** If a cache miss occurs, the route performs a live fetch, stores the result in Redis with a 7-day TTL, and returns the data.

## 3. Deterministic Interaction (The "Click Contract")
Because the Gateway utilizes HTMX for zero-JS-build DOM swaps, network latency during form submissions can cause the UI to feel unresponsive.

* **Global Interception:** The system enforces a strict Vanilla JS event listener on `htmx:beforeRequest`.
* **State Mutation:** Any button or form submitted instantly receives the Bulma `is-loading` CSS class and the `disabled` attribute. This guarantees 0ms perceived latency for the user and structurally prevents database corruption from double-submissions.

## 4. Bipartite Validation
Users configure rules against a highly volatile upstream Jira schema. Validating these rules synchronously against Jira's API during a "Save" operation violates the Zero-I/O mandate.

* **Instant Persistence:** Clicking "Save" writes the rule to SQLite instantly. The UI perceived latency is <50ms.
* **Proactive Shadow Mapping:** Validation is decoupled from creation. An ARQ cron job (`validate_routing_rules_task`) routinely dry-runs all active rules against the live Jira schema.
* **The 400 Trap:** If a rule is saved with a structurally invalid mapping, the local database accepts it. The first time a worker attempts to use the rule, Jira returns an `HTTP 400`. The worker intercepts this, surgically purges the offending schema from the Redis cache, and yields.