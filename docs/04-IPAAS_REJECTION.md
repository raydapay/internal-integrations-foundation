# Architectural Decision Record: iPaaS Rejection (Code-First vs. Visual)

> **"Infrastructure must scale with complexity, not just volume."**

This document outlines the systemic rationale for building a custom Python/FastAPI integration gateway instead of leveraging commercial Integration Platform as a Service (iPaaS) solutions such as n8n, Zapier, or Make.com.

## 1. The Cost of Asynchronous Polling
The primary forward vector (PeopleForce ➡️ Jira) operates on a continuous delta-sync polling loop because PeopleForce lacks granular webhooks for task mutations.
* **The iPaaS Limitation:** Visual programming tools charge per "task" or "execution step." Polling an API every 60 seconds to compute state hashes results in ~43,000 executions per month *per domain*, even if no data has mutated. This artificial cost ceiling prohibits real-time state reconciliation.
* **The Custom Advantage:** A dedicated ARQ worker running an `asyncio` loop consumes negligible CPU/RAM during idle polling and incurs zero per-execution costs.

## 2. Cryptographic Security & Zero-Trust
The return vector (Jira ➡️ PeopleForce) relies on Atlassian System Webhooks.
* **The iPaaS Limitation:** Jira secures webhooks via an `X-Hub-Signature` (HMAC-SHA256) computed against the raw byte string of the request body. Most visual builders parse the incoming JSON before evaluating headers, destroying the raw byte sequence and making constant-time cryptographic validation impossible. Bypassing this requires downgrading to static bearer tokens, violating our zero-trust architecture.
* **The Custom Advantage:** FastAPI middleware intercepts the ASGI stream, computes the hash directly against `await request.body()`, and drops forged packets before routing logic is ever invoked.

## 3. Distributed State Management
To prevent infinite sync loops, the system must maintain a highly concurrent ledger of known states (`last_sync_hash`) and implement distributed locking (`redis.lock`).
* **The iPaaS Limitation:** Visual tools handle stateless, linear A-to-B transformations excellently. They fail catastrophically when attempting to manage persistent distributed locks or execute complex, transactional database mutations with rollback capabilities.
* **The Custom Advantage:** Python provides native `asyncio` locking mechanisms and robust ORM transaction boundaries (SQLAlchemy/SQLModel) to ensure atomicity across disparate SaaS platforms.
* **The Cache Invalidation Gap:** Our integration requires a two-tier caching strategy (L1 Redis Cache for schemas) with precise, reactive invalidation (purging only `jira:createmeta:IT:10010` on a specific HTTP 400 response). iPaaS platforms lack the granular, programmatic control required to execute surgical cache purges based on deeply nested HTTP exception inspection.

## 4. CI/CD and Version Control
* **The iPaaS Limitation:** Visual workflows are stored as proprietary JSON blobs or database entries. Peer review (pull requests), unit testing (mocking external APIs), and deterministic rollbacks are practically non-existent.
* **The Custom Advantage:** A code-first approach guarantees that integration logic, database schemas, and infrastructure definitions (Docker) evolve simultaneously within a single Git repository, subject to standard software engineering rigor (`unittest`, `ruff`, `ty`).

## 5. Dynamic Schema Volatility (The "Moving Target" Challenge)
Jira projects are notoriously dynamic. Administrators frequently alter Field Configurations, making optional fields mandatory or deprecating `allowedValues` in dropdowns.
* **The iPaaS Limitation:** Visual integration tools rely on static mapping nodes configured at design time. If a Jira Admin adds a required "Cost Center" field, the iPaaS workflow will fail with a `400 Bad Request`. It will remain broken, generating infinite error loops or dropping data entirely, until a human logs in, re-fetches the visual schema, and manually maps the new field.
* **The Custom Advantage:** The custom gateway implements Just-In-Time (JIT) schema discovery and Reactive Cache Invalidation. It dynamically fetches Jira's `createmeta` schema at runtime, pre-flights the payload against strict validation matrices, and auto-heals by purging localized Redis cache keys and applying exponential backoff when API configuration drift is detected.

## 6. Proactive Circuit Breaking vs. Reactive Failure
Enterprise integrations must fail gracefully and alert accurately before business data is lost.
* **The iPaaS Limitation:** Error handling in iPaaS is typically reactive (e.g., "If node fails, send an email"). There is no concept of offline proactive validation. Poison payloads enter the system and fail at the point of execution, causing data loss and API rate-limit penalties.
* **The Custom Advantage:** A dedicated nightly asynchronous task performs "Shadow Mapping." It simulates payload generation against the live Jira schema to detect drift *before* a real task is processed. If a mapping becomes invalid, the engine acts as a proactive circuit breaker: it autonomously disables the specific routing rule, updates the Redis state, and alerts administrators precisely about the schema violation.