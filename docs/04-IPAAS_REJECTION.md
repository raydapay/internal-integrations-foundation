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

## 4. CI/CD and Version Control
* **The iPaaS Limitation:** Visual workflows are stored as proprietary JSON blobs or database entries. Peer review (pull requests), unit testing (mocking external APIs), and deterministic rollbacks are practically non-existent.
* **The Custom Advantage:** A code-first approach guarantees that integration logic, database schemas, and infrastructure definitions (Docker) evolve simultaneously within a single Git repository, subject to standard software engineering rigor (`unittest`, `ruff`, `ty`).