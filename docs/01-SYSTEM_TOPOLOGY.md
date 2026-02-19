# System Topology & Bounded Contexts

> **"Isolate the domains, unify the infrastructure."**

This document defines the systemic topology of the integration middleware. To prevent the emergence of a monolithic "God Service" while maintaining a low operational footprint, the system relies on a **Federated Gateway / Isolated Worker** architecture.



## 1. Architectural Model

The system is logically split into two distinct tiers:

### 1.1 The Unified Gateway (FastAPI)
* **Role:** The single ingress point for all incoming HTTP traffic (Webhooks, Bot Commands, UI Interactions).
* **Responsibilities:** * TLS/Domain termination at the Edge.
    * Authentication and Authorization (Google Workspace SSO).
    * Request-ID generation for distributed tracing.
    * Pydantic schema validation.
* **Constraint:** The Gateway must remain entirely free of business logic and blocking I/O. Its sole purpose is to validate the payload and dispatch it to the appropriate worker or queue.

### 1.2 Isolated Domain Workers (ARQ)
* **Role:** Dedicated, background `asyncio` processes that execute the actual integration logic (e.g., Pipedrive synchronization, Slack messaging, Jira state reconciliation).
* **Responsibilities:**
    * Third-party API communication (rate-limiting, pagination).
    * Data transformation and mapping.
    * Database writes.
* **Constraint:** Workers operate on isolated queues (e.g., `pf_jira_queue`, `slack_queue`). A critical failure, memory leak, or API rate limit in one domain must not degrade the performance or availability of the others.

---

## 2. Communication Patterns

Routing data from the Gateway to the Workers relies on two strict patterns, chosen based on the downstream caller's requirements.

### Pattern A: Asynchronous (Fire-and-Forget)
* **Trigger:** Standard Webhooks (Jira, PeopleForce, Pipedrive).
* **Flow:** 1. Gateway receives payload and validates it.
    2. Gateway enqueues the job to Redis via ARQ.
    3. Gateway immediately returns a `202 Accepted` to the caller.
* **Characteristics:** Highly resilient to downstream API latency. Zero risk of blocking the FastAPI event loop.

### Pattern B: Synchronous (Redis Pub/Sub)
* **Trigger:** Interactive endpoints requiring immediate data returns (e.g., Telegram bots, real-time UI queries).
* **Flow:**
    1. Gateway receives payload and enqueues the job, generating a unique `request_id`.
    2. Gateway creates an asynchronous subscription to a Redis channel: `result:{request_id}`.
    3. Worker processes the job and publishes the JSON result to `result:{request_id}`.
    4. Gateway receives the payload, closes the subscription, and returns the HTTP `200 OK` response.
* **Accepted Risk:** This holds a FastAPI worker connection open while waiting for the ARQ worker.
* **Mitigation:** To prevent resource starvation, all Pub/Sub await calls enforce a strict `25.0` second timeout, ensuring the connection is dropped before Edge load balancers terminate the request.



---

## 3. Concurrency & State Management

While domains are logically isolated, they share underlying state infrastructure to maintain a DRY codebase.

* **Job Queue & Pub/Sub:** A single Redis instance brokers all ARQ tasks and inter-process Pub/Sub messaging.
* **Persistence (SQLite WAL):** A single SQLite database (operating in Write-Ahead Logging mode) stores unified SSO sessions and domain-specific reconciliation states.
* **Concurrency Mitigation:** Because SQLite serializes writes, highly concurrent worker environments face `SQLITE_BUSY` contention. This is mitigated at the infrastructure level by initializing all `aiosqlite` connections with a `timeout=30.0` parameter, allowing processes to wait for the write lock rather than failing immediately.