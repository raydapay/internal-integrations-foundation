# Architecture & Stack Decisions

> **"Complexity is the enemy of reliability."**

This document outlines the architectural decisions for the PeopleForce-to-Jira Middleware. Every technology choice was made by evaluating **Total Cost of Ownership (TCO)**, **Observability**, and **Concurrency Requirements** specific to a high-latency, event-driven middleware.

---

## 1. Core Runtime & Dependency Management

### **Decision: `uv` (Astral)**
* **Status:** Adopted
* **Alternatives:** Pip, Poetry, Pipenv
* **Rationale:** * **Speed:** `uv` resolves dependencies in milliseconds (Rust-based), whereas Poetry/Pip can take minutes on complex trees. This significantly reduces CI/CD build times.
    * **Determinism:** Provides a universal lock file (`uv.lock`) ensuring identical environments across Dev (Windows) and Prod (Debian/Docker).
    * **Simplicity:** Eliminates the need for separate virtualenv management tools. It is a single binary drop-in.

### **Decision: Python 3.11+**
* **Status:** Adopted
* **Rationale:** * **Performance:** Python 3.11 introduced significant speedups (up to 60%) in the CPython interpreter.
    * **Exception Groups:** Native support for `ExceptionGroup` is critical for handling concurrent errors in `asyncio` tasks (e.g., when polling multiple pages simultaneously).

---

## 2. Static Analysis & Type Safety

### **Decision: `ty` (Astral)**
* **Status:** Adopted
* **Alternatives:** Mypy, Pyright, Pyre
* **Rationale:**
    * **Performance:** Native Rust implementation offering orders-of-magnitude faster type checking compared to Python-based Mypy. This enables "type-check on save" without latency.
    * **Ecosystem Unity:** Part of the Astral toolchain (`uv`, `ruff`, `ty`), reducing the number of disparate configs/parsers in the repo.
    * **Zero Config:** Adheres to the Astral philosophy of sensible defaults, avoiding the "configuration hell" typical of strict Mypy setups.
    * **Reference:** [https://github.com/astral-sh/ty](https://github.com/astral-sh/ty)

### **Decision: `ruff` (Astral)**
* **Status:** Adopted
* **Alternatives:** Black, Flake8, Isort
* **Rationale:**
    * **Performance:** Replaces the entire linting toolchain (Flake8, Black, Isort, Pylint) with a single Rust binary.
    * **Consolidation:** Reduces dev-dependency bloat by providing linting, formatting, and import sorting in one tool.

---

## 3. Asynchronous Framework & Queue

### **Decision: FastAPI + Uvicorn**
* **Status:** Adopted
* **Rationale:**
    * **Native Async:** Built on `Starlette`, allowing non-blocking I/O for network-bound tasks (external API calls to PF/Jira).
    * **Pydantic Integration:** Automated data validation reduces the attack surface and guarantees strict typing for incoming Webhooks.

### **Decision: ARQ (Async Redis Queue)**
* **Status:** Adopted
* **Alternatives:** Celery, RQ (Redis Queue)
* **Rationale:**
    * **Concurrency Model:** Unlike Celery/RQ (which are synchronous and thread/process-based), ARQ is native to `asyncio`. This allows workers to share the same non-blocking `SQLModel` database sessions and HTTP clients (`httpx`) used by the main API.
    * **Overhead:** Celery requires complex configuration (flower, beat, separate workers). ARQ is a lightweight wrapper around `redis-py` (~2k LOC), reducing the maintenance footprint significantly.

---

## 4. HTTP Client

### **Decision: `httpx`**
* **Status:** Adopted
* **Alternatives:** Requests, Aiohttp
* **Rationale:**
    * **Non-Blocking I/O:** Unlike `requests` (synchronous), `httpx` supports `async`/`await`. Using `requests` in a FastAPI route would block the entire Event Loop, causing denial-of-service during high-latency calls to Jira/PeopleForce.
    * **API Parity:** Offers a near-identical API to `requests`, reducing the learning curve.
    * **HTTP/2 Support:** Future-proofs the integration for lower latency connections where supported.

---

## 5. Data Persistence

### **Decision: SQLite (WAL Mode)**
* **Status:** Adopted
* **Alternatives:** PostgreSQL, MySQL
* **Rationale:**
    * **Load Profile:** The system handles <100 RPM (Requests Per Minute). The overhead of managing a separate PostgreSQL container (RAM, CPU, Volume Management, Auth) is unjustified for this throughput.
    * **Concurrency:** Write-Ahead Logging (WAL) mode allows concurrent readers and atomic writes, satisfying the locking requirements for the state-reconciliation engine.
    * **Portability:** The database is a single file. Backups are trivial (file copy), and local development requires zero daemon setup.

### **Decision: SQLModel (SQLAlchemy 2.0)**
* **Status:** Adopted
* **Rationale:**
    * **Unified Schema:** Eliminates the duplication between ORM models (Database) and Pydantic models (Validation). One class defines both.
    * **Async Support:** Built on SQLAlchemy 1.4/2.0+ `asyncio` core, allowing non-blocking database queries (`aiosqlite`).

---

## 6. Frontend Architecture (The "No-Build" Stack)

### **Decision: Jinja2 + Bulma CSS + Vanilla JS**
* **Status:** Adopted
* **Alternatives:** React, Vue, Tailwind (Build-step version)
* **Rationale:**
    * **Total Cost of Ownership:** Eliminates the entire `node_modules` toolchain, Webpack/Vite configuration, and JavaScript vulnerability auditing. The application remains a pure Python artifact.
    * **Performance:** **Jinja2** performs Server-Side Rendering (SSR), delivering fully formed HTML. This is faster for internal dashboards than hydrating a client-side SPA.
    * **Maintenance:** **Bulma** is a modular, class-based CSS framework that does not require a pre-processor (unlike Tailwind CLI), allowing for rapid prototyping via static CSS files.

### **Decision: Tabulator**
* **Status:** Adopted
* **Rationale:**
    * **Data Density:** Provides Excel-like functionality (filtering, sorting, pagination) for high-density log/task views without requiring a React/Virtual-DOM runtime.

### Decision: Bipartite Frontend Data Flow (HTMX + SSE)
* **Status:** Adopted
* **Alternatives:** Strict JSON API with Client-Side Framework (React/Vue), Vanilla JS Imperative DOM Manipulation.
* **Rationale:**
    * **Elimination of State Duplication:** A strict JSON API forces the browser to maintain a secondary state machine (parsing JSON, updating a local store, hydrating the DOM). HTMX relies on HATEOAS (Hypermedia As The Engine Of Application State). The backend remains the single source of truth, returning fully rendered Jinja2 HTML fragments.
    * **Transaction vs. Telemetry:** We strictly divide the data flow. State-mutating transactions (e.g., triggering a sync) use HTMX POSTs to swap HTML fragments (toasts, table rows). Continuous observability (Seq logs, Queue depths) uses Vanilla JavaScript `EventSource` (SSE) for low-overhead, unidirectional telemetry.
    * **Future-Proofing:** HTMX is a dependency-free, HTML-extension library. It is immune to the build-step churn (Webpack/Vite) and declarative syntax deprecations typical of JavaScript micro-frameworks, minimizing Total Cost of Ownership.

---

## 7. Observability

### **Decision: Loguru -> Seq**
* **Status:** Adopted
* **Alternatives:** ELK Stack, SigNoz, Logfire, Datadog
* **Rationale:**
    * **Resource Efficiency:** ELK (Java) and SigNoz (ClickHouse) require 2GB+ RAM idle. Seq runs efficiently in a single Docker container with <200MB RAM.
    * **Structured Logging:** Text logs are useless for debugging distributed sync issues. Seq ingests JSON events, allowing SQL-like querying (e.g., `select * from stream where RequestId = '...'`) to trace a single transaction across the API and Background Workers.
    * **Cost:** Seq is free for single-user/development usage and self-hosted (zero SaaS bill).

---

## 8. Infrastructure & Networking

### **Decision: Cloudflare Tunnels (`cloudflared`)**
* **Status:** Adopted
* **Alternatives:** Ngrok, VPN, Open Inbound Ports
* **Rationale:**
    * **Security:** Eliminates the need to open inbound firewall ports (Port 80/443) to the public internet. The connection is outbound-only.
    * **Persistence:** Unlike free-tier Ngrok (ephemeral URLs), Cloudflare provides stable DNS entries (`pf-jira-sync.todaserv.com`) on our corporate domain.
    * **TLS Termination:** Handles HTTPS certificate management automatically at the Edge.

### **Decision: Docker Compose**
* **Status:** Adopted
* **Rationale:**
    * **Isomorphic Environment:** Guarantees that the Redis version, Seq configuration, and Python runtime are identical on the developer's Windows machine and the eventual Linux production VM.
