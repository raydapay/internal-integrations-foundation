# Integration Gateway

An asynchronous, fault-tolerant middleware foundation designed to broker state-reconciliation, webhook ingestion, and API synchronization across disparate SaaS platforms.

Originally conceived as a PeopleForce-to-Jira bridge, the system has evolved into a generalized **Federated Gateway / Isolated Worker** architecture, providing a robust backplane for all future internal integrations.

## 🏗️ Architectural Paradigm

The system is strictly divided into two execution tiers to prevent I/O blocking and enforce domain isolation (see [`docs/01-SYSTEM_TOPOLOGY.md`](docs/01-SYSTEM_TOPOLOGY.md) for deeper systemic analysis):

1. **The Unified Gateway (FastAPI):** Handles TLS termination, Google Workspace SSO, schema validation, and serving the Admin Dashboard via Jinja2 Server-Side Rendering (SSR).
2. **Isolated Domain Workers (ARQ):** Background `asyncio` processes that execute third-party API communication, state-reconciliation hashing, and database mutations over Redis queues.

## 🛠️ Technical Stack

Every technology choice was optimized for minimal Total Cost of Ownership (TCO) and high observability (see [`docs/02-TOOLING_DECISIONS.md`](docs/02-TOOLING_DECISIONS.md)).

* **Runtime:** Python 3.11+ (managed exclusively by `uv`)
* **Framework:** FastAPI + Uvicorn
* **Concurrency:** AsyncIO + ARQ (Redis-backed Job Queue)
* **Database:** SQLite (WAL Mode) via SQLModel (SQLAlchemy 2.0)
* **Frontend (No-Build):** Jinja2, HTMX (Transactional HATEOAS), Bulma CSS, Vanilla JS Server-Sent Events (SSE)
* **Observability:** Loguru (JSON Logger) -> Seq (Log Aggregation), `psutil` (Hardware Telemetry)

## 🚀 Core Features

* **Zero-JS-Build Admin UI:** A fully functional dashboard utilizing HTMX for DOM mutations and SSE for real-time Cloudflare-proof log streaming. No React, Webpack, or Node.js required.
* **Google SSO Security:** Edge-level access control via Authlib and session middleware.
* **Dynamic Mapping Engine:** SQLite-backed routing rules allowing administrators to map incoming SaaS webhooks to specific target systems without deploying code.
* **State Reconciliation:** Distributed locking and SHA-256 state hashing to detect API deltas when native vendor webhooks are unavailable.

## 🚦 Quick Start

### 1. Prerequisites
* [Docker Desktop](https://www.docker.com/) (for Redis and Seq)
* [UV](https://github.com/astral-sh/uv) (Extremely fast Python package manager)

### 2. Installation
Initialize the environment and sync the lockfile:
```bash
uv sync
```

### 3. Configuration
Duplicate the example environment file and populate your Google Auth, Jira, and PeopleForce credentials:
```bash
cp secrets/.env.example secrets/.env
```

### 4. Running the Stack (Local Bare-Metal execution)
To leverage rapid hot-reloading during development, run the infrastructure in Docker, but execute the Python processes natively:

**Terminal 1 (Infrastructure):**
```bash
docker compose up redis seq -d
```

**Terminal 2 (The Gateway):**
```bash
uv run uvicorn src.app.main:app --reload
```

**Terminal 3 (The Domain Worker):**
```bash
uv run arq src.domain.pf_jira.tasks.WorkerSettings --watch src
```

* **Integration Dashboard:** [http://localhost:8000/admin](http://localhost:8000/admin)
* **Log Aggregation (Seq):** [http://localhost:5341](http://localhost:5341)

## 🏗️ Architectural Paradigm

The system is strictly divided into two execution tiers to prevent I/O blocking and enforce domain isolation (see [`docs/01-SYSTEM_TOPOLOGY.md`](docs/01-SYSTEM_TOPOLOGY.md) for deeper systemic analysis).

*For a detailed breakdown of the synchronization polling, webhook cryptography, and Jira configuration, see [`docs/03-STATE_SYNC_MECHANICS.md`](docs/03-STATE_SYNC_MECHANICS.md).*

## 📂 Project Structure

```text
├── data/                  # SQLite WAL database files (gitignored)
├── docs/                  # Architectural Decision Records (ADRs)
├── secrets/               # Environment variables and OAuth JSONs
├── src/
│   ├── app/               # FastAPI ingress, Admin UI routes, Lifespan
│   ├── config/            # Pydantic BaseSettings
│   ├── core/              # Global dependencies (Clients, DB, Broadcaster)
│   ├── domain/            # Isolated business logic boundaries
│   │   ├── pf_jira/       # PeopleForce <-> Jira reconciliation
│   │   ├── users/         # SSO and Identity models
│   │   └── webhooks/      # Ingress payload routing
│   ├── static/            # Bulma custom CSS & SSE Vanilla JS
│   └── templates/         # Jinja2 Layouts and HTMX partial fragments
└── tests/                 # Unittest suites (E2E and Mocks)
```