# PeopleForce <-> Jira Middleware

An asynchronous, fault-tolerant middleware designed to synchronize tasks between PeopleForce (HRIS) and Jira. It overcomes the limitations of the PeopleForce API (lack of webhooks, no delta sync) by implementing a state-reconciliation engine with distributed locking.

## ⚡ Technical Stack

* **Runtime:** Python 3.11+ (managed by `uv`)
* **Framework:** FastAPI + Uvicorn
* **Concurrency:** AsyncIO + ARQ (Redis-backed Job Queue)
* **Database:** SQLite (WAL Mode) via SQLModel (SQLAlchemy 2.0)
* **Observability:** Loguru (Logger) -> Seq (Log Aggregation & Dashboarding)
* **Infrastructure:** Docker Compose + Cloudflare Tunnels

## 🚀 Quick Start

### 1. Prerequisites
* [Docker Desktop](https://www.docker.com/) (or Engine)
* [UV](https://github.com/astral-sh/uv) (Fast Python Package Manager)

### 2. Installation
Initialize the environment and install dependencies instantly:
```bash
uv sync
```

### 3. Configuration
Create a secret configuration file:
```bash
cp secrets/.env.example secrets/.env
# Edit secrets/.env with your API keys
```

### 4. Running the Stack
Launch the Application, Redis, and Seq:
```bash
docker compose up -d
```
* **API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
* **Log Dashboard (Seq):** [http://localhost:5341](http://localhost:5341)

## 🏗 Architecture

### Directory Structure
* `src/core`: Database, Logging, and Security configuration.
* `src/domain`: Feature modules (Sync logic, Webhooks, Auth).
* `src/app`: Entry points and Middleware.

### Queue System (ARQ)
We use **ARQ** for background processing to avoid blocking the FastAPI event loop during heavy I/O (e.g., polling PeopleForce).
* **Producer:** FastAPI routes push jobs to Redis.
* **Consumer:** ARQ worker process executes jobs (configured in `src/app/worker.py`).

## 🌐 Cloudflare Tunnel Setup (Webhooks)

To receive `jira:issue_updated` events on your local machine without opening ports:

1.  **Install `cloudflared`:**
    ```bash
    # Debian/Ubuntu
    sudo apt-get update && sudo apt-get install cloudflared
    ```

2.  **Authenticate & Create Tunnel:**
    ```bash
    cloudflared tunnel login
    cloudflared tunnel create pf-jira-sync
    cloudflared tunnel route dns pf-jira-sync dev-sync.yourdomain.com
    ```

3.  **Configure Ingress (`~/.cloudflared/config.yml`):**
    ```yaml
    tunnel: <UUID>
    credentials-file: /home/<user>/.cloudflared/<UUID>.json
    ingress:
      - hostname: dev-sync.yourdomain.com
        service: [http://127.0.0.1:8000](http://127.0.0.1:8000)
      - service: http_status:404
    ```

4.  **Run:**
    ```bash
    cloudflared tunnel run pf-jira-sync
    ```