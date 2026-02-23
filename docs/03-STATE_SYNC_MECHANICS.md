# State Synchronization & Webhook Mechanics

> **"Rely on systemic state, not human behavior."**

This document outlines the bi-directional state reconciliation mechanics between PeopleForce and Jira, including the required Jira configuration, the Tick/Yield polling model, and the systemic rationale for rejected alternative approaches.

## 1. The Forward Vector (PeopleForce ➡️ Jira)

The forward vector operates on an asynchronous polling loop (`sync_pf_to_jira_task`) managed by ARQ.

### 1.1 The Tick/Yield Execution Model
Workers operate continuously, but execution intervals are dictated dynamically by a `DomainConfig` lock in SQLite. This decouples the runtime from static environment variables, allowing administrators to pause integrations (`is_active = False`) or adjust polling frequencies without restarting the underlying OS processes.

### 1.2 State Hashing
Because PeopleForce lacks granular webhooks for task mutations, the Gateway maintains a local SQLite table (`SyncState`). Upon fetching a task from PeopleForce, the worker computes a deterministic SHA-256 hash of the task's dictionary representation. If the hash matches the stored `last_sync_hash`, the loop yields, eliminating redundant network I/O to Jira.

### 1.3 Jira Metadata Injection
During Jira issue creation, the worker injects two critical pieces of metadata:
1.  **Folksonomy & Triggers (Labels):** The array `["PeopleForce"]` is appended to the issue's labels.
2.  **Immutable Lineage (Entity Properties):** A hidden JSON object (`pf_sync_metadata`) containing the PeopleForce `task_id` is attached to the issue via Jira's Entity Properties API. This metadata is invisible in the UI and immune to human deletion.

---

## 2. The Return Vector (Jira ➡️ PeopleForce)

The return vector operates via real-time Atlassian System Webhooks intercepted by the FastAPI ingress router.

### 2.1 Webhook Cryptography
The Gateway operates on a Zero-Trust model. All incoming payloads must contain an Atlassian `X-Hub-Signature`. The Gateway computes a constant-time HMAC-SHA256 hash against the raw byte string of the request to prevent timing attacks and serialization drift before passing the payload to the ARQ worker pool.

### 2.2 Jira Webhook Configuration
To establish the return vector, configure the following in Jira Cloud:

1.  Navigate to **Settings (Gear Icon) -> System -> Advanced -> Webhooks**.
2.  Click **Create a WebHook**.
3.  **Name:** `PF-Jira Sync: Task Completion Return Vector`.
4.  **URL:** `https://<YOUR_GATEWAY_DOMAIN>/api/v1/webhooks/jira`.
5.  **Secret:** Input the exact high-entropy string defined in your `JIRA_WEBHOOK_SECRET` environment variable.
6.  **Events:** Under the "Issue" category, check **ONLY** `updated`.
7.  **JQL Filter:** ```jql
    labels = PeopleForce AND statusCategory = Done
    ```

---

## 3. Eventual Consistency (The Zombie Sweeper)

Webhooks are inherently fragile. Network partitions or Gateway downtime can result in lost payloads, leaving tasks completed in Jira but open in PeopleForce (Zombie Tasks).

To guarantee eventual consistency without CPU-bounding the Python workers, an ARQ cron job (`zombie_recovery_task`) executes a daily reverse-vector sweep.

### 3.1 JQL Reverse-Vector Sweep
Instead of iterating over every open task in the local `SyncState` database and querying Jira individually ($O(N)$), the engine executes a single $O(1)$ batch query against Jira: `jql=labels = PeopleForce AND statusCategory = Done AND updated >= -24h`. The results are then intersected against the local SQLite state, and any unresolved issues are delegated to the standard webhook processing pipeline for closure.

---

## 4. Architectural Decisions (The "Negative World")

The following alternative architectures were evaluated and explicitly rejected to minimize Total Cost of Ownership (TCO) and administrative friction.

### 4.1 Rejected: JQL with Hardcoded Projects
* **Proposed:** `project in (HR, IT) AND statusCategory = Done`
* **Why it was rejected:** This couples the Jira infrastructure directly to the Gateway's routing logic. If an administrator adds a new project mapping rule in the Gateway UI (e.g., routing legal tasks to the `LEGAL` project), they would be forced to manually update the Jira Webhook JQL. Relying on the `PeopleForce` label ensures the webhook JQL remains static and universally applicable regardless of downstream project routing.

### 4.2 Rejected: Custom Fields as Triggers
* **Proposed:** Injecting the PeopleForce Task ID into a visible Jira Custom Field and triggering the webhook based on that field's presence.
* **Why it was rejected:** Custom fields impose a high administrative burden. They require manual creation by a Jira Administrator, explicit binding to specific project screens, and continuous maintenance. Labels and Entity Properties are native to the Jira API and require zero UI configuration.

### 4.3 Rejected: Querying Entity Properties via JQL
* **Proposed:** Using the immutable Entity Property for the webhook trigger instead of the fragile `PeopleForce` label: `issue.property[pf_sync_metadata].pf_task_id is not empty`.
* **Why it was rejected:** Atlassian strictly prohibits querying Entity Properties via JQL unless the Jira instance has installed a custom Forge/Connect application with a registered `jira:entityProperty` descriptor to index the JSON fields. Because this Gateway operates as a standalone server rather than an Atlassian App, the JQL parser will reject the query. We must use `labels` for the JQL trigger while retaining the Entity Property for immutable data lineage.

### 4.4 Rejected: Background SQLite Audit Loop
* **Proposed:** A secondary ARQ cron worker that iterates over the `SyncState` database every 24 hours to check if Jira issues were closed without triggering the webhook.
* **Why it was rejected:** Querying Jira iteratively for every open local state creates massive network I/O overhead and increases SQLite WAL locking contention. The JQL Reverse-Vector Sweep (Section 3.1) achieves the same consistency guarantee with a fraction of the network calls.