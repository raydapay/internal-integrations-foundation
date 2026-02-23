# Architectural Decision Record: Routing & State Recovery

> **"Route linearly. Fail gracefully. Self-heal automatically."**

This document outlines the design of the Gateway's internal routing engine and its bi-modal state-recovery mechanisms for handling data corruption and network partitions.

## 1. The Routing Engine (The Firewall Model)

### **The Problem**
As integration rules scale, administrators need to route tasks based on multiple factors (e.g., "If assignee is IT *AND* title contains 'onboarding'"). The standard approach is to build a Boolean Abstract Syntax Tree (AST) engine.

### **The Decision: Rejected AST in favor of Linear Priority**
We explicitly rejected building a nested boolean logic engine.
* **Why:** Evaluating recursive JSON logic graphs CPU-bounds the Python workers, increasing Redis lock contention. Furthermore, building a web UI for nested AND/OR/NOT blocks violates our strict zero-JS-build (HTMX) frontend paradigm.
* **The Solution (The Firewall Model):** We unified `ProjectRoutingRule` and `TaskTypeRule` into a single `RoutingRule` table. Rules are evaluated in a strict, linear O(N) sequence based on a `priority` integer (exactly like an AWS Network ACL or firewall).
* **Execution:** A single rule acts as an implicit `AND` across its conditions. Multiple rules act as an implicit `OR` across the system. The evaluator yields on the first match, resulting in highly deterministic and low-latency dispatching.

---

## 2. State Recovery & Eventual Consistency

State fragmentation occurs across two primary vectors. The system implements specific, isolated recovery mechanisms for each.

### 2.1 Forward Vector Failure: Ghost Records (The 404 Edge Case)
**The Problem:** The integration relies on a local SQLite `SyncState` ledger to compute deltas. If a user manually deletes an issue directly via the Jira UI, the local database creates a "Ghost Record". When the ARQ worker attempts to mutate that deleted entity, the upstream API returns an HTTP `404 Not Found`.

**The Solution: Catastrophic Intercept & Purge**
By default, ARQ workers raise exceptions on HTTP errors, placing the job into an exponential backoff loop. We explicitly catch `httpx.HTTPStatusError` during mutation phases (`update_issue` and `complete_task`). If the status code is strictly `404`, the worker **purges** the local `SyncState` ledger entry, logs an `ERROR` to the `SyncAuditLog`, and gracefully yields. On the next polling cycle, the Gateway evaluates the entity as entirely new, self-healing the state by re-creating the missing downstream ticket.

### 2.2 Return Vector Failure: Zombie Tasks (Webhook Loss)
**The Problem:** Webhooks from Jira to the Gateway can be dropped due to network partitions, DNS failures, or Gateway deployments. This leaves tasks marked as 'Done' in Jira but forever 'Open' in PeopleForce.

**The Solution: The Nightly Sweeper**
To bridge the eventual consistency gap, an ARQ cron job executes a nightly reverse-vector search against the Jira API (`jql=labels = PeopleForce AND statusCategory = Done AND updated >= -24h`). It intersects these recently closed issues with the local `SyncState` ledger. Any local states still marked `is_completed=False` are instantly delegated to the webhook processor, forcibly closing the orphaned tasks in PeopleForce.