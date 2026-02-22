# Architectural Decision Record: Routing & State Recovery

> **"Route linearly. Fail gracefully. Self-heal automatically."**

This document outlines the design of the Gateway's internal routing engine and its state-recovery mechanisms for handling upstream data corruption (Ghost Records).

## 1. The Routing Engine (The Firewall Model)

### **The Problem**
As integration rules scale, administrators need to route tasks based on multiple factors (e.g., "If assignee is IT *AND* title contains 'onboarding'"). The standard approach is to build a Boolean Abstract Syntax Tree (AST) engine.

### **The Decision: Rejected AST in favor of Linear Priority**
We explicitly rejected building a nested boolean logic engine.
* **Why:** Evaluating recursive JSON logic graphs CPU-bounds the Python workers, increasing Redis lock contention. Furthermore, building a web UI for nested AND/OR/NOT blocks violates our strict zero-JS-build (HTMX) frontend paradigm.
* **The Solution (The Firewall Model):** We unified `ProjectRoutingRule` and `TaskTypeRule` into a single `RoutingRule` table. Rules are evaluated in a strict, linear O(N) sequence based on a `priority` integer (exactly like an AWS Network ACL or firewall).
* **Execution:** A single rule acts as an implicit `AND` across its conditions. Multiple rules act as an implicit `OR` across the system. The evaluator yields on the first match, resulting in highly deterministic and low-latency dispatching.

## 2. Ghost Records & Self-Healing State

### **The Problem (The 404 Edge Case)**
The integration relies on a local SQLite `SyncState` ledger to compute deltas. If a user manually deletes an issue in Jira (or a task in PeopleForce) directly via the vendor UI, the local database is unaware. This creates a "Ghost Record". When the ARQ worker attempts to mutate that deleted entity, the upstream API returns an HTTP `404 Not Found`.

### **The Decision: Catastrophic Intercept & Purge**
By default, ARQ workers raise exceptions on HTTP errors, placing the job into an exponential backoff loop.
* **The Solution:** We explicitly catch `httpx.HTTPStatusError` during mutation phases (`update_issue` and `complete_task`). If the status code is strictly `404`, the worker **purges** the local `SyncState` ledger entry, logs an `ERROR` to the `SyncAuditLog`, and gracefully yields.
* **The Result:** On the next polling cycle, the Gateway evaluates the entity as entirely new, effectively self-healing the state discrepancy by re-creating the missing downstream ticket.