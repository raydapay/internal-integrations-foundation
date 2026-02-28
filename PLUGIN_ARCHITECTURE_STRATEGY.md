# Architectural Decision Record 09: Plugin & Connector Topology

> **"Share infrastructure vertically. Isolate workflows horizontally."**

## 🎯 Objective

The Integration Gateway currently suffers from **Monolithic Coupling**. The core infrastructure (`src/app/main.py`, `src/domain/pf_jira/tasks.py`, and `src/templates/base.html`) explicitly imports and hardcodes the PeopleForce-Jira integration.

Adding a new integration (e.g., Pipedrive, Slack bots) currently requires modifying the Gateway's core lifecycle files, increasing the risk of breaking existing integrations or creating deployment bottlenecks.

This document defines the transition to a **Dynamic Plugin Architecture** utilizing a Hexagonal-inspired topology.

**The Mandate:** The Core Gateway must act strictly as an agnostic host environment. It dynamically discovers, loads, and routes traffic to isolated plugin modules while providing a shared pool of stateless API connectors.

------------------------------------------------------------------------

## 🏗️ Core Principles & Constraints

To prevent a tangled dependency graph (where plugins implicitly rely on each other and crash if one is disabled), the system is bifurcated into two strict layers:

### 1. The Vertical Layer: Connectors (The "Ingredients")
* **Definition:** Pure, stateless API wrapper classes (e.g., `JiraClient`, `PeopleForceClient`, `SlackClient`).
* **Location:** `src/connectors/`
* **Constraint:** Connectors must contain **zero business logic**. They handle authentication, rate-limiting, and serialization via the globally shared `HTTPClientManager`. They are universally available to all plugins.

### 2. The Horizontal Layer: Plugins (The "Recipes")
* **Definition:** Isolated modules containing specific business logic, routing rules, webhooks, and ARQ worker tasks (e.g., `pf_jira_sync`).
* **Location:** `src/plugins/`
* **Constraint A (Strict Isolation):** A plugin may import freely from `src/connectors/`, but **a plugin may NEVER import from another plugin**.
* **Constraint B (Namespace Isolation):** To prevent routing collisions, the Plugin Manager forces all plugin webhooks into strict URL prefixes: `/api/webhooks/{plugin.name}/...`.

------------------------------------------------------------------------

## 🗺️ System Topology Pivot

### Current State (Coupled)
```text
src/
  ├── app/main.py         <-- Hardcodes pf_jira routers
  ├── domain/pf_jira/     <-- Tangled domain logic & API clients
  │   └── tasks.py        <-- Hardcodes pf_jira workers into ARQ
```

### Target State (Decoupled & Hexagonal)
```text
src/
  ├── app/main.py             <-- Asks PluginManager for active routers
  ├── core/
  │   ├── plugin.py           <-- Defines BasePlugin interface
  │   └── manager.py          <-- Discovers and loads plugins dynamically
  ├── connectors/             <-- SHARED INFRASTRUCTURE (Ingredients)
  │   ├── jira.py
  │   └── peopleforce.py
  └── plugins/                <-- ISOLATED WORKFLOWS (Recipes)
      ├── pf_jira_sync/       <-- Uses connectors/jira.py
      └── pipedrive_alerts/   <-- Uses connectors/jira.py
```

------------------------------------------------------------------------

## 📜 The Integration Contract (BasePlugin)

Every plugin must inherit from `src.core.plugin.BasePlugin`. This abstract base class enforces a strict schema that the `PluginManager` uses to hook the domain into the Gateway during the FastAPI `lifespan` and ARQ `on_startup` events.

```python
from abc import ABC, abstractmethod
from typing import Callable
from fastapi import APIRouter
from arq.cron import cron

class BasePlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Internal identifier used for routing prefixes (e.g., 'pf_jira')."""
        pass

    def get_admin_routers(self) -> list[APIRouter]:
        """Returns FastAPI routers mounted at /admin/plugins/{name}/"""
        return []

    def get_webhook_routers(self) -> list[APIRouter]:
        """Returns FastAPI routers forcibly mounted at /api/webhooks/{name}/"""
        return []

    def get_worker_functions(self) -> list[Callable]:
        """Returns async functions to register with the ARQ worker pool."""
        return []

    def get_cron_jobs(self) -> list[cron]:
        """Returns ARQ cron schedules (e.g., nightly cache validation)."""
        return []

    def get_admin_menu(self) -> dict[str, str | list[dict]]:
        """Returns metadata for dynamic injection into the Bulma sidebar."""
        return {}
```

------------------------------------------------------------------------

## 🚀 Execution Phases

### Phase 1: The Infrastructure Layer (Connectors)
* **Action:** Extract `JiraClient` and `PeopleForceClient` from the current monolithic domain into the globally accessible `src/connectors/` directory.
* **Verification:** The API wrappers are completely devoid of workflow-specific mapping logic.

### Phase 2: The Contract & Manager (Core)
* **Action:** Create `src/core/plugin.py` (Base interface) and `src/core/manager.py` (Registry).
* **Action:** Modify `src/app/main.py` and `src/domain/pf_jira/tasks.py` (soon to be `src/worker.py`) to dynamically bootstrap from the `PluginManager`.
* **Verification:** Core boots successfully with zero active plugins.

### Phase 3: The `pf_jira` Extraction (Refactor)
* **Action:** Create `src/plugins/pf_jira/`. Move all mapping logic, routers, and specific tasks into this directory, importing clients from `src/connectors/`.
* **Action:** Implement `BasePlugin` inside `src/plugins/pf_jira/plugin.py`.
* **Verification:** The `unittest` regression harness passes at 100%. The system operates identically but is loaded dynamically.

### Phase 4: UI Decoupling (Frontend)
* **Action:** Remove hardcoded "PF ↔ Jira" links from `src/templates/base.html`.
* **Action:** Inject `PluginManager.get_admin_menus()` into the Jinja2 context globally.
* **Verification:** The Admin UI renders the sidebar dynamically based strictly on the active plugin registry.

### Phase 5: Developer Experience (The Demo Plugin)
* **Action:** Create a minimal, non-mutating `src/plugins/demo_plugin/` to serve as a living template.
* **Action:** Write `docs/10-HOW_TO_BUILD_A_PLUGIN.md`.
* **Verification:** A developer can copy the `demo_plugin` directory, rename it, and immediately start writing business logic without reverse-engineering the Gateway core.

------------------------------------------------------------------------

## ✅ Definition of Success
1. **Zero Domain Bleed:** `grep -r "pf_jira" src/app/ src/core/ src/templates/` returns **zero results**.
2. **True Modularity:** Deleting a plugin directory from `src/plugins/` gracefully removes its routes, workers, and UI elements upon restart without throwing `ImportError` or crashing the Gateway.
3. **Namespace Integrity:** Webhook paths are deterministically isolated, eliminating the possibility of routing collisions between competing plugins.
"""