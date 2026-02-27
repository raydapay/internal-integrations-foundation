# Plugin Architecture Strategy

## Inversion of Control & Domain Decoupling

------------------------------------------------------------------------

## 🎯 Objective

The Integration Gateway currently suffers from **Monolithic Coupling**. [cite_start]The core infrastructure (`src/app/main.py`, `src/domain/pf_jira/tasks.py`, and `src/templates/base.html`) explicitly imports and hardcodes the PeopleForce-Jira integration.

Adding a new integration (e.g., Pipedrive, Slack bots) currently requires modifying the Gateway's core lifecycle files, increasing the risk of breaking existing integrations.

This document defines the transition to a **Dynamic Plugin Architecture**, where:

> **The Core Gateway knows absolutely nothing about the domains it runs. It acts strictly as a host environment, dynamically discovering, loading, and routing traffic to isolated plugin modules.**

------------------------------------------------------------------------

# Core Principles

1. **Strict Inversion of Control (IoC):** Core files (`main.py`, `tasks.py`) must never import from a plugin domain.
2. **Zero-Touch Core Expansion:** Adding a new integration should only require adding a new folder to `src/plugins/`. No core files should need modification.
3. **Encapsulation:** Plugins must fully encapsulate their own models, routers, worker functions, and UI templates.

------------------------------------------------------------------------

# System Topology Pivot

### Current State (Coupled)
```text
src/
  ├── app/main.py         <-- Hardcodes pf_jira routers
  ├── domain/pf_jira/     <-- Tangled domain logic
  │   └── tasks.py        <-- Hardcodes pf_jira workers into ARQ
```

### Target State (Decoupled)
```text
src/
  ├── app/main.py         <-- Asks PluginManager for active routers
  ├── core/
  │   ├── plugin.py       <-- Defines BasePlugin interface
  │   └── manager.py      <-- Discovers and loads plugins
  ├── plugins/
  │   ├── pf_jira/        <-- Fully isolated plugin
  │   └── pipedrive/      <-- Future plugin
  ```
## The Integration Contract (BasePlugin)

Every plugin must inherit from `src.core.plugin.BasePlugin`. This abstract base class enforces a strict schema that the `PluginManager` uses to hook the domain into the Gateway.

```python
class BasePlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Internal plugin identifier (e.g., 'pf_jira')."""
        pass

    def get_routers(self) -> list[APIRouter]:
        """Returns FastAPI routers (API endpoints, Webhooks, Admin UI)."""
        return []

    def get_worker_functions(self) -> list[Callable]:
        """Returns async functions to register with the ARQ worker pool."""
        return []

    def get_cron_jobs(self) -> list[cron]:
        """Returns ARQ cron schedules (e.g., nightly validation)."""
        return []

    def get_admin_menu(self) -> dict[str, str | list[dict]]:
        """Returns metadata for dynamic injection into the Bulma navigation bar."""
        return {}
```
## Execution Phases

### Phase 1: The Contract & Manager (Core)
* Action: Create `src/core/plugin.py` (Base interface) and `src/core/manager.py` (Dynamic discovery engine using pkgutil or explicit registry).
* Verification: Core boots successfully with zero active plugins.

### Phase 2: Lifecycle Injection (Gateway & ARQ)
* Action: Modify `src/app/main.py` lifespan to iterate over `PluginManager.get_routers()` and dynamically `app.include_router()`.
* Action: Modify `src/domain/pf_jira/tasks.py` (soon to be generic src/worker.py) to dynamically build the `WorkerSettings.functions` and `cron_jobs` lists from the `PluginManager`.
* Verification: The application still boots, though routing is handled dynamically.

### Phase 3: The pf_jira Extraction (Refactor)
* Action: Create `src/plugins/pf_jira/`. Move all models, routers, mapping logic, and specific tasks into this directory.
* Action: Create `src/plugins/pf_jira/plugin.py` implementing the BasePlugin interface.
* Verification: The unittest regression harness passes at 100%. The pf_jira integration operates identically but is loaded dynamically.

### Phase 4: UI Decoupling (Frontend)

* Action: Remove hardcoded "PF ↔ Jira" links from `src/templates/base.html`.
* Action: Inject `PluginManager.get_admin_menus()` into the Jinja2 context globally.
* Action: Use a Jinja2 `{% for plugin in active_plugins %}` loop to generate the sidebar/navbar dynamically.
* Verification: The Admin UI renders the PF-Jira menu natively via the plugin registry.

## Phase 5: Developer Experience (The Demo Plugin)
* **Action:** Create a minimal, non-mutating `src/plugins/demo_plugin/` to serve as a living template.
* **Action:** The demo plugin will register a dummy ARQ task, a simple `/admin/demo` route, and a sidebar menu link.
* **Action:** Write a `docs/09-HOW_TO_BUILD_A_PLUGIN.md` step-by-step guide referencing the demo plugin.
* **Verification:** A developer can read the guide, copy the `demo_plugin` directory, rename it to `pipedrive`, and immediately start writing business logic without reverse-engineering the Gateway.

---

## Definition of Success
* `grep -r "pf_jira" src/app/ src/core/ src/templates/` returns zero results.
* A new developer can add a `slack_bot` plugin purely by creating `src/plugins/slack_bot/plugin.py` without touching the FastAPI application state.

---

