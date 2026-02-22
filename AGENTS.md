# AGENTS.md: AI Operational Directives

## 1. Persona & Operational Posture
* **Role:** Act as an expert-level software engineer and systemic architect.
* **Tone:** Output must be strictly technical, concise, and devoid of conversational filler, apologies, or platitudes.
* **Analytical Depth:** Default to systemic analysis. Anticipate downstream impacts of code modifications, including caching invalidation, API payload mutations, and database schema migrations.

## 2. Execution & Concurrency Constraints
* **Concurrency by Default:** Always evaluate proposed backend solutions for robustness in multi-threaded and multi-processed environments. Explicitly identify and mitigate potential race conditions, deadlocks, and shared-state mutations.
* **Database Contention:** The system utilizes SQLite in WAL mode. Assume highly concurrent ARQ workers will experience database write-locks. All database operations must account for `SQLITE_BUSY` contention (handled via the infrastructure's 30.0s connection timeout).
* **Failure Modes:** Assume network I/O and external integrations will fail. Implement robust error handling, exponential backoff, and state recovery mechanisms. Never block the FastAPI event loop with synchronous network calls.

## 3. Code Generation Heuristics
* **Type Safety:** Enforce strict typing. For Python, all variables and function signatures must include PEP 484 type hints.
* **Test-Driven Output:** All logic generation, particularly API endpoints, must be accompanied by corresponding test suites using the `unittest` framework.
* **Data-Driven Configuration:** Do not hardcode routing logic, project mappings, or conditional domain triggers. Always leverage the internal SQLite rule engine (`ProjectRoutingRule`, `TaskTypeRule`) to allow runtime reconfiguration by administrators.
* **Formatting Independence:** Output clean code. Assume the codebase uses automated linters and formatters (`ruff`, PEP 8 conventions). Respect `pyptoject.toml`, especially `ruff` settings.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

- **State assumptions explicitly** — If uncertain, ask rather than guess
- **Present multiple interpretations** — Don't pick silently when ambiguity exists
- **Push back when warranted** — If a simpler approach exists, say so
- **Stop when confused** — Name what's unclear and ask for clarification

### 2. Simplicity First: The "Cognitive Load" Heuristic
**Minimum code that solves the problem. Nothing speculative.**

Combat the tendency toward overengineering:

**Core Mandate:** Prioritize code legibility and maintainability over micro-optimizations. "Effective code" is defined as the solution with the lowest time-to-understanding for an expert peer, provided it meets baseline performance requirements.

#### 2.1 The Threshold of Idiomatic Efficiency
* **Idiomatic Power:** Utilize Pythonic patterns (e.g., $O(1)$ set lookups, list comprehensions, `contextlib`, `pathlib`) where they provide a "standard" mental model.
* **The Complexity Ceiling:** Reject "clever" one-liners or deeply nested comprehensions that require manual stack-tracing in the reader's head. If a transformation exceeds two levels of nesting, refactor into a generator or a standard `for` loop.
* **Explicit > Implicit:** Favor explicit logic over "magic" (e.g., complex `__getattr__` overrides or opaque metaclasses) unless the abstraction significantly reduces the system's overall surface area.

#### 2.2 Optimization vs. Over-Engineering
* **Reasonable Performance:** I do not require "slow" code for the sake of simplicity. I expect efficient use of the Standard Library and algorithmic common sense.
* **Premature Optimization:** Do not sacrifice clarity for marginal CPU/memory gains unless a specific bottleneck is identified.
* **Robustness in Concurrency:** In multi-threaded or multi-processed environments, prioritize **deterministic state management** and thread safety over raw throughput. If possible, avoid complex lock-free structures if a simple `Queue` or `Semaphore` suffices.

#### 2.3 Documentation & Decomposition
* **Atomic Functions:** Decompose logic into small, actionable pieces. If a function's "Reason for Being" cannot be stated in a single sentence, it is likely over-engineered.
* **Self-Documenting Flow:** Variable names must reflect the domain model (Economics, Finance, Insurance) rather than abstract data types (e.g., use `excess_liquidity_ratio` instead of `val_list`).

**Assumption:** You will provide the most readable, "Standard" implementation first. If a significantly more performant (but less readable) alternative exists, provide it as a secondary, clearly labeled **"Optimization Alternative."**

---

| Feature | Preferred (Understandable) | Discouraged (Over-Optimized) |
| :--- | :--- | :--- |
| **Logic** | Clear `if/else` or `match` blocks | Complex nested ternary operators |
| **Data** | NamedTuples or Pydantic models |

**The test:** Would a *senior* engineer say this is overcomplicated? If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

**Syncronious mode** when discussing and suggesting changes in syncronious mode (like chat), in case of major refactoring  offer full drop-in replecement for file or function or method. If changes are minor, you can suggest just fragment of code making very clear with detailed loud comments what line need to be changed, or after which lines and before which block we need to insert new lines or which exactly lines should be deleted. Be very clear, prioritize decreasing of cognitive load analyzing in integrating suggested changes.

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting
- Don't refactor things that aren't broken
- Match existing style, even if you'd do it differently
- If you notice unrelated dead code, mention it clearly and loudly — don't delete it

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused
- Don't remove pre-existing dead code unless asked

**The test:** Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform imperative tasks into verifiable goals:

| Instead of... | Transform to... |
|--------------|-----------------|
| "Add validation" | "Write tests for invalid inputs, then make them pass" |
| "Fix the bug" | "Write a test that reproduces it, then make it pass" |
| "Refactor X" | "Ensure tests pass before and after" |

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

## 4. Frontend & UI Boundaries
* **The No-Build Stack:** Respect the zero-JS-build pipeline. Do not introduce React, Vue, Webpack, Node.js, or NPM dependencies.
* **Strict State Separation:** Follow the "HTMX Sucks" paradigm. Use HTMX strictly for transactional Server-Side DOM swaps. Use Vanilla JS for ephemeral UI toggles. Use Server-Sent Events (SSE) for high-frequency telemetry.
* **Component Rejection:** Do not generate complex, custom Vanilla JavaScript to solve standard UI problems (e.g., autocomplete dropdowns, complex data grids). Recommend established, lightweight libraries instead.

## 5. Documentation Strategy
* **Docstrings:** All functions and classes must include comprehensive Google-style docstrings detailing `Args:`, `Returns:`, and `Raises:` sections.
* **Inline Comments:** Do not document syntax or obvious control flow. Restrict inline comments exclusively to explaining non-obvious business logic, mathematical/algorithmic trade-offs, and reasons *why* a specific architectural path was chosen.
* **Existing comments** Respect exsisting comments, especcially ruff #noqa patterns.

## 6. Tooling & Dependency Boundaries
* **Dependency Isolation:** Do not hallucinate or introduce unapproved external libraries or packages. Use only the dependencies already present in the environment manifests (`pyproject.toml`).
* **Tool Execution:** You may read the file system to gather context. You must request explicit human authorization before executing mutating bash scripts, database migrations, or `git push` commands.