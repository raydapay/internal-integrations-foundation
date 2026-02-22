# Frontend Strategy: The "HTMX Sucks" Paradigm

> **"Render on the server. Mutate on the client. Stream the telemetry."**

This application utilizes a strict "No-Build" frontend architecture to minimize Total Cost of Ownership (TCO). It relies on Jinja2, HTMX, Bulma CSS, and Vanilla JS.

To prevent architectural degradation, this document enforces the [HTMX Sucks](https://htmx.org/essays/htmx-sucks/) paradigm, clearly defining the operational boundaries for each technology.

## 1. Transactional State (The HTMX Boundary)
HTMX is used **exclusively** for executing transactions where the server is the absolute source of truth.
* **Permitted:** Submitting database forms (e.g., creating a new routing rule), paginating server-side data, or triggering background worker tasks.
* **Mechanism:** HTMX issues an asynchronous POST/GET request and swaps the resulting Jinja2 HTML fragment directly into the DOM (Hypermedia As The Engine Of Application State).
* **Prohibited:** Using HTMX for ephemeral UI state. Do not trigger network requests to toggle a modal, open a dropdown, or filter a list of elements already present in the DOM.

## 2. Ephemeral State (The Vanilla JS Boundary)
Vanilla JavaScript is used **exclusively** for transient, client-side UI interactions that do not require server validation.
* **Permitted:** Toggling Bulma `.is-active` CSS classes on modals/dropdowns, client-side table sorting (e.g., via Tabulator), or basic DOM event listeners.
* **Prohibited:** Re-implementing complex UI components from scratch. If an interactive component (like an autocomplete searchable dropdown) requires significant custom Vanilla JS, the implementation must be rejected in favor of an established, dependency-light library (e.g., Tom Select, Choices.js).

## 3. Telemetry & Observability (The SSE Boundary)
Server-Sent Events (SSE) via the native browser `EventSource` API are used for all real-time, unidirectional telemetry.
* **Permitted:** Streaming log aggregates from Loguru/Seq, updating ARQ queue depths, or visualizing active worker heartbeats.
* **Mechanism:** The server holds an open HTTP connection and pushes JSON/Text payloads. A lightweight Vanilla JS listener parses the payload and imperatively updates the DOM.
* **Prohibited:** Using HTMX polling (`hx-trigger="every 1s"`) for high-frequency data streams. Polling introduces massive HTTP overhead, connection thrashing, and exhausts Uvicorn worker threads.