# UI Latency Strategy

## Instant Interaction & I/O Isolation Architecture

------------------------------------------------------------------------

## 🎯 Objective

The current admin UI experiences perceptible latency (1--2s spikes)
caused by:

-   Blocking external I/O (Jira APIs, Redis, ARQ lifecycle)
-   Worker queue scheduling delays
-   Metadata cache misses triggering live schema fetches
-   Tight coupling between UI actions and background validation

This document defines the transition to an **Ultra-Responsive UI
architecture**, where:

> **Every click reacts instantly (\<50ms perceived), and all heavy work
> is decoupled from the request-response cycle.**

The UI must never block on network, workers, or cache warmups.

------------------------------------------------------------------------

# Core Principles

1.  UI must respond instantly to user interaction.
2.  No external I/O may block admin routes.
3.  All metadata must be served from cache or lazy-hydrated.
4.  Validation and heavy work must run asynchronously.
5.  Cold-start latency must never freeze the interface.

------------------------------------------------------------------------

# Phase 0 --- Non-Negotiable Rule

## ❗ No External I/O in Synchronous Admin Routes

Admin endpoints must not:

-   Call Jira APIs
-   Fetch createmeta from upstream
-   Block waiting for ARQ jobs
-   Warm caches synchronously
-   Wait for Redis pub/sub confirmation

If external I/O is required: - Use cached data - Or return immediately
and hydrate asynchronously

------------------------------------------------------------------------

# Phase 1 --- Instant Click Feedback

## Goal

Every click produces visible feedback immediately (0ms perceived
latency).

## Required Behaviors

-   Buttons enter loading state on click (before network request).
-   Buttons disable immediately to prevent double submit.
-   Modals render instantly.
-   Save operations show optimistic UI updates when safe.

------------------------------------------------------------------------

# Phase 2 --- Modal Skeleton Architecture

## Problem

The Create Routing Rule and Edit Routing Rule modals currently trigger
live metadata hydration before rendering, causing blocking delays.

## Goal

Modal frame renders instantly. All dynamic content loads after display.

## Architecture

### Modal Shell (DB-only)

Route returns: - Static rule fields (priority, action, conditions) -
Empty selects with loading placeholders

It does NOT call Jira.

### Lazy Hydration Fragments

Dynamic sections load independently using HTMX with hx-trigger="load".

Each fragment: - Reads from cache - Never blocks on upstream - Triggers
background refresh if stale

------------------------------------------------------------------------

# Phase 3 --- Multi-Layer Metadata Caching

## Goal

Jira metadata must never be fetched during interactive UI flow.

## Cache Layers

Layer 1: In-memory (per process)\
Layer 2: Redis\
Layer 3: Jira (background only)

Requests may use Layer 1 or 2 only.

------------------------------------------------------------------------

## Stale-While-Revalidate Strategy

1.  Always serve cached value (even if expired).
2.  Trigger async refresh in background.
3.  Replace cache once refreshed.

------------------------------------------------------------------------

# Phase 4 --- Worker Isolation (UI Fast Lane)

## Problem

ARQ queue delays create unpredictable UI latency when workers are busy.

## Goal

UI-triggered tasks must never wait behind heavy background jobs.

## Solution

Dedicated UI queue: - Queue name: ui_fast - Dedicated worker process -
High concurrency - Strict runtime limit

Rules: - UI queue must not call external APIs. - Heavy validation uses
default queue. - UI may enqueue heavy job but must not await completion.

------------------------------------------------------------------------

# Phase 5 --- Decouple Rule Save from Validation

## Target Flow

1.  Save rule to DB instantly.
2.  Return success response immediately.
3.  Background job validates schema.
4.  Rule row displays status badge (Valid / Validating / Invalid).

UI must not block on validation.

------------------------------------------------------------------------

# Phase 6 --- Predictive Prewarming

On admin page load silently prefetch:

-   jira_projects
-   issue_type_map
-   createmeta for most-used pairs

When user opens modal → metadata already warm.

------------------------------------------------------------------------

# Phase 7 --- SSE Reactive Feedback

Replace polling-based validation with SSE for:

-   Real-time status updates
-   Reduced server load
-   Smoother UX

------------------------------------------------------------------------

# Phase 8 --- I/O Control Panel

Add /admin/io section with:

## 🧹 Purge Metadata Cache

Clears: - jira_projects - issue_type_map - createmeta cache

Non-blocking background task.

## 🔄 Force Metadata Refresh

Triggers immediate metadata refresh.

## 📊 Cache Diagnostics

Display: - Total cache keys - Hit ratio - Last refresh timestamp -
Memory usage

------------------------------------------------------------------------

# Phase 9 --- Micro-UX Stability

-   Avoid full-table re-renders (row-level swaps only)
-   Preserve scroll position
-   Prevent layout shift inside modals
-   Reserve height for schema sections
-   Use subtle CSS transitions (\<150ms)

------------------------------------------------------------------------

# Phase 10 --- Instrumentation & Metrics

Track:

-   Modal open duration (p50 / p95)
-   Rule save duration
-   Queue wait time
-   Cache hit ratio
-   createmeta load time

------------------------------------------------------------------------

# Definition of Success

-   Opening modal consistently \<60ms.
-   Saving rule consistently \<50ms.
-   Cold metadata does not freeze UI.
-   Queue load does not impact responsiveness.
-   External API latency never blocks interface.

The UI must behave as if:

-   Jira is local.
-   Workers are idle.
-   Redis is in-memory.
-   Network latency does not exist.

Even when it does.
