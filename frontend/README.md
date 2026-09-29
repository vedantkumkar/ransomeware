# RansomGuard IR
### Automated Ransomware Containment & Incident Response Orchestrator

A professional enterprise-grade Security Operations Center (SOC) dashboard for automated ransomware detection, containment, and incident response orchestration.

> **Status:** Frontend only — defaults to **mock mode** and runs without any backend. A Python/FastAPI backend will be connected later.

---

## Features

- **Dashboard** — Real-time SOC overview with active incident monitoring, response performance metrics, and incident trend charts
- **Incidents** — Full incident list with severity/status filtering, search, and sorting
- **Incident Details** — Deep-dive view with affected endpoint info, threat details, risk score breakdown, automated response timeline, and analyst action controls
- **Endpoints** — Endpoint inventory with agent status, network isolation state, and risk scoring
- **Evidence & Forensics** — Evidence packages with SHA-256 hashes, integrity verification, and chain of custody
- **Activity Log** — Chronological SOC audit trail of automated and manual actions
- **Settings** — Detection policy thresholds and automation toggles (demo mode)

## Tech Stack

- React 19 + TypeScript
- Vite 7
- Tailwind CSS v4
- shadcn/ui (new-york style)
- Lucide React icons
- Recharts (charts)
- React Router (navigation)
- Sonner (toasts)

## Getting Started

```bash
# Clone the repository
git clone <repository-url>
cd <project-folder>

# Install dependencies
npm install

# Start the dev server
npm run dev
```

The app runs at `http://localhost:5173` by default.

## npm Commands

| Command | Description |
|---------|-------------|
| `npm run dev` | Start Vite dev server |
| `npm run build` | Type-check and build for production |
| `npm run preview` | Preview the production build locally |
| `npm run typecheck` | Run TypeScript type checking |

## Project Structure

```
src/
  components/       # Reusable UI components (sidebar, topbar, badges, risk score)
    ui/             # shadcn/ui component primitives
  pages/            # Route-level page components
  layouts/          # Layout wrappers (app shell with sidebar + topbar)
  services/         # API service layer (api.ts — future backend integration point)
  data/             # Mock data for incidents, endpoints, evidence, etc.
  types/            # TypeScript interfaces and type definitions
  hooks/            # Custom React hooks
  lib/              # Utility functions
```

## Mock Data

All data is currently mocked in `src/data/mockData.ts`. The primary demonstration incident is:

- **Incident:** RAN-2026-001
- **Host:** VICTIM-PC-01 (192.168.56.105)
- **User:** demo-user
- **Process:** DemoRansomware.exe
- **Risk Score:** 96/100 (Critical)
- **Status:** Contained

This corresponds to a Windows VM ransomware simulation scenario.

## Data Access & Mock/API Mode

All runtime data access goes through **`src/services/api.ts`**. Pages and components never import mock data directly.

- `VITE_USE_MOCK_API=true` (default) → data comes from `src/data/mockData.ts`; the app runs fully standalone.
- `VITE_USE_MOCK_API=false` → the service layer issues real HTTP requests to the FastAPI backend at `VITE_API_BASE_URL` (not implemented yet).

If the environment variables are absent, the app safely defaults to mock mode.

## Backend Integration

The frontend is architected so a Python FastAPI backend can be connected **without redesigning the UI** — only the service layer in `src/services/api.ts` talks to the network.

1. **Environment:** Copy `.env.example` to `.env` and set:
   ```
   VITE_USE_MOCK_API=false
   VITE_API_BASE_URL=http://localhost:8000
   ```

2. **Expected Endpoints:**
   ```
   GET  /api/health
   GET  /api/dashboard
   GET  /api/incidents
   GET  /api/incidents/{incident_id}
   GET  /api/incidents/{incident_id}/evidence
   GET  /api/incidents/{incident_id}/timeline
   GET  /api/endpoints
   GET  /api/endpoints/{endpoint_id}
   GET  /api/evidence
   GET  /api/activity
   GET  /api/notifications

   POST /api/incidents/{incident_id}/isolate
   POST /api/incidents/{incident_id}/release
   POST /api/incidents/{incident_id}/suspend-user
   POST /api/incidents/{incident_id}/collect-evidence
   POST /api/incidents/{incident_id}/false-positive
   POST /api/incidents/{incident_id}/close
   ```

   The VM detector agent later reports detections via `POST /api/events/detection` — the frontend does **not** call that endpoint.

3. **No UI changes needed:** Components consume typed models (`Incident`, `Endpoint`, `EvidenceItem`, `TimelineEvent`, `DashboardStats`, `Alert`, `ActivityLogEntry`, …) from `src/types/` via the service layer. In mock mode, analyst actions simulate success, update frontend state, and append entries to the activity log.

## Deployment

The app builds to static files in `dist/` and can be deployed to GitHub Pages, Vercel, or Netlify.

```bash
npm run build    # outputs to dist/
npm run preview  # preview locally
```

Vercel and Netlify serve the SPA from the domain root, so the default configuration works as-is. **GitHub Pages** serves the app from a subpath (`/<repository-name>/`), so once the repository name is known, set `base: '/<repository-name>/'` in `vite.config.ts` (and use a 404.html redirect copy for `BrowserRouter` deep links, or switch to `HashRouter` if you prefer zero server config). No repository-specific base path is hardcoded now, so local/Vercel/Netlify behavior is unaffected.

No API keys or secrets are required. The app works immediately after cloning.

## Notes

- Dark theme is the default (enterprise SOC aesthetic)
- A light/dark toggle is available via the theme system
- All analyst actions (isolate, release, suspend, etc.) are simulated frontend-only
- No real backend, database, or external services are used
