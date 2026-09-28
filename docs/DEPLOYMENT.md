# RansomGuard IR — Deployment Guide

The project splits cleanly into two independently deployable pieces:

| Piece | What it is | Hosting |
|---|---|---|
| **Frontend** | Static SPA (Vite build in `frontend/dist`) | GitHub Pages, Vercel, Netlify, any static host |
| **Backend** | FastAPI + SQLite (Python process) | Your laptop/VM, LAN server, or any PaaS that runs Python (Render/Railway/Fly/Koyeb free tiers) |

> GitHub Pages **cannot** host the FastAPI backend — static hosting serves the UI
> only. For the live demo, run the backend on your laptop and point the frontend
> at it (mock mode also works with no backend at all).

---

## A. Frontend deployment

### Modes (build-time, via env vars)

| Variable | Default | Meaning |
|---|---|---|
| `VITE_USE_MOCK_API` | `true` | `true` = self-contained mock demo (no backend needed) |
| `VITE_API_BASE_URL` | `http://localhost:8000` | Backend URL when `VITE_USE_MOCK_API=false` |
| `VITE_BASE_PATH` | `/` | Base path — set `/<repo-name>/` for GitHub Pages |

### GitHub Pages (automated)

A workflow is included: [.github/workflows/deploy-frontend.yml](../.github/workflows/deploy-frontend.yml).

1. Push the repository to GitHub.
2. **Settings → Pages → Build and deployment → Source: "GitHub Actions".**
3. Push to `main` (or run the workflow manually via **Run workflow**).
4. The site is served at `https://<user>.github.io/<repo-name>/`.

The workflow:
- reads the **repository name automatically** (no hardcoded repo name),
- builds with `VITE_BASE_PATH=/<repo-name>/` and copies `index.html` to
  `404.html` so `BrowserRouter` deep links (`/incidents`, `/incidents/RAN-2026-001`)
  work on Pages,
- defaults to **mock mode** — a fully clickable demo with zero backend setup.

**Live backend on Pages:** set repository *Variables* (Settings → Secrets and
variables → Actions → Variables → New repository variable):
- `FRONTEND_USE_MOCK_API` = `false`
- `BACKEND_PUBLIC_URL` = `https://<your-deployed-backend>` (must be reachable
  over HTTPS from browsers; re-run the workflow after changing).

### Vercel / Netlify (root hosting)

Import the repository, set:
- Root directory: `frontend`
- Build command: `npm run build` · Output directory: `dist`
- Env vars as needed (`VITE_USE_MOCK_API=false`, `VITE_API_BASE_URL=https://<backend>`)

Root hosting serves the SPA from `/`, so the default base path works and no
`404.html` trick is needed (both platforms rewrite unknown routes to `index.html`
with the standard SPA rewrite rule).

### Manual static hosting

```bash
cd frontend
npm run build            # → dist/
# host dist/ on any static server with SPA fallback to index.html
```

---

## B. Backend deployment

Configuration is environment-driven (see [`backend/.env.example`](../backend/.env.example)):

| Variable | Default |
|---|---|
| `HOST` / `PORT` | `0.0.0.0` / `8000` |
| `CORS_ORIGINS` | `*` (comma-separated list for restricted deployments) |
| `RANSOMGUARD_DB_PATH` | `backend/ransomguard.db` |
| `DETECTION_COOLDOWN_SECONDS` | `300` |

### Local / LAN (recommended for the demo)

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The VM detector reaches it on the host's LAN IP (`http://<host-ip>:8000`);
the dashboard on the same host uses `http://localhost:8000`.

### Free PaaS (Render / Railway / Fly / Koyeb)

Any service that runs a Python process works — no vendor config files are needed:

- **Start command:** `python -m app.main` (reads the provider-injected `PORT`)
  from the `backend/` directory, or `python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Build command:** `pip install -r requirements.txt`
- Set `CORS_ORIGINS` to your frontend origin (e.g. `https://<user>.github.io`).
- SQLite lives on the service's filesystem; set `RANSOMGUARD_DB_PATH` to a
  persistent mount if the platform offers one (otherwise the demo DB resets on
  redeploy — acceptable for this demo).
- Then point the frontend's `VITE_API_BASE_URL` at the public URL.

⚠️ The deployed backend is a **demo instance** — it has no authentication. Do not
expose it to the public internet with sensitive data; keep it for reviews.

---

## C. VM detector distribution

A ready-to-copy package lives in [`release/vm-agent/`](../release/vm-agent/):
copy it to the VM, create `config.ini` from `config.example.ini` (set the
backend URL), and run `start-agent.bat`. See its `README.txt`.
