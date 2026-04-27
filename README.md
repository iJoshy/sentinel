# Sentinel

**Production:** [https://d2ffskcz761exz.cloudfront.net/](https://d2ffskcz761exz.cloudfront.net/)

**Sentinel** is an AI-powered incident intelligence platform. It turns raw logs and incident narratives into structured analysis—summaries, severity, likely root cause, evidence-grounded remediation, and exportable reports—so teams can respond faster with less manual triage.

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+"></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/FastAPI-API-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI"></a>
  <a href="https://docs.pydantic.dev/"><img src="https://img.shields.io/badge/Pydantic-v2-E92063?style=flat-square&logo=pydantic&logoColor=white" alt="Pydantic v2"></a>
  <a href="https://docs.astral.sh/uv/"><img src="https://img.shields.io/badge/uv-astral-915CFF?style=flat-square&logo=uv&logoColor=white" alt="uv"></a>
  <a href="https://pytest.org/"><img src="https://img.shields.io/badge/tests-pytest-0A9EDC?style=flat-square&logo=pytest&logoColor=white" alt="pytest"></a>
  <a href="https://nextjs.org/"><img src="https://img.shields.io/badge/Next.js-14-000000?style=flat-square&logo=nextdotjs&logoColor=white" alt="Next.js 14"></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React 18"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-LTS-339933?style=flat-square&logo=nodedotjs&logoColor=white" alt="Node.js"></a>
  <a href="https://clerk.com/"><img src="https://img.shields.io/badge/Clerk-auth-6C47FF?style=flat-square&logo=clerk&logoColor=white" alt="Clerk"></a>
  <a href="https://www.terraform.io/"><img src="https://img.shields.io/badge/Terraform-IaC-844FBA?style=flat-square&logo=terraform&logoColor=white" alt="Terraform"></a>
  <a href="https://aws.amazon.com/"><img src="https://img.shields.io/badge/AWS-cloud-FF9900?style=flat-square&logo=amazonaws&logoColor=white" alt="AWS"></a>
  <a href="https://mermaid.js.org/"><img src="https://img.shields.io/badge/Mermaid-diagrams-FF3670?style=flat-square&logo=mermaid&logoColor=white" alt="Mermaid"></a>
  <a href="https://recharts.org/"><img src="https://img.shields.io/badge/Recharts-2.12-8884d8?style=flat-square" alt="Recharts"></a>
</p>

## Architecture

### Architecture overview

Sentinel uses an **event-driven, serverless** layout on AWS. Operators use the **CloudFront-hosted Next.js** dashboard; traffic goes through **API Gateway** to the **Lambda API**, which persists **incidents, jobs, and analysis** in **Aurora Serverless** and enqueues work on **SQS**. The **Planner Lambda** runs the pipeline (**normalizer → summarizer → investigator → remediator**). **Amazon Bedrock** powers the heavy reasoning steps, and the **App Runner Intel service** adds supporting analysis. Results are stored and surfaced back in the dashboard for visualization and reporting.

### Diagram

![Sentinel Architecture](assets/sentinel-architecture.png)

### Local development

For day-to-day work, the UI and API run on your machine; the database is typically SQLite unless you point the app at Aurora.

```mermaid
graph LR
  subgraph Local["Local dev"]
    UI[Next.js]
    API[FastAPI]
    DB[(SQLite / Aurora)]
  end
  UI --> API
  API --> DB
```

Deeper reference: [guides/architecture.md](guides/architecture.md), [guides/agent_architecture.md](guides/agent_architecture.md), and [intel.md](intel.md).

**Agent roles** (see [AGENTS.md](AGENTS.md)):

| Module | Role |
|--------|------|
| **Planner** | Orchestrates the incident analysis flow |
| **Normalizer** | Cleans input, guardrails, evidence snippets |
| **Summarizer** | Short narrative + severity |
| **Investigator** | Root-cause analysis (strong model; Nova Pro in AWS guidance) |
| **Remediator** | Remediation plan and next steps (strong model) |

---

## Table of contents

- [Architecture](#architecture)
- [Why Sentinel](#why-sentinel)
- [What you get](#what-you-get)
- [Repository layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Running locally](#running-locally)
- [API overview](#api-overview)
- [Frontend](#frontend)
- [Bulk ZIP upload](#bulk-zip-upload)
- [Slack and generic webhooks](#slack-and-generic-webhooks)
- [Tests](#tests)
- [AWS deployment](#aws-deployment)
- [Documentation](#documentation)
- [Squad contributions](#squad-contributions)
- [Tech stack](#tech-stack)

---

## Why Sentinel

Production incidents rarely arrive as clean stories. Operators paste logs, paste Slack threads, and work under time pressure. Sentinel runs a **modular agent pipeline** (normalize → summarize → investigate → remediate) with **guardrails** (prompt-injection handling, evidence extraction, confidence-aware behavior) and surfaces results in a **Next.js dashboard** backed by a **FastAPI** service.

---

## What you get

- **Incident analysis**: Automated summary, severity, root-cause hypotheses, and prioritized remediation actions.
- **Operational UI**: Submit incidents, review jobs, charts, and deep-dive reports ([frontend](#frontend)).
- **Real-time feedback**: Server-Sent Events for pipeline stages and investigation streaming (see [API overview](#api-overview)).
- **Remediation workflow**: Track actions, per-action chat for guidance, follow-ups, and clarification Q&A.
- **Reporting**: JSON/PDF exports, audit PDFs, periodic digests, post-incident review (PIR) helpers.
- **Integrations & webhooks**: Alertmanager / CloudWatch-style **ingestion** hooks, optional email reminders (Resend), and **outbound** notifications (**Slack** incoming webhooks and **generic HTTP webhooks**) when analysis completes at high or critical severity (see [Slack and generic webhooks](#slack-and-generic-webhooks)).
- **Bulk ZIP upload**: Upload a `.zip` of log-like files from **Analyze** to create many incidents and jobs in one step, with archive-wide guardrails (see [Bulk ZIP upload](#bulk-zip-upload)).
- **Auth**: [Clerk](https://clerk.com/) for production-style sign-in; local bypass when Clerk is not configured.

---

## Repository layout

| Path | Purpose |
|------|---------|
| [backend/](backend/) | FastAPI app, agents, pipeline, store, reports, scheduler, ingest |
| [backend/tests/](backend/tests/) | Consolidated backend pytest suite |
| [frontend/](frontend/) | Next.js 14 (Pages Router) dashboard |
| [terraform/](terraform/) | Stage-based AWS IaC (see guides 1–8) |
| [scripts/](scripts/) | Local orchestration (`run_local.py`), utilities |
| [guides/](guides/) | Permissions, SageMaker, ingestion, DB, agents, frontend, enterprise |
| [intel.md](intel.md) | Deep-dive: files, APIs, frontend, infra |
| [gameplan.md](gameplan.md) | Delivery sequence and guardrail strategy |

---

## Prerequisites

- **Python** ≥ 3.12
- **[uv](https://docs.astral.sh/uv/)** for installing and running Python tools
- **Node.js** and **npm** (for the frontend)

---

## Quick start

1. **Clone** the repository and enter the project root.

2. **Environment file**

   ```bash
   cp .env.example .env
   ```

   Edit `.env` so **exactly one** of `USE_OPEN_ROUTER` or `USE_BEDROCK` is `true` for LLM calls (see [Configuration](#configuration)).

3. **Install frontend dependencies** (first run only)

   ```bash
   cd frontend && npm install && cd ..
   ```

4. **Start backend + frontend** (recommended)

   ```bash
   cd scripts && uv run run_local.py
   ```

   - Backend: [http://localhost:8000](http://localhost:8000)
   - Frontend: [http://localhost:3000](http://localhost:3000)

   If Clerk JWKS / issuer URLs are **not** set, the orchestrator sets `AUTH_DISABLED=true` so you can develop without signing in.

---

## Configuration

Copy [.env.example](.env.example) to `.env` at the repo root. Important groups:

### LLM provider (pick one)

| Mode | When to use | Key variables |
|------|-------------|----------------|
| **OpenRouter** | Easiest for local development | `USE_OPEN_ROUTER=true`, `USE_BEDROCK=false`, `OPENROUTER_API_KEY`, optional `OPENROUTER_MODEL` (default `openai/gpt-4o-mini`) |
| **AWS Bedrock** | Production / AWS-aligned setup | `USE_BEDROCK=true`, `USE_OPEN_ROUTER=false`, AWS credentials, `BEDROCK_MODEL_ID`, region |

### Authentication (Clerk)

- `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`, `CLERK_SECRET_KEY`, `CLERK_JWKS_URL` or `CLERK_ISSUER` (as used by the backend) enable full auth.
- Omitting Clerk config triggers **auth disabled** mode when using `scripts/run_local.py`, as described above.

### Notifications (Resend)

- `RESEND_API_KEY`, `RESEND_FROM` for follow-up emails (test sender supported).

### Optional AWS

- `S3_BUCKET` for uploads / PDF flows that use S3.
- `DEFAULT_AWS_REGION`, account and access keys as needed for Bedrock or S3.

### Outbound integrations (Slack / webhooks)

These control **when** and **where** completed analysis is pushed after a job finishes (not ingestion of external alerts):

- **`INTEGRATION_NOTIFY_SEVERITIES`** — Comma-separated list of severities that trigger dispatch (default: `high,critical`). Example: `high,critical` or `critical` only.
- **`SENTINEL_PUBLIC_URL`** or **`NEXT_PUBLIC_APP_URL`** — Public dashboard base URL (no trailing slash). When set, generic webhook payloads include a **`dashboard_url`** pointing at the job; when unset, `dashboard_url` is `null`.

Integrations themselves are stored per user in the database and configured in the UI under **Settings** (see [Slack and generic webhooks](#slack-and-generic-webhooks)).

For narrative setup instructions, see the **Local Development** section in [intel.md](intel.md).

---

## Running locally

### Both services

```bash
cd scripts
uv run run_local.py
```

### Backend only

```bash
cd backend
uv run uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### Frontend only

```bash
cd frontend
npm install
npm run dev
```

**Health check**: `GET http://localhost:8000/health`

---

## API overview

Base URL in local development: `http://localhost:8000`

| Area | Examples |
|------|----------|
| **Core** | `GET /health`, `GET /api/me`, `GET /api/team/members` |
| **Incidents & jobs** | `POST /api/incidents`, `POST /api/incidents/analyze-sync`, `POST /api/incidents/bulk-zip` (multipart field **`archive`**, optional query `title_prefix`, `source`, `max_files`), `GET /api/jobs`, `GET /api/jobs/{job_id}`, `POST /api/jobs/{job_id}/run`, `GET /api/jobs/{job_id}/workflow` |
| **Streaming** | `GET /api/jobs/{job_id}/stream`, `POST /api/stream/investigate` |
| **Exports** | `GET /api/jobs/{job_id}/export`, `GET /api/jobs/{job_id}/audit/pdf` |
| **Remediation** | `GET/PATCH .../actions`, chat `GET/POST .../actions/{action_id}/chat`, `POST .../actions/{action_id}/evaluate` |
| **Follow-ups & clarify** | follow-ups under `/api/jobs/{job_id}/follow-ups`, clarifications under `/api/jobs/{job_id}/clarify` |
| **Integrations** | `GET/POST/DELETE /api/integrations` (Slack, generic webhook, Jira, PagerDuty configs); **ingestion** webhooks under `/api/ingest/webhook*` |
| **Analytics & reports** | `GET /api/analytics/mttr`, `POST /api/reports/digest`, PIR routes under `/api/jobs/{job_id}/pir` |

Interactive docs: when the API is running, OpenAPI is available at `/docs` (Swagger UI) unless disabled in your build.

---

## Frontend

Next.js **Pages Router** app (`frontend/pages/`):

| Route | Purpose |
|-------|---------|
| `/` | Analyze: paste incident text or **Upload ZIP (bulk)** for many jobs from one archive |
| `/dashboard` | Jobs, stats, analysis detail |
| `/audit` | Audit-oriented views |
| `/settings` | Integrations and preferences |
| `/sign-in`, `/sign-up` | Clerk auth |

The UI calls the API at **`NEXT_PUBLIC_API_URL`** when set; otherwise it defaults to `http://localhost:8000` (see [frontend/lib/api.js](frontend/lib/api.js)). With `run_local.py`, you can put `NEXT_PUBLIC_*` and Clerk keys in the **root** `.env`. If you run `npm run dev` alone, you can instead use **`frontend/.env.local`** (see [frontend/README.md](frontend/README.md)).

---

## Bulk ZIP upload

Use this when you have many small log files (for example per-service `.txt` or `.log` exports) and want one **incident + job per member file** without pasting each by hand.

### In the UI

On **`/`** (Analyze), choose **Upload ZIP (bulk)**. The client sends `multipart/form-data` with the file in field **`archive`** to `POST /api/incidents/bulk-zip`. The page shows **Bulk Upload Results** (created jobs, skipped members) and lets you open each job in the analysis panel.

### API behavior

| Topic | Detail |
|--------|--------|
| **Endpoint** | `POST /api/incidents/bulk-zip` |
| **Multipart** | Form field name must be **`archive`** (see [backend/test_bulk_zip_api.py](backend/test_bulk_zip_api.py)). |
| **Raw body** | You may instead POST the raw ZIP bytes with `Content-Type: application/zip` (or `application/octet-stream`) for scripts. |
| **Query** | `source` (default `upload`), optional `title_prefix` (prepended to each incident title), `max_files` (default **25**, max **100**). |
| **Archive size (entries)** | Archives with more than **400** file entries are rejected (**400**) before reading bodies, to bound CPU/memory on pathological zips. |
| **Ingested extensions** | `.txt`, `.log`, `.json`, `.ndjson`, `.md`, `.csv` |
| **Per-file size** | Members larger than **500 KB** are skipped (not ingested). |
| **Finder metadata** | Paths under **`__MACOSX`** and AppleDouble `._*` files are not ingested as incidents but are **still scanned** for hidden threats; a bad payload there fails the **whole** archive. |
| **Preflight** | If any scanned member fails guardrails (for example prompt-injection-like content in a log line), the API returns **400** with `detail.error === "bulk_zip_validation_failed"` and a **`failures`** list — **no** incidents are created (all-or-nothing). |

Automated coverage: [backend/common/test_bulk_zip_preflight.py](backend/common/test_bulk_zip_preflight.py), [backend/test_bulk_zip_api.py](backend/test_bulk_zip_api.py).

---

## Slack and generic webhooks

Sentinel can notify external systems when a job’s analysis completes, for severities configured by **`INTEGRATION_NOTIFY_SEVERITIES`** (see [Configuration](#configuration)).

### Configure in the app

1. Open **`/settings`** while signed in (or in local auth-disabled mode as your dev user).
2. Under **Add Integration**, pick **Slack** or **Generic Webhook** and paste the webhook URL.
3. Save. Other types (Jira, PagerDuty) may be present in the same list; this section focuses on Slack and HTTP JSON webhooks.

**Slack:** Use a real [Incoming Webhook](https://api.slack.com/messaging/webhooks) URL (`https://hooks.slack.com/services/...` with three path segments). Do not paste documentation placeholders that use a Unicode ellipsis (`…`) in the path — the API rejects those because Slack responds with redirects, not a successful post.

### Generic webhook payload

The server `POST`s JSON to your URL. Top-level fields include:

- **`event`**: `sentinel.analysis.completed`
- **`incident_id`**, **`job_id`**
- **`incident_title`**, **`incident_source`** — Title is typically the incident label (for bulk ZIP, often `title_prefix` + member file name); source is usually `upload` or `manual`.
- **`severity`**, **`summary`**, **`severity_reason`**, root cause fields, **`recommended_actions`**, **`next_checks`**, **`risk_if_unresolved`**
- **`dashboard_url`** — Absolute link when `SENTINEL_PUBLIC_URL` / `NEXT_PUBLIC_APP_URL` is set; otherwise `null`.

**Manual smoke test** (from `backend/`): `WEBHOOK_URL=https://… uv run python -m integrations.manual_dispatch` (optional `INTEGRATION_TYPE=slack`, `INCIDENT_TITLE`, `INCIDENT_SOURCE`).

Dispatch runs from the same **`run_job`** path used locally and on **Lambda**. Packaging scripts include `common/` and `integrations/` but **skip** `test_*.py` / `*_test.py` so pytest modules are not shipped in deployment zips. After changing integration code, **redeploy** the Lambdas that run the pipeline (see [AWS deployment](#aws-deployment)).

---

## Tests

Backend tests use **pytest**. From the repo root:

```bash
uv run --project backend pytest backend/tests
```

Test directory:

- `backend/tests/`

---

## AWS deployment

Infrastructure is organized as **independent Terraform stages** under [terraform/](terraform/), aligned with [guides/1_permissions.md](guides/1_permissions.md) through [guides/8_enterprise.md](guides/8_enterprise.md). Use each stage’s `terraform.tfvars.example` (where present) as a template.

**Suggested order** is documented in [gameplan.md](gameplan.md): permissions → SageMaker → ingestion → intel → database → agents → frontend → enterprise monitoring.

---

## Documentation

| Document | Contents |
|----------|----------|
| [intel.md](intel.md) | End-to-end intelligence: env, agents, API, frontend, Terraform |
| [gameplan.md](gameplan.md) | MVP outcomes, guide order, guardrails, delivery focus |
| [SENTINEL_HANDOVER.md](SENTINEL_HANDOVER.md) | Scaffold / handover status |
| [guides/agent_architecture.md](guides/agent_architecture.md) | Agent sequence and data flow |
| [AGENTS.md](AGENTS.md) | Tooling and model conventions for this repo |

---

## Squad contributions

| Name | Role |
|------|------|
| Eben and Michael | Backend and frontend: APIs, agent pipeline, and dashboard UI |
| Joshua | Deployment: AWS, Terraform stages, and end-to-end infrastructure delivery |
| Tunde | Demo presentation |
| Ayesha | Base codebase setup and repository documentation; **bulk ZIP upload** (API preflight guardrails, Analyze UI, job table); **Slack** and **generic webhook** outbound integrations (payload fields, severity-based dispatch, dashboard links); test engineering including bulk ZIP and dispatcher coverage |
| Oluwagbamila | End-to-end application: full product flow from incident intake through analysis to dashboard delivery |

---

## Tech stack

| Category | Stack |
|----------|--------|
| **Language** | Python 3.12+ |
| **Backend** | FastAPI, Uvicorn, Pydantic v2, httpx, PyJWT, fpdf2, python-dotenv, Mangum (Lambda adapter) |
| **Frontend** | Next.js 14, React 18, Pages Router, Clerk, Recharts |
| **LLM** | OpenRouter or Amazon Bedrock (via boto3) |
| **Data** | SQLite (local dev); Aurora Serverless v2 + RDS Data API (AWS deployment) |
| **Cloud** | API Gateway, Lambda, SQS, CloudFront, S3, App Runner (Intel), EventBridge, CloudWatch |
| **IaC** | Terraform — staged modules in [`terraform/`](terraform/) |
| **Auth** | Clerk (JWT); optional `AUTH_DISABLED` for local development |
| **Tooling** | uv, npm, pytest |
---

## Version

Application packages in this repo are currently versioned at **0.3.0** (see `backend/pyproject.toml` and `frontend/package.json`).
