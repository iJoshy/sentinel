# Sentinel GCP Deployment

This file is the working runbook and knowledge base for moving Sentinel from AWS to GCP.

## Target Architecture

- Frontend: static Next.js export on Firebase Hosting project `sentinel-center`.
- API: FastAPI container on Cloud Run, with scale-to-zero and a low max instance cap.
- Worker: Pub/Sub-triggered Cloud Run Function running `gcp_function.pubsub_run_job`.
- Database: fresh Cloud SQL for PostgreSQL schema.
- Schema artifact: `backend/database/migrations/001_schema.sql` uploaded to Cloud Storage.
- LLM: Vertex AI Gemini `gemini-2.5-flash`.
- Secrets: Secret Manager for Clerk, Cloud SQL password, SendGrid, and Pushover.
- Async queue: Pub/Sub topic plus dead-letter topic.

Primary docs checked while planning:

- Cloud Run can connect to Cloud SQL via `/cloudsql/INSTANCE_CONNECTION_NAME`; the current runtime uses the Cloud SQL Python Connector for both Cloud Run and Cloud Functions: https://cloud.google.com/sql/docs/postgres/connect-run and https://cloud.google.com/sql/docs/postgres/connect-functions
- Firebase Hosting deploys static assets from a configured public directory: https://firebase.google.com/docs/hosting
- Pub/Sub supports dead-letter topics for failed delivery attempts: https://cloud.google.com/pubsub/docs/dead-letter-topics
- Vertex AI Gemini model calls use the Vertex AI publisher model endpoint: https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/inference

## Files Added

- `terraform/gcp/main.tf`: single-file GCP Terraform deployment.
- `terraform/gcp/destroy_gcp.sh`: destroys the GCP stack from `terraform/gcp`.
- `terraform/aws_destroy.sh`: destroys existing AWS stages in reverse dependency order after explicit confirmation.
- `backend/Dockerfile.gcp`: Cloud Run API image.
- `backend/cloudbuild.gcp.yaml`: Cloud Build recipe for the API image.
- `backend/gcp_function.py`: Pub/Sub Cloud Function entrypoint.
- `backend/requirements.txt`: Cloud Functions Python dependency file.
- `firebase.json`, `.firebaserc`, and `.firebaserc.example`: Firebase Hosting configuration.

## Runtime Changes

- `USE_VERTEX_AI=true` routes model calls to Vertex AI Gemini.
- `GCP_CLOUDSQL_CONNECTION_NAME` selects the new Postgres/Cloud SQL store through the Cloud SQL Python Connector.
- The Artifact Registry Docker repository is treated as pre-existing because the image build step creates or uses it before Terraform apply.
- `PUBSUB_JOBS_TOPIC` makes `POST /api/incidents` publish jobs instead of only using local FastAPI background tasks.
- `SENDGRID_API_KEY` enables SendGrid follow-up reminder email; Resend remains as fallback.
- `PUSHOVER_TOKEN` and `PUSHOVER_USER_KEY` enable server-level Pushover notifications for configured severities.

## First Deploy

1. Prepare GCP project and Firebase:

   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   npx firebase-tools login
   ```

2. Build and push the API image:

   ```bash
   gcloud services enable artifactregistry.googleapis.com cloudbuild.googleapis.com
   gcloud artifacts repositories create sentinel \
     --repository-format=docker \
     --location=europe-west1 \
     --description="Sentinel container images" || true

   IMAGE_TAG="api-$(date +%Y%m%d%H%M%S)"
   API_IMAGE="europe-west1-docker.pkg.dev/YOUR_PROJECT_ID/sentinel/sentinel-api:${IMAGE_TAG}"

   gcloud builds submit backend \
     --config backend/cloudbuild.gcp.yaml \
     --substitutions _IMAGE="${API_IMAGE}"
   ```

3. Create `terraform/gcp/terraform.tfvars`:

   ```hcl
   project_id       = "YOUR_PROJECT_ID"
   region           = "europe-west1"
   artifact_region  = "europe-west1"
   firebase_site_id = "YOUR_UNIQUE_FIREBASE_SITE_ID"
   api_image        = "europe-west1-docker.pkg.dev/YOUR_PROJECT_ID/sentinel/sentinel-api:YOUR_IMAGE_TAG"

   clerk_jwks_url   = "https://YOUR-CLERK-DOMAIN/.well-known/jwks.json"
   clerk_issuer     = "https://YOUR-CLERK-DOMAIN"
   clerk_secret_key = "..."

   sendgrid_api_key = "..."
   sendgrid_from    = "Sentinel <ops@example.com>"
   pushover_token   = "..."
   pushover_user_key = "..."
   ```

   A local, gitignored `terraform/gcp/terraform.tfvars` has already been created from `.env` for the current workspace. Terraform still tracks the generated `sentinel-center-67a8c` site in `etcy-systems-prod`, but the active Firebase deploy target is the existing `sentinel-center` site in the `sentinel-center` Firebase project. The Cloud Run API CORS allowlist includes both Firebase site IDs.

4. Apply GCP infrastructure:

   ```bash
   cd terraform/gcp
   terraform init
   terraform apply
   terraform output
   ```

   If an earlier apply failed before these fixes, rebuild the API image first so Cloud Run picks up the container startup patch:

   ```bash
   IMAGE_TAG="api-$(date +%Y%m%d%H%M%S)"
   API_IMAGE="europe-west1-docker.pkg.dev/etcy-systems-prod/sentinel/sentinel-api:${IMAGE_TAG}"

   gcloud builds submit backend \
     --config backend/cloudbuild.gcp.yaml \
     --substitutions _IMAGE="${API_IMAGE}"

   cd terraform/gcp
   sed -i.bak "s#api_image *=.*#api_image = \"${API_IMAGE}\"#" terraform.tfvars
   terraform apply
   ```

5. Initialize the fresh Cloud SQL schema.

   Terraform uploads the SQL to Cloud Storage and prints `schema_sql_uri`. Use Cloud SQL import so you do not need a local Cloud SQL Proxy or `psql` install:

   ```bash
   SCHEMA_URI="$(cd terraform/gcp && terraform output -raw schema_sql_uri)"

   gcloud sql import sql sentinel-postgres "${SCHEMA_URI}" \
     --project=etcy-systems-prod \
     --database=sentinel \
     --quiet
   ```

   If this returns a storage permission error, rerun `terraform apply` first. The Terraform stack grants the Cloud SQL service account read access to the schema bucket.

6. Configure frontend env and deploy Firebase Hosting:

   ```bash
   printf 'NEXT_PUBLIC_API_URL=%s\n' "$(cd terraform/gcp && terraform output -raw next_public_api_url)" >> frontend/.env.local

   cd frontend
   NEXT_PUBLIC_API_URL="$(cd ../terraform/gcp && terraform output -raw next_public_api_url)" npm run build
   cd ..
   npx firebase-tools deploy --only hosting
   ```

   If the browser shows `Failed to fetch` / `NetworkError when attempting to fetch resource`, inspect the deployed JS bundle and confirm it contains the Cloud Run URL, not the old AWS API Gateway URL:

   ```bash
   curl -s https://sentinel-center.web.app/ \
     | rg -o '/_next/static/[^" ]+\\.js' \
     | sort -u \
     | while read -r js; do curl -s "https://sentinel-center.web.app${js}"; done \
     | rg 'run.app|execute-api'
   ```

   Current hosting target:

   - Firebase project: `sentinel-center`
   - Hosting site: `sentinel-center`
   - URL: `https://sentinel-center.web.app`

7. Smoke test:

   ```bash
   API_URL="$(cd terraform/gcp && terraform output -raw api_url)"
   curl "${API_URL}/health"
   ```

   Then open the Firebase Hosting URL, sign in with Clerk, submit one incident, and confirm the job completes.

## Cost Controls

- Cloud Run API: `min_instance_count = 0`, `max_instance_count = 3`, `cpu_idle = true`.
- Cloud Function worker: `min_instance_count = 0`, `max_instance_count = 2`.
- Cloud SQL: default `db-f1-micro`, zonal, 10 GB HDD, backups disabled for the initial cost-focused migration.
- Pub/Sub retention is one day and DLQ max delivery attempts is three.

Raise these defaults only after the GCP smoke tests pass and real traffic requires it.

## AWS Teardown

Do not destroy AWS until GCP smoke tests pass and you explicitly decide to cut over.

When ready:

```bash
cd terraform
./aws_destroy.sh
```

The script asks for the exact phrase `destroy-aws-sentinel` and then destroys stages in this order:

1. `8_enterprise`
2. `7_frontend`
3. `6_agents`
4. `5_database`
5. `4_intel`
6. `3_ingestion`
7. `2_sagemaker`

## Validation Checklist

- `terraform fmt -check terraform/gcp/main.tf`
- `terraform validate` from `terraform/gcp`
- `uv run --project backend pytest backend/tests`
- `npm run build` from `frontend`
- `GET /health` on Cloud Run returns `{"status":"ok","service":"sentinel-api"}`
- Firebase frontend calls Cloud Run through `NEXT_PUBLIC_API_URL`
- One incident creates a pending job, Pub/Sub triggers the worker, and Cloud SQL stores completed analysis
- Saved analysis includes `models.model = "gemini-2.5-flash"`
- SendGrid and Pushover skip cleanly without secrets and deliver when configured

## Known Follow-Ups

- Existing Aurora data is intentionally not migrated in this first cutover.
- Live CloudWatch board code is still AWS-specific. For GCP-native live monitoring, replace it with Cloud Logging queries in a later pass.
- The runtime uses the Cloud SQL Python Connector with the Cloud SQL Client IAM role, so Cloud Run and the Pub/Sub function do not need static database IP allowlists.
