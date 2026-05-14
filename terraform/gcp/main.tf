terraform {
  required_version = ">= 1.5.0"

  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.45"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.45"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  description = "GCP project id."
  type        = string
}

variable "region" {
  description = "Primary GCP region."
  type        = string
  default     = "us-central1"
}

variable "artifact_region" {
  description = "Artifact Registry region."
  type        = string
  default     = "us-central1"
}

variable "api_image" {
  description = "Prebuilt Cloud Run API image, for example us-central1-docker.pkg.dev/PROJECT/sentinel/sentinel-api:latest."
  type        = string
}

variable "allowed_origins" {
  description = "Comma-separated CORS origins for the FastAPI service."
  type        = string
  default     = "*"
}

variable "clerk_jwks_url" {
  description = "Clerk JWKS URL."
  type        = string
  default     = ""
}

variable "clerk_issuer" {
  description = "Clerk issuer URL."
  type        = string
  default     = ""
}

variable "clerk_secret_key" {
  description = "Clerk backend secret key."
  type        = string
  sensitive   = true
  default     = ""
}

variable "sendgrid_api_key" {
  description = "SendGrid API key for reminder email."
  type        = string
  sensitive   = true
  default     = ""
}

variable "sendgrid_from" {
  description = "SendGrid sender, e.g. Sentinel <ops@example.com>."
  type        = string
  default     = ""
}

variable "pushover_token" {
  description = "Pushover application token."
  type        = string
  sensitive   = true
  default     = ""
}

variable "pushover_user_key" {
  description = "Pushover user or group key."
  type        = string
  sensitive   = true
  default     = ""
}

variable "integration_notify_severities" {
  description = "Comma-separated severities that trigger outbound integrations."
  type        = string
  default     = "high,critical"
}

variable "live_ingest_token" {
  description = "Shared token used by service-to-service Live Incident log ingestion endpoints."
  type        = string
  sensitive   = true
  default     = ""
}

variable "db_name" {
  description = "Cloud SQL database name."
  type        = string
  default     = "sentinel"
}

variable "db_user" {
  description = "Cloud SQL application user."
  type        = string
  default     = "sentinel"
}

variable "db_tier" {
  description = "Cost-conscious Cloud SQL tier."
  type        = string
  default     = "db-f1-micro"
}

variable "firebase_site_id" {
  description = "Firebase Hosting site id. Must be globally unique within Firebase Hosting."
  type        = string
}

locals {
  name_prefix = "sentinel"
  labels = {
    project    = "sentinel"
    managed_by = "terraform"
  }

  required_services = toset([
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "run.googleapis.com",
    "eventarc.googleapis.com",
    "firebase.googleapis.com",
    "firebasehosting.googleapis.com",
    "iam.googleapis.com",
    "pubsub.googleapis.com",
    "secretmanager.googleapis.com",
    "serviceusage.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "aiplatform.googleapis.com",
  ])
}

data "google_project" "current" {
  project_id = var.project_id
}

resource "google_project_service" "required" {
  for_each           = local.required_services
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

resource "random_password" "db_password" {
  length  = 24
  special = true
}

data "google_artifact_registry_repository" "repo" {
  location      = var.artifact_region
  repository_id = local.name_prefix
  depends_on    = [google_project_service.required]
}

resource "google_sql_database_instance" "db" {
  name                = "${local.name_prefix}-postgres"
  database_version    = "POSTGRES_15"
  region              = var.region
  deletion_protection = false

  settings {
    tier              = var.db_tier
    availability_type = "ZONAL"
    disk_type         = "PD_HDD"
    disk_size         = 10
    disk_autoresize   = true

    backup_configuration {
      enabled = false
    }

    ip_configuration {
      ipv4_enabled = true
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_sql_database" "app" {
  name     = var.db_name
  instance = google_sql_database_instance.db.name
}

resource "google_sql_user" "app" {
  name     = var.db_user
  instance = google_sql_database_instance.db.name
  password = random_password.db_password.result
}

resource "google_storage_bucket" "schema" {
  name                        = "${var.project_id}-${local.name_prefix}-schema"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
  labels                      = local.labels

  depends_on = [google_project_service.required]
}

resource "google_storage_bucket_object" "schema_sql" {
  name   = "sql/001_schema.sql"
  bucket = google_storage_bucket.schema.name
  source = "${path.module}/../../backend/database/migrations/001_schema.sql"
}

resource "google_storage_bucket_iam_member" "schema_sql_import_reader" {
  bucket = google_storage_bucket.schema.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_sql_database_instance.db.service_account_email_address}"
}

resource "google_storage_bucket" "function_source" {
  name                        = "${var.project_id}-${local.name_prefix}-function-source"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
  labels                      = local.labels

  depends_on = [google_project_service.required]
}

data "archive_file" "backend_source" {
  type        = "zip"
  source_dir  = "${path.module}/../../backend"
  output_path = "${path.module}/.terraform/backend-source.zip"
  excludes = [
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "dist",
    "*.pyc",
  ]
}

resource "google_storage_bucket_object" "function_source" {
  name   = "functions/backend-${data.archive_file.backend_source.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.backend_source.output_path
}

resource "google_pubsub_topic" "jobs_dlq" {
  name   = "${local.name_prefix}-jobs-dlq"
  labels = local.labels

  depends_on = [google_project_service.required]
}

resource "google_pubsub_topic" "jobs" {
  name   = "${local.name_prefix}-jobs"
  labels = local.labels

  depends_on = [google_project_service.required]
}

resource "google_pubsub_subscription" "jobs" {
  name  = "${local.name_prefix}-jobs-subscription"
  topic = google_pubsub_topic.jobs.id

  ack_deadline_seconds       = 600
  message_retention_duration = "86400s"

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.jobs_dlq.id
    max_delivery_attempts = 5
  }

  depends_on = [google_pubsub_topic_iam_member.pubsub_dlq_publisher]
}

resource "google_pubsub_topic_iam_member" "pubsub_dlq_publisher" {
  topic  = google_pubsub_topic.jobs_dlq.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_pubsub_subscription_iam_member" "pubsub_jobs_subscriber" {
  subscription = google_pubsub_subscription.jobs.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = "${local.name_prefix}-db-password"
  labels    = local.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db_password.result
}

resource "google_secret_manager_secret" "clerk_secret_key" {
  secret_id = "${local.name_prefix}-clerk-secret-key"
  labels    = local.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "clerk_secret_key" {
  secret      = google_secret_manager_secret.clerk_secret_key.id
  secret_data = var.clerk_secret_key
}

resource "google_secret_manager_secret" "sendgrid_api_key" {
  secret_id = "${local.name_prefix}-sendgrid-api-key"
  labels    = local.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "sendgrid_api_key" {
  secret      = google_secret_manager_secret.sendgrid_api_key.id
  secret_data = var.sendgrid_api_key
}

resource "google_secret_manager_secret" "live_ingest_token" {
  secret_id = "${local.name_prefix}-live-ingest-token"
  labels    = local.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "live_ingest_token" {
  secret      = google_secret_manager_secret.live_ingest_token.id
  secret_data = var.live_ingest_token
}

resource "google_secret_manager_secret" "pushover_token" {
  secret_id = "${local.name_prefix}-pushover-token"
  labels    = local.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "pushover_token" {
  secret      = google_secret_manager_secret.pushover_token.id
  secret_data = var.pushover_token
}

resource "google_secret_manager_secret" "pushover_user_key" {
  secret_id = "${local.name_prefix}-pushover-user-key"
  labels    = local.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "pushover_user_key" {
  secret      = google_secret_manager_secret.pushover_user_key.id
  secret_data = var.pushover_user_key
}

resource "google_service_account" "api" {
  account_id   = "${local.name_prefix}-api"
  display_name = "Sentinel Cloud Run API"
}

resource "google_service_account" "worker" {
  account_id   = "${local.name_prefix}-worker"
  display_name = "Sentinel Pub/Sub worker function"
}

resource "google_project_iam_member" "api_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "worker_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_project_iam_member" "api_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "worker_vertex_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_project_iam_member" "api_vertex_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "worker_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_cloud_run_v2_service" "api" {
  name     = "${local.name_prefix}-api"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"
  labels   = local.labels

  template {
    service_account                  = google_service_account.api.email
    timeout                          = "900s"
    max_instance_request_concurrency = 20

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.db.connection_name]
      }
    }

    containers {
      image = var.api_image

      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
        cpu_idle = true
      }

      ports {
        container_port = 8080
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      env {
        name  = "ALLOWED_ORIGINS"
        value = var.allowed_origins
      }
      env {
        name  = "AUTH_DISABLED"
        value = "false"
      }
      env {
        name  = "CLERK_JWKS_URL"
        value = var.clerk_jwks_url
      }
      env {
        name  = "CLERK_ISSUER"
        value = var.clerk_issuer
      }
      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "GCP_LOCATION"
        value = var.region
      }
      env {
        name  = "USE_VERTEX_AI"
        value = "true"
      }
      env {
        name  = "VERTEX_AI_MODEL"
        value = "gemini-2.5-flash"
      }
      env {
        name  = "GCP_CLOUDSQL_CONNECTION_NAME"
        value = google_sql_database_instance.db.connection_name
      }
      env {
        name  = "GCP_DB_NAME"
        value = var.db_name
      }
      env {
        name  = "GCP_DB_USER"
        value = var.db_user
      }
      env {
        name  = "GCP_USE_CLOUDSQL_CONNECTOR"
        value = "false"
      }
      env {
        name  = "PUBSUB_JOBS_TOPIC"
        value = google_pubsub_topic.jobs.id
      }
      env {
        name  = "SENDGRID_FROM"
        value = var.sendgrid_from
      }
      env {
        name  = "INTEGRATION_NOTIFY_SEVERITIES"
        value = var.integration_notify_severities
      }
      env {
        name = "GCP_DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_password.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "LIVE_INGEST_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.live_ingest_token.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "CLERK_SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.clerk_secret_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "SENDGRID_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.sendgrid_api_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "PUSHOVER_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.pushover_token.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "PUSHOVER_USER_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.pushover_user_key.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [
    google_project_iam_member.api_pubsub_publisher,
    google_project_iam_member.api_secret_accessor,
    google_project_iam_member.api_sql_client,
    google_project_iam_member.api_vertex_user,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "api_public" {
  location = google_cloud_run_v2_service.api.location
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloudfunctions2_function" "worker" {
  name        = "${local.name_prefix}-worker"
  location    = var.region
  description = "Runs Sentinel incident analysis jobs from Pub/Sub"

  build_config {
    runtime     = "python312"
    entry_point = "pubsub_run_job"
    environment_variables = {
      GOOGLE_FUNCTION_SOURCE = "main.py"
    }
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 2
    min_instance_count    = 0
    available_memory      = "1Gi"
    timeout_seconds       = 540
    service_account_email = google_service_account.worker.email

    environment_variables = {
      GCP_PROJECT_ID                = var.project_id
      GCP_LOCATION                  = var.region
      USE_VERTEX_AI                 = "true"
      VERTEX_AI_MODEL               = "gemini-2.5-flash"
      GCP_CLOUDSQL_CONNECTION_NAME  = google_sql_database_instance.db.connection_name
      GCP_DB_NAME                   = var.db_name
      GCP_DB_USER                   = var.db_user
      GCP_USE_CLOUDSQL_CONNECTOR    = "true"
      SENDGRID_FROM                 = var.sendgrid_from
      INTEGRATION_NOTIFY_SEVERITIES = var.integration_notify_severities
    }

    secret_environment_variables {
      key        = "GCP_DB_PASSWORD"
      project_id = var.project_id
      secret     = google_secret_manager_secret.db_password.secret_id
      version    = "latest"
    }
    secret_environment_variables {
      key        = "CLERK_SECRET_KEY"
      project_id = var.project_id
      secret     = google_secret_manager_secret.clerk_secret_key.secret_id
      version    = "latest"
    }
    secret_environment_variables {
      key        = "SENDGRID_API_KEY"
      project_id = var.project_id
      secret     = google_secret_manager_secret.sendgrid_api_key.secret_id
      version    = "latest"
    }
    secret_environment_variables {
      key        = "PUSHOVER_TOKEN"
      project_id = var.project_id
      secret     = google_secret_manager_secret.pushover_token.secret_id
      version    = "latest"
    }
    secret_environment_variables {
      key        = "PUSHOVER_USER_KEY"
      project_id = var.project_id
      secret     = google_secret_manager_secret.pushover_user_key.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.jobs.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.worker.email
  }

  depends_on = [
    google_project_iam_member.worker_secret_accessor,
    google_project_iam_member.worker_sql_client,
    google_project_iam_member.worker_vertex_user,
  ]
}

resource "google_firebase_project" "default" {
  provider = google-beta
  project  = var.project_id

  depends_on = [google_project_service.required]
}

resource "google_firebase_hosting_site" "frontend" {
  provider = google-beta
  project  = var.project_id
  site_id  = var.firebase_site_id

  depends_on = [google_firebase_project.default]
}

output "artifact_repository" {
  value = data.google_artifact_registry_repository.repo.name
}

output "api_url" {
  value = google_cloud_run_v2_service.api.uri
}

output "cloud_sql_connection_name" {
  value = google_sql_database_instance.db.connection_name
}

output "database_name" {
  value = google_sql_database.app.name
}

output "db_user" {
  value = google_sql_user.app.name
}

output "firebase_site_id" {
  value = google_firebase_hosting_site.frontend.site_id
}

output "jobs_topic" {
  value = google_pubsub_topic.jobs.id
}

output "schema_sql_uri" {
  value = "gs://${google_storage_bucket.schema.name}/${google_storage_bucket_object.schema_sql.name}"
}

output "next_public_api_url" {
  value = google_cloud_run_v2_service.api.uri
}
