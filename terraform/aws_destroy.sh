#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

stages=(
  "8_enterprise"
  "7_frontend"
  "6_agents"
  "5_database"
  "4_intel"
  "3_ingestion"
  "2_sagemaker"
)

echo "This will destroy Sentinel AWS Terraform stages in reverse dependency order."
echo "AWS resources should only be destroyed after GCP smoke tests pass."
read -r -p "Type destroy-aws-sentinel to continue: " confirmation

if [[ "${confirmation}" != "destroy-aws-sentinel" ]]; then
  echo "Aborted."
  exit 1
fi

for stage in "${stages[@]}"; do
  dir="${ROOT}/${stage}"
  if [[ ! -d "${dir}" ]]; then
    echo "Skipping missing stage ${stage}"
    continue
  fi
  if [[ ! -f "${dir}/main.tf" ]]; then
    echo "Skipping ${stage}; no main.tf found"
    continue
  fi
  echo "Destroying terraform/${stage}"
  (cd "${dir}" && terraform init && terraform destroy)
done
