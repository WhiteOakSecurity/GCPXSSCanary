// SPDX-License-Identifier: GPL-3.0-or-later
# Local TF Vars
# ----------------------------------------------
locals {
    project = "<PROJECT>"
    region = "us-central1"
    function_name = "xsscanary"
}

provider "google-beta" {
    project = local.project
}

# IAM Permissions for Service Account
# ----------------------------------------------
resource "google_service_account" "sa" {
  account_id    = "${local.project}-service-account"
  display_name  = "A service account for the XSS collection function"
  provider      = google-beta
}

# Allow SA service account to create temporary metadata tokens
# Now that you've read the blog post, is this over permissioned?
resource "google_service_account_iam_member" "sa_token_creator" {
  provider = google-beta
  service_account_id = google_service_account.sa.id
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.sa.email}"
}


# Create the storage buckets
# ----------------------------------------------
resource "google_storage_bucket" "source_bucket" {
  provider                      = google-beta
  name                          = "${local.project}-gcf-source-${uuid()}" 
  location                      = "${local.region}"
  uniform_bucket_level_access   = true
}

resource "google_storage_bucket" "image_store" {
    name                        = "${local.project}-image-store-${uuid()}"
    location                    = "${local.region}"
    force_destroy               = true
    uniform_bucket_level_access = true
    storage_class               = "ARCHIVE"
    provider                    = google-beta

    lifecycle_rule {
        condition {
            age = 3
        }
        action {
            type = "Delete"
        }
    }
}

# Set IAM permissions on the image bucket
resource "google_storage_bucket_iam_member" "image_store_member" {
    for_each = toset([
        "roles/storage.objectCreator",
        "roles/storage.objectViewer"
        ])
    role = each.key
    member = "serviceAccount:${google_service_account.sa.email}"
    bucket = google_storage_bucket.image_store.name
    provider = google-beta
}

# Upload source code
# ----------------------------------------------
data "archive_file" "sourcezip" {
  type        = "zip"
  output_path = "${path.module}/files/source.zip"
  source_dir = "${path.module}/source/"
}

resource "google_storage_bucket_object" "object" {
  provider = google-beta
  name   = "source.zip"
  bucket = google_storage_bucket.source_bucket.name
  source = "${path.root}/files/source.zip" 
}

# Retrieve Secrets
# ----------------------------------------------
data "google_secret_manager_secret_version" "secret_slack_token" {
    provider = google-beta
    secret = "${local.project}-slack-secret"
}
data "google_secret_manager_secret_version" "secret_slack_channel" {
    provider = google-beta
    secret = "${local.project}-slack-channel"
}
resource "google_secret_manager_secret_iam_member" "secret_slack_token_member" {
  provider = google-beta
  project = data.google_secret_manager_secret_version.secret_slack_token.project
  secret_id = data.google_secret_manager_secret_version.secret_slack_token.name
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.sa.email}"
}
resource "google_secret_manager_secret_iam_member" "secret_slack_channel_member" {
  provider = google-beta
  project = data.google_secret_manager_secret_version.secret_slack_channel.project
  secret_id = data.google_secret_manager_secret_version.secret_slack_channel.name
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.sa.email}"
}

# Create the function
# ----------------------------------------------
resource "google_cloudfunctions_function" "function" {
  name        = "${local.function_name}"
  description = "XSS Canary Function"
  runtime     = "nodejs16"
  provider    = google-beta
  region = "${local.region}"

  available_memory_mb          = 128
  source_archive_bucket        = google_storage_bucket.source_bucket.name
  source_archive_object        = google_storage_bucket_object.object.name
  trigger_http                 = true
  https_trigger_security_level = "SECURE_ALWAYS"
  timeout                      = 60
  entry_point                  = "api"

  environment_variables = {
      STORAGE_BUCKET_NAME = google_storage_bucket.image_store.name
      SECRET_SLACK_TOKEN_NAME = data.google_secret_manager_secret_version.secret_slack_token.name
      SECRET_SLACK_CHANNEL_NAME = data.google_secret_manager_secret_version.secret_slack_channel.name
      GCF_HTTP_URL = "https://${local.region}-${local.project}.cloudfunctions.net/${local.function_name}/collect" 
  }
  service_account_email = google_service_account.sa.email
}

# IAM entry for all users to invoke the function (public HTTP)
resource "google_cloudfunctions_function_iam_member" "invoker" {
  project        = google_cloudfunctions_function.function.project
  region         = google_cloudfunctions_function.function.region
  cloud_function = google_cloudfunctions_function.function.name
  provider = google-beta
  role   = "roles/cloudfunctions.invoker"
  member = "allUsers"
}

# OUTPUT
# ----------------------------------------------
output "function_uri" { 
  value = google_cloudfunctions_function.function.https_trigger_url
}