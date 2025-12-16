resource "google_service_account" "run_app_sa" {
  account_id   = "run-app-sa"
  display_name = "Cloud Run Runtime Service Account"
}

resource "google_project_iam_member" "run_sa_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.run_app_sa.email}"
}