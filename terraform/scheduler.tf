resource "google_service_account" "scheduler_sa" {
  account_id   = "scheduler-sa"
  display_name = "Cloud Scheduler Service Account"
}

resource "google_project_iam_member" "scheduler_run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:${google_service_account.scheduler_sa.email}"
}

resource "google_cloud_scheduler_job" "cron_job" {
  name        = "run-every-15-mins"
  description = "Trigger Cloud Run Job every 15 minutes"
  schedule    = "*/15 * * * *"
  time_zone   = "Asia/Tokyo"
  region      = var.region

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/v2/${google_cloud_run_v2_job.default.id}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler_sa.email
    }
  }
}