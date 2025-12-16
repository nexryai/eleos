resource "google_cloud_run_v2_job" "default" {
  name     = "db-update-job"
  location = var.region

  template {
    task_count  = 1
    # parallelism = 1

    template {
      max_retries = 0

      containers {
        image = var.image_url
        resources {
          limits = {
            cpu    = "1000m"
            memory = "512Mi"
          }
        }
      }
    }
  }
}