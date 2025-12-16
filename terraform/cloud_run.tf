resource "google_cloud_run_v2_job" "default" {
  name     = "db-update-job"
  location = var.region

  template {
    task_count = 1

    template {
      service_account = google_service_account.run_app_sa.email

      max_retries = 0

      containers {
        image = var.image_url
        
        resources {
          limits = {
            cpu    = "1000m"
            memory = "512Mi"
          }
        }

        env {
          name = "DB_CONNECT_STRING"
          value_source {
            secret_key_ref {
              secret = google_secret_manager_secret.app_env.secret_id
              version = "latest"
            }
          }
        }

        volume_mounts {
          name       = "cert-volume"
          mount_path = "/var/certs"
        }
      }

      volumes {
        name = "cert-volume"
        secret {
          secret = google_secret_manager_secret.client_cert.secret_id
          default_mode = 0444
          
          items {
            version = "latest"
            path    = "client.pem"
          }
        }
      }
    }
  }
}