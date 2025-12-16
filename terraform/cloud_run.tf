resource "google_cloud_run_v2_job" "default" {
  name     = "my-cron-job"
  location = var.region

  template {
    template {
      containers {
        image = var.image_url
        
        resources {
          limits = {
            cpu    = "1000m" # 1 vCPU
            memory = "512Mi"
          }
        }
        
        env {
          name  = "ENV_VAR"
          value = "value"
        }
      }
      
      max_retries = 0 
      task_count  = 1
    }
  }
}