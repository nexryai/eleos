resource "google_artifact_registry_repository" "repo" {
  location      = var.region
  repository_id = "app-repo"
  description   = "Docker repository for Cloud Run"
  format        = "DOCKER"

  cleanup_policies {
    id     = "keep-minimum-versions"
    action = "KEEP"
    most_recent_versions {
      keep_count = 2
    }
  }

  cleanup_policies {
    id     = "delete-unprotected-images"
    action = "DELETE"
    condition {
      older_than = "0s"
    }
  }
}