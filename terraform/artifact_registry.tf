resource "google_artifact_registry_repository" "repo" {
  location      = var.region
  repository_id = "app-repo"
  description   = "Docker repository for Cloud Run"
  format        = "DOCKER"

  cleanup_policies {
    id     = "keep-minimum-versions"
    action = "KEEP"
    most_recent_versions {
      keep_count = 3 # 最新の3つだけ残す
    }
  }

  cleanup_policies {
    id     = "delete-old-images"
    action = "DELETE"
    condition {
      # 上記KEEPルールにマッチしない、かつアップロードから一定時間経過したものを削除
      older_than = "86400s" # 1日以上経過したもの
    }
  }
}