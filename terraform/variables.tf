variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region (e.g., asia-northeast1)"
  default     = "asia-northeast1"
}

variable "github_repo" {
  description = "GitHub Repository (username/reponame)"
  type        = string
}

variable "image_url" {
  description = "Container image URL for Cloud Run"
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}