terraform {
  backend "gcs" {
    bucket  = "eleos-terraform-state"
    prefix  = "terraform/state"
  }
}