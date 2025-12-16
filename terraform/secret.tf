resource "google_secret_manager_secret" "app_env" {
  secret_id = "updater-mongo-connection-string"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "client_cert" {
  secret_id = "updater-mongo-client-cert"
  replication {
    auto {}
  }
}