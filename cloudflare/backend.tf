terraform {
  backend "gcs" {
    bucket = "cloudshield-ai-terraform-state"
    prefix = "cloudflare-infra/appointy/state"
  }
}