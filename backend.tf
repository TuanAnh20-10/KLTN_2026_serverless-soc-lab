
terraform {
  backend "gcs" {
    bucket = "kltn-soc-terraform-state-bucket"
    prefix = "serverless-soc-lab/state"
  }
}