terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.80" }
  }
  # backend "s3" { bucket = "acme-tfstate", key = "irg/production.tfstate", region = "eu-central-1", dynamodb_table = "tf-locks", encrypt = true }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { project = "identity-risk-graph", environment = var.environment, managed_by = "terraform" }
  }
}
