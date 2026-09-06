terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      # >= 5.80 for aws_sfn_state_machine encryption_configuration (customer-managed KMS).
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.region
}
