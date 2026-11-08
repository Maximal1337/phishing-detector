terraform {
  required_version = "~> 1.17"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.71.0"
    }
  }
}

provider "aws" {
  region              = var.region
  profile             = var.aws_profile
  allowed_account_ids = var.allowed_account_ids

  default_tags {
    tags = {
      Project    = "phishing-detector"
      Stack      = "foundation"
      NamePrefix = var.name_prefix # tells copies of the stacks in one account apart
    }
  }
}
