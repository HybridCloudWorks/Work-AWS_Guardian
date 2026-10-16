terraform {
  required_version = ">= 1.8.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.68.0"
    }
  }

  cloud {
    organization = "hcw"

    workspaces {
      name = "compliance_guardian"
    }
  }
}
