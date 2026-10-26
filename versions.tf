terraform {
  required_version = ">= 1.8.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.64.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # NOTE: No backend/cloud block is declared here so this configuration can be
  # consumed as a distributable module and initialized against ANY backend the
  # operator chooses (local, S3, or their own HCP Terraform workspace).
  #
  # To use a backend, copy backend.tf.example to backend.tf (gitignored) and run
  # `terraform init`. See DISTRIBUTION.md. The project's own HCP wiring lives in
  # backend.tf.example as the HCP option.
}
