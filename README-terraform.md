# Terraform layout

The deployable configuration lives at the repository root (`main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`), with reusable modules under `modules/`.

No backend is declared in source so this configuration is consumable as a module; the operator chooses a backend by copying `backend.tf.example` to `backend.tf` (gitignored) - local, S3, or their own HCP workspace. When run under HCP Terraform, AWS authentication uses OIDC dynamic credentials via the `TFC_AWS_PROVIDER_AUTH` and `TFC_AWS_RUN_ROLE_ARN` workspace variables; otherwise configure the AWS provider's `assume_role` with the `ccg-deploy` role from `deploy/bootstrap-role.yaml`. See DISTRIBUTION.md.

```powershell
terraform init
terraform plan
```

Never commit state or credentials. Applies are triggered by the VCS-driven workflow after a reviewed plan.
