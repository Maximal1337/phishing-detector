# HTTP Basic auth credentials for the web UI. Terraform creates only the
# empty secret; the operator sets the value from the CLI, so the password is
# never in code, variables or Terraform state.
resource "aws_secretsmanager_secret" "basic_auth" {
  #checkov:skip=CKV_AWS_149:Encrypted with the AWS-managed Secrets Manager key; a customer-managed KMS key is a documented next step.
  #checkov:skip=CKV2_AWS_57:The operator sets and changes this password by hand; rotation would need a rotation Lambda.
  name        = "${var.name_prefix}/basic-auth"
  description = "Web UI Basic auth credentials, JSON {\"username\": ..., \"password\": ...}; set by the operator"

  # Delete immediately on destroy, so destroy + apply can reuse the name.
  recovery_window_in_days = 0
}
