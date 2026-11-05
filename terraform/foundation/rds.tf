locals {
  db_identifier = "${var.name_prefix}-db"
}

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db"
  subnet_ids = aws_subnet.db[*].id

  tags = { Name = "${var.name_prefix}-db" }
}

resource "aws_db_parameter_group" "postgres" {
  name        = "${var.name_prefix}-postgres18"
  family      = "postgres18"
  description = "Require TLS; log slow statements"

  # Default since PostgreSQL 15 on RDS; set explicitly so it is visible and enforced.
  # RDS reports this parameter back with apply_method "pending-reboot"; declaring
  # the same here avoids a permanent diff. The value is already 1 (the default).
  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  # Log statements slower than 500 ms (statement text only, no bind values).
  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }
}

# Created before the instance with a retention period; otherwise RDS creates
# it on first export and keeps the logs forever.
resource "aws_cloudwatch_log_group" "rds" {
  #checkov:skip=CKV_AWS_158:CloudWatch Logs encrypts at rest by default; a customer-managed KMS key is a documented next step.
  #checkov:skip=CKV_AWS_338:7-day retention is enough for a short-lived demo stack and keeps storage cost down.
  name              = "/aws/rds/instance/${local.db_identifier}/postgresql"
  retention_in_days = var.log_retention_days
}

resource "aws_db_instance" "main" {
  #checkov:skip=CKV_AWS_157:Single-AZ to halve the cost; the app tier is the highly available part (see README).
  #checkov:skip=CKV_AWS_353:Performance Insights is an add-on not used here; standard RDS metrics feed the dashboard.
  #checkov:skip=CKV_AWS_118:Enhanced monitoring needs an extra IAM role and log ingestion; standard RDS metrics are enough here.
  #checkov:skip=CKV_AWS_161:The app uses the RDS-managed password from Secrets Manager; IAM database auth is a documented next step.
  #checkov:skip=CKV_AWS_293:The stack must be destroyable with terraform destroy at the end of the review.
  identifier     = local.db_identifier
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true

  db_name  = "phishdet"
  username = "phishdet"
  # RDS generates the password and keeps it in Secrets Manager; it never
  # appears in Terraform code, variables or state.
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.postgres.name
  publicly_accessible    = false
  multi_az               = false

  backup_retention_period    = 1
  copy_tags_to_snapshot      = true
  auto_minor_version_upgrade = true
  apply_immediately          = true

  enabled_cloudwatch_logs_exports = ["postgresql"]

  # The stack is torn down after the review: no final snapshot, automated
  # backups deleted with the instance, no lock. Nothing outlives destroy.
  skip_final_snapshot      = true
  delete_automated_backups = true
  deletion_protection      = false

  depends_on = [aws_cloudwatch_log_group.rds]
}
