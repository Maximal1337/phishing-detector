resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.name_prefix}-cache"
  subnet_ids = aws_subnet.db[*].id
}

# Valkey slow log (commands slower than the engine's slowlog threshold).
resource "aws_cloudwatch_log_group" "cache_slow_log" {
  #checkov:skip=CKV_AWS_158:CloudWatch Logs encrypts at rest by default; a customer-managed KMS key is a documented next step.
  #checkov:skip=CKV_AWS_338:7-day retention is enough for a short-lived demo stack and keeps storage cost down.
  name              = "/${var.name_prefix}/valkey/slow-log"
  retention_in_days = var.log_retention_days
}

# Lets the AWS log delivery service write the slow log into that one group.
# Without it, AWS creates a broader policy of its own outside Terraform,
# which would survive terraform destroy.
data "aws_iam_policy_document" "cache_log_delivery" {
  statement {
    sid     = "ValkeySlowLogDelivery"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    resources = ["${aws_cloudwatch_log_group.cache_slow_log.arn}:log-stream:*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "cache_log_delivery" {
  policy_name     = "${var.name_prefix}-valkey-slow-log-delivery"
  policy_document = data.aws_iam_policy_document.cache_log_delivery.json
}

# One Valkey node. The cache only holds scan results keyed by the email's
# SHA-256 for an hour; losing it costs a re-scan, so no replica or backups.
resource "aws_elasticache_replication_group" "main" {
  #checkov:skip=CKV_AWS_191:Encrypted at rest with the AWS-owned key; a customer-managed KMS key is a documented next step.
  #checkov:skip=CKV_AWS_31:TLS is on and only the app security group can connect; an AUTH token is a documented next step.
  #checkov:skip=CKV2_AWS_50:Single node on purpose - a cache miss only means a re-scan, so no replica or failover.
  replication_group_id = "${var.name_prefix}-cache"
  description          = "Scan result cache"

  engine         = "valkey"
  engine_version = var.cache_engine_version
  node_type      = var.cache_node_type
  # No parameter is changed, so the default group is enough.
  # tflint-ignore: aws_elasticache_replication_group_default_parameter_group
  parameter_group_name = "default.valkey8"
  port                 = 6379
  num_cache_clusters   = 1

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.cache.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  automatic_failover_enabled = false
  multi_az_enabled           = false
  snapshot_retention_limit   = 0
  auto_minor_version_upgrade = true
  apply_immediately          = true

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.cache_slow_log.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }

  depends_on = [aws_cloudwatch_log_resource_policy.cache_log_delivery]
}
