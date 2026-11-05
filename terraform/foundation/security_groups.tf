# All security groups live in this stack so that RDS and ElastiCache can
# reference the app group before the app stack exists. Groups created with
# aws_security_group lose AWS's default allow-all egress rule; every allowed
# flow below is explicit.

data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "alb" {
  #checkov:skip=CKV2_AWS_5:Attached to the load balancer in the app stack.
  name        = "${var.name_prefix}-alb"
  description = "ALB: HTTP from CloudFront only, to the app instances only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-alb" }
}

resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:Attached to the instances in the app stack.
  name        = "${var.name_prefix}-app"
  description = "App instances: port 8000 from the ALB only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-app" }
}

resource "aws_security_group" "db" {
  name        = "${var.name_prefix}-db"
  description = "RDS: PostgreSQL from the app instances only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-db" }
}

resource "aws_security_group" "cache" {
  name        = "${var.name_prefix}-cache"
  description = "ElastiCache: Valkey from the app instances only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-cache" }
}

# --- ALB ---

resource "aws_vpc_security_group_ingress_rule" "alb_from_cloudfront" {
  #checkov:skip=CKV_AWS_260:False positive - the source is the CloudFront managed prefix list, not 0.0.0.0/0.
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from CloudFront origin-facing addresses"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  prefix_list_id    = data.aws_ec2_managed_prefix_list.cloudfront.id
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To the app containers"
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
  referenced_security_group_id = aws_security_group.app.id
}

# --- App instances ---

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "From the ALB"
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to AWS APIs (ECR, SSM, CloudWatch, Secrets Manager) and S3"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id            = aws_security_group.app.id
  description                  = "PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.db.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_cache" {
  security_group_id            = aws_security_group.app.id
  description                  = "Valkey"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = aws_security_group.cache.id
}

# --- Data tier (no egress rules at all) ---

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from the app instances"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_ingress_rule" "cache_from_app" {
  security_group_id            = aws_security_group.cache.id
  description                  = "Valkey from the app instances"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = aws_security_group.app.id
}
