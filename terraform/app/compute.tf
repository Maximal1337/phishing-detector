# Two (up to four) t3.micro instances in the private app subnets, each running the
# app container from ECR under systemd. A new image tag = a new launch template
# version = a rolling instance refresh.

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_default_tags" "current" {}

resource "aws_cloudwatch_log_group" "app" {
  #checkov:skip=CKV_AWS_338:7-day retention is enough for a short-lived stack.
  #checkov:skip=CKV_AWS_158:AWS-owned encryption at rest; a customer-managed KMS key is a documented next step.
  name              = "/${local.name_prefix}/app"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "cloud_init" {
  #checkov:skip=CKV_AWS_338:7-day retention is enough for a short-lived stack.
  #checkov:skip=CKV_AWS_158:AWS-owned encryption at rest; a customer-managed KMS key is a documented next step.
  name              = "/${local.name_prefix}/cloud-init"
  retention_in_days = var.log_retention_days
}

locals {
  # By digest: the instances run exactly the image that build_push.sh saw pass the scan.
  image = "${local.foundation.ecr_repository_url}@${var.image_digest}"

  # Environment of the app container; no secret values, only where to find them.
  app_env = {
    APP_VERSION     = var.image_tag
    AWS_REGION      = var.region
    DB_HOST         = local.foundation.db_address
    DB_PORT         = local.foundation.db_port
    DB_NAME         = local.foundation.db_name
    DB_SSLMODE      = "require"
    DB_SECRET_ARN   = local.foundation.db_secret_arn
    AUTH_SECRET_ARN = local.foundation.auth_secret_arn
    CACHE_URL       = "rediss://${local.foundation.cache_address}:${local.foundation.cache_port}/0"
  }
}

resource "aws_launch_template" "app" {
  #checkov:skip=CKV_AWS_341:Hop limit 2 so the container, one hop behind the Docker bridge, can get the role's credentials (IMDSv2 only).
  name_prefix   = "${local.name_prefix}-app-"
  image_id      = data.aws_ssm_parameter.al2023.insecure_value # a public AMI id, not a secret
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.app.arn
  }
  vpc_security_group_ids = [local.foundation.app_security_group_id]

  # Unlimited credits, set explicitly (D-30): t3 in standard mode gets no launch credits, so a new
  # instance would boot at the 10 % baseline and miss the 180 s health-check grace. Unlimited costs
  # extra only while the average CPU stays above the baseline (README, "Cost").
  credit_specification {
    cpu_credits = "unlimited"
  }

  # IMDSv2 only; hop limit 2 so the container (one network hop further) can get the role's credentials.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = "gp3"
      volume_size           = 8
      encrypted             = true
      delete_on_termination = true
    }
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tftpl", {
    region           = var.region
    registry         = split("/", local.foundation.ecr_repository_url)[0]
    image            = local.image
    app_log_group    = aws_cloudwatch_log_group.app.name
    cloud_init_group = aws_cloudwatch_log_group.cloud_init.name
    app_env          = local.app_env
  }))

  # Provider default tags don't reach the instances and volumes; copy them.
  tag_specifications {
    resource_type = "instance"
    tags          = merge(data.aws_default_tags.current.tags, { Name = "${local.name_prefix}-app" })
  }
  tag_specifications {
    resource_type = "volume"
    tags          = merge(data.aws_default_tags.current.tags, { Name = "${local.name_prefix}-app" })
  }
}

resource "aws_lb_target_group" "app" {
  #checkov:skip=CKV_AWS_378:HTTP from the ALB to the instances inside the VPC; TLS on this hop is a next step (with a domain and certificates).
  name_prefix          = "app-"
  port                 = 8000
  protocol             = "HTTP"
  vpc_id               = local.foundation.vpc_id
  deregistration_delay = 30

  health_check {
    path                = "/healthz"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "app" {
  name_prefix               = "${local.name_prefix}-app-"
  min_size                  = var.asg_min
  desired_capacity          = var.asg_min
  max_size                  = var.asg_max
  vpc_zone_identifier       = local.foundation.app_subnet_ids
  target_group_arns         = [aws_lb_target_group.app.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 180

  launch_template {
    id      = aws_launch_template.app.id
    version = aws_launch_template.app.latest_version
  }

  # A changed launch template (new image, new AMI) replaces the instances: launch first, then terminate.
  # With 100 / 200 % the group adds new instances up to twice its size, waits until they are healthy and
  # warmed up, and only then stops old ones, so capacity never drops below the two instances.
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 100
      max_healthy_percentage = 200
      instance_warmup        = 120
    }
  }

  enabled_metrics = [
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-app"
    propagate_at_launch = false # the launch template tags the instances
  }

  lifecycle {
    # The scaling policy (stage 8) changes the desired count; don't fight it on every apply.
    ignore_changes = [desired_capacity]
  }
}
