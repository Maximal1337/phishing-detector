resource "aws_lb" "main" {
  #checkov:skip=CKV_AWS_150:No deletion protection, so terraform destroy works at the end of the review.
  #checkov:skip=CKV2_AWS_20:Viewers are redirected to HTTPS by CloudFront; the ALB only accepts CloudFront's addresses and has no certificate.
  #checkov:skip=CKV2_AWS_28:WAF is a paid add-on not used here; documented next step.
  name               = "${local.name_prefix}-alb"
  load_balancer_type = "application"
  internal           = false
  subnets            = local.foundation.public_subnet_ids

  # The foundation's ALB group: HTTP only from CloudFront's origin-facing
  # addresses, outbound only to the app instances.
  security_groups = [local.foundation.alb_security_group_id]

  drop_invalid_header_fields = true
  enable_deletion_protection = false

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb"
    enabled = true
  }

  # ALB checks that it can write to the bucket when logging is enabled.
  depends_on = [aws_s3_bucket_policy.alb_logs]
}

# Placeholder until the instances exist (stage 7 switches this to forward
# to the target group).
resource "aws_lb_listener" "http" {
  #checkov:skip=CKV_AWS_2:No domain, so no certificate for the ALB; viewer TLS ends at CloudFront. ALB certificate or VPC origin is a next step.
  #checkov:skip=CKV_AWS_103:Same reason - this listener has no TLS at all.
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "placeholder: the app is not deployed yet"
      status_code  = "200"
    }
  }
}
