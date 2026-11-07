# Target tracking on requests per instance, measured at the load balancer every minute.
# Not CPU: the bottleneck is the two gunicorn workers waiting on PostgreSQL and Valkey, which
# doesn't show as CPU; without detailed monitoring the EC2 CPU metric comes every 5 minutes;
# and CPU above the t3 baseline costs extra in unlimited mode (README, "Scaling").
resource "aws_autoscaling_policy" "requests_per_target" {
  name                   = "${local.name_prefix}-requests-per-target"
  autoscaling_group_name = aws_autoscaling_group.app.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.main.arn_suffix}/${aws_lb_target_group.app.arn_suffix}"
    }
    target_value = var.requests_per_target_per_minute
  }
}
