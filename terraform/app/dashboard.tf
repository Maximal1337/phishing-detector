# One CloudWatch dashboard for the whole stack: health, load, errors, latency, the
# database, app failure events and the latest log lines.

locals {
  lb  = aws_lb.main.arn_suffix
  tg  = aws_lb_target_group.app.arn_suffix
  asg = aws_autoscaling_group.app.name

  widgets = [
    {
      title = "Targets (load balancer health check)"
      metrics = [["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", local.tg, "LoadBalancer", local.lb, { stat = "Minimum", label = "healthy" }],
      ["AWS/ApplicationELB", "UnHealthyHostCount", "TargetGroup", local.tg, "LoadBalancer", local.lb, { stat = "Maximum", label = "unhealthy", color = "#d62728" }]]
    },
    {
      title = "Instances (Auto Scaling group, EC2 status checks)"
      metrics = [["AWS/AutoScaling", "GroupInServiceInstances", "AutoScalingGroupName", local.asg, { stat = "Average", label = "in service" }],
        ["AWS/AutoScaling", "GroupDesiredCapacity", "AutoScalingGroupName", local.asg, { stat = "Average", label = "desired" }],
      ["AWS/EC2", "StatusCheckFailed", "AutoScalingGroupName", local.asg, { stat = "Maximum", label = "status check failed", color = "#d62728" }]]
    },
    {
      title   = "Requests through the load balancer"
      metrics = [["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.lb, { stat = "Sum", label = "requests" }]]
    },
    {
      title = "Answers by status"
      metrics = [["AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "app 2xx", color = "#2ca02c" }],
        ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "app 4xx (401 = no password)", color = "#ff7f0e" }],
        ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "app 5xx", color = "#d62728" }],
      ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "load balancer 5xx", color = "#9467bd" }]]
    },
    {
      title = "Response time (target)"
      metrics = [["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.lb, { stat = "p50", label = "p50" }],
      ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.lb, { stat = "p95", label = "p95" }]]
    },
    {
      title   = "App instances: CPU"
      metrics = [["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", local.asg, { stat = "Average", label = "CPU % (average)" }]]
    },
    {
      title   = "App instances: memory and disk (CloudWatch agent)"
      metrics = [[{ expression = "SEARCH('{CWAgent,InstanceId} MetricName=\"mem_used_percent\"', 'Average', 60)", id = "mem", label = "memory %" }], [{ expression = "SEARCH('{CWAgent,InstanceId,device,fstype,path} MetricName=\"disk_used_percent\"', 'Maximum', 300)", id = "disk", label = "disk %" }]]
    },
    {
      title = "Database (RDS)"
      metrics = [["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", local.db_identifier, { stat = "Average", label = "CPU %" }],
      ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", local.db_identifier, { stat = "Maximum", label = "connections", yAxis = "right" }]]
    },
    {
      title   = "Database free storage (bytes)"
      metrics = [["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", local.db_identifier, { stat = "Minimum", label = "free storage" }]]
    },
    {
      title   = "App failure events (from the JSON logs)"
      metrics = [for event, metric in local.log_events : [local.metrics_namespace, metric, { stat = "Sum", label = event }]]
    },
  ]
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${local.name_prefix}-overview"
  dashboard_body = jsonencode({
    widgets = concat(
      [for i, w in local.widgets : {
        type   = "metric"
        x      = (i % 2) * 12
        y      = floor(i / 2) * 6
        width  = 12
        height = 6
        properties = {
          title   = w.title
          region  = var.region
          view    = "timeSeries"
          stacked = false
          period  = 60
          metrics = w.metrics
        }
      }],
      [{
        type   = "log"
        x      = 0
        y      = ceil(length(local.widgets) / 2) * 6
        width  = 24
        height = 6
        properties = {
          title  = "Latest app events other than successful requests"
          region = var.region
          view   = "table"
          query  = "SOURCE '${aws_cloudwatch_log_group.app.name}' | fields @timestamp, coalesce(event, @message) as event_or_line, path, status, error, message, verdict, duration_ms | filter event != \"request\" or status >= 400 or not ispresent(event) | sort @timestamp desc | limit 50"
        }
      }],
    )
  })
}
