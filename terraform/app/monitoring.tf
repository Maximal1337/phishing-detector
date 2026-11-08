# Monitoring: alarms to an e-mail topic (with recovery notices), metrics from the app's
# JSON log lines, one dashboard and saved Logs Insights queries.

locals {
  metrics_namespace = local.name_prefix                          # custom metrics from the app logs
  db_identifier     = split(".", local.foundation.db_address)[0] # the RDS endpoint starts with the instance id
  alb_dimensions    = { LoadBalancer = aws_lb.main.arn_suffix }
  tg_dimensions     = { LoadBalancer = aws_lb.main.arn_suffix, TargetGroup = aws_lb_target_group.app.arn_suffix }
  alarm_actions     = [aws_sns_topic.alarms.arn]

  # One metric per app failure event (history failures alarm; cache problems only show on the dashboard).
  log_events = {
    history_read_failed  = "HistoryReadFailed"
    history_write_failed = "HistoryWriteFailed"
    cache_failed         = "CacheFailed"
    cache_decode_failed  = "CacheDecodeFailed"
  }
}

# --- notifications ------------------------------------------------------

resource "aws_sns_topic" "alarms" {
  #checkov:skip=CKV_AWS_26:CloudWatch alarms can't publish to a topic encrypted with aws/sns; a customer-managed key is a next step (README).
  name = "${local.name_prefix}-alarms"
}

data "aws_iam_policy_document" "alarms_topic" {
  statement {
    sid       = "CloudWatchAlarmsOfThisStack"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alarms.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudwatch:${var.region}:${data.aws_caller_identity.current.account_id}:alarm:${local.name_prefix}-*"]
    }
  }
}

resource "aws_sns_topic_policy" "alarms" {
  arn    = aws_sns_topic.alarms.arn
  policy = data.aws_iam_policy_document.alarms_topic.json
}

# Max confirms the subscription from the e-mail AWS sends; until then nothing is delivered.
resource "aws_sns_topic_subscription" "alarm_email" {
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# --- metrics from the app's JSON log lines ------------------------------

resource "aws_cloudwatch_log_metric_filter" "app_events" {
  for_each       = local.log_events
  name           = "${local.name_prefix}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = "{ $.event = \"${each.key}\" }"

  metric_transformation {
    name      = each.value
    namespace = local.metrics_namespace
    value     = "1"
  }
}

# --- alarms (each also sends an OK notice when it recovers) -------------

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "${local.name_prefix}-unhealthy-hosts"
  alarm_description   = "At least one app instance fails the load balancer health check."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  dimensions          = local.tg_dimensions
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "http_5xx" {
  alarm_name          = "${local.name_prefix}-http-5xx"
  alarm_description   = "5 or more 5xx answers in a minute, from the app or the load balancer (includes 503 when the Basic-auth secret can't be read)."
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions

  metric_query {
    id          = "errors"
    expression  = "FILL(target, 0) + FILL(elb, 0)"
    label       = "5xx answers"
    return_data = true
  }
  metric_query {
    id = "target"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "HTTPCode_Target_5XX_Count"
      dimensions  = local.alb_dimensions
      stat        = "Sum"
      period      = 60
    }
  }
  metric_query {
    id = "elb"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "HTTPCode_ELB_5XX_Count"
      dimensions  = local.alb_dimensions
      stat        = "Sum"
      period      = 60
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "asg_cpu" {
  alarm_name          = "${local.name_prefix}-app-cpu"
  alarm_description   = "Average CPU of the app instances above 80 % for 10 minutes."
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  dimensions          = { AutoScalingGroupName = aws_autoscaling_group.app.name }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${local.name_prefix}-db-cpu"
  alarm_description   = "RDS CPU above 80 % for 10 minutes."
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = local.db_identifier }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "rds_free_storage" {
  alarm_name          = "${local.name_prefix}-db-free-storage"
  alarm_description   = "Less than 2 GiB free on the RDS volume (20 GiB allocated)."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = local.db_identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = 2 * 1024 * 1024 * 1024
  treat_missing_data  = "breaching" # no storage metric at all is itself a problem
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "history_store_errors" {
  alarm_name          = "${local.name_prefix}-history-store-errors"
  alarm_description   = "The scan history (RDS) failed to read or write at least once in 5 minutes; scans fall back to cautious verdicts (D-70)."
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions

  metric_query {
    id          = "errors"
    expression  = "FILL(reads, 0) + FILL(writes, 0)"
    label       = "History store errors"
    return_data = true
  }
  metric_query {
    id = "reads"
    metric {
      namespace   = local.metrics_namespace
      metric_name = local.log_events["history_read_failed"]
      stat        = "Sum"
      period      = 300
    }
  }
  metric_query {
    id = "writes"
    metric {
      namespace   = local.metrics_namespace
      metric_name = local.log_events["history_write_failed"]
      stat        = "Sum"
      period      = 300
    }
  }
}

# --- saved Logs Insights queries ----------------------------------------

resource "aws_cloudwatch_query_definition" "errors_by_type" {
  name            = "${local.name_prefix}/errors-by-type"
  log_group_names = [aws_cloudwatch_log_group.app.name]
  query_string    = <<-EOT
    fields @timestamp, event, error, status, path
    | filter (event != "request" and ispresent(error)) or status >= 400
    | stats count(*) as count by event, error, status
    | sort count desc
  EOT
}

resource "aws_cloudwatch_query_definition" "scans_by_verdict" {
  name            = "${local.name_prefix}/scans-by-verdict"
  log_group_names = [aws_cloudwatch_log_group.app.name]
  query_string    = <<-EOT
    filter event = "request" and path = "/api/scan" and status = 200
    | stats count(*) as scans by verdict, bin(1h) as hour
    | sort hour desc
  EOT
}

resource "aws_cloudwatch_query_definition" "scan_latency" {
  name            = "${local.name_prefix}/scan-latency"
  log_group_names = [aws_cloudwatch_log_group.app.name]
  query_string    = <<-EOT
    filter event = "request" and path = "/api/scan"
    | stats pct(duration_ms, 50) as p50_ms, pct(duration_ms, 95) as p95_ms, count(*) as scans by bin(5m)
  EOT
}
