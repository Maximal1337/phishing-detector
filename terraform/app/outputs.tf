output "url" {
  description = "Public HTTPS address of the web UI."
  value       = "https://${aws_cloudfront_distribution.main.domain_name}"
}

output "alb_dns_name" {
  description = "Not reachable directly: the ALB only accepts CloudFront's addresses."
  value       = aws_lb.main.dns_name
}

output "alb_logs_bucket" {
  value = aws_s3_bucket.alb_logs.id
}

output "nat_public_ip" {
  value = aws_eip.nat.public_ip
}

output "asg_name" {
  description = "Auto Scaling group of the app instances."
  value       = aws_autoscaling_group.app.name
}

output "app_log_group" {
  description = "CloudWatch log group with the app's JSON log lines."
  value       = aws_cloudwatch_log_group.app.name
}

output "image_tag" {
  description = "Image tag the instances run."
  value       = var.image_tag
}
