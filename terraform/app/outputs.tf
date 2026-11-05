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
