# HTTPS for the web UI without owning a domain: viewers connect to the
# *.cloudfront.net address with CloudFront's default certificate. Caching is
# off, so every request reaches the ALB and shows up in its metrics and logs.

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

data "aws_cloudfront_response_headers_policy" "security_headers" {
  name = "Managed-SecurityHeadersPolicy"
}

resource "aws_cloudfront_distribution" "main" {
  #checkov:skip=CKV_AWS_86:Caching is off, so every request reaches the ALB, whose access logs record it in this Region.
  #checkov:skip=CKV_AWS_68:WAF is a paid add-on not used here; documented next step.
  #checkov:skip=CKV2_AWS_47:No WAF attached (see CKV_AWS_68).
  #checkov:skip=CKV_AWS_174:No domain - the default *.cloudfront.net certificate doesn't allow raising the minimum TLS version; custom domain is a next step.
  #checkov:skip=CKV2_AWS_42:No domain to issue a custom certificate for (see CKV_AWS_174).
  #checkov:skip=CKV_AWS_310:One origin; availability comes from the ALB and the two instances behind it.
  #checkov:skip=CKV_AWS_374:Reviewers may be anywhere; access is limited by Basic auth instead.
  #checkov:skip=CKV_AWS_305:The origin is an application that serves its own root path.
  enabled         = true
  comment         = "${local.name_prefix} web UI"
  price_class     = "PriceClass_100"
  http_version    = "http2and3"
  is_ipv6_enabled = true

  origin {
    origin_id   = "alb"
    domain_name = aws_lb.main.dns_name

    # No domain means no certificate for the ALB, so CloudFront talks HTTP to it.
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer.id
    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.security_headers.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
