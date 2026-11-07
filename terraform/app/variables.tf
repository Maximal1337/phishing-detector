variable "region" {
  description = "AWS Region; must be the foundation stack's Region."
  type        = string
  default     = "eu-north-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use. null means the default credential chain."
  type        = string
  default     = null
}

variable "allowed_account_ids" {
  description = "If set, Terraform refuses to run against any other AWS account."
  type        = list(string)
  default     = null
}

variable "foundation_state_path" {
  description = "Path to the foundation stack's local state file."
  type        = string
  default     = "../foundation/terraform.tfstate"
}

variable "log_retention_days" {
  description = "Retention for the logs this stack creates (ALB access logs in S3)."
  type        = number
  default     = 7
}

variable "image_tag" {
  description = "Tag of the app image in ECR (the git SHA printed by scripts/build_push.sh); shown as the app version."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{12}$", var.image_tag))
    error_message = "Use the 12-character git SHA that scripts/build_push.sh pushed."
  }
}

variable "image_digest" {
  description = "Digest of that image (sha256:..., printed by scripts/build_push.sh); the instances pull by digest."
  type        = string
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "Use the sha256:... digest that scripts/build_push.sh printed."
  }
}

variable "instance_type" {
  description = "EC2 instance type for the app (t3.small if t3.micro runs out of memory)."
  type        = string
  default     = "t3.micro"
}

variable "asg_min" {
  description = "Minimum (and initial) number of app instances, one per Availability Zone."
  type        = number
  default     = 2
}

variable "asg_max" {
  description = "Maximum number of app instances when scaling out."
  type        = number
  default     = 4
}

variable "alarm_email" {
  description = "E-mail address for CloudWatch alarm notifications (SNS); confirm the subscription mail AWS sends."
  type        = string
  sensitive   = true # kept out of plan output; set it only in the git-ignored terraform.tfvars
}

variable "requests_per_target_per_minute" {
  description = "Scaling target: requests per minute per instance (60 % of the ~121 req/s each t3.micro served with the pool and 2 x 4 threads)."
  type        = number
  default     = 4400
}
