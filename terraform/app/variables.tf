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
