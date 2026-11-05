variable "region" {
  description = "AWS Region for every resource."
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

variable "name_prefix" {
  description = "Prefix for every resource name, so a second copy of the stack can coexist."
  type        = string
  default     = "phishdet"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,14}$", var.name_prefix))
    error_message = "name_prefix: 2-15 characters, lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "vpc_cidr" {
  description = "VPC address range. Subnets are /24 blocks carved out of it."
  type        = string
  default     = "10.20.0.0/16"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_engine_version" {
  description = "PostgreSQL major version; RDS picks the default minor and upgrades minors automatically."
  type        = string
  default     = "18"
}

variable "db_allocated_storage" {
  description = "RDS storage in GiB (gp3 minimum is 20)."
  type        = number
  default     = 20
}

variable "cache_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.t4g.micro"
}

variable "cache_engine_version" {
  description = "Valkey engine version."
  type        = string
  default     = "8.2"
}

variable "log_retention_days" {
  description = "Retention for the CloudWatch log groups this stack creates."
  type        = number
  default     = 7
}
