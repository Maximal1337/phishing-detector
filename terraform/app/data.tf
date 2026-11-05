# The foundation stack (network, security groups, RDS, Valkey, ECR, secrets)
# is created in advance; this stack reads its outputs from the local state.
data "terraform_remote_state" "foundation" {
  backend = "local"

  config = {
    path = var.foundation_state_path
  }
}

data "aws_caller_identity" "current" {}

locals {
  foundation = data.terraform_remote_state.foundation.outputs

  # Same prefix as the foundation, so a second copy of both stacks never collides.
  name_prefix = local.foundation.name_prefix
}
