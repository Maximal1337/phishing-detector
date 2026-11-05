# Read by the app stack through terraform_remote_state.

output "region" {
  value = var.region
}

output "name_prefix" {
  value = var.name_prefix
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "app_subnet_ids" {
  value = aws_subnet.app[*].id
}

output "app_route_table_id" {
  description = "The app stack adds the 0.0.0.0/0 route to its NAT gateway here."
  value       = aws_route_table.app.id
}

output "alb_security_group_id" {
  value = aws_security_group.alb.id
}

output "app_security_group_id" {
  value = aws_security_group.app.id
}

output "db_address" {
  value = aws_db_instance.main.address
}

output "db_port" {
  value = aws_db_instance.main.port
}

output "db_name" {
  value = aws_db_instance.main.db_name
}

output "db_secret_arn" {
  description = "RDS-managed secret with the master username and password."
  value       = aws_db_instance.main.master_user_secret[0].secret_arn
}

output "cache_address" {
  value = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "cache_port" {
  value = aws_elasticache_replication_group.main.port
}

output "ecr_repository_name" {
  value = aws_ecr_repository.app.name
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "ecr_repository_arn" {
  value = aws_ecr_repository.app.arn
}

output "auth_secret_name" {
  value = aws_secretsmanager_secret.basic_auth.name
}

output "auth_secret_arn" {
  value = aws_secretsmanager_secret.basic_auth.arn
}
