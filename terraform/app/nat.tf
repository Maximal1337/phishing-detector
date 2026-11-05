# Outbound internet for the private app subnets (ECR, SSM, CloudWatch,
# Secrets Manager APIs). One NAT gateway in the first AZ for both subnets
# halves the hourly cost; if that AZ fails, instances in the other AZ keep
# serving requests but lose outbound access. Documented trade-off.

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = { Name = "${local.name_prefix}-nat" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = local.foundation.public_subnet_ids[0]

  tags = { Name = "${local.name_prefix}-nat" }
}

# Added to the foundation's app route table, so the NAT and its route come
# and go with this stack.
resource "aws_route" "app_default" {
  route_table_id         = local.foundation.app_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}
