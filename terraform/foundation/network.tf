data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:Only the first two names in sorted order are used; a new AZ sorts after them and changes nothing.
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  # Two AZs: enough for the ALB (needs two) and for spreading the two instances.
  azs = slice(sort(data.aws_availability_zones.available.names), 0, 2)
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

# Terraform takes over the VPC's default security group and removes all of its
# rules, so nothing can be launched into it by accident with open access.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-default-unused" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-igw" }
}

# Public subnets: only the ALB and the NAT gateway live here. No automatic
# public IPs, so an instance launched here by mistake is not exposed.
resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-public-${local.azs[count.index]}", Tier = "public" }
}

# Private subnets for the EC2 instances.
resource "aws_subnet" "app" {
  count = 2

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 10 + count.index)
  availability_zone = local.azs[count.index]

  tags = { Name = "${var.name_prefix}-app-${local.azs[count.index]}", Tier = "app" }
}

# Private subnets for RDS and ElastiCache. No route out of the VPC.
resource "aws_subnet" "db" {
  count = 2

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 20 + count.index)
  availability_zone = local.azs[count.index]

  tags = { Name = "${var.name_prefix}-db-${local.azs[count.index]}", Tier = "db" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# One route table for both app subnets. The app stack adds the default route
# to its NAT gateway here, so the hourly NAT cost goes away with that stack.
resource "aws_route_table" "app" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-app" }
}

resource "aws_route_table_association" "app" {
  count = 2

  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app.id
}

resource "aws_route_table" "db" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-db" }
}

resource "aws_route_table_association" "db" {
  count = 2

  subnet_id      = aws_subnet.db[count.index].id
  route_table_id = aws_route_table.db.id
}

# Free S3 gateway endpoint: ECR image layers and the Amazon Linux package
# repositories are served from S3, so that traffic skips the NAT gateway.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.app.id]

  tags = { Name = "${var.name_prefix}-s3" }
}
