# Optional egress-containment network (var.enable_vpc). A VPC with a single private subnet,
# NO internet gateway, NO NAT — so the default route does not reach the internet — and a
# security group with NO egress rules (fully closed outbound). This is the architectural half
# of the egress story (§2.4): the aegis-egress allowlist decides what MAY leave, and the
# network guarantees nothing else CAN. The Lambda still executes and returns normally.

resource "aws_vpc" "this" {
  count                = var.enable_vpc ? 1 : 0
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${var.project_name}-vpc" })
}

resource "aws_subnet" "private" {
  count             = var.enable_vpc ? 1 : 0
  vpc_id            = aws_vpc.this[0].id
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = merge(local.tags, { Name = "${var.project_name}-private" })
}

# A dedicated route table with only the implicit local route — no 0.0.0.0/0 entry.
resource "aws_route_table" "private" {
  count  = var.enable_vpc ? 1 : 0
  vpc_id = aws_vpc.this[0].id
  tags   = merge(local.tags, { Name = "${var.project_name}-private-rt" })
}

resource "aws_route_table_association" "private" {
  count          = var.enable_vpc ? 1 : 0
  subnet_id      = aws_subnet.private[0].id
  route_table_id = aws_route_table.private[0].id
}

# Closed-egress security group: no egress blocks => Terraform leaves zero egress rules, so the
# function's ENI has no permitted outbound path at all. S3 is reached via the gateway endpoint
# below, which is a route-table entry (prefix list) and does not require an SG egress rule.
resource "aws_security_group" "lambda" {
  count       = var.enable_vpc ? 1 : 0
  name        = "${var.project_name}-lambda-sg"
  description = "Closed-egress SG for the Aegis agent Lambda"
  vpc_id      = aws_vpc.this[0].id
  tags        = merge(local.tags, { Name = "${var.project_name}-lambda-sg" })
}

# S3 gateway VPC endpoint: adds an S3 prefix-list route to the private route table so the
# extension can fetch policy artifacts from S3 without any internet route. Gateway endpoints
# are free and traffic stays on the AWS network.
resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_vpc ? 1 : 0
  vpc_id            = aws_vpc.this[0].id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private[0].id]
  tags              = merge(local.tags, { Name = "${var.project_name}-s3-endpoint" })
}
