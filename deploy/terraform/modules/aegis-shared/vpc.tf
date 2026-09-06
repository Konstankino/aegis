# Optional shared, no-default-route VPC for egress containment (§2.4). Two private subnets, NO
# IGW/NAT, a closed-ish security group (only in-VPC HTTPS), and the VPC endpoints the agents need
# so they can still reach AWS services without an internet route:
#   * S3 + DynamoDB       — gateway endpoints (free; policy fetch + checkpointer)
#   * Bedrock runtime     — interface endpoint (the LLM call)
#   * X-Ray + CloudWatch  — interface endpoints, only when the OTel collector is enabled (export)
#
# CloudWatch *Logs* need no endpoint: Lambda delivers function/extension logs via the Lambda
# service, not the function's ENI.

data "aws_availability_zones" "available" {
  count = var.enable_vpc ? 1 : 0
  state = "available"
}

resource "aws_vpc" "this" {
  count                = var.enable_vpc ? 1 : 0
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${var.name_prefix}-vpc" })
}

resource "aws_subnet" "private" {
  count             = var.enable_vpc ? 2 : 0
  vpc_id            = aws_vpc.this[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available[0].names[count.index]
  tags              = merge(local.tags, { Name = "${var.name_prefix}-private-${count.index}" })
}

# Route table with only the implicit local route — no 0.0.0.0/0.
resource "aws_route_table" "private" {
  count  = var.enable_vpc ? 1 : 0
  vpc_id = aws_vpc.this[0].id
  tags   = merge(local.tags, { Name = "${var.name_prefix}-private-rt" })
}

resource "aws_route_table_association" "private" {
  count          = var.enable_vpc ? 2 : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# The Lambda ENI security group. Containment is the ROUTE TABLE (no default route) — nothing can
# reach the internet regardless of SG rules — so egress is left open here: this keeps both the
# gateway endpoints (S3/DynamoDB, whose traffic targets AWS prefix-list IPs outside the VPC CIDR)
# and the interface endpoints reachable without prefix-list plumbing. The only routes that exist
# are the implicit local route plus the gateway-endpoint prefix lists.
resource "aws_security_group" "lambda" {
  count       = var.enable_vpc ? 1 : 0
  name        = "${var.name_prefix}-lambda-sg"
  description = "Agent Lambda ENIs (containment is the no-default-route table, not this SG)"
  vpc_id      = aws_vpc.this[0].id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.tags, { Name = "${var.name_prefix}-lambda-sg" })
}

# The CODE-RUNNER security group (ASI05): deny-all egress. Unlike the agent SG above, the runner
# needs to reach NOTHING — not even the VPC endpoints (its IAM role grants no AWS API access) — so
# we omit every egress rule. With no egress rules Terraform leaves the group with zero outbound
# permissions, which combined with the no-default-route table means a code breakout cannot make a
# single outbound connection. (Ingress is unused; CloudWatch Logs are delivered out-of-band.)
resource "aws_security_group" "runner" {
  count       = var.enable_vpc ? 1 : 0
  name        = "${var.name_prefix}-runner-sg"
  description = "Code-runner ENIs: deny-all egress (belt-and-suspenders over the no-route table)"
  vpc_id      = aws_vpc.this[0].id
  # No egress {} blocks on purpose: zero outbound.
  tags = merge(local.tags, { Name = "${var.name_prefix}-runner-sg" })
}

# Security group for the interface endpoints: accept HTTPS from within the VPC.
resource "aws_security_group" "endpoints" {
  count       = var.enable_vpc ? 1 : 0
  name        = "${var.name_prefix}-vpce-sg"
  description = "VPC interface endpoints: HTTPS from the VPC"
  vpc_id      = aws_vpc.this[0].id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  tags = merge(local.tags, { Name = "${var.name_prefix}-vpce-sg" })
}

# ── Gateway endpoints (route-table based, free) ────────────────────────────────────────────────
resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_vpc ? 1 : 0
  vpc_id            = aws_vpc.this[0].id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private[0].id]
  tags              = merge(local.tags, { Name = "${var.name_prefix}-s3-vpce" })
}

resource "aws_vpc_endpoint" "dynamodb" {
  count             = var.enable_vpc ? 1 : 0
  vpc_id            = aws_vpc.this[0].id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private[0].id]
  tags              = merge(local.tags, { Name = "${var.name_prefix}-ddb-vpce" })
}

# ── Interface endpoints ────────────────────────────────────────────────────────────────────────
resource "aws_vpc_endpoint" "bedrock" {
  count               = var.enable_vpc ? 1 : 0
  vpc_id              = aws_vpc.this[0].id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
  tags                = merge(local.tags, { Name = "${var.name_prefix}-bedrock-vpce" })
}

# X-Ray + CloudWatch interface endpoints only when the OTel collector will export from in-VPC.
resource "aws_vpc_endpoint" "xray" {
  count               = var.enable_vpc && var.enable_otel_endpoints ? 1 : 0
  vpc_id              = aws_vpc.this[0].id
  service_name        = "com.amazonaws.${var.region}.xray"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
  tags                = merge(local.tags, { Name = "${var.name_prefix}-xray-vpce" })
}

resource "aws_vpc_endpoint" "monitoring" {
  count               = var.enable_vpc && var.enable_otel_endpoints ? 1 : 0
  vpc_id              = aws_vpc.this[0].id
  service_name        = "com.amazonaws.${var.region}.monitoring"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
  tags                = merge(local.tags, { Name = "${var.name_prefix}-cw-vpce" })
}
