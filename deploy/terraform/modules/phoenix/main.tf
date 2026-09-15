# Arize Phoenix dashboard module — the observability service.
#
# Phoenix runs as a Fargate service behind an INTERNAL load balancer. It serves the UI and accepts
# OTLP-over-HTTP on port 6006 (`/v1/traces`), so the extension's OTEL exporter points at the endpoint
# this module outputs. Optionally persists to the L2 traces Postgres via PHOENIX_SQL_DATABASE_URL.
#
# Private by design: the LB is internal; reach the UI over a VPN/bastion (see `ui_ingress_cidrs`).

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.80" }
  }
}

# Derive the VPC from the subnets, so callers pass only what aegis-shared already outputs.
data "aws_subnet" "first" {
  id = var.subnet_ids[0]
}

locals {
  port   = 6006 # Phoenix UI + OTLP-over-HTTP
  name   = "${var.project_name}-phoenix"
  vpc_id = data.aws_subnet.first.vpc_id
}

# ── Logs ──────────────────────────────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "this" {
  name              = "/aegis/${local.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

# ── Security groups: LB accepts from clients + UI CIDRs; service accepts only from the LB ──────────
resource "aws_security_group" "lb" {
  name        = "${local.name}-lb"
  description = "Aegis Phoenix internal LB."
  vpc_id      = local.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "lb_from_clients" {
  security_group_id            = aws_security_group.lb.id
  description                  = "OTLP from the app tier."
  from_port                    = local.port
  to_port                      = local.port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.client_security_group_id
}

resource "aws_vpc_security_group_ingress_rule" "lb_from_ui" {
  for_each          = toset(var.ui_ingress_cidrs)
  security_group_id = aws_security_group.lb.id
  description       = "Phoenix UI access."
  from_port         = local.port
  to_port           = local.port
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value
}

resource "aws_security_group" "service" {
  name        = "${local.name}-svc"
  description = "Aegis Phoenix Fargate service — from the LB only."
  vpc_id      = local.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "svc_from_lb" {
  security_group_id            = aws_security_group.service.id
  description                  = "Phoenix container port from the LB."
  from_port                    = local.port
  to_port                      = local.port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.lb.id
}

resource "aws_vpc_security_group_egress_rule" "svc_egress" {
  security_group_id = aws_security_group.service.id
  description       = "Egress for image pull + Postgres."
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ── Internal load balancer ─────────────────────────────────────────────────────────────────────────
resource "aws_lb" "this" {
  name               = local.name
  internal           = true
  load_balancer_type = "application"
  subnets            = var.subnet_ids
  security_groups    = [aws_security_group.lb.id]
  tags               = var.tags
}

resource "aws_lb_target_group" "this" {
  name        = local.name
  port        = local.port
  protocol    = "HTTP"
  vpc_id      = local.vpc_id
  target_type = "ip"
  health_check {
    path    = "/healthz"
    matcher = "200"
  }
  tags = var.tags
}

resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.this.arn
  port              = local.port
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# ── ECS Fargate service ────────────────────────────────────────────────────────────────────────────
resource "aws_ecs_cluster" "this" {
  name = local.name
  tags = var.tags
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Read the DB URL secret when persistence is configured.
data "aws_iam_policy_document" "secret" {
  count = var.database_url_secret_arn == "" ? 0 : 1
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.database_url_secret_arn]
  }
}

resource "aws_iam_role_policy" "secret" {
  count  = var.database_url_secret_arn == "" ? 0 : 1
  name   = "${local.name}-secret"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.secret[0].json
}

resource "aws_ecs_task_definition" "this" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn

  container_definitions = jsonencode([{
    name         = "phoenix"
    image        = var.image
    essential    = true
    portMappings = [{ containerPort = local.port, protocol = "tcp" }]
    secrets = var.database_url_secret_arn == "" ? [] : [
      { name = "PHOENIX_SQL_DATABASE_URL", valueFrom = var.database_url_secret_arn }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.this.name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "phoenix"
      }
    }
  }])

  tags = var.tags
}

data "aws_region" "current" {}

resource "aws_ecs_service" "this" {
  name            = local.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "phoenix"
    container_port   = local.port
  }

  depends_on = [aws_lb_listener.this]
  tags       = var.tags
}
