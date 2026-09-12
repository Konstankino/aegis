# JIT credential brokering (ASI03/ASI06). The /credentials/issue gate exchanges a validated
# identity credential for a real, short-lived, tightly-scoped cloud credential — an STS session
# (narrowed by an inline session policy at mint time) or a just-in-time Secrets Manager fetch.
#
# The whole point: the STANDING agent role gets NO data-plane access. Instead, per-grant roles are
# trusted by (and only assumable by) the agent role, and the agent role may only `sts:AssumeRole`
# those specific role ARNs (plus `GetSecretValue` on specific secret ARNs). Data access becomes a
# per-call, minutes-long, resource-scoped session rather than a broad long-lived grant.

locals {
  jit_sts_grants    = { for k, g in var.jit_grants : k => g if g.kind == "sts" }
  jit_secret_grants = { for k, g in var.jit_grants : k => g if g.kind == "secret" }
  jit_secret_arns   = [for g in local.jit_secret_grants : g.secret_arn]
}

# ── Per-grant STS roles ──────────────────────────────────────────────────────────────────────────

# Trust policy: ONLY the agent execution role may assume a per-grant role, and only with an
# ExternalId that ties the assume-call to this project (defense in depth against a confused deputy).
data "aws_iam_policy_document" "jit_assume" {
  for_each = local.jit_sts_grants
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["${var.project_name}-jit"]
    }
  }
}

# Permission policy (the ceiling): the data-plane actions this grant may perform on its resources.
# The gate's inline session policy narrows the actual session further at mint time.
data "aws_iam_policy_document" "jit_permissions" {
  for_each = local.jit_sts_grants
  statement {
    effect    = "Allow"
    actions   = each.value.actions
    resources = each.value.resource_arns
  }
}

resource "aws_iam_role" "jit" {
  for_each             = local.jit_sts_grants
  name                 = "${var.project_name}-jit-${each.key}"
  assume_role_policy   = data.aws_iam_policy_document.jit_assume[each.key].json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "jit" {
  for_each = local.jit_sts_grants
  name     = "${var.project_name}-jit-${each.key}-perms"
  role     = aws_iam_role.jit[each.key].id
  policy   = data.aws_iam_policy_document.jit_permissions[each.key].json
}

# ── Agent role: the ONLY new standing permissions are AssumeRole on the per-grant roles and
#    GetSecretValue on the named secrets. No direct data-plane access. ─────────────────────────────

data "aws_iam_policy_document" "agent_jit" {
  # Assume any per-grant STS role (each is itself narrow + resource-scoped).
  dynamic "statement" {
    for_each = length(local.jit_sts_grants) > 0 ? [1] : []
    content {
      sid       = "AssumeJitRoles"
      actions   = ["sts:AssumeRole"]
      resources = [for r in aws_iam_role.jit : r.arn]
    }
  }
  # Fetch only the specific secrets named by secret grants.
  dynamic "statement" {
    for_each = length(local.jit_secret_arns) > 0 ? [1] : []
    content {
      sid       = "GetJitSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = local.jit_secret_arns
    }
  }
}

# Only attach the policy when there is at least one grant (an empty policy document is invalid).
resource "aws_iam_role_policy" "agent_jit" {
  count  = length(var.jit_grants) > 0 ? 1 : 0
  name   = "${var.project_name}-agent-jit"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.agent_jit.json
}
