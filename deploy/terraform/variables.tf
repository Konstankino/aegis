variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix for all created resources."
  type        = string
  default     = "aegis-demo"
}

variable "architecture" {
  description = "Lambda + extension CPU architecture. Must match what build.sh cross-compiles."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.architecture)
    error_message = "architecture must be \"arm64\" or \"x86_64\"."
  }
}

variable "python_runtime" {
  description = "Python runtime for the agent handler Lambda."
  type        = string
  default     = "python3.12"
}

variable "enable_vpc" {
  description = <<-EOT
    Place the agent Lambda in a private subnet with NO default route and a closed-egress
    security group, so the egress-containment posture (§2.4) is real: a fooled model cannot
    reach any endpoint the allowlist does not name. The function still runs and returns (its
    response travels via the Lambda control plane, not the VPC ENI). Set false for a faster,
    simpler deploy without networking resources.
  EOT
  type        = bool
  default     = true
}

variable "run_demo" {
  description = "Invoke the function during apply and surface the Aegis decision trace as an output."
  type        = bool
  default     = true
}

variable "auto_approve" {
  description = <<-EOT
    Deploy the auto-approver Lambda that resumes waitForTaskToken pauses automatically, so the
    Step Functions demo completes end to end without a human. Set false to approve manually
    (the task token is delivered to the approval SQS queue).
  EOT
  type        = bool
  default     = true
}

variable "jit_grants" {
  description = <<-EOT
    JIT credential grants (ASI03/ASI06). For each entry Terraform provisions the least-privilege
    IAM plumbing the /credentials/issue gate needs — WITHOUT giving the standing agent role any
    data-plane access:

      * kind = "sts"    → a dedicated per-grant IAM role whose trust policy lets ONLY the agent
                          role assume it, plus a permission policy scoped to `actions` on
                          `resource_arns`. The agent role is granted sts:AssumeRole on just these
                          role ARNs. At mint time the gate further narrows the session with an
                          inline session policy. Put the created role ARN (see the `jit_role_arns`
                          output) into the matching grant's `role_arn` in policies/grants.toml.
      * kind = "secret" → the agent role is granted secretsmanager:GetSecretValue on `secret_arn`
                          only (JIT fetch; never a standing broad grant).

    Empty by default: no grants → the gate denies every credential request (safe by default).
  EOT
  type = map(object({
    kind          = string
    actions       = optional(list(string), [])
    resource_arns = optional(list(string), [])
    secret_arn    = optional(string, "")
  }))
  default = {}

  validation {
    condition     = alltrue([for g in var.jit_grants : contains(["sts", "secret"], g.kind)])
    error_message = "each jit_grants entry's kind must be \"sts\" or \"secret\"."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the agent function."
  type        = number
  default     = 14
}

variable "otel_collector_layer_arn" {
  description = <<-EOT
    ARN of an OpenTelemetry collector Lambda layer (e.g. the AWS Distro for OpenTelemetry /
    ADOT collector layer for your region+arch). When set, it is attached to the agent function,
    the extension is pointed at it (OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317), and the
    role is granted X-Ray + CloudWatch metrics permissions. Leave empty to run with structured
    logs only (still fully functional — the extension degrades gracefully with no endpoint).
    Find ADOT ARNs at https://aws-otel.github.io/docs/getting-started/lambda
  EOT
  type        = string
  default     = ""
}
