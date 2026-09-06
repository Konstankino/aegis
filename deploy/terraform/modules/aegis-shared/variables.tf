variable "name_prefix" {
  description = "Prefix for shared resource names (e.g. \"aegis\")."
  type        = string
  default     = "aegis"
}

variable "region" {
  type = string
}

variable "workspace_dir" {
  description = "Absolute path to the aegis Cargo workspace root."
  type        = string
}

variable "build_script" {
  description = "Path to build.sh that cross-compiles the extension and stages the layer."
  type        = string
}

variable "architecture" {
  type    = string
  default = "arm64"
}

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "enable_vpc" {
  description = "Create a no-default-route VPC + endpoints (S3/DynamoDB/Bedrock) for egress containment."
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "enable_otel_endpoints" {
  description = "Also create X-Ray + CloudWatch interface endpoints (needed when the OTel collector exports from in-VPC)."
  type        = bool
  default     = false
}
