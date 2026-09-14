# Arize Phoenix module — outputs (the interface other layers read).

output "endpoint" {
  description = "Internal base URL for Phoenix (UI + OTLP-over-HTTP), e.g. http://<lb-dns>:6006."
  value       = "http://${aws_lb.this.dns_name}:6006"
}

output "otlp_endpoint" {
  description = "OTLP-over-HTTP endpoint the extension's OTEL_EXPORTER_OTLP_ENDPOINT should point at."
  value       = "http://${aws_lb.this.dns_name}:6006"
}

output "client_note" {
  description = "How the app tier reaches Phoenix."
  value       = "Set OTEL_EXPORTER_OTLP_ENDPOINT to the otlp_endpoint on the agent/extension function."
}
