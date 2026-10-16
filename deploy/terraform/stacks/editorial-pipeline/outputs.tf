output "pipelines" {
  description = "Per-pipeline endpoints and resources."
  value = {
    for name, m in module.pipeline : name => {
      api_base_url      = m.api_base_url
      state_machine_arn = m.state_machine_arn
      agent_function    = m.agent_function
      ledger_bucket     = m.ledger_bucket
      # The principal to authorize on the source bucket's KMS key policy (S3 file-drop pipelines).
      source_read_role_arn    = m.source_read_role_arn
      source_read_external_id = m.source_read_external_id
      source_drop_rule        = m.source_drop_rule
    }
  }
}
