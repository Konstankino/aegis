output "pipelines" {
  description = "Per-pipeline endpoints and resources."
  value = {
    for name, m in module.pipeline : name => {
      api_base_url      = m.api_base_url
      state_machine_arn = m.state_machine_arn
      agent_function    = m.agent_function
      ledger_bucket     = m.ledger_bucket
    }
  }
}
