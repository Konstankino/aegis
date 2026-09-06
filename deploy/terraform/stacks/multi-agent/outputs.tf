output "projects" {
  description = "Per-project endpoints and resources."
  value = {
    for name, m in module.agents : name => {
      api_base_url      = m.api_base_url
      state_machine_arn = m.state_machine_arn
      worker_function   = m.agent_function
      ledger_bucket     = m.ledger_bucket
    }
  }
}
