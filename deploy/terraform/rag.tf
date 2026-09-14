# RAG engine — a SEPARATE, optional module (the RAG *engine* Aegis governs, not part of the core
# plane). Off by default; toggle with `enable_rag`. See modules/rag/ and docs/infrastructure-layers.md.
#
# Consumes the network (L1) + foundation (L0) layers and exposes a vector-DB endpoint the application
# layer reads. Keeping it a module means a deployment can omit it, swap it, or point the adapter at an
# existing vector store — the guardrail plane is unchanged.

module "rag" {
  count  = var.enable_rag ? 1 : 0
  source = "./modules/rag"

  project_name          = var.project_name
  tags                  = local.tags
  subnet_ids            = aws_subnet.private[*].id
  app_security_group_id = one(aws_security_group.lambda[*].id)
  kms_key_arn           = aws_kms_key.cmk.arn
}

# The vector DB lives in the private subnets, so RAG needs the network layer.
check "rag_requires_vpc" {
  assert {
    condition     = !var.enable_rag || var.enable_vpc
    error_message = "enable_rag requires enable_vpc = true (the vector DB lives in the private subnets)."
  }
}
