# Soc Analyst Agent — dev/us/rag-hybrid environment
include "root" {
  path = find_in_parent_folders()
}

terraform {
  source = "../../../modules//appops/vectorstore"
}

inputs = {
  environment = "dev"
  agent_name  = "soc-analyst-agent"
}
