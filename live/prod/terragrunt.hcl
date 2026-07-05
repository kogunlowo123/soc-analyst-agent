# Soc Analyst Agent — prod environment
include "root" {
  path = find_in_parent_folders()
}

terraform {
  source = "../../../modules//appops/vectorstore"
}

inputs = {
  environment = "prod"
  agent_name  = "soc-analyst-agent"
}
