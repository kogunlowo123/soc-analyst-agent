terraform {
  backend "s3" {
    bucket         = "soc-analyst-agent-tfstate"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "soc-analyst-agent-tflock"
    kms_key_id     = "alias/soc-analyst-terraform"
  }
}
