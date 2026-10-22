variable "region" {
  type    = string
  default = "eu-central-1" # Frankfurt: EU data residency
}
variable "environment" {
  type    = string
  default = "production"
}
variable "name" {
  type    = string
  default = "irg"
}
variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}
variable "azs" {
  type    = list(string)
  default = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
}
variable "eks_version" {
  type    = string
  default = "1.32"
}
variable "eks_public_access_cidrs" {
  description = "CIDRs allowed to reach the EKS API endpoint (office/VPN). Empty = private endpoint only."
  type        = list(string)
  default     = []
}
variable "node_instance_types" {
  type    = list(string)
  default = ["m7g.large"]
}
variable "db_instance_class" {
  type    = string
  default = "db.r7g.large"
}
variable "bedrock_model_arns" {
  description = "Bedrock foundation models the app may invoke (finding explanations)."
  type        = list(string)
  default     = ["arn:aws:bedrock:eu-central-1::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1:0"]
}
