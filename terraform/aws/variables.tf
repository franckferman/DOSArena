# terraform/aws/variables.tf
# Copy to terraform.tfvars and fill in your values:
#
#   key_pair = "my-ec2-keypair"
#   your_ip  = "1.2.3.4/32"
#   region   = "eu-west-1"

variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-1"
}

variable "key_pair" {
  description = "Name of existing EC2 key pair for SSH access"
  type        = string
}

variable "your_ip" {
  description = "Your public IP in CIDR notation (e.g. 1.2.3.4/32) for SSH access"
  type        = string
}

variable "attacker_instance_type" {
  description = "EC2 instance type for attacker node"
  type        = string
  default     = "t3.medium"
}

variable "target_instance_type" {
  description = "EC2 instance type for target nodes"
  type        = string
  default     = "t3.small"
}
