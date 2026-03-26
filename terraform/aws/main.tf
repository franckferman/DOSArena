# terraform/aws/main.tf
# DOSArena — AWS cloud lab
# Provisions attacker + target nodes in isolated VPC
#
# Usage:
#   terraform init
#   terraform plan -var="key_pair=your-key"
#   terraform apply -var="key_pair=your-key"
#
# Requirements:
#   - AWS credentials configured (aws configure)
#   - EC2 key pair already created in the target region

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# ============================================================================
# VARIABLES
# ============================================================================

variable "region" {
  description = "AWS region"
  default     = "eu-west-1"
}

variable "key_pair" {
  description = "EC2 key pair name for SSH access"
  type        = string
}

variable "attacker_instance_type" {
  description = "Instance type for attacker node"
  default     = "t3.medium"   # 2 vCPU, 4GB RAM — sufficient for FloodKit
}

variable "target_instance_type" {
  description = "Instance type for target nodes"
  default     = "t3.small"    # 2 vCPU, 2GB RAM
}

variable "your_ip" {
  description = "Your public IP for SSH access (CIDR, e.g. 1.2.3.4/32)"
  type        = string
}

# ============================================================================
# NETWORKING
# ============================================================================

resource "aws_vpc" "dosarena" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "dosarena-vpc", Project = "DOSArena" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.dosarena.id
  tags   = { Name = "dosarena-igw" }
}

# Attacker subnet
resource "aws_subnet" "attacker" {
  vpc_id                  = aws_vpc.dosarena.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = { Name = "dosarena-attacker-subnet" }
}

# DMZ subnet (vulnerable targets)
resource "aws_subnet" "dmz" {
  vpc_id                  = aws_vpc.dosarena.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags = { Name = "dosarena-dmz-subnet" }
}

# Protected subnet
resource "aws_subnet" "protected" {
  vpc_id                  = aws_vpc.dosarena.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags = { Name = "dosarena-protected-subnet" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.dosarena.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "dosarena-public-rt" }
}

resource "aws_route_table_association" "attacker" {
  subnet_id      = aws_subnet.attacker.id
  route_table_id = aws_route_table.public.id
}

# ============================================================================
# SECURITY GROUPS
# ============================================================================

# Attacker: SSH from your IP only
resource "aws_security_group" "attacker" {
  name   = "dosarena-attacker-sg"
  vpc_id = aws_vpc.dosarena.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.your_ip]
    description = "SSH from operator IP"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "dosarena-attacker-sg" }
}

# DMZ targets: all traffic from attacker subnet
resource "aws_security_group" "dmz" {
  name   = "dosarena-dmz-sg"
  vpc_id = aws_vpc.dosarena.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.1.0/24"]
    description = "All traffic from attacker subnet"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.your_ip]
    description = "SSH from operator IP"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "dosarena-dmz-sg" }
}

# Protected: only from attacker subnet, limited ports
resource "aws_security_group" "protected" {
  name   = "dosarena-protected-sg"
  vpc_id = aws_vpc.dosarena.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.your_ip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "dosarena-protected-sg" }
}

# ============================================================================
# AMI — Latest Ubuntu 22.04 LTS
# ============================================================================

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ============================================================================
# ATTACKER NODE
# ============================================================================

resource "aws_instance" "attacker" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.attacker_instance_type
  subnet_id              = aws_subnet.attacker.id
  vpc_security_group_ids = [aws_security_group.attacker.id]
  key_name               = var.key_pair

  # Enhanced networking for higher PPS
  source_dest_check = false

  user_data = base64encode(templatefile("${path.module}/user_data/attacker.sh", {}))

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  tags = {
    Name    = "dosarena-attacker"
    Project = "DOSArena"
    Role    = "attacker"
  }
}

# ============================================================================
# TARGET NODES
# ============================================================================

resource "aws_instance" "apache_vuln" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.target_instance_type
  subnet_id              = aws_subnet.dmz.id
  vpc_security_group_ids = [aws_security_group.dmz.id]
  key_name               = var.key_pair
  private_ip             = "10.0.2.20"

  user_data = base64encode(templatefile("${path.module}/user_data/apache_vuln.sh", {}))

  tags = {
    Name    = "dosarena-apache-vuln"
    Project = "DOSArena"
    Role    = "target"
    Vuln    = "slowloris,syn_flood,http_flood"
  }
}

resource "aws_instance" "apache_protected" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.target_instance_type
  subnet_id              = aws_subnet.protected.id
  vpc_security_group_ids = [aws_security_group.protected.id]
  key_name               = var.key_pair
  private_ip             = "10.0.3.20"

  user_data = base64encode(templatefile("${path.module}/user_data/apache_protected.sh", {}))

  tags = {
    Name    = "dosarena-apache-protected"
    Project = "DOSArena"
    Role    = "target-protected"
  }
}

resource "aws_instance" "nginx_protected" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.target_instance_type
  subnet_id              = aws_subnet.protected.id
  vpc_security_group_ids = [aws_security_group.protected.id]
  key_name               = var.key_pair
  private_ip             = "10.0.3.21"

  user_data = base64encode(templatefile("${path.module}/user_data/nginx_protected.sh", {}))

  tags = {
    Name    = "dosarena-nginx-protected"
    Project = "DOSArena"
    Role    = "target-protected"
  }
}

resource "aws_instance" "dns_open" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.target_instance_type
  subnet_id              = aws_subnet.dmz.id
  vpc_security_group_ids = [aws_security_group.dmz.id]
  key_name               = var.key_pair
  private_ip             = "10.0.2.30"

  user_data = base64encode(templatefile("${path.module}/user_data/dns_open.sh", {}))

  tags = {
    Name    = "dosarena-dns-open"
    Project = "DOSArena"
    Role    = "target"
    Vuln    = "dns_amp"
  }
}

resource "aws_instance" "ntp_vuln" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.target_instance_type
  subnet_id              = aws_subnet.dmz.id
  vpc_security_group_ids = [aws_security_group.dmz.id]
  key_name               = var.key_pair
  private_ip             = "10.0.2.31"

  user_data = base64encode(templatefile("${path.module}/user_data/ntp_vuln.sh", {}))

  tags = {
    Name    = "dosarena-ntp-vuln"
    Project = "DOSArena"
    Role    = "target"
    Vuln    = "ntp_amp"
  }
}

resource "aws_instance" "snmp_vuln" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.target_instance_type
  subnet_id              = aws_subnet.dmz.id
  vpc_security_group_ids = [aws_security_group.dmz.id]
  key_name               = var.key_pair
  private_ip             = "10.0.2.32"

  user_data = base64encode(templatefile("${path.module}/user_data/snmp_vuln.sh", {}))

  tags = {
    Name    = "dosarena-snmp-vuln"
    Project = "DOSArena"
    Role    = "target"
    Vuln    = "snmp_amp"
  }
}

resource "aws_instance" "mysql_vuln" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.target_instance_type
  subnet_id              = aws_subnet.dmz.id
  vpc_security_group_ids = [aws_security_group.dmz.id]
  key_name               = var.key_pair
  private_ip             = "10.0.2.40"

  user_data = base64encode(templatefile("${path.module}/user_data/mysql_vuln.sh", {}))

  tags = {
    Name    = "dosarena-mysql-vuln"
    Project = "DOSArena"
    Role    = "target"
    Vuln    = "nuke"
  }
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "attacker_public_ip" {
  value       = aws_instance.attacker.public_ip
  description = "SSH: ssh ubuntu@<ip> -i your-key.pem"
}

output "targets_summary" {
  value = {
    apache_vuln       = aws_instance.apache_vuln.private_ip
    apache_protected  = aws_instance.apache_protected.private_ip
    nginx_protected   = aws_instance.nginx_protected.private_ip
    dns_open          = aws_instance.dns_open.private_ip
    ntp_vuln          = aws_instance.ntp_vuln.private_ip
    snmp_vuln         = aws_instance.snmp_vuln.private_ip
    mysql_vuln        = aws_instance.mysql_vuln.private_ip
  }
}

output "ssh_command" {
  value = "ssh ubuntu@${aws_instance.attacker.public_ip} -i ~/.ssh/${var.key_pair}.pem"
}
