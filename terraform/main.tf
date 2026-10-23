# PatchScope PoC 테스트 환경
#   생성: VPC 1, 퍼블릭 서브넷 1, IGW, SG 2, IAM Role/Profile, EC2 3 (analysis, al2023, rhel8)
#   접속: SSM Session Manager 만 사용 (SSH 22 미개방, key pair 없음)
#   삭제: terraform destroy (모든 리소스에 Project=patchscope 태그)

data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true # 외부 저장소 다운로드용. 인바운드는 SG 로 차단
  tags                    = { Name = "${var.name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Security Groups
#   target  : 같은 SG 내부 통신만 허용 (테스트 서비스), 공개 포트 없음
#   analysis: 443 은 target SG + operator_cidrs 만 허용
# ---------------------------------------------------------------------------
resource "aws_security_group" "target" {
  name        = "${var.name}-target-sg"
  description = "PatchScope target hosts"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-target-sg" }
}

resource "aws_security_group" "analysis" {
  name        = "${var.name}-analysis-sg"
  description = "PatchScope analysis server"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-analysis-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "target_self" {
  security_group_id            = aws_security_group.target.id
  referenced_security_group_id = aws_security_group.target.id
  ip_protocol                  = "-1"
  description                  = "intra target test traffic"
}

resource "aws_vpc_security_group_ingress_rule" "analysis_from_agents" {
  security_group_id            = aws_security_group.analysis.id
  referenced_security_group_id = aws_security_group.target.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "agent HTTPS ingestion"
}

resource "aws_vpc_security_group_ingress_rule" "analysis_from_operator" {
  for_each          = toset(var.operator_cidrs)
  security_group_id = aws_security_group.analysis.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "operator HTTPS"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  for_each = {
    target   = aws_security_group.target.id
    analysis = aws_security_group.analysis.id
  }
  security_group_id = each.value
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "outbound for repos and SSM"
}

# ---------------------------------------------------------------------------
# IAM - SSM Session Manager 만
# ---------------------------------------------------------------------------
resource "aws_iam_role" "ec2" {
  name = "${var.name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${var.name}-ec2-profile"
  role = aws_iam_role.ec2.name
}

# ---------------------------------------------------------------------------
# EC2
# ---------------------------------------------------------------------------
locals {
  hosts = {
    analysis = {
      ami           = var.analysis_ami
      instance_type = var.analysis_instance_type
      volume_size   = var.analysis_volume_size
      sg            = aws_security_group.analysis.id
      role          = "analysis"
      os_family     = "al2023"
    }
    al2023 = {
      ami           = var.al2023_target_ami
      instance_type = var.target_instance_type
      volume_size   = var.target_volume_size
      sg            = aws_security_group.target.id
      role          = "target"
      os_family     = "al2023"
    }
    rhel8 = {
      ami           = var.rhel8_target_ami
      instance_type = var.target_instance_type
      volume_size   = var.target_volume_size
      sg            = aws_security_group.target.id
      role          = "target"
      os_family     = "rhel8"
    }
  }
}

resource "aws_instance" "host" {
  for_each = local.hosts

  ami                    = each.value.ami
  instance_type          = each.value.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [each.value.sg]
  iam_instance_profile   = aws_iam_instance_profile.ec2.name

  user_data = templatefile("${path.module}/user_data.sh", {
    host_key  = each.key
    role      = each.value.role
    os_family = each.value.os_family
    region    = var.region
    repo_url  = var.repo_url
  })
  user_data_replace_on_change = true

  root_block_device {
    volume_type           = "gp3"
    volume_size           = each.value.volume_size
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2
    http_endpoint = "enabled"
  }

  tags = {
    Name = "${var.name}-${each.key}"
    Role = each.value.role
  }
}
