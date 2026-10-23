variable "name" {
  description = "리소스 이름 prefix"
  type        = string
  default     = "patchscope"
}

variable "region" {
  description = "AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "aws_profile" {
  description = "AWS CLI SSO 프로필 이름 (terraform.tfvars 에서 지정)"
  type        = string
}

variable "vpc_cidr" {
  type    = string
  default = "10.70.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.70.1.0/24"
}

variable "operator_cidrs" {
  description = "분석 서버 443 직접 접근 허용 CIDR. 기본은 비움(SSM 포트 포워딩 사용)"
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.operator_cidrs, "0.0.0.0/0")
    error_message = "0.0.0.0/0 은 허용하지 않습니다."
  }
}

# ---------------------------------------------------------------------------
# AMI 고정 (2026-10-24 서울 리전에서 존재 확인)
#  - 구버전 대상 AMI 는 deprecated 상태지만 ID 로 실행 가능
#  - AMI 를 바꾸면 인스턴스가 재생성됨
# ---------------------------------------------------------------------------
variable "analysis_ami" {
  description = "분석/빌드 서버: AL2023 2023.12.20261021.0 kernel-6.1 x86_64"
  type        = string
  default     = "ami-0a1a6513ade0d71e0"
}

variable "al2023_target_ami" {
  description = "AL2023 패치 전 대상: 2023.0.20230315.0 kernel-6.1 x86_64"
  type        = string
  default     = "ami-0b23bb3616e3892a6"
}

variable "rhel8_target_ami" {
  description = "RHEL 8.10 패치 전 대상: RHEL-8.10.0_HVM-20240514-x86_64-76-Hourly2-GP3"
  type        = string
  default     = "ami-0a001d6063b79b0ed"
}

variable "analysis_instance_type" {
  description = "분석 서버 겸 eBPF/Go 빌드 서버"
  type        = string
  default     = "t3.large"
}

variable "target_instance_type" {
  type    = string
  default = "t3.medium"
}

variable "analysis_volume_size" {
  type    = number
  default = 40
}

variable "target_volume_size" {
  type    = number
  default = 30
}

variable "repo_url" {
  description = "코드 레포 (public)"
  type        = string
  default     = "https://github.com/yeongki0944/ebpf-patch-precheck.git"
}
