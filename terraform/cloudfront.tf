# ---------------------------------------------------------------------------
# 운영자 웹 접근: CloudFront (기본 *.cloudfront.net 인증서) → VPC origin → 분석 EC2 nginx:80
#   - ALB 없음. CloudFront 가 VPC 안에 만든 ENI 로 분석 서버 private IP 에 직접 연결 (인터넷 경유 안 함)
#   - 캐시 모두 끔 (CachingDisabled), 쿠키·헤더·쿼리 전부 원본으로 전달 (AllViewer)
#   - 분석 서버의 공인 443 은 닫음. 80 은 CloudFront VPC origin 보안그룹에서만 허용
#   - 에이전트 수집 경로(443, 사설 CA, VPC 내부)는 그대로
#   - 접속 IP 제한: CloudFront Function 으로 operator_cidrs 만 허용 (비우면 제한 없음, 비밀번호 로그인은 유지)
#   destroy: CloudFront 배포 비활성화·삭제에 수 분 소요
# ---------------------------------------------------------------------------
resource "aws_cloudfront_vpc_origin" "analysis" {
  vpc_origin_endpoint_config {
    name                   = "${var.name}-analysis"
    arn                    = aws_instance.host["analysis"].arn
    http_port              = 80
    https_port             = 443
    origin_protocol_policy = "http-only"

    origin_ssl_protocols {
      items    = ["TLSv1.2"]
      quantity = 1
    }
  }

  timeouts {
    create = "30m"
    update = "30m"
    delete = "30m"
  }
}

# VPC origin 생성 시 AWS 가 만드는 서비스 관리 SG (이름 고정 패턴)
data "aws_security_group" "cloudfront_vpc_origin" {
  vpc_id = aws_vpc.this.id
  filter {
    name   = "group-name"
    values = ["CloudFront-VPCOrigins-Service-SG"]
  }
  depends_on = [aws_cloudfront_vpc_origin.analysis]
}

resource "aws_vpc_security_group_ingress_rule" "analysis_from_cloudfront" {
  security_group_id            = aws_security_group.analysis.id
  referenced_security_group_id = data.aws_security_group.cloudfront_vpc_origin.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
  description                  = "CloudFront VPC origin only"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

resource "aws_cloudfront_function" "ip_allow" {
  name    = "${var.name}-ip-allow"
  runtime = "cloudfront-js-2.0"
  comment = "operator_cidrs allow list (empty = allow all)"
  publish = true
  code = templatefile("${path.module}/cf-ip-allow.js.tftpl", {
    cidrs = jsonencode(var.operator_cidrs)
  })
}

resource "aws_cloudfront_distribution" "web" {
  enabled         = true
  comment         = "${var.name} operator web"
  price_class     = "PriceClass_200"
  http_version    = "http2"
  is_ipv6_enabled = false # IP 허용 목록이 IPv4 만이므로

  origin {
    origin_id   = "analysis"
    domain_name = aws_instance.host["analysis"].private_dns
    vpc_origin_config {
      vpc_origin_id            = aws_cloudfront_vpc_origin.analysis.id
      origin_read_timeout      = 60
      origin_keepalive_timeout = 5
    }
  }

  default_cache_behavior {
    target_origin_id         = "analysis"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id
    compress                 = true

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.ip_allow.arn
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
