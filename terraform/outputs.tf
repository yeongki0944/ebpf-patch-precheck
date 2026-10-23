output "instance_ids" {
  value = { for k, v in aws_instance.host : k => v.id }
}

output "private_ips" {
  value = { for k, v in aws_instance.host : k => v.private_ip }
}

output "analysis_private_dns" {
  description = "에이전트 전송 대상 / 서버 인증서 SAN"
  value       = aws_instance.host["analysis"].private_dns
}

output "ssm_connect" {
  value = { for k, v in aws_instance.host : k => "aws ssm start-session --profile ${var.aws_profile} --region ${var.region} --target ${v.id}" }
}

output "artifacts_bucket" {
  value = aws_s3_bucket.artifacts.bucket
}
