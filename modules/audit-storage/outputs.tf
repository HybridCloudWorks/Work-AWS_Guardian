output "bucket_name" {
  description = "Private audit bucket name."
  value       = aws_s3_bucket.audit.bucket
}

output "bucket_arn" {
  description = "Private audit bucket ARN."
  value       = aws_s3_bucket.audit.arn
}
output "access_logging_enabled" {
  description = "Whether S3 server access logging is configured (self-logging under log/ prefix)."
  value       = var.enable_access_logging
}
