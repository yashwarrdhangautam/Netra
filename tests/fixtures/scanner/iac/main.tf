resource "aws_s3_bucket" "logs" {
  bucket = "netra-lab-logs"
  acl    = "public-read"
}
