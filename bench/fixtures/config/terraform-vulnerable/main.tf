# Benchmark fixture: intentionally-misconfigured Terraform.
# DO NOT terraform apply. Used by `secscan config` (Trivy)
# to verify cloud / IAM auth checks fire.

resource "aws_s3_bucket" "public_bucket" {
  bucket = "secscan-bench-public"
  # ❌ AVD-AWS-0086 / 0087: missing public access block
  # ❌ AVD-AWS-0088: missing server-side encryption
  # ❌ AVD-AWS-0089: missing logging
  # ❌ AVD-AWS-0090: missing versioning
}

resource "aws_iam_policy" "wildcard_policy" {
  name = "bench-wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"            # ❌ AVD-AWS-0057 wildcard action
      Resource = "*"            # ❌ AVD-AWS-0345 wildcard resource
    }]
  })
}

resource "aws_security_group" "wide_open" {
  name = "wide-open"
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]   # ❌ AVD-AWS-0107 open to world
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
