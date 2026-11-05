resource "aws_ecr_repository" "app" {
  #checkov:skip=CKV_AWS_136:Encrypted at rest with AES-256; a customer-managed KMS key is a documented next step.
  name = "${var.name_prefix}/app"

  # Tags are git commit SHAs and can't be overwritten, so a tag always means
  # the same image (rollback = deploy the previous tag).
  image_tag_mutability = "IMMUTABLE"

  # Lets terraform destroy remove the repository with its images.
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}
