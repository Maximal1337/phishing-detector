#!/usr/bin/env bash
# Build the app image for linux/amd64 and push it to the project's ECR repository.
#
#   AWS_PROFILE=<profile> AWS_REGION=eu-north-1 scripts/build_push.sh
#
# The tag is the current commit (12 characters), so a tag always names exactly
# one version of the code; ECR tags are immutable. Prints the tag at the end:
# put it into terraform/app/terraform.tfvars as image_tag.
set -euo pipefail

: "${AWS_PROFILE:?set AWS_PROFILE}"
: "${AWS_REGION:?set AWS_REGION}"
cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
  echo "The working tree has uncommitted changes; commit first so the tag matches the code." >&2
  exit 1
fi
tag=$(git rev-parse --short=12 HEAD)

repo_name=$(cd terraform/foundation && terraform output -raw ecr_repository_name)
repo_uri=$(aws ecr describe-repositories --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --repository-names "$repo_name" --query 'repositories[0].repositoryUri' --output text)
registry=${repo_uri%%/*}

docker build --platform linux/amd64 --build-arg APP_VERSION="$tag" -t "$repo_uri:$tag" .
aws ecr get-login-password --profile "$AWS_PROFILE" --region "$AWS_REGION" |
  docker login --username AWS --password-stdin "$registry"
docker push "$repo_uri:$tag"

echo "pushed tag: $tag"
