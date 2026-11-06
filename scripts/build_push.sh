#!/usr/bin/env bash
# Build the app image for linux/amd64, push it to the project's ECR repository,
# wait for the ECR vulnerability scan and print the image digest to deploy.
#
#   AWS_PROFILE=<profile> AWS_REGION=eu-north-1 scripts/build_push.sh
#
# The tag is the current commit (12 characters) and is for people; ECR tags are
# immutable. Deployments use the digest, so EC2 runs exactly the scanned image:
# put both into terraform/app/terraform.tfvars (image_tag, image_digest).
# Fails if the scan doesn't complete or finds anything CRITICAL.
set -euo pipefail

: "${AWS_PROFILE:?set AWS_PROFILE}"
: "${AWS_REGION:?set AWS_REGION}"
cd "$(dirname "$0")/.."
aws_ecr() { aws ecr "$@" --profile "$AWS_PROFILE" --region "$AWS_REGION"; }

if [ -n "$(git status --porcelain)" ]; then
  echo "The working tree has uncommitted changes; commit first so the tag matches the code." >&2
  exit 1
fi
tag=$(git rev-parse --short=12 HEAD)

repo_name=$(cd terraform/foundation && terraform output -raw ecr_repository_name)
repo_uri=$(aws_ecr describe-repositories --repository-names "$repo_name" --query 'repositories[0].repositoryUri' --output text)
registry=${repo_uri%%/*}

# One plain image manifest: no provenance or SBOM attestations, which would turn the
# push into an image index whose scan result sits on an untagged child (README, "Security").
docker build --platform linux/amd64 --provenance=false --sbom=false --build-arg APP_VERSION="$tag" -t "$repo_uri:$tag" .
aws_ecr get-login-password | docker login --username AWS --password-stdin "$registry"
docker push "$repo_uri:$tag"

digest=$(aws_ecr describe-images --repository-name "$repo_name" --image-ids imageTag="$tag" --query 'imageDetails[0].imageDigest' --output text)
media=$(aws_ecr describe-images --repository-name "$repo_name" --image-ids imageTag="$tag" --query 'imageDetails[0].imageManifestMediaType' --output text)
case "$media" in
  *index* | *manifest.list*) echo "Pushed an image index ($media), not a single manifest" >&2; exit 1 ;;
esac

# Poll rather than use `aws ecr wait`: right after a push the scan may not exist yet,
# and the waiter treats that as a failure.
echo "waiting for the ECR scan of $digest ..."
status=PENDING
for _ in $(seq 1 60); do # up to 5 minutes
  status=$(aws_ecr describe-image-scan-findings --repository-name "$repo_name" --image-id imageDigest="$digest"     --query 'imageScanStatus.status' --output text 2>/dev/null) || status=PENDING
  case "$status" in PENDING | IN_PROGRESS) sleep 5 ;; *) break ;; esac
done
counts=$(aws_ecr describe-image-scan-findings --repository-name "$repo_name" --image-id imageDigest="$digest" --query 'imageScanFindings.findingSeverityCounts' --output json)
echo "scan $status: $counts"
if [ "$status" != "COMPLETE" ]; then
  echo "The scan did not complete." >&2
  exit 1
fi
if echo "$counts" | grep -q '"CRITICAL"'; then
  echo "CRITICAL findings: not deploying this image." >&2
  exit 1
fi

echo "image_tag    = \"$tag\""
echo "image_digest = \"$digest\""
