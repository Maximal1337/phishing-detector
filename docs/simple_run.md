# Simple run: from a fresh clone to cleanup

One straight path through the README: install, tests, the local stack, both AWS stacks, the smoke test, the UI,
tear-down and cleanup. The README stays the reference for why things are the way they are. Each step says where to
run it:

- **[Terminal]**: bash. On macOS, open Terminal and type `bash` first: the default zsh doesn't treat a trailing `#` as a
  comment. On Windows, use Git Bash.
- **[browser]**, **[AWS console]**, **[mail]**.

Times and results are from two runs of this path on 2026-11-08: Windows with Git Bash (prefix `pdcheck`) and macOS on
Apple Silicon (prefix `pdmac`). Where only one run measured something, the text says which.

Where macOS and Windows differ, the step says so in one line.

## 0. Before you start

Tools as in the README's prerequisites table: AWS CLI v2 with a profile for your account (not the root user),
Terraform 1.17, Docker with buildx (Docker Desktop running), Python 3.13, git, curl. Check the versions:

**[Terminal]**

```bash
aws --version
```

```bash
terraform version
```

```bash
docker version
```

`docker version` must show a `Server` section; without it Docker Desktop isn't running.

```bash
docker buildx version
```

```bash
python3.13 --version
```

Windows: `py -3.13 --version`.

```bash
bash --version
```

bash 3.2 (the macOS one) is enough.

## 1. Clone and set the profile and prefix once

**[Terminal]** Go to a folder of your own and clone the repository with its HTTPS URL (GitHub → Code → HTTPS):

```bash
git clone https://github.com/<owner>/phishing-detector.git
```

On Windows, pick a short folder (for example `/c/run`): Terraform's provider path inside `.terraform` is long.

```bash
cd phishing-detector
```

Set your AWS CLI profile, the Region and a name prefix. Every later command uses these variables, so this is the
only place to change them. The prefix starts every resource name; pick one that isn't already used in the account.

```bash
export AWS_PROFILE=upwind
```

```bash
export AWS_REGION=eu-north-1
```

```bash
export NAME_PREFIX=phishdet
```

Print the account number; you will type it into `terraform.tfvars` in step 5:

```bash
aws sts get-caller-identity --profile "$AWS_PROFILE" --query Account --output text
```

Expected: 12 digits. An error here means the profile is wrong: fix it before going on.

## 2. Python environment and tests

**[Terminal]**

```bash
python3.13 -m venv .venv
```

Windows: `py -3.13 -m venv .venv`.

```bash
source .venv/bin/activate
```

Windows: `source .venv/Scripts/activate`.

```bash
pip install -r requirements-dev.txt
```

Took 56 s on Windows.

```bash
which python aws terraform docker
```

`python` must be the one in `.venv`.

```bash
python -m pytest -q
```

Expected: `216 passed, 10 skipped`, in about 6 s. The 10 skipped are the PostgreSQL tests, which need
`TEST_DATABASE_URL`.

## 3. Local stack with docker compose (optional)

**[Terminal]**

```bash
cp .env.example .env
```

```bash
nano .env
```

Use nano, not TextEdit: TextEdit turns `"` into curly quotes. Type a password of your own after `DB_PASSWORD=`, then
save (Ctrl+O, Enter) and exit (Ctrl+X). Leave the Basic-auth lines empty for a local run. The whole file:

```
# Copy to .env (git-ignored) and replace the placeholders with your own values.
DB_PASSWORD=your-own-local-password
# Leave both empty to run without Basic auth (local use only); set both to turn it on.
BASIC_AUTH_USER=
BASIC_AUTH_PASSWORD=
```

```bash
docker compose up -d --build
```

```bash
docker inspect --format '{{.State.Health.Status}}' phishing-detector-app-1
```

Expected: `healthy`. For the first 15-30 s it says `starting`; run it again. It took 15 s on Windows with the image
already built, and about 30 s on macOS.

**[browser]** Open http://127.0.0.1:8000, upload `samples/phishing_lookalike_sender.eml`, then upload it again: the
second result says "from cache".

**[Terminal]** Stop the stack and delete its local database:

```bash
docker compose down -v
```

## 4. If you continue in a new terminal window

The variables and the virtual environment belong to one window. In a new one:

**[Terminal]**

```bash
bash
```

macOS only.

```bash
cd ~/phishing-detector
```

Use the path you cloned into.

```bash
source .venv/bin/activate
```

Windows: `source .venv/Scripts/activate`.

Then run the three `export` lines from step 1 again. For the commands in steps 7 and 8, also run the `URL=` and
`SECRET=` lines again.

## 5. Foundation stack

**[Terminal]**

```bash
cd terraform/foundation
```

```bash
cp terraform.tfvars.example terraform.tfvars
```

```bash
nano terraform.tfvars
```

Make the file look like this, with your profile and prefix from step 1 and the 12 digits from step 1:

```hcl
# Copy to terraform.tfvars (git-ignored) and fill in your own values.

aws_profile         = "upwind"
allowed_account_ids = ["<the 12 digits from step 1>"]

# Start of every resource name and the NamePrefix tag; the app stack takes it from this
# stack's state. Another prefix gives a second, separate copy of both stacks in the same
# account: 2-15 characters, lowercase letters, digits and hyphens, starting with a letter.
name_prefix = "phishdet"

# Optional overrides (defaults shown):
# region = "eu-north-1"
```

```bash
terraform init
```

Took 41 s on Windows.

```bash
terraform validate
```

Optional. Expected: `Success! The configuration is valid.`

```bash
git status --porcelain
```

Expected: nothing. `terraform.tfvars` and `.terraform/` are ignored, and `.terraform.lock.hcl` must not change.

```bash
terraform apply
```

Terraform prints the plan and asks for `yes`. Read the plan first. Expected: `Plan: 47 to add, 0 to change,
0 to destroy`, every name starting with your prefix. Then type `yes`. The apply took 10:15 on Windows and 10:20 on
macOS; RDS and ElastiCache take about 10 minutes each, in parallel.

```bash
cd ../..
```

## 6. Basic-auth password

**[Terminal]** Terraform created the secret empty.

```bash
SECRET=$(cd terraform/foundation && terraform output -raw auth_secret_name)
```

```bash
echo "$SECRET"
```

Expected: your prefix followed by `/basic-auth`, for example `phishdet/basic-auth`.

```bash
read -rs PW
```

Type the password and press Enter; nothing is shown. Don't use `"` or `\`.

```bash
aws secretsmanager put-secret-value --profile "$AWS_PROFILE" --region eu-north-1 --secret-id "$SECRET" --secret-string "{\"username\":\"reviewer\",\"password\":\"$PW\"}"
```

Expected: JSON with the secret's `ARN`, `Name` and a `VersionId`.

```bash
unset PW
```

## 7. Image and app stack

**[Terminal]** Build, push and scan the image. The script reads `AWS_PROFILE` and `AWS_REGION` from step 1.

```bash
time scripts/build_push.sh
```

Expected at the end:

- `scan COMPLETE`, then the finding counts;
- no `CRITICAL` key: the script stops if there is one;
- the last two lines are `image_tag = "…"` and `image_digest = "sha256:…"`. Keep them for the next file.

On 2026-11-08 the counts were HIGH 4, MEDIUM 10, LOW 4; new advisories can change them over time. The build took 41 s
on Windows, with layers cached from earlier builds. On macOS it finished within a few minutes and wasn't timed.

To compare the HIGH findings with the table under Security in the README:

```bash
aws ecr describe-image-scan-findings --profile "$AWS_PROFILE" --region eu-north-1 --repository-name "$(cd terraform/foundation && terraform output -raw ecr_repository_name)" --image-id imageTag="$(git rev-parse --short=12 HEAD)" --query 'imageScanFindings.findings[?severity==`HIGH`].name' --output text
```

Expected: the two glibc and the two zlib CVEs from that table.

```bash
cd terraform/app
```

```bash
cp terraform.tfvars.example terraform.tfvars
```

```bash
nano terraform.tfvars
```

Make the file look like this:

- `image_tag` and `image_digest`: the two lines `build_push.sh` printed;
- `alarm_email`: where alarm mails should go;
- the profile and the account: as in step 5.

```hcl
# Copy to terraform.tfvars (git-ignored) and fill in your own values.
# Use the same profile and account as the foundation stack; the name prefix comes
# from the foundation's state.

aws_profile         = "upwind"
allowed_account_ids = ["<the 12 digits from step 1>"]

# Both printed by scripts/build_push.sh: the tag (git SHA) and the digest the instances pull.
image_tag    = "<image_tag from build_push.sh>"
image_digest = "sha256:<image_digest from build_push.sh>"

# Where alarm notifications go (SNS e-mail; confirm the subscription mail).
alarm_email = "you@example.com"

# Optional overrides (defaults shown):
# region                = "eu-north-1"
# foundation_state_path = "../foundation/terraform.tfstate"
# instance_type         = "t3.micro"
# asg_min               = 2
# asg_max               = 4
```

```bash
terraform init
```

```bash
terraform plan -out=app.tfplan
```

Expected: `Plan: 39 to add, 0 to change, 0 to destroy`.

**Read this plan now.** The next command applies the saved plan without asking `yes`.

```bash
time terraform apply app.tfplan
```

Took 5:04 on Windows and 2:50 on macOS. It ends with the outputs; `url` is the address of the UI. The apply returns
when the resources exist, not when the instances answer. On Windows both targets were healthy 2:37 after the start,
and the first 200 through CloudFront came at 4:37.

**[mail]** AWS sends "AWS Notification - Subscription Confirmation" to `alarm_email`. Confirm it if you want the alarm
mails.

```bash
cd ../..
```

## 8. Smoke test and the UI

**[Terminal]**

```bash
URL=$(cd terraform/app && terraform output -raw url)
```

```bash
SECRET=$(cd terraform/foundation && terraform output -raw auth_secret_name)
```

```bash
curl -s "$URL/healthz"
```

Expected: `{"status":"ok"}`. Anything else, or an error page, means the instances or CloudFront aren't ready yet:
wait a minute and run it again.

```bash
python scripts/smoke_test.py "$URL" --secret-id "$SECRET"
```

The script reads `AWS_PROFILE` from step 1. Expected: `PASS` on every line and `0 failed` at the end, in about 4 s.
That covers the Basic-auth checks, the 15 samples with their expected verdicts, a cache hit and the history from RDS.

```bash
echo "$URL"
```

**[browser]** Open that address and log in as `reviewer` with the password from step 6. Upload a file from `samples/`
or paste an email's source, and look at "History of scans". If a file is chosen, the file is scanned and the pasted
text is ignored; reload the page to clear the choice.

**[AWS console]** Region eu-north-1, the names start with your prefix:

- CloudWatch → Dashboards → `<prefix>-overview`;
- CloudWatch → Alarms;
- CloudWatch → Logs Insights → Saved queries;
- EC2 → Target groups → Targets.

## 9. Tear down

**[Terminal]** Make sure you are at the root of the clone:

```bash
pwd
```

```bash
cd terraform/app && terraform destroy
```

Expected: `Plan: 0 to add, 0 to change, 39 to destroy`; type `yes`. Took 3:24 on Windows.

```bash
cd ../foundation && terraform destroy
```

Expected: `47 to destroy`; type `yes`. Took 4:29 on Windows. The ECR repository goes with its images, and the
Basic-auth secret is deleted at once. RDS keeps no final snapshot and deletes its own password secret.

```bash
cd ../..
```

## 10. Check that nothing is left

**[Terminal]**

```bash
(cd terraform/app && terraform state list)
```

```bash
(cd terraform/foundation && terraform state list)
```

Expected: both print nothing.

```bash
aws ec2 describe-instances --profile "$AWS_PROFILE" --region eu-north-1 --filters Name=tag:NamePrefix,Values="$NAME_PREFIX" --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text
```

Expected: `terminated`, or nothing once AWS stops listing them.

```bash
aws ec2 describe-nat-gateways --profile "$AWS_PROFILE" --region eu-north-1 --filter Name=tag:NamePrefix,Values="$NAME_PREFIX" --query 'NatGateways[].[NatGatewayId,State]' --output text
```

Expected: `deleted`, or nothing.

```bash
aws ec2 describe-volumes --profile "$AWS_PROFILE" --region eu-north-1 --filters Name=tag:NamePrefix,Values="$NAME_PREFIX" --query 'Volumes[].[VolumeId,State]' --output text
```

Expected: nothing.

```bash
aws resourcegroupstaggingapi get-resources --tag-filters Key=NamePrefix,Values="$NAME_PREFIX" --profile "$AWS_PROFILE" --region eu-north-1 --query 'ResourceTagMappingList[].ResourceARN' --output text
```

The tagging API lags far behind deletes. It still listed deleted resources 10 minutes after the macOS destroy. Two
hours after the Windows destroy, it still listed two instances and the S3 gateway endpoint, although describe calls by
their IDs no longer found them. An entry there is a leftover only if the service itself still has it. What stays by
design: the `AWSServiceRoleForAutoScaling` service-linked role and the empty local state files.

## 11. Cleanup, in this order

1. **[Terminal]** Optionally, run the tagging check from step 10 again later, until it prints nothing.
2. **[Terminal]** Delete the clone. It holds both `terraform.tfvars` files, `.env` and the empty state files. Run
   this from the folder you cloned into: `rm -rf phishing-detector`.
3. **[browser]** If you created a GitHub token for the clone, delete it: GitHub → Settings → Developer settings →
   Personal access tokens.
4. **[AWS console]** Last, if you created an access key just for this run: IAM → Users → your user → Security
   credentials → Access keys → Deactivate, then Delete. The checks above need the key, so it goes last.

## If something goes wrong

- **Compose: `starting`.** For the first 15-30 s this is normal; run `docker inspect` again.
- **Compose: `unhealthy` that doesn't go away**, after you ran compose before with another `DB_PASSWORD` (in this
  clone or another one). The compose project name is fixed, so every clone uses the same `phishing-detector_db-data`
  volume, and PostgreSQL takes the password only when the volume is first created. `docker compose down -v` deletes
  the volume, and with it the local history; then run `docker compose up -d --build` again. Seen in the Windows run.
- **"Access denied when attempting to assume role" on the first apply of the app stack**, on an account that never
  had an Auto Scaling group. AWS creates the `AWSServiceRoleForAutoScaling` role during that apply, and the first
  launches can fail until it has propagated. Terraform then marks the group as tainted. In `terraform/app`:

  ```bash
  terraform untaint aws_autoscaling_group.app
  ```

  then `terraform plan -out=app.tfplan` and `terraform apply app.tfplan` again.
- **The build is slow on Apple Silicon.** The image is built for x86 (`linux/amd64`, the t3 instances), so Docker
  Desktop runs the build under emulation; the Rosetta option is in Settings → General. Steps such as `pip install` can
  stay silent for a while. An arm64 image would not start on the instances.
- **502 or 503 in the smoke test right after the apply.** The instances or CloudFront aren't ready yet (see step 7).
  Wait until `curl -s "$URL/healthz"` prints `{"status":"ok"}`, then run the smoke test again.
- **`build_push.sh` says "uncommitted changes".** It refuses to build when the working tree differs from the commit,
  so the image tag always names the code inside. `git status --porcelain` shows what differs. macOS `.DS_Store` files
  are ignored by `.gitignore`. Don't run "Updating the dependency lock" from the README unless you changed
  `requirements.txt`: it rewrites `requirements.lock`.
- **The foundation apply fails on the secret's name** right after a destroy with the same prefix. Secrets Manager
  finishes the deletion in the background; run the apply again a little later.
