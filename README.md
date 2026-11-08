# Phishing detector on AWS

A rule-based email phishing detector (command line and web UI) and the Terraform that deploys it on AWS:
two EC2 instances behind an Application Load Balancer, with scan history in Amazon RDS.

> This README is an outline; each section is filled in as the corresponding part is built.

## What it does

_Input formats, the indicator families, how the risk score and verdict are computed, example output._

The detector (`phishing_detector/`, Python standard library only) reads one email and reports whether it is likely phishing and why.
It is rule-based: every point of the score comes from a named indicator with its evidence, and each rule has its own tests.
The priority is precision: when it says "phishing" it should be right, even if that means missing phishing that has no
visible tell; "suspicious" is the level that trades some false alarms for more catches.

**Input.** A raw email with headers (`.eml`, or a text file in that format), or just the body text.
For body-only input the authentication, sender and history checks are skipped, and the result says so.

**Indicators** (weights in [`scoring.py`](phishing_detector/scoring.py), one table):

| Family | What is checked |
|---|---|
| Authentication | SPF, DKIM and DMARC results from the topmost `Authentication-Results` header only; the lower ones can be written by the sender. A missing header is neutral. |
| Sender | Display name that shows another domain's address or names a brand the mail doesn't come from; sender domain that imitates a protected brand (homoglyphs such as `examp1ebank`, `exarnplebank` or Cyrillic letters, small edit distance, brand plus extra words); punycode; Reply-To or Return-Path at another domain. |
| Links | Bare IP hosts; link text that shows another domain than the link; lookalike domains; a brand in front of or in the path of an unrelated domain (`examplebank.test.login.example.net`, `files.example.net/examplebank/`); a brand named in the mail with no link to it; the recipient's address in a link (also base64-encoded), as phishing kits use to pre-fill a fake login; redirect parameters and AMP pages; free hosting, storage and form services; "Sign in" / "View document" buttons; punycode; `user@host` tricks; `javascript:`/`data:` URLs; password fields in the email; often-abused TLDs; URL shorteners; unusual ports. |
| HTML tricks | A lot of text hidden with CSS (a short hidden preview line is normal); invisible characters inside words; a mail that is just an image with a link. |
| Wording | Urgency, threats, credential requests, payment pressure, prize bait and generic greetings, each counted once. |
| Attachments | From MIME metadata only: programs and scripts, macro-enabled Office files, HTML/SVG files, archives and disk images, double extensions and the right-to-left override trick, a harmless declared type on a risky file, an archive password in the text. |
| History | Earlier phishing verdicts for the same sender domain (web app only, see below). |

**Score and verdict.** The score is the sum of the indicator weights, capped at 100:
`phishing` from 50, `suspicious` from 25, `likely_legitimate` below 25.

**Safety.** Emails are treated as hostile data: links are parsed as text and never fetched or resolved,
HTML is never rendered, and attachment payloads are never decoded (a test asserts it).
Evidence shows domains, defanged URLs (`hxxp://evil[.]example/login`), matched phrases and attachment names,
never full email addresses or the subject.

**History without poisoning.** An earlier phishing verdict counts against a sender domain only if that email
passed DMARC for the domain or the domain was itself a lookalike. Otherwise anyone could put a bank's address
in the From line of a phishing mail and make the bank's real mail look suspicious afterwards.

**When the history is unavailable** (for example the database is down), the scan still runs (fail-open),
but carefully: the result says `history_status: unavailable`, the CLI and the UI show a warning, and if an earlier
flag on the sender domain (+20) could have pushed the score over the next threshold, the verdict is raised one level
with the reason `history unavailable`. The score itself still counts only what is in the email.
An outage can therefore produce extra `suspicious` results, but never a phishing mail rated lower than with the history up;
a test checks this for every sample. Failing closed (refusing to scan, or rating everything phishing)
would turn a database outage into an outage of the whole service, and failing open without the raise
would quietly miss mail that the history would have caught.

Example:

```text
$ python -m phishing_detector scan samples/phishing_spoofed_bank.eml
Verdict: PHISHING (score 100/100)
Input: email with headers
Indicators (9):
  [+30] links.ip_host: A link points to a bare IP address instead of a domain name (hxxp://203[.]0[.]113[.]45:8080/examplebank/verify)
  [+25] auth.dmarc_fail: DMARC failed: the From domain is probably spoofed (dmarc=fail)
  [+15] auth.spf_fail: SPF failed: the sending server isn't allowed to send for that domain (spf=fail)
  [+15] sender.reply_to_mismatch: Replies would go to a different domain than the sender's (replies go to example[.]net)
  [+15] wording.credentials: Asks to verify an account or to enter a password ("confirm ... identity")
  [+10] links.nonstandard_port: A link uses an unusual port number (hxxp://203[.]0[.]113[.]45:8080/examplebank/verify)
  [+10] wording.threat: Threats of suspension, closure or other trouble ("card ... locked"; "unauthorized activity")
  [+5] sender.return_path_mismatch: The bounce address (Return-Path) is at another domain (common for mailing services too) (bounces go to example[.]net)
  [+5] wording.generic_greeting: Generic greeting instead of the recipient's name ("dear customer")
Notes:
  - History check skipped: no scan history was provided.
```

## Architecture

_Diagram and request flow: CloudFront, ALB, Auto Scaling group of two EC2 instances, RDS PostgreSQL, ElastiCache, logging and monitoring._

- **Two Terraform stacks.** `terraform/foundation` holds what is slow to create or keeps data: the network, all security groups,
  RDS PostgreSQL, ElastiCache Valkey, the ECR repository, the Basic-auth secret and VPC flow logs.
  `terraform/app` (load balancer, CloudFront, instances, monitoring) reads the foundation's outputs and is applied and destroyed on its own.
- **Three subnet tiers in two Availability Zones.** Public: the load balancer and the NAT gateway only, no automatic public IPs.
  App: the instances, outbound only through the NAT gateway and a free S3 gateway endpoint. Data: RDS and Valkey, with no route out of the VPC.
- **Security groups reference each other instead of address ranges:**
  CloudFront origin-facing prefix list → load balancer :80 → app :8000 → PostgreSQL :5432 and Valkey :6379.
  The data-tier groups have no outbound rules, and the VPC's default security group is emptied.

## Repository layout

_What lives where._

## Run locally

_Command-line scan without Docker; the web app with docker compose; running the tests._

### Command line (Python 3.13, no dependencies)

```bash
python -m phishing_detector scan samples/phishing_lookalike_sender.eml
python -m phishing_detector scan samples/plain_phishing.txt --json
```

### Web app with docker compose (the main local path)

The app with PostgreSQL 18 and Valkey 8, as in AWS. The images are pinned by digest.

```bash
cp .env.example .env        # then set your own DB_PASSWORD (and BASIC_AUTH_* to turn on Basic auth)
docker compose up -d --build
docker inspect --format '{{.State.Health.Status}}' phishing-detector-app-1     # healthy
```

Open http://127.0.0.1:8000, upload a file from `samples/` or paste an email's source. A second scan of the same
email says "from cache"; every scan appears under "History of scans". Stop with `docker compose down`
(`down -v` also deletes the local database). Without `DB_HOST` the app keeps its history in memory instead.

API: `POST /api/scan` (multipart field `email`, or form field `text`) returns the result as JSON plus `cached`;
`GET /api/history?limit=20`; `GET /api/version` (image tag and rules version); `GET /healthz` (no auth, only `{"status": "ok"}`).

```bash
curl -s -F "email=@samples/phishing_spoofed_bank.eml" http://127.0.0.1:8000/api/scan
```

**Updating the dependency lock** (after changing `requirements.txt`; network on; the image below is the one the current lock was made with):

```bash
IMAGE=python:3.13.17-slim@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962
docker run --rm -v "$(pwd):/src:ro" -v "$(pwd)/build:/out" $IMAGE \
  pip install --dry-run --ignore-installed --uploaded-prior-to P7D --report /out/report.json -r /src/requirements.txt
python scripts/lock_requirements.py build/report.json > requirements.lock
```

### Tests

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt      # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest -q
```

These commands were run on Linux (a `python:3.13.17-slim` container) and on Windows; CI runs them on
`ubuntu-latest` for every push. On macOS, use the Linux commands.

`tests/test_postgres.py` runs only when `TEST_DATABASE_URL` points at a PostgreSQL database, for example the compose one:
`TEST_DATABASE_URL=postgresql://phishdet:<your DB_PASSWORD>@127.0.0.1:15432/phishdet` (it works in its own schema and drops it).

### CI

`.github/workflows/ci.yml` runs four jobs on every push to `main` and every pull request, with no AWS credentials:

- **tests**: the commands above, with a throwaway PostgreSQL service container (the compose image, by digest), so
  the PostgreSQL tests run too;
- **image**: the same `docker build` as `scripts/build_push.sh` (no push), then the container started with the EC2
  flags (read-only root, no capabilities) and `/healthz` checked;
- **terraform**: `terraform fmt -check`, `init -backend=false` and `validate` in both roots, tflint with the pinned AWS
  ruleset;
- **checkov** on Python 3.12, the version its package supports (locally it runs on 3.13).

Actions are pinned to commit SHAs, and the tool versions match the ones used locally.

## Deploy to AWS

_Prerequisites and tool versions, the two Terraform stacks and the order to apply them, setting the access secret, building and pushing the image._

### 1. Foundation (once, before the demo)

```bash
cd terraform/foundation
cp terraform.tfvars.example terraform.tfvars   # your AWS CLI profile and account ID
terraform init
terraform apply                                # review the plan, then confirm
```

`allowed_account_ids` makes Terraform refuse to run against any other account.
The apply took about 11 minutes in our test, mostly RDS and ElastiCache (about 10 minutes each, in parallel).

### 2. Basic-auth password for the web UI

Terraform creates the secret empty, so the password never appears in code, variables or Terraform state.
Set it from a shell; `read -s` keeps it off the screen and out of the shell history (don't use `"` or `\` in it):

```bash
read -rs PW
aws secretsmanager put-secret-value --profile <your-profile> --region eu-north-1 \
  --secret-id phishdet/basic-auth \
  --secret-string "{\"username\":\"reviewer\",\"password\":\"$PW\"}"
unset PW
```

### 3. Image and app stack

```bash
AWS_PROFILE=<profile> AWS_REGION=eu-north-1 scripts/build_push.sh   # prints image_tag and image_digest
cd terraform/app
cp terraform.tfvars.example terraform.tfvars                        # profile, account, image_tag, image_digest
terraform init
terraform plan -out=app.tfplan
terraform apply app.tfplan
cd ../.. && AWS_PROFILE=<profile> python scripts/smoke_test.py "$(cd terraform/app && terraform output -raw url)"
```

In our run, two healthy targets came about 3 minutes 20 seconds after the apply started (cloud-init takes about
85 seconds per instance). `scripts/smoke_test.py` reads the Basic-auth secret inside its own process and never prints it.

On an account that has never had an Auto Scaling group, AWS creates the `AWSServiceRoleForAutoScaling` service-linked role
during the first apply, and the first launches can fail with "Access denied when attempting to assume role" until it has
propagated. The group retries by itself a minute later, but Terraform marks it as tainted. Then run
`terraform untaint aws_autoscaling_group.app` and apply again; the role stays in the account afterwards.

**Rollout and rollback.** `build_push.sh` → new `image_tag` and `image_digest` in `terraform.tfvars` → plan → apply.
The new launch template version starts an instance refresh with `min_healthy_percentage = 100` and
`max_healthy_percentage = 200`: new instances are launched first and the old ones stopped only once the new ones are
healthy and warmed up, so the site never runs on fewer than two instances (with the default "terminate first", one
instance would carry all traffic for minutes, and a bad image would be found only after half the capacity was gone).
A rollback is the same path with the previous tag and digest. Both versions share Valkey: a cache entry one version
can't read counts as a miss (logged as `cache_decode_failed`), never as an error.

Measured on 2026-11-06 and 2026-11-07 with two t3.micro instances, `scripts/smoke_test.py --watch` scanning a sample every 2 seconds
through CloudFront the whole time:

| Change | Instance refresh | Both versions answering | Requests that were not 200 |
|---|---|---|---|
| rollout 4340dddf6d3d → ce067dbcc400 | 4 min 37 s | about 1.5 min | 0 |
| rollback ce067dbcc400 → 4340dddf6d3d | 5 min 14 s | about 1 min 50 s | 0 |
| rollout again → ce067dbcc400 | 4 min 9 s | about 50 s | 0 |
| rollout → d7263e177739 (2026-11-07) | 4 min 28 s | about 1 min | 0 |

`terraform apply` itself takes about 10 seconds; the refresh runs on after it. A first deployment of the app stack
(nothing running yet) reached two healthy targets 3 minutes 20 seconds after the apply started.

## Invoke

_Using the web UI and the HTTP API on the deployed stack._

## Monitor

- **Dashboard** `phishdet-overview` (CloudWatch): healthy and unhealthy targets; instances in service, desired, and EC2 status
  checks; requests through the load balancer; answers by status (app 2xx, 4xx, 5xx, load balancer 5xx); response time
  p50 and p95; CPU; memory and disk from the CloudWatch agent; RDS CPU, connections and free storage; the app's failure
  events; and a table of the latest log events other than successful requests.
- **Logs:** the app writes one JSON line per request and per failure event (never email content) to
  `/phishdet/app`, one stream per instance; boot logs go to `/phishdet/cloud-init`. Successful health checks aren't logged.
  Metric filters count `history_read_failed`, `history_write_failed`, `cache_failed` and `cache_decode_failed`.
- **Saved Logs Insights queries:** `phishdet/errors-by-type`, `phishdet/scans-by-verdict`, `phishdet/scan-latency`.
- **Alarms** go to an SNS e-mail topic (the address is a Terraform variable; confirm the subscription mail), each with an
  OK notice when it recovers: unhealthy targets, 5xx answers (this includes 503 when the Basic-auth secret can't be read,
  while `/healthz` stays 200), app CPU, RDS CPU, RDS free storage, and history-store errors (scans then fall back to
  cautious verdicts).
- **Planned replacement vs sudden failure.** A rollout or rollback (instance refresh) had no failed request: an old
  instance is taken out of the load balancer first (deregistration, 30 s to finish requests in flight) and only then
  stopped. A sudden failure is different: until the health check notices it, the load balancer keeps sending part of
  the traffic to the dead instance and those requests get 502. With checks every 15 s and 2 failures to mark a target
  unhealthy, that window is up to about 30 s. The interval is a trade-off: shorter detects faster but marks a target
  unhealthy on a brief hiccup (a slow start, a garbage-collection pause) and adds check traffic; longer means a longer
  502 window. 15 s × 2 is kept.
- **Drill (measured 2026-11-07).** `systemctl stop phishdet` on one of the two instances (through SSM) while
  `smoke_test.py --watch` scanned every 2 seconds: 502 for 18 seconds (9 failed requests, about half of those sent in
  that window); the target was unhealthy after 21 s; the Auto Scaling group started a replacement after 48 s; two
  healthy targets again after about 2.5 minutes. The alarm mails (unhealthy targets, and 5xx) arrived 3–4 minutes after
  the failure, with OK mails 1–2 minutes later: load balancer metrics reach CloudWatch with a delay, so the alarms tell
  people what happened; the health check and the Auto Scaling group do the recovery.

## Tear down

_`terraform destroy` order and the CLI checks that confirm nothing is left._

## Cost

_What each resource costs per day and the total for the test period._

- **CPU credits of the t3.micro instances: unlimited, set explicitly.** In standard mode a t3 gets no launch credits
  ([AWS docs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/burstable-performance-instances-standard-mode-concepts.html)),
  so a new instance would boot at the 10 % baseline: the boot (Docker, the CloudWatch agent, the image pull) would not
  finish within the 180-second health-check grace period, and every rollout or replacement would be minutes slower.
  Unlimited mode costs extra only while an instance's average CPU stays above the baseline: surplus credits are billed
  per vCPU-hour ($0.05 in the AWS example for us-east-1), so the worst case, 100 % CPU around the clock, is about
  $2 per day per instance (2 vCPUs × 90 % above baseline × 24 h × $0.05). The `phishdet-app-cpu` alarm (above 80 % for
  10 minutes) and the AWS budget alert catch that long before it adds up.

## Security

_IAM, network exposure, encryption, secrets handling, untrusted email handling, and the justification for every wildcard permission and every skipped scanner check._

- Nothing in the data tier is public: RDS has `publicly_accessible = false`, and RDS and Valkey sit in subnets without a route out of the VPC.
- Encryption at rest everywhere it is offered (RDS, Valkey, ECR, Secrets Manager, CloudWatch Logs), with AWS-managed keys.
  In transit: PostgreSQL requires TLS (`rds.force_ssl = 1`, set explicitly in the parameter group), and Valkey requires TLS.
- The RDS master password is generated by RDS and kept in Secrets Manager (`manage_master_user_password`); Terraform never sees it.
- Logging: VPC flow logs (all traffic), PostgreSQL logs including statements slower than 500 ms, and the Valkey slow log, each in CloudWatch Logs for 7 days.
  The log-delivery permission for the Valkey slow log is a Terraform-managed resource policy limited to that log group,
  so AWS does not create a broader one of its own that `terraform destroy` would leave behind.
- The ALB access-log bucket blocks all public access, lets only the ALB log-delivery service write under this account's prefix,
  and denies every request without TLS. That deny is the one place a policy uses `*` (all principals, all S3 actions): it only ever takes access away.
- The only IAM role in the foundation is for flow logs: it trusts `vpc-flow-logs.amazonaws.com` only for this account's flow logs and can write only to its log group.
- The app instances' role can pull only the app's ECR repository, read only the two app secrets (database and Basic auth),
  and write only to the two app log groups. Two statements use `*` because the API has no resource-level permissions:
  `ecr:GetAuthorizationToken`, and `cloudwatch:PutMetricData`, which is limited by condition to the `CWAgent` namespace.
  Session Manager access comes from the AWS-managed `AmazonSSMManagedInstanceCore` policy (no SSH, no open ports).
  Instances use IMDSv2 only, encrypted gp3 volumes and no public IP; the container gets only where the secrets are, never their values.
- Dependencies are pinned to exact versions, and each pinned version had been public for at least 7 days when it was pinned,
  so a broken or compromised release has time to be noticed and yanked before it reaches the image.
  The image installs from `requirements.lock`: every package, transitive ones included, pinned with the SHA-256 of
  each of its files and installed with `pip install --require-hashes` (wheels only). The lock is generated from
  `requirements.txt` by pip's resolver limited to releases at least 7 days old (`--uploaded-prior-to P7D`), and
  `scripts/lock_requirements.py` checks every release's age against PyPI again before writing it (see "Run locally").
- The web app: HTTP Basic auth on everything except `/healthz` (credentials from Secrets Manager, compared in constant
  time; if the secret can't be read, requests are refused); uploads over 1 MB get 413; responses carry
  `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. The page never renders email HTML: every value is set
  with `textContent`, and links are shown defanged, never as clickable links. The container runs as UID 10001 with a
  read-only root filesystem, no Linux capabilities and `no-new-privileges`. Logs are JSON lines with request ids,
  status, verdict and score only, never email content.
  The 7-day rule is for third-party packages and tools. The Docker base image (`python:3.13.18-slim`, pinned by digest)
  is decided by the ECR vulnerability scan instead: if a newer `python:3.13-slim` fixes HIGH or CRITICAL findings,
  the image moves to it (again pinned by digest) without waiting. That is how 3.13.18 was chosen a day after its release:
  it fixed the HIGH finding in `apt` that the scan reported on 3.13.17 (5 HIGH before, 4 after; MEDIUM 9, LOW 3 unchanged).
- Every push is scanned by ECR (basic scanning); `scripts/build_push.sh` waits for the result, prints the counts and
  stops on an incomplete scan or any CRITICAL finding. The instances run the image by digest (`repository@sha256:…`),
  so EC2 runs exactly the image that was scanned; the tag (the commit) is for people. HIGH findings accepted for now,
  in the image pushed for deployment (tag 4340dddf6d3d):

  | CVE | Package (version) | Fix available? | Why accepted |
  |---|---|---|---|
  | CVE-2026-5435, CVE-2026-19499 | glibc (2.41-12+deb13u4) | No: Debian trixie and trixie-security have no newer package (checked 2026-11-06) | Nothing to upgrade to yet. Exposure is limited: non-root, read-only container without capabilities, private subnets, Basic auth in front. The CVE details were not analysed further |
  | CVE-2026-85091, CVE-2026-76844 | zlib (1.3.dfsg+really1.3.1-1+b1) | No, same check | Same as above |

  Policy: rebuild and redeploy when Debian or a newer `python:3.13-slim` ships a fix; a CRITICAL finding blocks the push.
- Build attestations are off (`--provenance=false --sbom=false`). They were unsigned and nothing checked them, but they
  turned each push into an image index whose scan result sat on an untagged child manifest instead of the tagged image,
  and added two extra entries per push to the repository. Integrity comes from the digest deployment, immutable tags,
  hashed dependencies and the scan gate. Next step: signing (cosign with a KMS key, or AWS Signer/Notation) with the
  signature checked before `docker run`, and an SBOM as a separate artifact.

### Scanner findings that are not fixed

`terraform fmt`, `terraform validate`, tflint (with the AWS ruleset) and checkov run before every apply and in CI.
Each finding below is skipped in the code with an inline comment, for the reason given.

| Check | Resource | Why it is skipped |
|---|---|---|
| CKV_AWS_136, CKV_AWS_149, CKV_AWS_158, CKV_AWS_191 | ECR, Secrets Manager, CloudWatch log groups, ElastiCache | Encrypted at rest with AWS-managed keys. A customer-managed KMS key ($1/month plus a key policy) is a next step. |
| CKV_AWS_157 | RDS | Single-AZ to halve the database cost; the two-instance app tier is the highly available part. |
| CKV_AWS_353, CKV_AWS_118 | RDS | Performance Insights and enhanced monitoring are paid add-ons; the standard RDS metrics feed the dashboard. |
| CKV_AWS_161 | RDS | The app authenticates with the RDS-managed password from Secrets Manager; IAM database authentication is a next step. |
| CKV_AWS_293 | RDS | No deletion protection, so `terraform destroy` works at the end of the review. |
| CKV_AWS_31 | ElastiCache | TLS is on and only the app security group can connect; a Valkey AUTH token is a next step. |
| CKV2_AWS_50 | ElastiCache | One node on purpose: losing the cache only means re-scanning, so no replica or failover. |
| CKV_AWS_338 | CloudWatch log groups | 7-day retention is enough for a short-lived stack. |
| CKV2_AWS_57 | Secrets Manager (Basic auth) | The operator sets the password by hand; rotation would need a rotation Lambda. |
| CKV2_AWS_5 | ALB and app security groups | False positive across stacks: the groups are attached in the app stack. |
| CKV_AWS_260 | ALB ingress rule | False positive: the source is the CloudFront managed prefix list, not 0.0.0.0/0. |
| CKV_AWS_394 | Availability-zone data source | Only the first two zone names in sorted order are used; a new zone sorts after them. |
| tflint `aws_elasticache_replication_group_default_parameter_group` | ElastiCache | No cache parameter is changed, so the default parameter group is enough. |
| CKV_AWS_2, CKV_AWS_103, CKV2_AWS_20 | ALB listener | Without a domain there is no certificate for the ALB. Viewers get HTTPS from CloudFront (HTTP is redirected there); only CloudFront can reach the ALB. |
| CKV_AWS_174, CKV2_AWS_42 | CloudFront | The default `*.cloudfront.net` certificate doesn't allow a custom certificate or a higher minimum TLS version; that needs a domain. |
| CKV_AWS_68, CKV2_AWS_47, CKV2_AWS_28 | CloudFront, ALB | WAF is a paid add-on and not used; a next step. |
| CKV_AWS_86 | CloudFront | Caching is off, so every request reaches the ALB, whose access logs record it. |
| CKV_AWS_310 | CloudFront | One origin; availability comes from the ALB and the two instances behind it. |
| CKV_AWS_374 | CloudFront | Reviewers may be anywhere; Basic auth limits access instead of geography. |
| CKV_AWS_305 | CloudFront | The origin is an application that serves its own root path. |
| CKV_AWS_150 | ALB | No deletion protection, so `terraform destroy` works. |
| CKV_AWS_341 | Launch template | IMDS hop limit 2, so the container (one hop behind the Docker bridge) can get the instance role's credentials; IMDSv2 tokens are required. |
| CKV_AWS_378 | Target group | HTTP from the ALB to the instances, inside the VPC; TLS on this hop is a next step together with a domain. |
| CKV_AWS_145 | ALB log bucket | ALB access logs support only SSE-S3, not KMS. |
| CKV_AWS_18, CKV_AWS_21, CKV_AWS_144, CKV2_AWS_62 | ALB log bucket | It is the log bucket itself: no access log of it, no versioning or replica for 7-day logs, no event consumers. |

## Assumptions

_How ambiguous points in the assignment were interpreted._

## Limitations

_What the detector and the infrastructure do not cover._

- The detector is rule-based: a well-written phishing email with no technical tells (clean domain, no links or attachments,
  neutral wording) scores low. On public data, without the era-biased signals, it catches about 21 % of phishing at the
  phishing level and 56 % at "suspicious", flagging 1-1.5 % of legitimate mail as suspicious (see Evaluation).
- Some weights are tuned on public corpora whose legitimate mail is from 2002 and mostly personal or mailing-list mail;
  the modern legitimate set is a technical mailing list. Modern transactional mail ("Dear customer", payment updates,
  password resets, HTML buttons) is underrepresented in both, so expect more false positives on it. The others are set by hand.
- Valkey holds two small caches, both keyed by the detector's rules version, so a new version never reuses an old entry:
  - **The email's own analysis** (`static:<rules version>:<sha256>`, 1 hour): saves little. Measured in the container, the
    analysis takes 3 ms at the median and 14 ms at the 95th percentile on corpus mail (15 synthetic samples: 1.7 / 4.3 ms);
    a cache read in compose takes 0.07 ms. Byte-identical repeats are rare too: the mails of one campaign differ in
    recipient, links and tracking ids, so each has its own SHA-256. It is the pattern a slower detector (URL reputation,
    a model) would need. Under load the measured benefit is 8-13 ms per repeated scan on the server (cached p50 12 vs 20 ms with the pool, 27 vs 39 ms with threads; see "Performance and scaling").
  - **Domain reputation** (`flag:<rules version>:<domain>`, 7 days): the SHA-256s of up to five emails that flagged a
    sender domain under the poisoning rule, written only after the scan row is committed to PostgreSQL. This one serves
    campaigns (many different mails from one flagged domain) and resilience: while the database is down, a known-bad
    domain still gets the history signal instead of only a cautious verdict. Only "flagged" is cached, never "not
    flagged": a new flag has to count on every instance at once, and a miss costs one indexed count in PostgreSQL, after
    which a found flag restores the mark. A test runs the same sequence of scans with and without Valkey and expects the
    same verdicts.
- Links wrapped by a mail gateway's link protection are unwrapped statically (Microsoft Safe Links: the `url` parameter;
  Proofpoint URL Defense v2 and v3: their own encoding) and every link check runs on the real target. Mimecast-protected
  links carry the target in an opaque token and can't be unwrapped offline; they are judged as links to Mimecast.
- Without the full Public Suffix List, the registrable domain is "the last two labels", plus a short list of
  two-label suffixes such as `co.uk` and `co.il`.
- Lookalike detection only protects the brands listed in `phishing_detector/data/brands.txt`; the TLD and shortener lists are hand-picked.
- Links are judged from their text only (never fetched or resolved), so a clean-looking URL that redirects somewhere bad is not caught.
- `Authentication-Results` is trusted as written by the receiving server; the detector can't tell which server that was.

- One NAT gateway, in the first Availability Zone (eu-north-1a), serves both app subnets, to save the cost of a second one.
  If that zone fails, the instance in the other zone keeps answering requests but loses outbound access
  (image pulls from ECR, CloudWatch Logs, Secrets Manager) until the zone recovers.
- RDS and Valkey each run in a single Availability Zone, also for cost.
  If their zone fails, the database or the cache is unavailable until AWS recovers it;
  the two app instances in different zones are the highly available part of the design.

- The Valkey cache has no AUTH token. Only the app security group can reach it, every connection uses TLS,
  entries expire after 1 hour, and cached results hold no email addresses or subjects.
  The Valkey slow log (CloudWatch Logs, 7 days) can contain truncated command arguments, such as a cache key (an email's SHA-256).
- The PostgreSQL log (CloudWatch Logs, 7 days) records statements slower than 500 ms with their bind values: an email's
  SHA-256, the sender domain and the signal ids, never email content. Setting `log_parameter_max_length` to 0 in the
  parameter group would drop the values.

## Data sets

_Source and license of every data set used for testing and evaluation._

- `samples/`: twelve synthetic emails written for this project, using reserved names only
  ([RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) domains such as `example.com` and `.test`,
  [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) documentation addresses) and placeholder attachment bytes.
  `tests/test_samples.py` pins the expected verdict of each.
- Phishing for the evaluation: [Nazario phishing corpus](https://monkey.org/~jose/phishing/) by Jose Nazario,
  files `phishing-2023`, `phishing-2024`, `phishing-2025` (1303 messages), license CC BY 4.0.
- Legitimate mail for the evaluation: [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/),
  `20030228_easy_ham`, `easy_ham_2` and `hard_ham` (4150 messages, 2002-2003); no formal license,
  "Copyright for the text in the messages remains with the original senders".
- Modern legitimate mail for the evaluation: the public [users@tomcat.apache.org archive](https://lists.apache.org/list.html?users@tomcat.apache.org),
  22 monthly mbox files, 2024-01 to 2025-10 (2843 messages); public under the
  [Apache public forum archive policy](https://www.apache.org/foundation/public-archives.html), no reuse license,
  copyright stays with the senders.
- There is no public corpus of modern personal and transactional mail with full headers, so two proxies are used,
  each with its own bias: ham-2002 is old (no Authentication-Results, little HTML), ham-2024 is modern but a technical
  mailing list (plain-text questions and answers, hardly any marketing or transactional mail). Weights are tuned on
  ham-2002 only; ham-2024 is reported separately.
- None of the corpora is in this repository: `scripts/fetch_datasets.py` downloads them into a Docker volume and checks pinned SHA-256 values.
  The Apache archive builds each mbox on request, so a later download can differ in bytes (for example if a message was
  removed from the archive); the script then prints the mismatch and both message counts and keeps going, and the
  numbers may differ slightly from the ones below.
  Only aggregate results are published ([docs/evaluation.md](docs/evaluation.md)).

## Evaluation

The detector was measured on the public corpora above; full results and method in [docs/evaluation.md](docs/evaluation.md).
On the held-out test split (379 phishing, 1250 ham-2002, 868 ham-2024), without the signals that only tell the corpora's
eras apart (second test run, after a recall iteration on dev; the first run is in the evaluation document too):

| Flagged at | Precision | Recall | False positives, ham-2002 | False positives, ham-2024 |
|---|---|---|---|---|
| phishing (score ≥ 50) | 0.987 | 0.206 | 0.1 % | 0.0 % |
| suspicious or worse (score ≥ 25) | 0.918 | 0.559 | 1.5 % | 1.0 % |

With all signals counted, recall is 0.404 at ≥ 50 and 0.760 at ≥ 25 (false positives 1.6 % and 1.4 % at ≥ 25).

When it says phishing it is nearly always right; "suspicious" catches more than half.

**Working threshold: ≥ 25.** "Suspicious" means "don't trust this mail before checking it another way"; ≥ 50 ("phishing")
is the high-confidence verdict. **Overfitting check:** one tuning parameter, picked on dev only, and dev and test agree
(at ≥ 25 without era signals, recall 0.560 on dev and 0.559 on test; ham-2002 false positives 1.8 % and 1.5 %).
Two anti-evasion changes made after test run 2 moved the dev metrics by at most 0.4 points, so the test split was not run again.
The tuning ham is from 2002 and the phishing from 2023-2025, so signals that depend on the era (all `auth.*`, punycode,
new TLDs, URL shorteners, free hosting, redirects, buttons, HTML tricks) were left out of the tuning and of the headline
numbers and keep small hand-set weights. On modern legitimate mail (ham-2024) none of the `auth.*` failures fired.
The weights marked `tuned` in [`scoring.py`](phishing_detector/scoring.py) come from a one-parameter rule on the dev split
(weight = k x ln of how much more often a signal fires in phishing), explained in the evaluation document.

**Reproduce it** (Docker; the corpora go into a named volume, never onto the host filesystem;
the repository is mounted read-only; only the download step has network access):

```bash
docker volume create phishdet-corpora
IMAGE=python:3.13.17-slim@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962

# 1. Download and verify the 28 files, about 82 MB (network on).
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v "$(pwd):/src:ro" -v phishdet-corpora:/data \
  $IMAGE python -I -B /src/scripts/fetch_datasets.py --dest /data

# 2. Evaluate (no network, unprivileged user, data read-only); --split dev or test.
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  --user 65534:65534 -v "$(pwd):/src:ro" -v phishdet-corpora:/data:ro \
  $IMAGE python -I -B /src/scripts/evaluate.py --data /data --split test
```

Run it from the repository root (in Git Bash on Windows, set `MSYS_NO_PATHCONV=1` first).
The report goes to standard output; it contains only counts, metrics and signal ids.

## Performance and scaling

Measured on 2026-11-07 with `scripts/load_test.py` from a PC through CloudFront: scans only, 80 % unique emails and
20 % repeats, one minute per step, two t3.micro instances (each run ended before the group scaled out). Client times
include about 80 ms of network. The last column is after the history query fix below.

| | Before (sync, new DB connection per call) | + connection pool | + 2 workers × 4 threads (gthread) | + history query fix (D-112, D-113) |
|---|---|---|---|---|
| Requests/s at 5 / 10 / 20 / 30 / 50 concurrent | 33 / 53 / 53 / 52 / 52 | 48 / 96 / 124 / 96 / 137 | 47 / 91 / 163 / 217 / 243 | 49 / 93 / 182 / 249 / **297** |
| Client p50 / p95 at 10 concurrent | 177 / 274 ms | 102 / 120 ms | 107 / 135 ms | 103 / 143 ms |
| Client p95 at 50 concurrent | 1932 ms | 554 ms | 324 ms | **246 ms** |
| Errors | 0 | 504 from 20 concurrent (56 in all) | 0 | **0** |
| Server time, uncached p50 / p95 | 68 / 95 ms | 20 / 31 ms | 39 / 95 ms | 29 / 67 ms |
| Server time, cached p50 / p95 | 59 / 87 ms | 12 / 24 ms | 27 / 81 ms | 17 / 45 ms |
| CPU, RDS (max) / app instances (max) | 63 % / 42 % | 33 % / 41 % | 62 % / 72 % | **20 %** / 88 % |
| Rows in `scans` | ≈ 15 000 | ≈ 60 000 | ≈ 105 000 | ≈ 258 000 |

The stalls described below don't touch the gthread and fix columns. In those two windows the RDS log shows no
ANALYZE longer than 10 s (shorter ones aren't logged), and the server answered every scan within 1 s: 524 ms and
229 ms at most.

- **How the monitoring led to the cause.** In the first run throughput stopped at 52 requests/s while the app
  instances were at 42 % CPU and RDS at 63 %: the app wasn't busy, the database was. Every history call opened a new
  TLS connection, and PostgreSQL starts a new process for each. A small pool per worker (psycopg_pool, opened after
  gunicorn forks) cut the server time to a third and RDS CPU in half. The next limit was the two synchronous workers
  per instance waiting on the network; four threads per worker roughly doubled throughput again, at the cost of more
  CPU per request (threads share the CPU and the database). Server time grows with load in the last column because
  requests now wait on RDS together; at 243 requests/s RDS is back at 62 % and is the next limit.
- **The 504s in the middle run** were the load balancer failing to open TCP connections to the instances
  (`TargetConnectionErrorCount` matched them minute by minute). The load balancer's access logs show all of them
  (56 scans, plus 4 from a watch script) within 2.5 minutes, on both instances, each after exactly 10 seconds with no
  target status and `-1` processing times: the
  [10-second TCP connection timeout](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html)
  to the target. Meanwhile the same instances answered other requests in under 0.9 s, and gunicorn logged no worker
  timeouts or restarts. The 504s started about 5 minutes after the instances entered service, so they weren't part of
  the start-up. A repeat on the same instances at 20 concurrent requests had none, and the instances' ENA allowance
  counters (`conntrack_allowance_exceeded` and the bandwidth and packet allowances) and the container's listen-queue
  overflow counters didn't move, so the cause wasn't confirmed. With threads and keep-alive connections, all steps ran
  without an error and those counters stayed at 0.
- **Clean shutdown.** gunicorn's `worker_exit` hook closes the worker's connection pool. Before, the pool's threads
  were left running: psycopg_pool waited 5 s for each and logged a warning, and `docker stop` killed the container
  after its 10-second timeout (11 s locally; now 1 s, no warnings).
- **Keep-alive.** gunicorn keeps idle connections open for 75 seconds, longer than the load balancer's 60-second idle
  timeout, so the load balancer always closes an idle connection first. The other way round, the load balancer may send
  a request on a connection gunicorn is just closing, and the viewer gets a 502.
- **Scaling** is target tracking on requests per target (`ALBRequestCountPerTarget`, one-minute load balancer metric),
  aiming at 4400 requests per minute per instance: 60 % of the about 121 requests/s each instance served in the last
  run (the client's 50 concurrent requests didn't reach the instances' limit). Not CPU, because the bottleneck is the
  workers waiting on PostgreSQL and Valkey, which doesn't show as CPU (42 % in the first run while requests queued);
  without detailed monitoring the EC2 CPU metric arrives every 5 minutes, so scaling would lag by 10-15 minutes; and CPU
  above the t3 baseline costs extra in unlimited mode. Terraform sets the group's minimum (2) and maximum (4) and ignores
  its desired count (`ignore_changes = [desired_capacity]`): the policy owns the number of instances, and a plan after a
  scale-out doesn't pull the group back to two.
- **First scale-out test** (2026-11-07, 12 minutes at 50 concurrent requests, before the history query fix). The
  policy worked:
  - the alarm fired 4 min 57 s after the load started, after three one-minute datapoints of 6168-6608 requests per
    target;
  - the group went from 2 to 3 instances (target tracking asked for 3, not 4: 2 × 6168 / 4400 = 2.8);
  - the new instance was healthy about 2 minutes after its launch;
  - no request failed during the run;
  - after the scale-out, Auto Scaling lowered the scale-in alarm's threshold from 3960 to 3080 requests per target.
    Once the per-target count had stayed below it for 15 minutes, the group went back to 2 instances, 18 minutes after
    the load ended;
  - a full `terraform plan` afterwards showed no changes: the group's desired count isn't managed by Terraform.

  But throughput didn't grow. It fell from 231 to 145 requests/s, client p95 rose from 337 to 800 ms, and RDS CPU went
  from 54 % to 98 %. The database had become the limit:
  - Each scan counts the earlier phishing verdicts for its sender domain (the history check). That query reads every
    phishing row of the domain, so it slows down as the table grows.
  - The table grew from about 105 000 to 236 000 rows during the run. The load test reuses 15 sample emails, so a few
    domains collect all the rows; real traffic spreads over more domains, but a busy one would grow the same way.
  - Locally, `EXPLAIN ANALYZE` of that count on 150 000 rows of one domain read every page of the table (30 ms). The
    pages read grow in step with the rows.
- **Scale-out test after the fix** (2026-11-07, 10 minutes at 50 concurrent requests). The policy and the throughput
  both worked:
  - the alarm fired after 1.5 minutes: the load steps just before had already pushed the per-target count over the
    target;
  - the policy asked for 5 instances (2 × about 9000 / 4400) and got the maximum of 4; both new instances were healthy
    about 2 minutes later;
  - throughput rose with the instances: 281-302 requests/s on 2 instances, 268-437 on 4. On the client, p50 fell from
    158 to 110 ms; on the server, from 42 to 23 ms;
  - RDS CPU went from 21-25 % to 32-44 %, and no request failed;
  - scale-in went one instance at a time: 4 → 3 seventeen minutes after the load, 3 → 2 about five minutes later. The
    stopped instances shut down cleanly in 0.4 s, and the full `terraform plan` afterwards had no changes.

  During the run, requests stalled together. About every 70 seconds every connection stopped for 2-14 s, and the
  slow requests on every instance ended in the same second. Throughput swung between 268 and 437 requests/s and client
  p99 reached 1 s; no request failed. The diagnosis below ties the stalls to automatic ANALYZE, not to the number of
  instances.
- **The maximum of 4 instances** stays. The task needs 2, and 2 instances have a large margin: 297 requests/s at 20 %
  RDS CPU.

### Stalls under load: diagnosis (2026-11-07)

A third run with the same load (50 concurrent for 10 minutes, the group again went from 2 to 4). On a separate
read-only connection through SSM, `pg_stat_activity` was sampled every 0.5 s. Before and after, `pg_stat_wal` and
`pg_stat_checkpointer` were read, and the checkpoint and autovacuum lines were taken from the RDS log.

**What was observed.**
- Five stalls in 10 minutes, 4-52 s long, the longest request 16 s.
- Three of them came while the group still had 2 instances (16 connections). The number of instances and connections
  isn't the trigger.

**Every stall was an automatic ANALYZE of `scans`.**
- The RDS log logs ANALYZE runs longer than 10 s. Each stall started and ended in the same seconds as one of them:
  5 of 5 in this run and 5 of 5 in the run before.
- Each ANALYZE took 18-52 s but used only 2-5 s of CPU.
- **How often depends on the insert rate.** Autovacuum analyzes a table again after 5 % of its rows have changed
  (`autovacuum_analyze_scale_factor` 0.05, the RDS setting). The load test inserts about 300 rows a second, so here
  ANALYZE ran every 1-2 minutes. That's a property of the synthetic load: a real mail flow changes the table far more
  slowly, so ANALYZE would be rare.

**What the database showed during a stall.**
- The sampler's own query didn't return for 8-23 s.
- Around that gap, the app's connections were `active` with no wait event, next to an active autovacuum worker.
- No row or table lock waits; once, a single session briefly waited to extend the table (`Lock/extend`). WAL waits
  (`WALWrite`, `WalSync`) were as rare as outside the stalls.

**Ruled out.**
- **Locks:** no row or table lock waits.
- **WAL and checkpoints:**
  - 117 MB of WAL in 14 minutes, 2.8 % of it full-page images;
  - 2 timed checkpoints and no requested ones;
  - WAL fsync took 1.0 ms on average;
  - checkpoints don't line up with the stalls.
- **Disk:** latency about 1 ms, queue at most 0.4.
- **Also normal:** CPU credits and Valkey.
- **The app:** the database stopped answering a separate session too, for all instances at once.

**Not proven: why one ANALYZE stops everything.** The working hypothesis is memory.
- The instance has 1 GiB, about 90 MB free and 85-133 MB in swap.
- ANALYZE holds a sample of 30 000 rows in memory, the jsonb `signals` included.
- Its high system CPU time fits page reclaim, which PostgreSQL doesn't report as a wait event.
- Against it: `SwapUsage` didn't rise at each stall. That metric shows swap in use, not paging.

**How to check.** Turn on Enhanced Monitoring (OS memory, swap in and out per second, the process list) or Database
Insights (wait events and CPU over time), then run the same test.

**What next, in order (none of it implemented or tested):**
1. Turn off or lower the statistics for `signals` and `email_sha256`: no query filters on them.
2. Give `scans` its own autoanalyze threshold, so a steady insert rate doesn't analyze it every minute or two.
3. Turn on Enhanced Monitoring and repeat the same test, to confirm the mechanism.
4. A retention period for scans, or monthly partitions: a smaller table makes each ANALYZE cheaper.
5. A larger database class.

### The history query (D-112, D-113)

**How it was found.** In the first scale-out test, a third instance made things worse: throughput fell from 231 to
145 requests/s while RDS CPU reached 98 %. The history check counted the earlier trusted phishing verdicts of the
sender domain, and `EXPLAIN` showed the count reading every phishing row of that domain, so each scan got slower as the
table grew.

**What changed.**
- The poisoning rule is a column PostgreSQL computes itself:
  `trusted boolean GENERATED ALWAYS AS (signals @> '[{"id":"auth.dmarc_pass"}]' OR signals @> '[{"id":"sender.lookalike_domain"}]') STORED`.
  Every writer fills it, also the previous app version during a rollout.
- One partial index holds only the rows the check can count.
- The check reads at most 5 of them and never the table (an index-only scan). It only needs to know that some exist,
  and the cache mark already held 5.

| Query | Index | Why |
|---|---|---|
| History check: `WHERE sender_domain = $1 AND verdict = 'phishing' AND trusted AND email_sha256 <> $2 ORDER BY email_sha256 LIMIT 5` | `scans_trusted_flag_shas`: `(sender_domain, email_sha256) WHERE verdict = 'phishing' AND trusted` | At most 5 index entries, whatever the table size. The query repeats the index's condition word for word, so the planner can use it, and only this index returns rows in that order (see the lesson below). |
| Latest scans (`/api/history`): `ORDER BY id DESC LIMIT n` | the primary key, read backwards | No extra index needed. |
| Insert a scan | the primary key; the partial index only for a trusted phishing row | The old `(sender_domain, verdict)` index took an entry for every row. Nothing but the old count used it (`EXPLAIN` and `pg_stat_user_indexes`), so it is dropped. |

**Why writes got cheaper.** Most inserts now update one index instead of two; only trusted phishing rows touch the
partial index. Its entries are larger, though: each carries the SHA-256 and can't be deduplicated. In the synthetic
benchmark, with 10 % trusted phishing rows, the new index is 20 MB against 10 MB for the old one at 1.5 million rows.
On RDS it is 3.1 MB for about 258 000 rows. Insert time wasn't measured.

**Why it matters for campaigns.** A campaign is one hot domain: thousands of phishing scans from the same sender within
hours. That was the worst case for the old count, which read all of them on every scan. Now a hot domain costs the
same as a quiet one: the first 5 entries end the lookup. A spoofed domain (phishing but never trusted) has no entries
at all.

**Measured locally** (`scripts/history_query_bench.py`, PostgreSQL 18 in Docker, rows shaped like the load test;
server execution time, median of 25):

| Rows | Domain | Before | After |
|---|---|---|---|
| 150 000 | hot (lookalike campaign) | 8.3 ms, 3963 pages | 0.012 ms, 4 pages |
| 150 000 | spoofed | 8.3 ms, 3963 pages | 0.009 ms, 3 pages |
| 1 500 000 | hot (lookalike campaign) | 125 ms, 39 606 pages | 0.012 ms, 7 pages |
| 1 500 000 | spoofed | 123 ms, 39 606 pages | 0.009 ms, 3 pages |

A quiet domain takes about 0.01 ms both ways.

**On RDS** (`EXPLAIN (ANALYZE, BUFFERS)` run read-only in the app container through SSM, about 258 000 rows):
- an index-only scan of `scans_trusted_flag_shas` for a hot, a trusted (legitimate, DMARC pass), a spoofed and a
  never-seen domain;
- 0.02-0.13 ms, 3-8 pages each;
- that held with no page marked all-visible yet (`relallvisible` 0 of 12 274 pages).

**A lesson about the planner.** The first version of the query (`... LIMIT 5`, no `ORDER BY`, index
`(sender_domain) INCLUDE (email_sha256)`) passed its local plan test and was 0.01 ms in the benchmark. On RDS it made
things worse: 71-82 requests/s at 98 % RDS CPU.
- **On RDS it ran as a sequential scan.** The planner treats the domain, the verdict and `trusted` as independent.
  Legitimate mail passes DMARC, so `trusted` is common, and phishing is common in the load test, so it expected about
  9000 matches for a domain that had none. With `LIMIT 5`, a sequential scan that stops after 5 rows looked cheap. For a
  domain with no flags it read the whole table, 16-17 ms each time.
- **Why the local test missed it.** Its data was unrepresentative: the quiet domains' mail didn't pass DMARC. It also
  ran `VACUUM ANALYZE` before `EXPLAIN`. VACUUM marks pages all-visible, which makes the index-only scan look cheap.
  After the migration rewrote the table on RDS, no page was all-visible.
- **What didn't help.** `ANALYZE` alone didn't change the plan. Extended statistics fixed the estimate for domains
  without flags, but then a hot campaign domain got the sequential scan; its rows are the newest, at the end of the
  table. `ORDER BY id DESC` let the planner walk the primary key backwards instead, with the same result.
- **The fix is the query's shape.** `email_sha256` is in the index key and the query orders by it. Only this index
  returns rows in that order, so it is the only plan that can stop after 5 rows. Any other plan has to read and sort
  every match. This holds whatever the statistics say: it was checked with and without `ANALYZE`, with an empty
  visibility map and for the generic plan of a prepared statement.
- **The plan test now** uses rows shaped like production (legitimate mail passes DMARC, the campaign comes last) and
  doesn't VACUUM. On the first version of the query it fails (sequential scan); on the current one it passes.

**The migration** runs at every start of every instance (`webapp/storage.py`, `migrate`):
- Each step runs only when needed.
- The instances take turns under an advisory lock. The lock is polled with `pg_try_advisory_lock`: a session blocked in
  `pg_advisory_lock` made a concurrent `CREATE INDEX CONCURRENTLY` fail with "deadlock detected" in a local test.
- An index left invalid by an interrupted build is dropped and built again.
- After building the index it runs `ANALYZE scans`, so the new column has statistics at once.
- **Adding the generated column rewrites the table under an exclusive lock.** On RDS, with about 250 000 rows, the
  whole first migration took 5.5 s. The slowest request in those seconds waited 1.9 s, and none failed. The migration
  gives up after 5 s of waiting for the lock rather than queue the app behind it. On a large table you'd instead add a
  plain column, fill it in batches, then switch the queries.
- **The index is built with `CONCURRENTLY`**, so writes continue. The second migration (new index, `ANALYZE`, drop the
  first partial index) took 2.3 s on RDS.
- **During the refresh**, the instances still on the old version count without an index (a full scan) until they are
  replaced.
- **A rollback to that version** builds the old index again at its start (a short write lock), and the next
  roll-forward drops it.

**Next steps:** a retention policy for scans (the check only needs recent history), or monthly partitions so old scans
are dropped a partition at a time. Beyond that, a larger database class.

## Screenshots

Taken on 2026-11-07 in the deployed stack; account numbers and ARNs are blurred.

- [`01-ui-scan-result.png`](docs/screenshots/01-ui-scan-result.png): The web UI through CloudFront: verdict, score and indicators of a synthetic phishing sample (links defanged, nothing clickable).
- [`02-basic-auth-prompt.png`](docs/screenshots/02-basic-auth-prompt.png): Basic auth in front of everything except `/healthz`.
- [`03-dashboard.png`](docs/screenshots/03-dashboard.png): Dashboard `phishdet-overview` around the drill: one unhealthy target, replacement, two healthy again.
- [`04-dashboard-latest-events.png`](docs/screenshots/04-dashboard-latest-events.png): The dashboard's latest-events table: app JSON lines; the bracketed lines are the previous version's gunicorn stop messages, from before gunicorn logged JSON.
- [`05-targets-unhealthy.png`](docs/screenshots/05-targets-unhealthy.png): Target group during the drill: one target unhealthy 21 s after the service stopped, the old one draining.
- [`05b-targets-healthy-after.png`](docs/screenshots/05b-targets-healthy-after.png): After the drill: both targets healthy.
- [`06-alarm-unhealthy-hosts.png`](docs/screenshots/06-alarm-unhealthy-hosts.png): Alarm `phishdet-unhealthy-hosts` and its history: OK → ALARM → OK, each "Successfully executed action".
- [`07-alarm-mails.png`](docs/screenshots/07-alarm-mails.png): The ALARM and OK e-mails (address hidden).
- [`08-asg-activity.png`](docs/screenshots/08-asg-activity.png): Auto Scaling activity: the failed instance terminated and a replacement launched within 48 s.
- [`09-asg-instance-refresh.png`](docs/screenshots/09-asg-instance-refresh.png): Instance refresh history: rollout, rollback and rollout again, each without failed requests.
- [`10-logs-insights-scans-by-verdict.png`](docs/screenshots/10-logs-insights-scans-by-verdict.png): Saved Logs Insights query `phishdet/scans-by-verdict`. The counts are smoke tests and the drill and rollout watches on the synthetic samples, not real traffic.
- [`11-ecr-scan.png`](docs/screenshots/11-ecr-scan.png): ECR scan of an image on the current base: 0 critical, 4 high (glibc, zlib; no fixed Debian package yet).
- [`12-log-groups.png`](docs/screenshots/12-log-groups.png): Where the logs are: five log groups, kept 7 days, four metric filters on the app log.

## Next steps

_What would come next with more time._

- Detector, beyond static rules:
  - URL reputation for links that no rule flags ([Google Safe Browsing](https://developers.google.com/safe-browsing),
    [URLhaus](https://urlhaus.abuse.ch/)), sending only the URL, never the email;
  - domain age from [RDAP](https://about.rdap.org/): phishing domains are often days old;
  - resolve Mimecast-protected links (opaque token, needs Mimecast's API) to check their real target;
  - machine learning on modern labelled data (phishing and legitimate mail of the same era, with headers),
    starting with logistic regression over these same rules so each rule keeps one readable weight.

- A NAT gateway in each Availability Zone, each app subnet routed to the one in its own zone
  (about $1.22 per day per extra NAT gateway with its public IPv4 address).
- Multi-AZ RDS (a standby in the second zone; db.t4g.micro goes from $0.016 to $0.033 per hour)
  and a Valkey replica in the second zone with automatic failover (one more cache.t4g.micro node, $0.016 per hour).
- A customer-managed KMS key for ECR, CloudWatch Logs, Secrets Manager, ElastiCache and the alarm topic (about $1 per month);
  it would close the KMS-related scanner findings listed under Security.
- A custom domain: an ACM certificate on CloudFront (TLS 1.2+ minimum) and HTTPS between CloudFront and the ALB,
  or a CloudFront VPC origin so the ALB can be internal. Optionally a secret origin header checked by the ALB, so only this distribution
  (not any CloudFront distribution) can reach it.
- AWS WAF on CloudFront (rate limiting, managed rule groups).
- ElastiCache IAM authentication for Valkey, so the app connects with its instance role instead of relying on network access alone.
