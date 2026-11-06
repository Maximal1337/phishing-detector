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

### Tests

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt      # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest -q
```

These commands were run on Linux (a `python:3.13.17-slim` container) and on Windows; CI runs them on
`ubuntu-latest` for every push. On macOS, use the Linux commands.

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

## Invoke

_Using the web UI and the HTTP API on the deployed stack._

## Monitor

_Dashboard, alarms, where the application logs are, and how to check instance health, CPU and memory, request counts and errors._

## Tear down

_`terraform destroy` order and the CLI checks that confirm nothing is left._

## Cost

_What each resource costs per day and the total for the test period._

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
- Dependencies are pinned to exact versions, and each pinned version had been public for at least 7 days when it was pinned,
  so a broken or compromised release has time to be noticed and yanked before it reaches the image.
  Transitive dependencies other than botocore are not pinned and resolve at install time.
  The 7-day rule is for third-party packages and tools. The Docker base image (`python:3.13.17-slim`, pinned by digest)
  is decided by the ECR vulnerability scan instead: if a newer `python:3.13-slim` fixes HIGH or CRITICAL findings,
  the image moves to it (again pinned by digest) without waiting.

### Scanner findings that are not fixed

`terraform fmt`, `terraform validate`, tflint (with the AWS ruleset) and checkov run before every apply.
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
