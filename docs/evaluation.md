# Evaluation on public corpora

How well the rule-based detector separates real phishing from legitimate mail, measured on public data.
Everything below is aggregate output of `scripts/evaluate.py`; no message text, address or subject is included.
How to reproduce it: README, section "Evaluation".

## Summary (test split, run once after tuning)

379 phishing and 1250 legitimate messages that were never looked at while tuning.

| Signals counted | Flagged as phishing (score ≥ 50) | Flagged suspicious or worse (score ≥ 25) |
|---|---|---|
| all signals | precision 0.980, recall 0.261, false positives 0.2 % | precision 0.948, recall 0.485, false positives 0.8 % |
| without era signals | precision 0.976, recall 0.219, false positives 0.2 % | precision 0.942, recall 0.430, false positives 0.8 % |

- **What it means:** when the detector says "phishing", it is almost always right (2 of 1250 legitimate mails),
  but it catches only a fifth to a quarter of real phishing at that level, and a little under half at "suspicious".
- **Where it misses:** on dev, 292 of the 748 phishing mails missed at ≥ 50 (39 %) have no indicator at all, although
  97 % of them contain links and 99 % HTML: they link to domains the rules don't consider suspicious and use no tell-tale
  wording. This is the honest limit of static rules without URL reputation.
- **The era bias is real:** 99.9 % of the phishing carries an `Authentication-Results` header, the 2002 ham none.
  Counting the era signals adds 4-6 points of recall (0.261 vs 0.219 at ≥ 50, 0.485 vs 0.430 at ≥ 25) that wouldn't
  hold on modern legitimate mail, which is why the "without era signals" row is the one to trust.

## Data

| Class | Source | Files | Messages | License |
|---|---|---|---|---|
| phishing | [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | `phishing-2023`, `phishing-2024`, `phishing-2025` | 1303 | CC BY 4.0, by Jose Nazario |
| legitimate | [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) | `20030228_easy_ham`, `20030228_easy_ham_2`, `20030228_hard_ham` | 4150 | no formal license; "Copyright for the text in the messages remains with the original senders" |

The files are fetched by `scripts/fetch_datasets.py` and checked against pinned SHA-256 values (recorded on the first
download, 2026-11-06; the sources publish no checksums). They are never committed; they live only in a Docker volume.

## Method

- **Split.** Each message's SHA-256 decides once whether it is in dev (70 %) or test (30 %).
  Weights were tuned on dev only; test was run once, with the final weights.
- **Era signals.** The legitimate mail is from 2002-2003, the phishing from 2023-2025. Signals that tell the eras apart
  rather than phishing from legitimate mail don't take part in tuning and keep their hand-set weights:
  all `auth.*` (no mail server added Authentication-Results in 2002), punycode (internationalised domains started in 2003),
  often-abused TLDs (mostly created after 2014) and URL shorteners (mostly after 2008). The list was written before looking at the data.
- **Tuning rule.** For each other signal with at least 10 hits on dev:
  weight = k x ln(rate in phishing / rate in legitimate mail), with add-one smoothing, rounded to 5, within 0-40.
  The single parameter k was picked on dev (k = 10): the best F1 at the phishing threshold while at most 1 % of legitimate mail
  is flagged phishing and at most 2 % suspicious or worse, measured without era signals.
  The second limit was added after a first run had picked k = 12, where one urgent word alone made a mail suspicious (5.4 % of dev ham).
- **Signals that point the wrong way here.** `sender.return_path_mismatch` (69 % of legitimate vs 12 % of phishing),
  `sender.reply_to_mismatch` (18 % vs 9 %) and `wording.prize` (0.9 % vs 0.3 %) are commoner in the legitimate mail,
  most of which is mailing-list traffic; their weights became 0. They still show up in a result, as information.

## Before and after tuning (dev split)

Hand-set weights (before):

| Signals | Flagged at | Precision | Recall | F1 | False-positive rate | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| all signals | phishing or suspicious (≥ 25) | 0.839 | 0.361 | 0.505 | 0.022 | 334 | 64 | 590 | 2836 |
| without auth.* | phishing (≥ 50) | 0.944 | 0.055 | 0.104 | 0.001 | 51 | 3 | 873 | 2897 |
| without auth.* | phishing or suspicious (≥ 25) | 0.828 | 0.333 | 0.475 | 0.022 | 308 | 64 | 616 | 2836 |
| without era signals | phishing (≥ 50) | 0.939 | 0.050 | 0.095 | 0.001 | 46 | 3 | 878 | 2897 |
| without era signals | phishing or suspicious (≥ 25) | 0.815 | 0.291 | 0.429 | 0.021 | 269 | 61 | 655 | 2839 |

Tuned weights (after): see the dev report in the appendix.

## Caveats

- The legitimate mail is old and mostly personal and mailing-list mail. Modern transactional mail from banks and shops
  ("Dear customer", "update your payment details", password resets) is barely represented, so the tuned wording weights
  (40 for credentials, payment and generic greeting) are probably too high for it: expect more false positives there than measured here.
- Nazario's corpus is one person's inbox, hand-classified ("it could contain errors"), so it is representative, not exhaustive.
- 1303 phishing messages are enough for the frequent signals; rare ones (executables, macros, password fields) had too few hits to tune and keep their hand-set weights.

## Appendix A: test report
## Evaluation report (test split)

### Data

| Corpus | File | Class | SHA-256 | dev | test |
|---|---|---|---|---|---|
| nazario | phishing-2023 | phishing | `5007f1c1dc91b15e93e988afa3a1cf402e15c88f765d3057be8bfec50dae1fe8` | 288 | 131 |
| nazario | phishing-2024 | phishing | `60afa40a2757170093a2bde31ec9cda4e54d33992203ce04bfbbc86d2e5e5b99` | 295 | 108 |
| nazario | phishing-2025 | phishing | `f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f` | 341 | 140 |
| spamassassin | 20030228_easy_ham.tar.bz2 | ham | `2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438` | 1730 | 770 |
| spamassassin | 20030228_easy_ham_2.tar.bz2 | ham | `b4bd3dc5ae5b40f38e99a0e41ad7d16b428b56e818e3a6ffa07330d62004dd38` | 983 | 417 |
| spamassassin | 20030228_hard_ham.tar.bz2 | ham | `ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9` | 187 | 63 |

Messages in this report: 379 phishing, 1250 ham.

### Era check (dev split)

- phishing: 99.9 % have an Authentication-Results header
- ham: 0.0 % have an Authentication-Results header

### What the mails contain (dev split)

| Group | Messages | With an http(s) link | With an HTML part | With an attachment |
|---|---|---|---|---|
| phishing | 924 | 91.0 % | 98.6 % | 12.4 % |
| ham | 2900 | 87.4 % | 4.8 % | 0.6 % |
| phishing with no indicator (era signals aside) | 292 | 96.9 % | 98.6 % | 5.5 % |

### Signal frequencies (dev split)

Era signals don't take part in weight tuning; the reason is in the last column.

| Signal | Weight | Phishing | Ham | Era signal |
|---|---|---|---|---|
| `attach.archive` | 10 | 4 (0.4 %) | 0 (0.0 %) |  |
| `attach.double_extension` | 35 | 2 (0.2 %) | 0 (0.0 %) |  |
| `attach.executable` | 40 | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.html` | 40 | 45 (4.9 %) | 1 (0.0 %) |  |
| `attach.macro_office` | 30 | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.password_hint` | 15 | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.type_mismatch` | 25 | 0 (0.0 %) | 0 (0.0 %) |  |
| `auth.dkim_fail` | 10 | 14 (1.5 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.dmarc_fail` | 25 | 16 (1.7 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.dmarc_pass` | 0 | 472 (51.1 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.spf_fail` | 15 | 42 (4.5 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.spf_softfail` | 5 | 102 (11.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `history.domain_flagged` | 20 | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.brand_in_subdomain` | 30 | 3 (0.3 %) | 0 (0.0 %) |  |
| `links.ip_host` | 30 | 1 (0.1 %) | 4 (0.1 %) |  |
| `links.lookalike_domain` | 25 | 35 (3.8 %) | 8 (0.3 %) |  |
| `links.nonstandard_port` | 5 | 3 (0.3 %) | 8 (0.3 %) |  |
| `links.password_form` | 35 | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.punycode` | 20 | 3 (0.3 %) | 0 (0.0 %) | internationalised domain names (punycode) only started in 2003 |
| `links.risky_tld` | 15 | 46 (5.0 %) | 2 (0.1 %) | most of the listed top-level domains (.xyz, .top, .zip, ...) didn't exist before 2014 |
| `links.script_scheme` | 30 | 0 (0.0 %) | 1 (0.0 %) |  |
| `links.shortener` | 10 | 71 (7.7 %) | 3 (0.1 %) | most of the listed URL shorteners (bit.ly, t.co, ...) started after 2008 |
| `links.text_href_mismatch` | 20 | 41 (4.4 %) | 17 (0.6 %) |  |
| `links.userinfo` | 25 | 2 (0.2 %) | 1 (0.0 %) |  |
| `sender.brand_mismatch` | 40 | 71 (7.7 %) | 1 (0.0 %) |  |
| `sender.display_name_address` | 20 | 8 (0.9 %) | 2 (0.1 %) |  |
| `sender.lookalike_domain` | 35 | 5 (0.5 %) | 0 (0.0 %) |  |
| `sender.punycode` | 20 | 1 (0.1 %) | 0 (0.0 %) | internationalised domain names (punycode) only started in 2003 |
| `sender.reply_to_mismatch` | 0 | 80 (8.7 %) | 516 (17.8 %) |  |
| `sender.return_path_mismatch` | 0 | 111 (12.0 %) | 1990 (68.6 %) |  |
| `wording.credentials` | 40 | 104 (11.3 %) | 3 (0.1 %) |  |
| `wording.generic_greeting` | 40 | 94 (10.2 %) | 2 (0.1 %) |  |
| `wording.payment` | 40 | 29 (3.1 %) | 1 (0.0 %) |  |
| `wording.prize` | 0 | 3 (0.3 %) | 26 (0.9 %) |  |
| `wording.threat` | 30 | 99 (10.7 %) | 17 (0.6 %) |  |
| `wording.urgency` | 20 | 272 (29.4 %) | 107 (3.7 %) |  |

### Metrics (test split)

Positive class: phishing. A mail counts as flagged when its score reaches the threshold.

| Signals | Flagged at | Precision | Recall | F1 | False-positive rate | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| all signals | phishing (≥ 50) | 0.980 | 0.261 | 0.413 | 0.002 | 99 | 2 | 280 | 1248 |
| all signals | phishing or suspicious (≥ 25) | 0.948 | 0.485 | 0.642 | 0.008 | 184 | 10 | 195 | 1240 |
| without auth.* | phishing (≥ 50) | 0.979 | 0.251 | 0.399 | 0.002 | 95 | 2 | 284 | 1248 |
| without auth.* | phishing or suspicious (≥ 25) | 0.944 | 0.441 | 0.601 | 0.008 | 167 | 10 | 212 | 1240 |
| without era signals | phishing (≥ 50) | 0.976 | 0.219 | 0.358 | 0.002 | 83 | 2 | 296 | 1248 |
| without era signals | phishing or suspicious (≥ 25) | 0.942 | 0.430 | 0.591 | 0.008 | 163 | 10 | 216 | 1240 |

### Score distribution (test split, without era signals)

| Score | Phishing | Ham |
|---|---|---|
| 0-0 | 148 | 1201 |
| 1-24 | 68 | 39 |
| 25-49 | 80 | 8 |
| 50-100 | 83 | 2 |

### Most common indicator sets among errors (test split, without era signals, flagged at ≥ 50)

**False positives (ham flagged):**

- 1 x links.ip_host, links.text_href_mismatch
- 1 x wording.credentials, wording.urgency

**False negatives (phishing missed):**

- 117 x (no indicators)
- 44 x wording.urgency
- 20 x sender.return_path_mismatch
- 12 x wording.credentials
- 11 x links.text_href_mismatch
- 11 x wording.threat
- 10 x sender.brand_mismatch
- 10 x attach.html


## Appendix B: dev report (final weights, with the tuning table)
## Evaluation report (dev split)

### Data

| Corpus | File | Class | SHA-256 | dev | test |
|---|---|---|---|---|---|
| nazario | phishing-2023 | phishing | `5007f1c1dc91b15e93e988afa3a1cf402e15c88f765d3057be8bfec50dae1fe8` | 288 | 131 |
| nazario | phishing-2024 | phishing | `60afa40a2757170093a2bde31ec9cda4e54d33992203ce04bfbbc86d2e5e5b99` | 295 | 108 |
| nazario | phishing-2025 | phishing | `f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f` | 341 | 140 |
| spamassassin | 20030228_easy_ham.tar.bz2 | ham | `2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438` | 1730 | 770 |
| spamassassin | 20030228_easy_ham_2.tar.bz2 | ham | `b4bd3dc5ae5b40f38e99a0e41ad7d16b428b56e818e3a6ffa07330d62004dd38` | 983 | 417 |
| spamassassin | 20030228_hard_ham.tar.bz2 | ham | `ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9` | 187 | 63 |

Messages in this report: 924 phishing, 2900 ham.

### Era check (dev split)

- phishing: 99.9 % have an Authentication-Results header
- ham: 0.0 % have an Authentication-Results header

### What the mails contain (dev split)

| Group | Messages | With an http(s) link | With an HTML part | With an attachment |
|---|---|---|---|---|
| phishing | 924 | 91.0 % | 98.6 % | 12.4 % |
| ham | 2900 | 87.4 % | 4.8 % | 0.6 % |
| phishing with no indicator (era signals aside) | 292 | 96.9 % | 98.6 % | 5.5 % |

### Signal frequencies (dev split)

Era signals don't take part in weight tuning; the reason is in the last column.

| Signal | Weight | Phishing | Ham | Era signal |
|---|---|---|---|---|
| `attach.archive` | 10 | 4 (0.4 %) | 0 (0.0 %) |  |
| `attach.double_extension` | 35 | 2 (0.2 %) | 0 (0.0 %) |  |
| `attach.executable` | 40 | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.html` | 40 | 45 (4.9 %) | 1 (0.0 %) |  |
| `attach.macro_office` | 30 | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.password_hint` | 15 | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.type_mismatch` | 25 | 0 (0.0 %) | 0 (0.0 %) |  |
| `auth.dkim_fail` | 10 | 14 (1.5 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.dmarc_fail` | 25 | 16 (1.7 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.dmarc_pass` | 0 | 472 (51.1 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.spf_fail` | 15 | 42 (4.5 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.spf_softfail` | 5 | 102 (11.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `history.domain_flagged` | 20 | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.brand_in_subdomain` | 30 | 3 (0.3 %) | 0 (0.0 %) |  |
| `links.ip_host` | 30 | 1 (0.1 %) | 4 (0.1 %) |  |
| `links.lookalike_domain` | 25 | 35 (3.8 %) | 8 (0.3 %) |  |
| `links.nonstandard_port` | 5 | 3 (0.3 %) | 8 (0.3 %) |  |
| `links.password_form` | 35 | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.punycode` | 20 | 3 (0.3 %) | 0 (0.0 %) | internationalised domain names (punycode) only started in 2003 |
| `links.risky_tld` | 15 | 46 (5.0 %) | 2 (0.1 %) | most of the listed top-level domains (.xyz, .top, .zip, ...) didn't exist before 2014 |
| `links.script_scheme` | 30 | 0 (0.0 %) | 1 (0.0 %) |  |
| `links.shortener` | 10 | 71 (7.7 %) | 3 (0.1 %) | most of the listed URL shorteners (bit.ly, t.co, ...) started after 2008 |
| `links.text_href_mismatch` | 20 | 41 (4.4 %) | 17 (0.6 %) |  |
| `links.userinfo` | 25 | 2 (0.2 %) | 1 (0.0 %) |  |
| `sender.brand_mismatch` | 40 | 71 (7.7 %) | 1 (0.0 %) |  |
| `sender.display_name_address` | 20 | 8 (0.9 %) | 2 (0.1 %) |  |
| `sender.lookalike_domain` | 35 | 5 (0.5 %) | 0 (0.0 %) |  |
| `sender.punycode` | 20 | 1 (0.1 %) | 0 (0.0 %) | internationalised domain names (punycode) only started in 2003 |
| `sender.reply_to_mismatch` | 0 | 80 (8.7 %) | 516 (17.8 %) |  |
| `sender.return_path_mismatch` | 0 | 111 (12.0 %) | 1990 (68.6 %) |  |
| `wording.credentials` | 40 | 104 (11.3 %) | 3 (0.1 %) |  |
| `wording.generic_greeting` | 40 | 94 (10.2 %) | 2 (0.1 %) |  |
| `wording.payment` | 40 | 29 (3.1 %) | 1 (0.0 %) |  |
| `wording.prize` | 0 | 3 (0.3 %) | 26 (0.9 %) |  |
| `wording.threat` | 30 | 99 (10.7 %) | 17 (0.6 %) |  |
| `wording.urgency` | 20 | 272 (29.4 %) | 107 (3.7 %) |  |

### Metrics (dev split)

Positive class: phishing. A mail counts as flagged when its score reaches the threshold.

| Signals | Flagged at | Precision | Recall | F1 | False-positive rate | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| all signals | phishing (≥ 50) | 0.995 | 0.231 | 0.374 | 0.000 | 213 | 1 | 711 | 2899 |
| all signals | phishing or suspicious (≥ 25) | 0.909 | 0.463 | 0.614 | 0.015 | 428 | 43 | 496 | 2857 |
| without auth.* | phishing (≥ 50) | 0.995 | 0.216 | 0.356 | 0.000 | 200 | 1 | 724 | 2899 |
| without auth.* | phishing or suspicious (≥ 25) | 0.902 | 0.431 | 0.583 | 0.015 | 398 | 43 | 526 | 2857 |
| without era signals | phishing (≥ 50) | 0.994 | 0.190 | 0.320 | 0.000 | 176 | 1 | 748 | 2899 |
| without era signals | phishing or suspicious (≥ 25) | 0.899 | 0.412 | 0.565 | 0.015 | 381 | 43 | 543 | 2857 |

### Score distribution (dev split, without era signals)

| Score | Phishing | Ham |
|---|---|---|
| 0-0 | 350 | 2738 |
| 1-24 | 193 | 119 |
| 25-49 | 205 | 42 |
| 50-100 | 176 | 1 |

### Most common indicator sets among errors (dev split, without era signals, flagged at ≥ 50)

**False positives (ham flagged):**

- 1 x sender.return_path_mismatch, wording.credentials, wording.payment, wording.urgency

**False negatives (phishing missed):**

- 292 x (no indicators)
- 126 x wording.urgency
- 31 x sender.return_path_mismatch
- 31 x wording.threat
- 26 x attach.html
- 25 x wording.credentials
- 25 x wording.generic_greeting
- 25 x sender.return_path_mismatch, wording.urgency

### Weight tuning (dev split only)

weight = k x ln(rate in phishing / rate in ham), add-one smoothing, rounded to 5, within 0..40.
Tuned: signals without era bias that fire at least 10 times on dev; all others keep their current weight.
k is picked for the best F1 at the phishing threshold (≥ 50) with at most 1% of ham flagged phishing and at most 2% flagged suspicious or worse (≥ 25), measured without era signals.

| k | Precision (≥ 50) | Recall (≥ 50) | F1 (≥ 50) | FP rate (≥ 50) | Recall (≥ 25) | FP rate (≥ 25) |
|---|---|---|---|---|---|---|
| 4 | 1.000 | 0.034 | 0.065 | 0.000 | 0.168 | 0.002 |
| 5 | 0.977 | 0.047 | 0.089 | 0.000 | 0.268 | 0.004 |
| 6 | 0.988 | 0.089 | 0.163 | 0.000 | 0.342 | 0.006 |
| 7 | 0.991 | 0.114 | 0.204 | 0.000 | 0.347 | 0.006 |
| 8 | 0.993 | 0.163 | 0.281 | 0.000 | 0.394 | 0.012 |
| 9 | 0.994 | 0.168 | 0.287 | 0.000 | 0.412 | 0.015 |
| 10 (picked) | 0.994 | 0.190 | 0.320 | 0.000 | 0.412 | 0.015 |
| 11 | 0.979 | 0.201 | 0.334 | 0.001 | 0.595 | 0.049 |
| 12 | 0.969 | 0.206 | 0.339 | 0.002 | 0.618 | 0.054 |
| 13 | 0.969 | 0.206 | 0.339 | 0.002 | 0.618 | 0.054 |
| 14 | 0.969 | 0.206 | 0.339 | 0.002 | 0.618 | 0.054 |
| 15 | 0.969 | 0.206 | 0.339 | 0.002 | 0.618 | 0.054 |
| 16 | 0.969 | 0.206 | 0.339 | 0.002 | 0.618 | 0.054 |

| Signal | Phishing hits | Ham hits | ln ratio | Current weight | Suggested (k = 10) |
|---|---|---|---|---|---|
| `attach.html` | 45 | 1 | +4.28 | 40 | 40 |
| `links.lookalike_domain` | 35 | 8 | +2.53 | 25 | 25 |
| `links.nonstandard_port` | 3 | 8 | +0.33 | 5 | 5 |
| `links.text_href_mismatch` | 41 | 17 | +1.99 | 20 | 20 |
| `sender.brand_mismatch` | 71 | 1 | +4.73 | 40 | 40 |
| `sender.display_name_address` | 8 | 2 | +2.24 | 20 | 20 |
| `sender.reply_to_mismatch` | 80 | 516 | -0.71 | 0 | 0 |
| `sender.return_path_mismatch` | 111 | 1990 | -1.74 | 0 | 0 |
| `wording.credentials` | 104 | 3 | +4.41 | 40 | 40 |
| `wording.generic_greeting` | 94 | 2 | +4.60 | 40 | 40 |
| `wording.payment` | 29 | 1 | +3.85 | 40 | 40 |
| `wording.prize` | 3 | 26 | -0.77 | 0 | 0 |
| `wording.threat` | 99 | 17 | +2.86 | 30 | 30 |
| `wording.urgency` | 272 | 107 | +2.07 | 20 | 20 |

