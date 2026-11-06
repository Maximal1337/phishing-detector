# Evaluation on public corpora

How well the rule-based detector separates real phishing from legitimate mail, measured on public data.
Everything below is aggregate output of `scripts/evaluate.py`; no message text, address or subject is included.
How to reproduce it: README, section "Evaluation".

## Summary: two test runs

The test split (30 % of every corpus, chosen by each message's SHA-256) was run twice, each time once, after tuning on dev.

| Signals counted | Flagged at | Test run 1 (k = 10) | Test run 2 (9 new signals, k = 6) |
|---|---|---|---|
| without era signals | phishing (≥ 50) | precision 0.976, recall 0.219, ham-2002 FP 0.2 % | precision 0.987, recall 0.206, ham-2002 FP 0.1 %, ham-2024 FP 0.0 % |
| without era signals | suspicious or worse (≥ 25) | precision 0.942, recall 0.430, ham-2002 FP 0.8 % | precision 0.918, recall **0.559**, ham-2002 FP 1.5 %, ham-2024 FP 1.0 % |
| all signals | phishing (≥ 50) | precision 0.980, recall 0.261, ham-2002 FP 0.2 % | precision 0.994, recall 0.404, ham-2002 FP 0.1 %, ham-2024 FP 0.0 % |
| all signals | suspicious or worse (≥ 25) | precision 0.948, recall 0.485, ham-2002 FP 0.8 % | precision 0.935, recall **0.760**, ham-2002 FP 1.6 %, ham-2024 FP 1.4 % |

Test run 2: 379 phishing, 1250 ham-2002 and 868 ham-2024 messages. Precision is computed against ham-2002 (the tuning set);
the ham-2024 column is the share of that set flagged.

- **What changed between the runs.** Run 1 showed that most missed phishing had no indicator at all. Iteration 2 added
  link and HTML signals that modern phishing kits leave (the recipient's address in a link, free hosting and form services,
  redirect parameters, "sign in / verify / open document" buttons, hidden text, zero-width characters, image-only mails),
  re-ran the same tuning rule (it picked k = 6) and added a modern legitimate set, ham-2024.
- **Honest note.** Iteration 2 was designed after reading run 1's aggregate test numbers, and all changes were then made
  and measured on dev only. Run 2 is therefore a second look at the same test split, not a fresh one; dev and test agree
  closely (dev at ≥ 25 without era signals: recall 0.560, ham-2002 FP 1.8 %, ham-2024 FP 1.2 %).
- **What it means.** At "suspicious" the detector now catches more than half of real phishing even without the era-biased
  signals, and three quarters with them, while flagging 1-1.6 % of legitimate mail. At "phishing" it stays very precise
  (one legitimate mail of 2118) but catches only a fifth to two fifths.
- **Where it still misses.** On dev, 73 of the 768 phishing mails missed at ≥ 50 have no indicator at all (run 1: 292 of 748);
  most others carry one or two weak signals. URL reputation and domain age would be the next step (README, "Next steps").

## Data

| Class | Set | Source | Files | Messages | License |
|---|---|---|---|---|---|
| phishing | phishing | [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | `phishing-2023`, `phishing-2024`, `phishing-2025` | 1303 | CC BY 4.0, by Jose Nazario |
| legitimate | ham-2002 | [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) | `20030228_easy_ham`, `20030228_easy_ham_2`, `20030228_hard_ham` | 4150 | no formal license; "Copyright for the text in the messages remains with the original senders" |
| legitimate | ham-2024 | [users@tomcat.apache.org archive](https://lists.apache.org/list.html?users@tomcat.apache.org) | 22 monthly mbox files, 2024-01 to 2025-10 | 2843 | public archive under the [Apache public forum archive policy](https://www.apache.org/foundation/public-archives.html); no reuse license, copyright stays with the senders |

The files are fetched by `scripts/fetch_datasets.py` and checked against pinned SHA-256 values (recorded on the first
download, 2026-11-06; the sources publish no checksums). They are never committed; they live only in a Docker volume.
The Apache archive builds each mbox on request, so a later download may differ in bytes; the script then reports the
mismatch and both message counts instead of stopping, and the numbers can differ slightly.

**Two proxies, each with its own bias.** There is no public corpus of modern personal and transactional mail with full
headers. ham-2002 is personal and mailing-list mail from 2002-2003 (no Authentication-Results, little HTML); ham-2024 is
a modern technical mailing list (real headers, but plain-text questions and answers, almost no HTML or marketing mail).
Neither looks like a bank's or a shop's mail, so false positives there may be higher than measured.

## Method

- **Split.** Each message's SHA-256 decides once whether it is in dev (70 %) or test (30 %), in every set.
  Weights were tuned on dev only; each test run used the final weights of its iteration.
- **Era signals.** The phishing is from 2023-2025 and ham-2002 is from 2002-2003. Signals that tell the eras apart
  rather than phishing from legitimate mail don't take part in tuning and keep hand-set weights: all `auth.*`
  (no mail server added Authentication-Results in 2002), punycode, often-abused TLDs, URL shorteners, and from
  iteration 2 free hosting services, redirect parameters, call-to-action buttons and the HTML-only signals
  (ham-2002 has almost no HTML). The iteration-2 ones are all below 25, so none makes a mail suspicious alone.
  The lists were written before looking at the data.
- **Tuning rule.** For each other signal with at least 10 hits on dev:
  weight = k x ln(rate in phishing / rate in ham-2002), with add-one smoothing, rounded to 5, within 0-40.
  The single parameter k was picked on dev: the best F1 at the phishing threshold while at most 1 % of ham-2002 is flagged
  phishing and at most 2 % suspicious or worse, measured without era signals. Run 1 picked k = 10; with the new signals
  the same rule picked k = 6 (at k = 7 `links.recipient_in_url` alone would reach 25 and flag 2.7 % of ham-2002).
- **ham-2024 is not used for tuning.** It is reported separately. Its dev part was used to check the new signals:
  any signal or combination that flagged more than 2 % of it would be narrowed or lowered. Two were narrowed
  (see below); no weight was changed.
- **Signals that point the wrong way here.** `sender.return_path_mismatch`, `sender.reply_to_mismatch` and
  `wording.prize` are commoner in the legitimate mail, most of which is mailing-list traffic; their weights are 0.
  They still show up in a result, as information.

## Iteration 2 on dev

| Signals | Flagged at | Run 1 weights: recall / ham-2002 FP | Iteration 2: recall / ham-2002 FP / ham-2024 FP |
|---|---|---|---|
| without era signals | phishing (≥ 50) | 0.190 / 0.0 % | 0.169 / 0.0 % / 0.0 % |
| without era signals | suspicious or worse (≥ 25) | 0.412 / 1.5 % | 0.560 / 1.8 % / 1.2 % |
| all signals | phishing (≥ 50) | 0.231 / 0.0 % | 0.368 / 0.0 % / 0.0 % |
| all signals | suspicious or worse (≥ 25) | 0.463 / 1.5 % | 0.763 / 1.8 % / 1.3 % |

The lower k costs a little recall at ≥ 50 without era signals (0.190 to 0.169) and buys a lot at ≥ 25.

**ham-2024 dev check (1975 messages).** The first run flagged 2.8 % of it at ≥ 25 (all signals). Two causes, both narrowed:
- Link-protection wrappers (Microsoft Defender Safe Links, also Proofpoint and Mimecast) rewrite every link into a redirect
  that carries the recipient's address, so `links.redirect_param` and `links.recipient_in_url` fired together (17 mails).
  Those two signals then skipped such wrappers; after test run 2 this was replaced by unwrapping them (see below).
- `github.io` (GitHub Pages) counted as a lookalike of `github.com` (14 mails); it is now one of GitHub's own domains.
  It stays on the free-hosting list (`links.abused_hosting`, 20, not enough alone).

After that: 1.3 % flagged at ≥ 25, none at ≥ 50; phishing recall and ham-2002 unchanged. Signals that still fire on more
than 2 % of ham-2024 dev all have small weights and none flags a mail alone: `wording.urgency` 12.1 % (weight 10),
`links.nonstandard_port` 4.6 % (0, links to local test servers), `links.brand_link_mismatch` 3.5 % (5).
The commonest remaining single cause is `wording.credentials` (25) in questions about configuring passwords (7 of 1975).

**Authentication on modern legitimate mail.** 99.8 % of ham-2024 carries an Authentication-Results header (phishing 99.9 %,
ham-2002 0 %). None of it has an SPF, DKIM or DMARC failure (phishing: SPF fail 4.5 %, softfail 11.0 %, DKIM fail 1.5 %,
DMARC fail 1.7 %). So the `auth.*` failure signals cause no false positives here; their weights stay hand-set.

## Anti-evasion changes after test run 2 (dev only)

Two changes close ways an attacker could switch signals off; both were measured on dev only.
- **Subscription links.** `links.recipient_in_url` now ignores a link only if its visible text says unsubscribe,
  opt out, preferences or manage subscription, or if it is the URL in the `List-Unsubscribe` header. The URL path no
  longer counts (the sender chooses it): a link to `/unsubscribe/` reading "Verify account" is flagged.
- **Link-protection wrappers.** Instead of skipping them, Safe Links (`url` parameter) and Proofpoint URL Defense v2/v3
  (their own encoding) are unwrapped statically, also when nested, and every link check runs on the inner URL.
  Mimecast's opaque token can't be unwrapped.

Shift on dev: at most **0.4 points** (precision at ≥ 25 without era signals, 0.909 → 0.905); recall at ≥ 25 unchanged
(0.560 / 0.763), at ≥ 50 down 0.1 point (0.169 → 0.168, 0.368 → 0.367); ham-2002 flagged at ≥ 25 1.8 % → 1.9 %,
ham-2024 1.3 % (25 → 26 of 1975). The tuning rule still picks k = 6 with the same weights. As the shift is under
0.5 points, the test split was not run a third time; the test numbers above are from test run 2, before these changes.

## Caveats

- Both legitimate sets are proxies (see "Two proxies" above). Modern transactional mail from banks and shops ("Dear customer",
  "update your payment details", password resets, HTML buttons) is barely represented, so the wording weights
  (credentials 25, payment 25, generic greeting 30) and the button signal may cause more false positives there than measured.
- Nazario's corpus is one person's inbox, hand-classified ("it could contain errors"), so it is representative, not exhaustive.
- 1303 phishing messages are enough for the frequent signals; rare ones (executables, macros, password fields) had too few
  hits to tune and keep their hand-set weights.
- Mimecast-protected links carry the target in an opaque token and can't be unwrapped offline; they are judged as links to Mimecast.

## Appendix A: test run 2 report

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
| apache | users_tomcat_2024-01.mbox | ham | `55cb5aa1ba195600a06b4fb55338cf75a6bfa76a309ef4bb26119f9962c8614e` | 84 | 34 |
| apache | users_tomcat_2024-02.mbox | ham | `ebfb805093b19c79c5e5c024f91a95d37fe1d725ce8ed2bfd71dd959911a1208` | 98 | 38 |
| apache | users_tomcat_2024-03.mbox | ham | `99f45b2bdb696d7533e9fdb908e4fc23568f5e979e7985ff440bbd1d2f01e50d` | 116 | 50 |
| apache | users_tomcat_2024-04.mbox | ham | `d9bf871c8a2627e649877998e251648f1b4170c797835e1e98abd1eb0329b7de` | 122 | 50 |
| apache | users_tomcat_2024-05.mbox | ham | `872977e03ca48cade35c2d7e13eba640b4a71af4ee7f28e9e3b30bfe5a9019ec` | 104 | 58 |
| apache | users_tomcat_2024-06.mbox | ham | `b7ecaf81585abbd7caecc13e4b3dd6cdef26c1b72b568a112a24e51d173cdac9` | 117 | 55 |
| apache | users_tomcat_2024-07.mbox | ham | `0320c6854844cc71ca875c176ede4a535763c1eb37138a5aefe1f7a13985ecf4` | 87 | 45 |
| apache | users_tomcat_2024-08.mbox | ham | `fb155fcece987f7c22825010b33b05c9a9795dc7ff478c6dad79fcf44a5036a5` | 106 | 37 |
| apache | users_tomcat_2024-09.mbox | ham | `57117b35c4ffef3d9a0b43d01cbf1181971bd30020a3cb421945c89d25a29443` | 100 | 42 |
| apache | users_tomcat_2024-10.mbox | ham | `e68a7c8eb9737670a4dfba271de6f6947db3aff55cde180d9ec6299f97210e30` | 97 | 39 |
| apache | users_tomcat_2024-11.mbox | ham | `1b2de75ec2d76c087dc6b53d7eaccd1e37d47358f41b0f5d9d261da22574b516` | 52 | 25 |
| apache | users_tomcat_2024-12.mbox | ham | `a346d4e0c8f9a10f18d106a24627f39e6fd0f92455048ba9ec897d413c8e7041` | 83 | 46 |
| apache | users_tomcat_2025-01.mbox | ham | `800a4bdb0d9f36c03bb26c8f932bf6c9b1fd71c693fc532f04d96d7c3bccdda4` | 91 | 30 |
| apache | users_tomcat_2025-02.mbox | ham | `0651c1bd9518e2d472088fc8049b47f71cc424b8869d01866725dfa76a279f35` | 80 | 46 |
| apache | users_tomcat_2025-03.mbox | ham | `38919cc2e7052854fa6cceb29f06d23ede3fba6457c942cb9312f94ed0479af5` | 77 | 37 |
| apache | users_tomcat_2025-04.mbox | ham | `67125d3f3f2e5d67e64e62641f4ed33c542cc165ca0fdea939a5d654913e07e8` | 100 | 46 |
| apache | users_tomcat_2025-05.mbox | ham | `11ba483dc1cae9aa5fab635e5f6ddddfdcf03ec79656293add2d719ca643f796` | 71 | 21 |
| apache | users_tomcat_2025-06.mbox | ham | `e0f72a8a8e6d697b71fb7e9c0e3e4bf64fc68f9b9b1b3a017ef90cb4a4d89202` | 64 | 21 |
| apache | users_tomcat_2025-07.mbox | ham | `f7fed5b6b294192c8fc0d22ec8561a4e1bd8a3b07e6e93df286db72a714f1b9f` | 74 | 25 |
| apache | users_tomcat_2025-08.mbox | ham | `4eaef33988b5c15abda7f5f4f9569cc6ddab5836790835966a0fb389515da12e` | 130 | 58 |
| apache | users_tomcat_2025-09.mbox | ham | `8f6bc4dbfbbeeafce76195f21bb0cdf3e805038ffeaaff74ce0109eda1d85b55` | 55 | 33 |
| apache | users_tomcat_2025-10.mbox | ham | `fbbddc2d7e130a254554fe64add2df2a89ac98c4637e834f262335d0bd4073c3` | 67 | 32 |

Messages in this report: 379 phishing, 1250 ham-2002 (SpamAssassin), 868 ham-2024 (Apache users@tomcat).
Main metrics and tuning use phishing and ham-2002 (SpamAssassin); the other legitimate sets are reported separately.

### Era check (dev split)

- phishing: 99.9 % have an Authentication-Results header
- ham-2002 (SpamAssassin): 0.0 % have an Authentication-Results header
- ham-2024 (Apache users@tomcat): 99.8 % have an Authentication-Results header

### What the mails contain (dev split)

| Group | Messages | With an http(s) link | With an HTML part | With an attachment |
|---|---|---|---|---|
| phishing | 924 | 91.0 % | 98.6 % | 12.4 % |
| ham-2002 (SpamAssassin) | 2900 | 87.4 % | 4.8 % | 0.6 % |
| ham-2024 (Apache users@tomcat) | 1975 | 51.9 % | 3.0 % | 1.3 % |
| phishing with no indicator (era signals aside) | 73 | 87.7 % | 94.5 % | 9.6 % |

### Signal frequencies (dev split)

Era signals don't take part in weight tuning; the reason is in the last column.

| Signal | Weight | Phishing | ham-2002 (SpamAssassin) | ham-2024 (Apache users@tomcat) | Era signal |
|---|---|---|---|---|---|
| `attach.archive` | 10 | 4 (0.4 %) | 0 (0.0 %) | 1 (0.1 %) |  |
| `attach.double_extension` | 35 | 2 (0.2 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.executable` | 40 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.html` | 25 | 45 (4.9 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `attach.macro_office` | 30 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.password_hint` | 15 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.type_mismatch` | 25 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `auth.dkim_fail` | 10 | 14 (1.5 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.dmarc_fail` | 25 | 16 (1.7 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.dmarc_pass` | 0 | 472 (51.1 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.spf_fail` | 15 | 42 (4.5 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.spf_softfail` | 5 | 102 (11.0 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `content.hidden_text` | 15 | 50 (5.4 %) | 0 (0.0 %) | 1 (0.1 %) | needs HTML; only about 5 % of the 2002 ham is HTML |
| `content.image_only` | 10 | 12 (1.3 %) | 0 (0.0 %) | 0 (0.0 %) | needs HTML; only about 5 % of the 2002 ham is HTML |
| `content.zero_width` | 20 | 26 (2.8 %) | 0 (0.0 %) | 0 (0.0 %) | needs HTML or Unicode-heavy text, both rare in the 2002 ham |
| `history.domain_flagged` | 20 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.abused_hosting` | 20 | 207 (22.4 %) | 0 (0.0 %) | 14 (0.7 %) | the listed hosting, storage and form services didn't exist in 2002 |
| `links.brand_in_path` | 15 | 11 (1.2 %) | 3 (0.1 %) | 14 (0.7 %) |  |
| `links.brand_in_subdomain` | 30 | 3 (0.3 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.brand_link_mismatch` | 5 | 169 (18.3 %) | 254 (8.8 %) | 69 (3.5 %) |  |
| `links.cta_text` | 10 | 175 (18.9 %) | 0 (0.0 %) | 0 (0.0 %) | needs HTML links; only about 5 % of the 2002 ham is HTML |
| `links.ip_host` | 30 | 1 (0.1 %) | 4 (0.1 %) | 1 (0.1 %) |  |
| `links.lookalike_domain` | 15 | 35 (3.8 %) | 8 (0.3 %) | 11 (0.6 %) |  |
| `links.nonstandard_port` | 0 | 3 (0.3 %) | 8 (0.3 %) | 90 (4.6 %) |  |
| `links.password_form` | 35 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.punycode` | 20 | 3 (0.3 %) | 0 (0.0 %) | 0 (0.0 %) | internationalised domain names (punycode) only started in 2003 |
| `links.recipient_in_url` | 20 | 549 (59.4 %) | 47 (1.6 %) | 2 (0.1 %) |  |
| `links.redirect_param` | 10 | 55 (6.0 %) | 1 (0.0 %) | 2 (0.1 %) | tracking redirects in links are far more common in today's mail than in 2002 mailing lists |
| `links.risky_tld` | 15 | 46 (5.0 %) | 2 (0.1 %) | 0 (0.0 %) | most of the listed top-level domains (.xyz, .top, .zip, ...) didn't exist before 2014 |
| `links.script_scheme` | 30 | 0 (0.0 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `links.shortener` | 10 | 71 (7.7 %) | 3 (0.1 %) | 0 (0.0 %) | most of the listed URL shorteners (bit.ly, t.co, ...) started after 2008 |
| `links.text_href_mismatch` | 10 | 41 (4.4 %) | 17 (0.6 %) | 2 (0.1 %) |  |
| `links.userinfo` | 25 | 2 (0.2 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `sender.brand_mismatch` | 30 | 71 (7.7 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `sender.display_name_address` | 15 | 8 (0.9 %) | 2 (0.1 %) | 7 (0.4 %) |  |
| `sender.lookalike_domain` | 35 | 5 (0.5 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `sender.punycode` | 20 | 1 (0.1 %) | 0 (0.0 %) | 0 (0.0 %) | internationalised domain names (punycode) only started in 2003 |
| `sender.reply_to_mismatch` | 0 | 80 (8.7 %) | 516 (17.8 %) | 1548 (78.4 %) |  |
| `sender.return_path_mismatch` | 0 | 111 (12.0 %) | 1990 (68.6 %) | 1547 (78.3 %) |  |
| `wording.credentials` | 25 | 104 (11.3 %) | 3 (0.1 %) | 7 (0.4 %) |  |
| `wording.generic_greeting` | 30 | 94 (10.2 %) | 2 (0.1 %) | 0 (0.0 %) |  |
| `wording.payment` | 25 | 29 (3.1 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `wording.prize` | 0 | 3 (0.3 %) | 26 (0.9 %) | 6 (0.3 %) |  |
| `wording.threat` | 15 | 99 (10.7 %) | 17 (0.6 %) | 16 (0.8 %) |  |
| `wording.urgency` | 10 | 272 (29.4 %) | 107 (3.7 %) | 238 (12.1 %) |  |

### Metrics (test split)

Positive class: phishing. A mail counts as flagged when its score reaches the threshold.

| Signals | Flagged at | Precision | Recall | F1 | False-positive rate | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| all signals | phishing (≥ 50) | 0.994 | 0.404 | 0.574 | 0.001 | 153 | 1 | 226 | 1249 |
| all signals | phishing or suspicious (≥ 25) | 0.935 | 0.760 | 0.838 | 0.016 | 288 | 20 | 91 | 1230 |
| without auth.* | phishing (≥ 50) | 0.993 | 0.377 | 0.547 | 0.001 | 143 | 1 | 236 | 1249 |
| without auth.* | phishing or suspicious (≥ 25) | 0.932 | 0.726 | 0.816 | 0.016 | 275 | 20 | 104 | 1230 |
| without era signals | phishing (≥ 50) | 0.987 | 0.206 | 0.341 | 0.001 | 78 | 1 | 301 | 1249 |
| without era signals | phishing or suspicious (≥ 25) | 0.918 | 0.559 | 0.695 | 0.015 | 212 | 19 | 167 | 1231 |

### False positives on each legitimate set (test split)

| Signals | Flagged at | ham-2002 (SpamAssassin) | ham-2024 (Apache users@tomcat) |
|---|---|---|---|
| all signals | phishing (≥ 50) | 0.1 % (1 of 1250) | 0.0 % (0 of 868) |
| all signals | phishing or suspicious (≥ 25) | 1.6 % (20 of 1250) | 1.4 % (12 of 868) |
| without auth.* | phishing (≥ 50) | 0.1 % (1 of 1250) | 0.0 % (0 of 868) |
| without auth.* | phishing or suspicious (≥ 25) | 1.6 % (20 of 1250) | 1.4 % (12 of 868) |
| without era signals | phishing (≥ 50) | 0.1 % (1 of 1250) | 0.0 % (0 of 868) |
| without era signals | phishing or suspicious (≥ 25) | 1.5 % (19 of 1250) | 1.0 % (9 of 868) |

### Synthetic modern legitimate mails (samples/, all signals)

| Sample | Score | Verdict | Indicators with weight |
|---|---|---|---|
| legit_modern_newsletter.eml | 10 | likely_legitimate | links.redirect_param +10 |
| legit_shared_document.eml | 10 | likely_legitimate | links.cta_text +10 |
| legit_mfa_code.eml | 0 | likely_legitimate | - |

### Score distribution (test split, without era signals)

| Score | Phishing | ham-2002 (SpamAssassin) | ham-2024 (Apache users@tomcat) |
|---|---|---|---|
| 0-0 | 46 | 1118 | 732 |
| 1-24 | 121 | 113 | 127 |
| 25-49 | 134 | 18 | 9 |
| 50-100 | 78 | 1 | 0 |

### Most common indicator sets among errors (test split, without era signals, flagged at ≥ 50)

**False positives (ham flagged):**

- 1 x links.recipient_in_url, wording.credentials, wording.urgency

**False negatives (phishing missed):**

- 71 x links.recipient_in_url
- 33 x links.recipient_in_url, wording.urgency
- 30 x (no indicators)
- 11 x wording.urgency
- 11 x sender.return_path_mismatch
- 10 x links.recipient_in_url, wording.credentials
- 9 x attach.html
- 8 x links.brand_link_mismatch

## Appendix B: dev report (iteration 2 weights, with the tuning table)

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
| apache | users_tomcat_2024-01.mbox | ham | `55cb5aa1ba195600a06b4fb55338cf75a6bfa76a309ef4bb26119f9962c8614e` | 84 | 34 |
| apache | users_tomcat_2024-02.mbox | ham | `ebfb805093b19c79c5e5c024f91a95d37fe1d725ce8ed2bfd71dd959911a1208` | 98 | 38 |
| apache | users_tomcat_2024-03.mbox | ham | `99f45b2bdb696d7533e9fdb908e4fc23568f5e979e7985ff440bbd1d2f01e50d` | 116 | 50 |
| apache | users_tomcat_2024-04.mbox | ham | `d9bf871c8a2627e649877998e251648f1b4170c797835e1e98abd1eb0329b7de` | 122 | 50 |
| apache | users_tomcat_2024-05.mbox | ham | `872977e03ca48cade35c2d7e13eba640b4a71af4ee7f28e9e3b30bfe5a9019ec` | 104 | 58 |
| apache | users_tomcat_2024-06.mbox | ham | `b7ecaf81585abbd7caecc13e4b3dd6cdef26c1b72b568a112a24e51d173cdac9` | 117 | 55 |
| apache | users_tomcat_2024-07.mbox | ham | `0320c6854844cc71ca875c176ede4a535763c1eb37138a5aefe1f7a13985ecf4` | 87 | 45 |
| apache | users_tomcat_2024-08.mbox | ham | `fb155fcece987f7c22825010b33b05c9a9795dc7ff478c6dad79fcf44a5036a5` | 106 | 37 |
| apache | users_tomcat_2024-09.mbox | ham | `57117b35c4ffef3d9a0b43d01cbf1181971bd30020a3cb421945c89d25a29443` | 100 | 42 |
| apache | users_tomcat_2024-10.mbox | ham | `e68a7c8eb9737670a4dfba271de6f6947db3aff55cde180d9ec6299f97210e30` | 97 | 39 |
| apache | users_tomcat_2024-11.mbox | ham | `1b2de75ec2d76c087dc6b53d7eaccd1e37d47358f41b0f5d9d261da22574b516` | 52 | 25 |
| apache | users_tomcat_2024-12.mbox | ham | `a346d4e0c8f9a10f18d106a24627f39e6fd0f92455048ba9ec897d413c8e7041` | 83 | 46 |
| apache | users_tomcat_2025-01.mbox | ham | `800a4bdb0d9f36c03bb26c8f932bf6c9b1fd71c693fc532f04d96d7c3bccdda4` | 91 | 30 |
| apache | users_tomcat_2025-02.mbox | ham | `0651c1bd9518e2d472088fc8049b47f71cc424b8869d01866725dfa76a279f35` | 80 | 46 |
| apache | users_tomcat_2025-03.mbox | ham | `38919cc2e7052854fa6cceb29f06d23ede3fba6457c942cb9312f94ed0479af5` | 77 | 37 |
| apache | users_tomcat_2025-04.mbox | ham | `67125d3f3f2e5d67e64e62641f4ed33c542cc165ca0fdea939a5d654913e07e8` | 100 | 46 |
| apache | users_tomcat_2025-05.mbox | ham | `11ba483dc1cae9aa5fab635e5f6ddddfdcf03ec79656293add2d719ca643f796` | 71 | 21 |
| apache | users_tomcat_2025-06.mbox | ham | `e0f72a8a8e6d697b71fb7e9c0e3e4bf64fc68f9b9b1b3a017ef90cb4a4d89202` | 64 | 21 |
| apache | users_tomcat_2025-07.mbox | ham | `f7fed5b6b294192c8fc0d22ec8561a4e1bd8a3b07e6e93df286db72a714f1b9f` | 74 | 25 |
| apache | users_tomcat_2025-08.mbox | ham | `4eaef33988b5c15abda7f5f4f9569cc6ddab5836790835966a0fb389515da12e` | 130 | 58 |
| apache | users_tomcat_2025-09.mbox | ham | `8f6bc4dbfbbeeafce76195f21bb0cdf3e805038ffeaaff74ce0109eda1d85b55` | 55 | 33 |
| apache | users_tomcat_2025-10.mbox | ham | `fbbddc2d7e130a254554fe64add2df2a89ac98c4637e834f262335d0bd4073c3` | 67 | 32 |

Messages in this report: 924 phishing, 2900 ham-2002 (SpamAssassin), 1975 ham-2024 (Apache users@tomcat).
Main metrics and tuning use phishing and ham-2002 (SpamAssassin); the other legitimate sets are reported separately.

### Era check (dev split)

- phishing: 99.9 % have an Authentication-Results header
- ham-2002 (SpamAssassin): 0.0 % have an Authentication-Results header
- ham-2024 (Apache users@tomcat): 99.8 % have an Authentication-Results header

### What the mails contain (dev split)

| Group | Messages | With an http(s) link | With an HTML part | With an attachment |
|---|---|---|---|---|
| phishing | 924 | 91.0 % | 98.6 % | 12.4 % |
| ham-2002 (SpamAssassin) | 2900 | 87.4 % | 4.8 % | 0.6 % |
| ham-2024 (Apache users@tomcat) | 1975 | 51.9 % | 3.0 % | 1.3 % |
| phishing with no indicator (era signals aside) | 73 | 87.7 % | 94.5 % | 9.6 % |

### Signal frequencies (dev split)

Era signals don't take part in weight tuning; the reason is in the last column.

| Signal | Weight | Phishing | ham-2002 (SpamAssassin) | ham-2024 (Apache users@tomcat) | Era signal |
|---|---|---|---|---|---|
| `attach.archive` | 10 | 4 (0.4 %) | 0 (0.0 %) | 1 (0.1 %) |  |
| `attach.double_extension` | 35 | 2 (0.2 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.executable` | 40 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.html` | 25 | 45 (4.9 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `attach.macro_office` | 30 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.password_hint` | 15 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `attach.type_mismatch` | 25 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `auth.dkim_fail` | 10 | 14 (1.5 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.dmarc_fail` | 25 | 16 (1.7 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.dmarc_pass` | 0 | 472 (51.1 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.spf_fail` | 15 | 42 (4.5 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `auth.spf_softfail` | 5 | 102 (11.0 %) | 0 (0.0 %) | 0 (0.0 %) | Authentication-Results (SPF, DKIM, DMARC) wasn't added by mail servers in 2002 |
| `content.hidden_text` | 15 | 50 (5.4 %) | 0 (0.0 %) | 1 (0.1 %) | needs HTML; only about 5 % of the 2002 ham is HTML |
| `content.image_only` | 10 | 12 (1.3 %) | 0 (0.0 %) | 0 (0.0 %) | needs HTML; only about 5 % of the 2002 ham is HTML |
| `content.zero_width` | 20 | 26 (2.8 %) | 0 (0.0 %) | 0 (0.0 %) | needs HTML or Unicode-heavy text, both rare in the 2002 ham |
| `history.domain_flagged` | 20 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.abused_hosting` | 20 | 207 (22.4 %) | 0 (0.0 %) | 14 (0.7 %) | the listed hosting, storage and form services didn't exist in 2002 |
| `links.brand_in_path` | 15 | 11 (1.2 %) | 3 (0.1 %) | 14 (0.7 %) |  |
| `links.brand_in_subdomain` | 30 | 3 (0.3 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.brand_link_mismatch` | 5 | 169 (18.3 %) | 254 (8.8 %) | 69 (3.5 %) |  |
| `links.cta_text` | 10 | 175 (18.9 %) | 0 (0.0 %) | 0 (0.0 %) | needs HTML links; only about 5 % of the 2002 ham is HTML |
| `links.ip_host` | 30 | 1 (0.1 %) | 4 (0.1 %) | 1 (0.1 %) |  |
| `links.lookalike_domain` | 15 | 35 (3.8 %) | 8 (0.3 %) | 11 (0.6 %) |  |
| `links.nonstandard_port` | 0 | 3 (0.3 %) | 8 (0.3 %) | 90 (4.6 %) |  |
| `links.password_form` | 35 | 0 (0.0 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `links.punycode` | 20 | 3 (0.3 %) | 0 (0.0 %) | 0 (0.0 %) | internationalised domain names (punycode) only started in 2003 |
| `links.recipient_in_url` | 20 | 549 (59.4 %) | 47 (1.6 %) | 2 (0.1 %) |  |
| `links.redirect_param` | 10 | 55 (6.0 %) | 1 (0.0 %) | 2 (0.1 %) | tracking redirects in links are far more common in today's mail than in 2002 mailing lists |
| `links.risky_tld` | 15 | 46 (5.0 %) | 2 (0.1 %) | 0 (0.0 %) | most of the listed top-level domains (.xyz, .top, .zip, ...) didn't exist before 2014 |
| `links.script_scheme` | 30 | 0 (0.0 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `links.shortener` | 10 | 71 (7.7 %) | 3 (0.1 %) | 0 (0.0 %) | most of the listed URL shorteners (bit.ly, t.co, ...) started after 2008 |
| `links.text_href_mismatch` | 10 | 41 (4.4 %) | 17 (0.6 %) | 2 (0.1 %) |  |
| `links.userinfo` | 25 | 2 (0.2 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `sender.brand_mismatch` | 30 | 71 (7.7 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `sender.display_name_address` | 15 | 8 (0.9 %) | 2 (0.1 %) | 7 (0.4 %) |  |
| `sender.lookalike_domain` | 35 | 5 (0.5 %) | 0 (0.0 %) | 0 (0.0 %) |  |
| `sender.punycode` | 20 | 1 (0.1 %) | 0 (0.0 %) | 0 (0.0 %) | internationalised domain names (punycode) only started in 2003 |
| `sender.reply_to_mismatch` | 0 | 80 (8.7 %) | 516 (17.8 %) | 1548 (78.4 %) |  |
| `sender.return_path_mismatch` | 0 | 111 (12.0 %) | 1990 (68.6 %) | 1547 (78.3 %) |  |
| `wording.credentials` | 25 | 104 (11.3 %) | 3 (0.1 %) | 7 (0.4 %) |  |
| `wording.generic_greeting` | 30 | 94 (10.2 %) | 2 (0.1 %) | 0 (0.0 %) |  |
| `wording.payment` | 25 | 29 (3.1 %) | 1 (0.0 %) | 0 (0.0 %) |  |
| `wording.prize` | 0 | 3 (0.3 %) | 26 (0.9 %) | 6 (0.3 %) |  |
| `wording.threat` | 15 | 99 (10.7 %) | 17 (0.6 %) | 16 (0.8 %) |  |
| `wording.urgency` | 10 | 272 (29.4 %) | 107 (3.7 %) | 238 (12.1 %) |  |

### Metrics (dev split)

Positive class: phishing. A mail counts as flagged when its score reaches the threshold.

| Signals | Flagged at | Precision | Recall | F1 | False-positive rate | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| all signals | phishing (≥ 50) | 0.997 | 0.368 | 0.538 | 0.000 | 340 | 1 | 584 | 2899 |
| all signals | phishing or suspicious (≥ 25) | 0.930 | 0.763 | 0.838 | 0.018 | 705 | 53 | 219 | 2847 |
| without auth.* | phishing (≥ 50) | 0.997 | 0.355 | 0.524 | 0.000 | 328 | 1 | 596 | 2899 |
| without auth.* | phishing or suspicious (≥ 25) | 0.927 | 0.725 | 0.814 | 0.018 | 670 | 53 | 254 | 2847 |
| without era signals | phishing (≥ 50) | 0.994 | 0.169 | 0.289 | 0.000 | 156 | 1 | 768 | 2899 |
| without era signals | phishing or suspicious (≥ 25) | 0.909 | 0.560 | 0.693 | 0.018 | 517 | 52 | 407 | 2848 |

### False positives on each legitimate set (dev split)

| Signals | Flagged at | ham-2002 (SpamAssassin) | ham-2024 (Apache users@tomcat) |
|---|---|---|---|
| all signals | phishing (≥ 50) | 0.0 % (1 of 2900) | 0.0 % (0 of 1975) |
| all signals | phishing or suspicious (≥ 25) | 1.8 % (53 of 2900) | 1.3 % (25 of 1975) |
| without auth.* | phishing (≥ 50) | 0.0 % (1 of 2900) | 0.0 % (0 of 1975) |
| without auth.* | phishing or suspicious (≥ 25) | 1.8 % (53 of 2900) | 1.3 % (25 of 1975) |
| without era signals | phishing (≥ 50) | 0.0 % (1 of 2900) | 0.0 % (0 of 1975) |
| without era signals | phishing or suspicious (≥ 25) | 1.8 % (52 of 2900) | 1.2 % (23 of 1975) |

### Synthetic modern legitimate mails (samples/, all signals)

| Sample | Score | Verdict | Indicators with weight |
|---|---|---|---|
| legit_modern_newsletter.eml | 10 | likely_legitimate | links.redirect_param +10 |
| legit_shared_document.eml | 10 | likely_legitimate | links.cta_text +10 |
| legit_mfa_code.eml | 0 | likely_legitimate | - |

### Score distribution (dev split, without era signals)

| Score | Phishing | ham-2002 (SpamAssassin) | ham-2024 (Apache users@tomcat) |
|---|---|---|---|
| 0-0 | 93 | 2516 | 1648 |
| 1-24 | 314 | 332 | 304 |
| 25-49 | 361 | 51 | 23 |
| 50-100 | 156 | 1 | 0 |

### Most common indicator sets among errors (dev split, without era signals, flagged at ≥ 50)

**False positives (ham flagged):**

- 1 x links.brand_link_mismatch, sender.return_path_mismatch, wording.credentials, wording.payment, wording.urgency

**False negatives (phishing missed):**

- 187 x links.recipient_in_url
- 94 x links.recipient_in_url, wording.urgency
- 73 x (no indicators)
- 26 x wording.urgency
- 24 x links.recipient_in_url, wording.threat
- 22 x attach.html
- 20 x wording.generic_greeting
- 20 x links.recipient_in_url, sender.reply_to_mismatch

### Weight tuning (dev split only)

weight = k x ln(rate in phishing / rate in ham), add-one smoothing, rounded to 5, within 0..40.
Tuned: signals without era bias that fire at least 10 times on dev; all others keep their current weight.
k is picked for the best F1 at the phishing threshold (≥ 50) with at most 1% of ham flagged phishing and at most 2% flagged suspicious or worse (≥ 25), measured without era signals.

| k | Precision (≥ 50) | Recall (≥ 50) | F1 (≥ 50) | FP rate (≥ 50) | Recall (≥ 25) | FP rate (≥ 25) |
|---|---|---|---|---|---|---|
| 4 | 0.980 | 0.054 | 0.103 | 0.000 | 0.468 | 0.006 |
| 5 | 0.992 | 0.137 | 0.241 | 0.000 | 0.525 | 0.017 |
| 6 (picked) | 0.994 | 0.169 | 0.289 | 0.000 | 0.560 | 0.018 |
| 7 | 0.991 | 0.241 | 0.388 | 0.001 | 0.800 | 0.027 |
| 8 | 0.980 | 0.319 | 0.482 | 0.002 | 0.808 | 0.031 |
| 9 | 0.977 | 0.456 | 0.621 | 0.003 | 0.827 | 0.038 |
| 10 | 0.977 | 0.461 | 0.626 | 0.003 | 0.827 | 0.038 |
| 11 | 0.919 | 0.492 | 0.641 | 0.014 | 0.870 | 0.066 |
| 12 | 0.917 | 0.492 | 0.641 | 0.014 | 0.876 | 0.069 |
| 13 | 0.917 | 0.492 | 0.641 | 0.014 | 0.876 | 0.069 |
| 14 | 0.907 | 0.494 | 0.639 | 0.016 | 0.876 | 0.069 |
| 15 | 0.898 | 0.495 | 0.638 | 0.018 | 0.876 | 0.069 |
| 16 | 0.894 | 0.495 | 0.637 | 0.019 | 0.876 | 0.069 |

| Signal | Phishing hits | Ham hits | ln ratio | Current weight | Suggested (k = 6) |
|---|---|---|---|---|---|
| `attach.html` | 45 | 1 | +4.28 | 25 | 25 |
| `links.brand_in_path` | 11 | 3 | +2.24 | 15 | 15 |
| `links.brand_link_mismatch` | 169 | 254 | +0.74 | 5 | 5 |
| `links.lookalike_domain` | 35 | 8 | +2.53 | 15 | 15 |
| `links.nonstandard_port` | 3 | 8 | +0.33 | 0 | 0 |
| `links.recipient_in_url` | 549 | 47 | +3.58 | 20 | 20 |
| `links.text_href_mismatch` | 41 | 17 | +1.99 | 10 | 10 |
| `sender.brand_mismatch` | 71 | 1 | +4.73 | 30 | 30 |
| `sender.display_name_address` | 8 | 2 | +2.24 | 15 | 15 |
| `sender.reply_to_mismatch` | 80 | 516 | -0.71 | 0 | 0 |
| `sender.return_path_mismatch` | 111 | 1990 | -1.74 | 0 | 0 |
| `wording.credentials` | 104 | 3 | +4.41 | 25 | 25 |
| `wording.generic_greeting` | 94 | 2 | +4.60 | 30 | 30 |
| `wording.payment` | 29 | 1 | +3.85 | 25 | 25 |
| `wording.prize` | 3 | 26 | -0.77 | 0 | 0 |
| `wording.threat` | 99 | 17 | +2.86 | 15 | 15 |
| `wording.urgency` | 272 | 107 | +2.07 | 10 | 10 |

The full test run 1 report is in this file's git history.
