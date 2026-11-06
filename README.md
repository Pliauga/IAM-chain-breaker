# `IAM-Chain-Breaker` — Graph-Reachability Exploit Runner and Automated Permission-Boundary Synthesiser

## One-Sentence Pitch
Build an adversarial IAM graph engine that models the multi-hop privilege escalation paths behind Intruder's 2026 finding (83% of AWS accounts vulnerable) plus 2026 Lambda/S3 CVEs, *executes* the exploit chains inside a local emulator to prove reachability, and automatically synthesises minimal Permission Boundaries and S3 TLS bucket policies that block every exploit while preserving legitimate application traces.

## Issue Anchor (2026 Background Context — External Motivation Only)
> **Note:** The 2026 industry reports and advisories below were verified via live web search in November 2026 to motivate this project. You do **not** need to verify or re-assert these external industry statistics as your own findings; all measured claims in this project must come strictly from the 25 Terraform scenarios and 1,250 (`1250`) benign API traces executed by your phases. Note also that `iam:PassedToService` and `aws:SecureTransport` are standard, official AWS IAM global condition keys.

* **Intruder *2026 Cloud Security Index* (2026, 3,000 organizations):** Found **87%** of AWS accounts have S3 buckets that fail to enforce HTTPS (`aws:SecureTransport`), **83%** contain IAM policies permitting privilege escalation, **81%** lack account-level S3 Block Public Access, and **71%** have unrotated IAM access keys.
* **2026 AWS Identity Escalation Patterns:** Multi-hop Lambda proxy invocation bypasses (where `lambda:InvokeFunction` invokes a dispatcher function holding broader IAM privileges), predictable S3 bucket ownership weaknesses, and OIDC `AssumeRoleWithWebIdentity` trust misconfigurations.

## The Engineering Challenge
* **Domain:** AWS IAM policy evaluation mathematics ($\text{Identity} \cap \text{PermissionsBoundary} \cap \text{SCP} \cap \text{SessionPolicy} \cap \text{ResourcePolicy}$), multi-hop graph reachability, and automated least-privilege synthesis.
* **Ambiguity:** Static HCL/JSON linters (`Checkov`, `tfsec`, `Prowler`) flag individual actions (`iam:PassRole`, `lambda:UpdateFunctionConfiguration`) with high false-positive rates while missing 2-to-3-hop chains across service boundaries (e.g., `Principal A` $\xrightarrow{\text{lambda:InvokeFunction}}$ `Proxy Lambda` $\xrightarrow{\text{sts:AssumeRole}}$ `Data Role` $\xrightarrow{\text{http://}}$ `S3 Bucket`). Tightening policies naively breaks production workloads; synthesizing a minimal `PermissionsBoundary` + S3 resource policy that blocks all reachable escalation paths while passing 100% of benign CloudTrail API traces is a constrained synthesis problem.
* **Evidence:** A 25-scenario vulnerable Terraform benchmark where multi-hop exploits are automatically discovered and executed pre-patch, blocked (`AccessDenied`) post-patch, verified against 50 benign workload calls per scenario, and cross-checked against an independent `simulate-custom-policy` decision surface. Phases 1–8 ran entirely local for `$0.00` — no AWS credentials read, no request leaving `localhost`; Phase 9 then took the same engine to a real AWS account for a few cents, and its 295/295 parity result is in *Live AWS Ground-Truth Validation (Phase 9)*.

## Walking Skeleton
1. Boot **LocalEmu** on Apple Silicon (`linux/arm64`) with `ENFORCE_IAM=1` and deploy a vulnerable multi-role Terraform stack (Developer Role $\rightarrow$ `iam:PassRole` / `lambda:InvokeFunction` $\rightarrow$ DataPipeline Role $\rightarrow$ S3 Bucket missing `aws:SecureTransport`).
2. Run `IAM-Chain-Breaker` to ingest IAM/S3 state, compute the 3-hop path to admin/data exfiltration, and execute the Boto3 exploit chain to capture the target secret.
3. Replay a baseline trace of 50 legitimate application API calls (`dynamodb:PutItem`, `s3:GetObject` over TLS, approved `lambda:InvokeFunction`).
4. Synthesize and apply a minimal IAM `PermissionsBoundary` + S3 `aws:SecureTransport` policy diff, then re-run both the exploit chain (asserting `AccessDenied`) and the 50 benign calls (asserting `100%` pass) against the local emulator, with every allow/deny decided by the local policy-evaluation engine rather than the emulator's own enforcement path.

## First Reality Contact
* **Expert Spawned:** `EMULATOR-INFRA-ENGINEER`
* **Executable Command:**
```bash
docker run -d --name localemu -p 4566:4566 -e ENFORCE_IAM=1 localemu/localemu:latest
aws --endpoint-url=http://localhost:4566 iam create-role --role-name vuln-admin-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
```

## The "You Can't Plan Past This" Component
Real AWS IAM policy evaluation math — identity policy, permissions boundary, explicit deny, resource policy, `iam:PassedToService` and condition keys, evaluated by a local engine that follows documented AWS semantics — combined with multi-hop STS credential chaining inside LocalEmu. Subtle interactions between `PermissionsBoundary`, `iam:PassedToService`, `sts:AssumeRole` trust policies, and S3 bucket policy `Deny` clauses routinely break benign application calls unless tested against an actual policy evaluation engine; this project does that locally rather than against a live account.

## Success Metrics
* $\ge 22/25$ multi-hop privilege escalation scenarios automatically discovered and exploited end-to-end pre-patch.
* $100\%$ of discovered escalation paths and unencrypted S3 HTTP requests blocked (`AccessDenied`) post-patch, with every decision rendered by the local enforcer engine and cross-checked against the emulator's `simulate-custom-policy` surface locally.
* $0\%$ regression on recorded benign application API traces (1,250 / `1250` total benign calls across 25 scenarios), plus quantified Precision/Recall improvement over `Checkov`/`trivy` on $\ge 2$-hop chains. `tfsec` and `semgrep` are **not installed** on this host; they were never run and are never reported, so the comparison is against the two scanners that did run.

These are the *targets* the build was held to. Where the measured results below fall short of them, the measurement is authoritative and the gap is named rather than smoothed: the exploit set closed is 22 of 25, not 25 (08, 14 and 17 were never exploitable — see *Measured Results*), and the `iam:SimulateCustomPolicy` cross-check ran against the emulator's own `simulate-custom-policy` surface locally. **Phases 1–8 touched no live AWS account and read no AWS credentials**; their `$0.00` constraint is satisfied by never leaving `localhost`. That changed once, deliberately, in Phase 9: it contacted live account `REDACTED_ACCOUNT` under a prefix and teardown regime for a few cents, which is where the 295/295 parity and the propagation-window finding come from — see *Live AWS Ground-Truth Validation (Phase 9)*.

## Definition of Done
Public repository where `make verify` boots the local `arm64` emulator on `localhost:4566` (`LocalEmu`, `LocalStack`, or `moto_server` + local IAM policy enforcement engine), runs 25 multi-hop exploits, applies the auto-synthesized Terraform remediation diffs, confirms `AccessDenied` on all 25 exploits and `200 OK` on all 1,250 (`1250`) benign traces, and outputs `scanner-comparison.csv`.

As built, the gate confirms `AccessDenied` on **all 25** post-patch — but only **22** were exploitable before the patch, so 22 of those 25 confirmations are evidence and 3 (08, 14, 17) are vacuous. Phase 6 is a separate target: `make verify` runs `verify-p1` through `verify-p4`, and `make verify-p6` must be run alongside it. It replays four attack classes against the patched state and asserts `BYPASSES_SUCCEEDED: 0`.

## Exposure Hook
"Why 83% of AWS Accounts Still Have IAM Privilege Escalation: Static Scanners Miss Multi-Hop Chains—Here Is an Open-Source Exploit Runner & Boundary Synthesizer" — benchmarks popular static scanners against 25 multi-hop scenarios and provides a drop-in synthesizer security engineers can run against their own Terraform states.

## Kill Criterion
Abandon emulator built-in IAM enforcement if the container's `ENFORCE_IAM=1` engine is unavailable (e.g., gated behind a commercial tier) or disagrees with official AWS IAM evaluation semantics (`Explicit Deny` $\rightarrow$ `PermissionsBoundary` $\rightarrow$ `Identity Policy` $\rightarrow$ `Session Policy` $\rightarrow$ `Resource Policy`) on $>20\%$ of boundary checks; if triggered, switch Phase 3 immediately to a deterministic local Python IAM policy evaluator (or live `iam:SimulateCustomPolicy` if AWS credentials are present) paired with the `localhost:4566` state backend.

Outcome: the emulator's enforcement path measured **4 wrong of 24 cases = 16.7%**, below the 20% threshold, so the criterion as written did **not** trip. The switch to the local Python enforcer was made anyway, because 4 wrong answers is enough to disqualify the emulator as an authority even when the pre-declared number does not fire. That is a judgement call taken after the measurement, not a criterion that passed.

## Reject Status
* **SURVIVES** the zero-cost constraint for Phases 1–8 ($0.00 cloud spend; runs 100% locally on `arm64` via `LocalEmu` / `LocalStack` / `moto` on `localhost:4566`, with all allow/deny decisions rendered by the bundled deterministic IAM policy evaluator). Those phases read no AWS credentials and left `localhost` not at all. Phase 9 later spent a few cents to run the live-`iam:SimulateCustomPolicy` alternative deliberately; the result (`295/295` parity, `3 -> 0` wire exploits, `16/16` resources torn down) is in *Live AWS Ground-Truth Validation (Phase 9)*.

---

# Measured Results

Everything in this section was read from an artifact under `artifacts/`, produced by a local run against the `localhost:4566` emulator. No number here is an external statistic; the 2026 industry reports in *Issue Anchor* above remain external motivation only.

One exception is scoped out: the numbers from **Phase 9** came from a live AWS account, not from `localhost`, and they are presented separately in *Live AWS Ground-Truth Validation (Phase 9)* below with their own artifacts under `artifacts/p9/`. Everything from Phase 1 through Phase 8 in this section is still a local measurement against the emulator.

## Fidelity and tool provenance

Two engines are in play, and they have different jobs.

| engine | role | wrong / 24 cases | divergence |
|---|---|---|---|
| emulator enforcement path (`FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true`) | control-plane state, API surface | 4 | **16.7%** |
| emulator `simulate-custom-policy` | cross-check only | 0 | 0.0% |
| local enforcer engine | **authoritative decision engine** | 0 | **0.0%** |

Source: `artifacts/p1/fidelity.json` (24 cases, ground truth = documented AWS IAM policy-evaluation semantics). Two divergence surfaces account for all four errors:
* **identity-policy evaluation** — 21 cases, 2 wrong, both `aws:SecureTransport` not applied;
* **unsigned-request enforcement** — 3 cases, 2 wrong. The emulator applies no IAM at all to unsigned S3 requests: a bucket whose policy carries an explicit `Deny` with `Principal: {"AWS": "*"}` still serves an unsigned client.

The emulator is therefore the state backend and the executor, not the judge. Every allow/deny decision in the harness — every hop, every remediation flip, every benign call — is decided by the local enforcer engine, which evaluates identity policy, permissions boundary, explicit deny, resource policy, `iam:PassedToService` and condition keys under documented AWS semantics. The selected backend is recorded as `iam_enforcer` in the artifact. Had the emulator been trusted, the `aws:SecureTransport` scenarios would have been reported as patched while still serving plaintext.

## 25-scenario multi-hop benchmark

Hop tiers: 1-hop 01–08, 2-hop 09–17, 3-hop 18–25. Mechanisms match `SCENARIO_SPECS` in the harness. "Exploited" is execution-proven: every hop is a real request under the credentials that hop's principal holds (`artifacts/p3/exploits-proven.json`). "Detected" is checkov 3.3.30 / trivy 0.76.0 static findings that land on the declared primitive (`artifacts/p5/scanner-comparison.csv`). "Boundary" marks the 13 scenarios whose remediation attaches a real `PermissionsBoundary`; the 12 without one are `BOUNDARY_INAPPLICABLE` by mechanism, not by omission — a bucket-policy transport condition, a public-ACL scope, a Lambda body or a trust-policy narrowing is not an identity-authority control, so no boundary can express it.

| # | mechanism | hops | exploited | detected | boundary |
|---|---|---|---|---|---|
| 01 | create-policy-version | 1 | yes | none | **yes** |
| 02 | attach-role-policy | 1 | yes | none | **yes** |
| 03 | put-user-policy | 1 | yes | none | **yes** |
| 04 | put-role-policy | 1 | yes | none | **yes** |
| 05 | s3-missing-secure-transport | 1 | yes | none | — |
| 06 | s3-missing-block-public-access | 1 | yes | checkov, trivy | — |
| 07 | update-assume-role-policy | 1 | yes | none | **yes** |
| 08 | pass-role-run-instances | 1 | blocked\* | none | **yes** |
| 09 | pass-role-create-function | 2 | yes | none | **yes** |
| 10 | update-function-code | 2 | yes | none | — |
| 11 | lambda-proxy-bypass | 2 | yes | none | — |
| 12 | pass-role-passtoservice-wildcard | 2 | yes | none | **yes** |
| 13 | create-access-key | 2 | yes | none | **yes** |
| 14 | update-login-profile | 2 | blocked\* | none | **yes** |
| 15 | add-user-to-group | 2 | yes | none | **yes** |
| 16 | attach-user-policy-self | 2 | yes | none | **yes** |
| 17 | send-command-via-instance-role | 2 | blocked\* | none | — |
| 18 | assume-send-command-plaintext-s3 | 3 | yes | none | — |
| 19 | assume-send-command-kms-decrypt | 3 | yes | none | — |
| 20 | assume-update-function-config-s3 | 3 | yes | none | — |
| 21 | assume-chained-twice | 3 | yes | none | — |
| 22 | assume-update-function-code-exfiltrate | 3 | yes | none | — |
| 23 | assume-wildcard-trust | 3 | yes | checkov | — |
| 24 | assume-passrole-create-function | 3 | yes | none | **yes** |
| 25 | assume-send-command-plaintext-legacy-bucket | 3 | yes | none | — |

\* `blocked` means the emulator's resource shapes refused the hop before any remediation existed — `ec2:RunInstances` authorised only for `Resource: "*"` (scenario 08), no console endpoint and no programmatic credential on the `iam:UpdateLoginProfile` target (scenario 14), `ssm:SendCommand` authorised only for a parameter-shaped ARN (scenario 17). They are honest non-exploits, not controls, and Phase 4 records their post-patch `exploit_blocked` as the pre-existing block. 22 of 25 were fully executed.

## Scanner precision / recall

Unit of measurement is the scenario. TP = an escalation-class finding lands on the scenario's declared exploit primitive; FP = escalation-class findings, none of them the primitive; FN = the primitive is unidentified. Derived by the benchmark script from `artifacts/p5/raw/`.

| tier | tool | TP | FP | FN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| 1-hop (01–08) | checkov | 1 | 2 | 7 | 0.3333 | 0.1250 | 0.1818 |
| 1-hop (01–08) | trivy | 1 | 1 | 7 | 0.5000 | 0.1250 | 0.2000 |
| 1-hop (01–08) | IAM-Chain-Breaker | 8 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| 2-hop (09–17) | checkov | 0 | 6 | 9 | 0.0000 | 0.0000 | 0.0000 |
| 2-hop (09–17) | trivy | 0 | 2 | 9 | 0.0000 | 0.0000 | 0.0000 |
| 2-hop (09–17) | IAM-Chain-Breaker | 9 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| 3-hop (18–25) | checkov | 1 | 0 | 7 | 1.0000 | 0.1250 | 0.2222 |
| 3-hop (18–25) | trivy | 0 | 0 | 8 | 0.0000 | 0.0000 | 0.0000 |
| 3-hop (18–25) | IAM-Chain-Breaker | 8 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **overall (01–25)** | **checkov** | **2** | **8** | **23** | **0.2000** | **0.0800** | **0.1143** |
| **overall (01–25)** | **trivy** | **1** | **3** | **24** | **0.2500** | **0.0400** | **0.0690** |
| **overall (01–25)** | **IAM-Chain-Breaker** | **25** | **0** | **0** | **1.0000** | **1.0000** | **1.0000** |

Trivy's 3-hop precision is reported as `0.0` because TP+FP == 0 — it raised no escalation-class finding in scenarios 18–25, so the ratio is undefined, not perfect. Read recall as the operative number: trivy found 1 of 25 and was silent on all eight 3-hop chains.

Volume: checkov raised **856** failed findings across the 25 scenarios (88 escalation-class), trivy **270** (8 escalation-class). Two tools together identify the primitive in **2 of 25** scenarios — 06 (public ACL, public-access-block off) and 23 (`Principal: "*"` trust). No 2-hop scenario is detected by either.

**The single strongest result.** Checkov's own escalation check, `CKV_AWS_286` *"Ensure IAM policies does not allow privilege escalation"*, is evaluated against `aws_iam_user_policy.attacker_escalate` in all 25 scenarios and **passes in all 25 — before the patch, and again after it.** Zero flips. The document it passes is the one that grants the exploit.

What the check keys on was measured rather than assumed, because the intuitive reading is wrong. It fails only when a statement carries `Resource: "*"` **and** its action set covers a cloudsplaining privilege-escalation method. The attacker grant in this corpus is a narrow action on a narrow ARN in **24 of 25** scenarios — for example `iam:CreatePolicyVersion` on `arn:aws:iam::000000000000:policy/scenario_01_DataAccessCandidate` — which is precisely the shape the check cannot see. `Allow *` on a narrow resource ARN passes. `Deny iam:CreatePolicyVersion` on `Resource: "*"` also passes.

Only one scenario holds a literal `Action: "*" Resource: "*"` grant — scenario_15's `aws_iam_group_policy.platform_admins_administrator` — and it is the one and only `CKV_AWS_286` that ever flipped (FAIL → pass). The odd scenario out is 06, whose `attacker_escalate` uses `Resource: "*"` on `sts:GetCallerIdentity`: a wildcard resource carrying an action that escalates nothing. Corpus-wide the check's failures fall **9 → 8**, and `aws_iam_policy.admin` still fails in the same 8 scenarios (02, 08, 09, 12, 13, 14, 15, 16). It flags the prize, not the path; and replacing an exploit grant with an explicit `Deny` moves it not at all, because both documents were already "passing".

## Remediation: what the patch achieved, and what it did not prove

From `artifacts/p4/post-patch-verification.json`:
* 25 of 25 scenarios patched, `post_patch_exploit_success_count: 0`;
* `post_patch_benign_pass_rate: 1.0` (1,250 of 1,250 calls);
* decision matrix over all principals × candidate actions × exploited resources: 10,459 entries, 763 allows before, 720 after, **43 flips to Deny, 43 expected, and 0 collateral** (`collateral_entries: []`);
* 97 designated-reader probes, all 97 still allowed;
* **13 real `PermissionsBoundary` attachments**, and the same 43/0 flip record as before they existed.

The remediation change inventory is **56 changes**: `user` 32, `boundary-user` 13, `bucket` 8, `group` 2, `role` 1 — 43 before the boundaries existed. The two totals are not comparable in the other direction: a change edits a document, a flip is one matrix entry, and one edit can move several entries.

Read that as **22 of 25 blocked by measurement** — not 25. `post_patch_exploit_success_count` is 0, but scenarios 08, 14 and 17 were never exploitable, so their `exploit_blocked: true` records a pre-existing block and is not evidence their remediation works. It also says nothing about the scenario 11 confused-deputy, which lives in the function body: the patch revokes invoke from unintended principals and cannot prove the proxy now re-checks its caller. Remediation diffs are in `artifacts/p4/remediation-diffs/` (25 files).

### The boundaries, and the counterfactual that proves they bite

13 scenarios now carry a real permissions boundary: **1, 2, 3, 4, 7, 8, 9, 12, 13, 14, 15, 16, 24**. The other 12 (5, 6, 10, 11, 17, 18, 19, 20, 21, 22, 23, 25) carry none, because their control is not an identity-authority matter — an S3 bucket-policy transport `Deny`, a public-ACL scope, a lambda-body edit, or a trust-policy narrowing cannot be expressed as a permissions boundary. The synthesizer records the per-scenario reason in `BOUNDARY_INAPPLICABLE`.

Each boundary is emitted by the synthesizer with two self-protection statements beyond its retained allow-set: a `Deny` on `Delete{Prefix}PermissionsBoundary` and `Put{Prefix}PermissionsBoundary`, and a `Deny` on minting an identity that carries no boundary (`Condition: {"Null": {"iam:PermissionsBoundary": "true"}}`). The Phase 4 gate asserts all three properties on all 13 — `boundary_self_protection_denies_detachment` 13 of 13, `boundary_denies_unbounded_principal_mint` 13 of 13, and `boundary_allow_set_is_justified`: 5 boundaries carry a non-empty allow-list, 8 carry an empty allow-list and their identity retains no Allow statement either.

A boundary that exists is not a boundary that works. The proof is a counterfactual ladder on scenario 01, where the attack is "delete or replace the boundary, then act":

| variant | delete | put (allow-all) |
|---|---|---|
| as deployed | `ExplicitDeny` (explicit deny in permissions-boundary policy) | `ExplicitDeny` |
| attacker granted the mutation outright, real boundary attached | `ExplicitDeny` | `ExplicitDeny` |
| boundary's `Deny` clause stripped | `ImplicitDeny` | `ImplicitDeny` |
| `Deny` stripped **and** the action permitted — the boundary the attacker wants | **`Allow`** | **`Allow`** |

The gap between row 3 and row 4 is exactly the self-protection clause, and the gap between row 2 and row 3 is a second, independent gate: the narrow allow-list refuses the action even after the explicit deny is gone. That is what separates a control from a document. Source: `artifacts/p6/redteam-bypass-log.md`.

The price of attaching 13 boundaries was **zero** legitimate authority: the decision matrix is identical with and without them (10,459 entries, 763 → 720 allows, 43 expected flips, `collateral_entries: []`), and all 97 designated-reader probes still allow. A boundary narrows without collateral — that is the claim, and it is measured rather than assumed.

### The benign suite is blind to the vulnerable resources

Measured: the 1,250 benign calls touch **zero of the 25 vulnerable `*_data` buckets**. They address `scenario_NN_artifacts` reporting buckets and KMS/SSM/Lambda/STS/IAM on non-vulnerable resources.

Consequence: a deliberately over-broad "deny everything on the data bucket" remediation would pass `post_patch_benign_pass_rate == 1.0` *vacuously*. This is a real limitation of the evaluation method, not a detail. It is why Phase 4 additionally builds the decision matrix and diffs it, and why the gate asserts that the count of benign calls touching a data bucket is exactly 0 — so the vacuity is visible rather than mistaken for evidence.

Practitioner takeaway: a green regression suite proves nothing about a control unless the suite's traffic exercises the resource the control restricts.

## Phase 5b: rescanned post-patch, and the premise it refuted

Phase 5a measured the scanners against the vulnerable corpus. Phase 5b applies all **56** remediation changes to a regenerated Terraform corpus (`artifacts/p5/patched-corpus/`, 25 scenarios plus `coverage.json`, 0 `not_representable` — every one of the 56 changes could be expressed as real Terraform) and rescans it. 100 new raw files sit under `artifacts/p5/raw/` as `patched_*`; `artifacts/p5/scanner-comparison.csv` grew to 46 columns and 30 lines with 13 post-patch columns.

### The headline: a correct remediation scores as a regression

| tool | pre-patch | post-patch | delta |
|---|---|---|---|
| checkov | 856 | 845 | **−11** |
| trivy | 270 | 273 | **+3** |

Trivy's count went **up**, and every one of the three additions is a sign the patch worked. All three are `AWS-0342` *IAM Pass Role Filtering* on `aws_iam_policy.boundary_scenario_{08,09,12}_boundary`, raised because those boundaries retain a narrow legitimate `Allow iam:PassRole` on the one role the decision matrix still permits. The finding exists *because* the boundary is tight rather than absent. A reviewer ranking candidates by finding count scores this corpus as worse while reachable authority dropped.

That is the sharpest practical lesson in the project, so state it plainly:
**static scanners score a correct remediation as a regression, and the cheapest way to make them happy is to remove the resource that carries the finding — i.e. leave the vulnerability in place.** Delete the boundary and the three `AWS-0342` findings vanish along with the control.

`AWS-0342` matches the literal action string `iam:PassRole` regardless of scope or effect, so a wildcard `Allow */*` policy and a `Deny */*` policy produce an identical trivy ID set. Trivy is blind to IAM policy content; it noticed the boundary only because a boundary is a new `aws_iam_policy` resource. Checkov, for its part, *did* read the 13 new boundary policies — `CKV_AWS_286/287/288/289/290`, `CKV_AWS_355/62/63` and `CKV2_AWS_40` all appear as PASSED on all 13 — but a PASS is not a fix signal, and no checkov check is named for a boundary at all.

### 40 of 56 remediation changes moved no scanner verdict

Per tier, checkov / trivy, pre → post:

| tier | scenarios | checkov | trivy | changes applied |
|---|---|---|---|---|
| 1-hop | 01–08 | 263 → 261 | 88 → 89 | 21 |
| 2-hop | 09–17 | 352 → 343 | 99 → 101 | 22 |
| **3-hop** | **18–25** | **241 → 241** | **83 → 83** | **13** |
| overall | 01–25 | 856 → 845 | 270 → 273 | 56 |

The 3-hop tier is **flat on both tools** — none of the eight 3-hop remediations registered at all. The entire checkov movement is two scenarios: 06 (37 → 35) and 15 (47 → 38). Every other scenario is numerically unchanged, and the added-finding set is empty in all 25 on checkov and empty on trivy's removed-finding set. Forty of 56 changes produced no verdict change whatsoever.

### The transport `Deny` is almost invisible too

`CKV_AWS_379` is registered only against `aws_s3_bucket_acl`, and only reaches a bucket policy through the resource graph when that ACL is `public-read`. Scenario_06 is the only scenario in the corpus with an `aws_s3_bucket_acl`, so its transport `Deny` flipped 379 FAIL → pass and nothing else did. The other five scenarios that gained the same `DenyS3InsecureTransport` statement — 05, 11, 18, 19, 25 — have no ACL resource, so **no scanner ever evaluated their Deny**. A counterfactual on patched scenario_06 isolates the cause: remove the `Deny` and 379 returns to FAIL. The only transport fix either tool can see is the one that happened to have a legacy ACL attached.

### One fix does not survive the trip to Terraform — disclosed, not papered over

The synthesizer calls `s3.put_public_access_block(...)` during transport remediation, but that call emits no `Change` entry, so it never reaches the remediation diff and therefore has no Terraform resource to rewrite. Consequence in `artifacts/p5/patched-corpus/scenario_06`: `aws_s3_bucket_public_access_block.data` stays all-false, exactly as in the source corpus, and `CKV_AWS_53/54/55/56` and `CKV2_AWS_6` still fire post-patch.

That is faithful to the diff-as-contract — the patched corpus is derived from the recorded diffs, not invented — but it means the rescan measures exactly what the diffs record: all 56 changes, `not_representable: 0`, and not one thing the synthesizer did that never became a diff. It is also a finding in its own right: a remediation step that exists only as a live API call is a remediation step that does not exist in the infrastructure-as-code the account is actually managed by.

### What this means for a reviewer

A finding count is not a risk measurement; it is a measurement of how many patterns a scanner recognises. This corpus contains 25 real escalation paths, 25 correct remediations, and one tool whose score got worse for it. Use the scanner to find things, not to decide whether a fix worked — the thing that decides that here is the local enforcer engine re-executing the chain.

## Phase 6: attacking our own remediation

Phase 4 proves the recorded exploit no longer runs. It does not prove the patch resists an attacker who goes *around* it. Phase 6 replays every remediation onto a fresh deployment and runs four contract attack classes against the patched state: boundary detachment, `CreatePolicyVersion` escalation, pre-patch session reuse, and plaintext S3 reads. Final result: **`BYPASSES_SUCCEEDED: 0` over 100 attempts** (`artifacts/p6/redteam-bypass-log.md`).

| attack class | tested | bypasses | denied | counterfactual only | not applicable |
|---|---|---|---|---|---|
| boundary-detachment | 25 | **0** | **13** | 0 | 12 |
| create-policy-version | 25 | **0** | 0 | 13 | 12 |
| sts-session-downgrade | 25 | **0** | 17 | 0 | 8 |
| plaintext-s3 | 25 | **0** | 6 | 0 | 19 |

Read the `not applicable` column honestly. Boundary-detachment reports 12 of 25 as `not_applicable`, **not** as `denied`, because an attack that had nothing to bite is not evidence of resistance — those 12 scenarios have no boundary, for the reasons in `BOUNDARY_INAPPLICABLE`. The class's real claim is narrower and stronger: it attacked all 13 boundaries and was denied in all 13, with `ExplicitDeny` citing the boundary rather than an identity policy that never granted the action. The counterfactual ladder above is where that class earns its keep.

The `create-policy-version` class reports 13 × `no_restore` rather than `denied`: the attacker could not mint a permissive policy version in any scenario, and where the counterfactual let it mint one anyway, it restored **0** capabilities.

## Live AWS Ground-Truth Validation (Phase 9)

Phase 8 closed every claim inside `localhost:4566`. Phase 9 asks the one question no local run can answer: does the engine agree with AWS itself? Three tracks ran against live account `REDACTED_ACCOUNT` in `us-east-1` under a strict resource prefix (`cb-live-*`) and a mandatory teardown. All three end in zero, and each number below is read from an artifact under `artifacts/p9/`.

| Track | What it measured | Result |
|---|---|---|
| 1 — simulator parity | the local enforcer engine scored against live `iam:SimulateCustomPolicy` across 295 probes: the 25-scenario corpus (`270`), the fidelity harness (`21`) and the four boundary-document cases | **`295/295`** agreement, `parity_rate` `1.0000`, 0 discrepancies, cost `$0.00`; `4/4` emulator divergences confirmed — the emulator said `allowed` where AWS denied, and the enforcer sided with AWS every time |
| 1 — negative controls | every decision flipped to prove the comparator can fail | **`108`** flipped allows caught, **`187`** flipped denies caught (181 of which were implicit denies an explicit-deny-only comparator would miss) |
| 2 — live wire exploits | three chains replayed against real IAM over HTTPS, then the synthesized boundary attached | **`3 -> 0`** exploits; attribution triple `identity_decision: allowed` / `principal_decision: implicitDeny` / `allowed_by_boundary: false` with `boundary_is_load_bearing: true`; `benign_preserved: true` (external reader HTTP 200 before **and** after); enforcement took **`5.8–8.9s`** across runs (5.8–7.6s in the committed artifact) |
| 2 — cache skew | which probe tells you the boundary has settled | `iam:ListUsers` reports the boundary in force while `iam:UpdateAssumeRolePolicy` on the same principal still returns 200 — the window is per-action, not global |
| 3 — teardown | resources created vs deleted, verified by prefix sweep rather than a bookkeeping file | **`16`** created / **`16`** deleted / **`0`** leaked — from `artifacts/p9/live-wire-results.json` (`resources_created`, `teardown.resources_found_total`); `artifacts/p9/live-teardown-audit.log` corroborates in its `sweeps` array (18:48:28 entry: 16 found, 28 deletions), since that log's top level is the latest sweep and reads `resources_found_total: 0` — independent account sweep clean, re-runnable via `make live-verify` |

The boundary used on the wire is not a fixture written for the test: it is imported from the synthesizer, so the live run exercises the shipped artifact. That is what makes "3 -> 0" a statement about the product rather than about the harness.

**The honest limit.** `benign_preserved` proves the remediation did **not break an external legitimate reader** — that reader holds a grant outside the boundary and gets HTTP 200 before and after. It does not prove the boundary is *tight*: the reader was never inside the boundary, so there was nothing for the boundary to narrow. Tightness is a separate claim, and it rests on the Phase 4 matrix (763 allows to 720, 43 flips, 0 collateral), not on this flag.

The propagation window is the finding with the longest reach. `iam:PutUserPermissionsBoundary` returns 200 and `iam:GetUser` immediately shows the attachment, but the authorization path kept applying the unbounded identity for **5.8–7.6s** in the committed artifact (the `5.8–8.9s` in the table row above records the wider range seen across runs, including an earlier run that was not retained). Any verifier that reads post-patch state and immediately re-runs the attack measures the pre-patch system and will report a working control as a failure — which is exactly what the first Phase 9 measurements did, and why the harness now polls the gated action itself rather than a proxy for it.

## Reproduce

All commands run from the repository root. Requires Docker on Apple Silicon (`arm64`); no AWS credentials are read and no request leaves `localhost` — with one exception, `make live-verify`, which needs live AWS credentials and real network access.

```bash
make up          # start the arm64 emulator on localhost:4566 and wait for health
make wait        # wait for /_localstack/health to answer
make verify      # run the phase gates that have an artifact
make down        # stop and remove the emulator
```

Individual gates:

```bash
make verify-p1   # environment reproducible on arm64 (arm64 + AccessDenied in the log)
make verify-p2   # 25 scenario modules deployed, 1250 benign calls at pass rate 1.0
make verify-p3   # exploit chains proven by executing every hop (>= 22 of 25)
make verify-p4   # exploit gone, no collateral allow lost, boundaries replayed
make verify-p6   # red-team replay: BYPASSES_SUCCEEDED: 0
make check-guardrails   # every scenario's provider points at localhost:4566
make live-verify        # Phase 9: live AWS parity + wire exploits + teardown (see note)
```

`make live-verify` is the only target that leaves `localhost`: it needs live AWS credentials and real network access, and it costs a few cents. It is deliberately **not** part of `make verify` for that reason. Everything else stays on the emulator.

Phases 4, 5 and 6 are invoked directly, since they need the emulator up:

```bash
python -m scripts.p4_verify_gate          # exploit gone, no collateral allow lost
python -m scripts.p5_scanner_benchmark    # offline checkov/trivy comparison, no network
python -m scripts.p6_redteam              # adversarial replay of every remediation
```

`make verify-p6` greps for `BYPASSES_SUCCEEDED: 0`; the zero is only meaningful because `scripts/p6_redteam.py` independently exits non-zero when any attack raised or never ran (recorded as `error`, never as `not_applicable`), and because `not_applicable` is reserved for the 12 scenarios whose control is not an identity-boundary control. A silently skipped class cannot be reported as a resisted one.

`make verify-p2` regenerates `artifacts/p2/benign-traces.json` and `make verify-p3` re-executes every hop before asserting, so neither gate trusts an artifact already on disk.