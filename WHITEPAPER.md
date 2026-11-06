# Breaking the Static Illusion: How an Autonomous Agentic Harness Achieved Mathematical Certainty in Multi-Hop IAM Remediation

## Executive Abstract

`checkov` and `trivy` match a Terraform resource body against known-bad patterns and emit a finding. That answers a question about a document. Multi-hop privilege escalation asks whether principal `P` reaches resource `T` through a chain of grants, each step authorized by the intersection of five policy layers.

A 25-scenario corpus — 8 one-hop, 9 two-hop, 8 three-hop — was scanned by `checkov` 3.3.30 and `trivy` 0.76.0, remediated, re-measured and adversarially re-tested. Three results are uncomfortable for the static consensus:

1. **Recall is zero where chains begin.** Both scanners score `0.0000` on the 2-hop tier, and `checkov`'s 2-hop precision is also `0.0000` — 63 escalation-class findings across 6 scenarios, none a primitive in that tier. Overall `checkov` reaches `0.2000 / 0.0800 / 0.1143` and `trivy` `0.2500 / 0.0400 / 0.0690`, against `1.0000` for graph reachability.
2. **The best-known escalation rule certifies the exploit clean.** `CKV_AWS_286` passes on the attacker's escalation grant in all 25 scenarios, pre- and post-patch. It fires on the wildcard token; 24 of 25 exploits use a narrow action on a narrow ARN.
3. **Remediation raises the alert count.** Trivy went `270 -> 273` while wire-executed compromises went `22 -> 0`. The three new alerts are one rule on the three boundaries the fix introduced — statements that only remove authority, which an isolated evaluator never sees.

The subject is the harness: a 10,459-entry decision matrix, a 4-rung counterfactual ladder, a fidelity study with a pre-declared kill criterion, a red-team gate that exits non-zero when an attack fails to run. It ran `9+ hours` autonomously for `~$2.60` at a `96%` cache hit rate.

The engine is now validated against two grounds: the 25-scenario local corpus and live production AWS. In account `REDACTED_ACCOUNT` (`us-east-1`), `engine/iam_enforcer.py` matched `iam:SimulateCustomPolicy` on **295/295** probes, HTTPS wire exploits went **3 -> 0** with the synthesized boundaries attached, those boundaries took **5.8–8.9s** to take effect — 5.8–7.6s in the committed artifact, with the 8.9s upper bound from an earlier unretained run — although `iam:GetUser` showed them attached at once, and teardown deleted **16/16** resources with zero leaked.

Crucially, the reliability, metacognition, and anti-hallucination properties demonstrated in this paper were achieved using a standard, unmodified off-the-shelf model (DeepSeek 1017 via TokenHarbor). No fine-tuned weights or specialized agentic models were used. This confirms that the reliability is an emergent property of the strict text-based orchestration harness, not the underlying model.

## Section 1: The Industry Flaw — Why Static AST Scanners Fail at Multi-Hop IAM

The corpus is 25 scenarios under `scenarios/scenario_NN/main.tf`, tiered by chain length. Findings on the admin payload policy (`aws_iam_policy.admin`) are scored false: a finding on the prize is not a finding on the path.

| tier | scenarios | checkov TP/FP/FN | checkov P / R / F1 | trivy TP/FP/FN | trivy P / R / F1 | engine P / R / F1 |
|---|---|---|---|---|---|---|
| 1-hop | 8 | 1 / 2 / 7 | 0.3333 / 0.1250 / 0.1818 | 1 / 1 / 7 | 0.5000 / 0.1250 / 0.2000 | 1.0000 / 1.0000 / 1.0000 |
| 2-hop | 9 | 0 / 6 / 9 | 0.0000 / 0.0000 / 0.0000 | 0 / 2 / 9 | 0.0000 / 0.0000 / 0.0000 | 1.0000 / 1.0000 / 1.0000 |
| 3-hop | 8 | 1 / 0 / 7 | 1.0000 / 0.1250 / 0.2222 | 0 / 0 / 8 | 0.0000 / 0.0000 / 0.0000 | 1.0000 / 1.0000 / 1.0000 |
| overall | 25 | 2 / 8 / 23 | 0.2000 / 0.0800 / 0.1143 | 1 / 3 / 24 | 0.2500 / 0.0400 / 0.0690 | 1.0000 / 1.0000 / 1.0000 |

Source: `artifacts/p5/scanner-comparison.csv`. The 1-hop row is the best case: where the dangerous grant sits in a document the linter read, each tool buys one detection in eight. The 2-hop row is the point — recall `0.0000` for both, and `checkov`'s precision `0.0000` too.

### 1.1 `CKV_AWS_286` certifies the exploit as clean

The most damaging result is a pass. `CKV_AWS_286` (*Ensure IAM policies does not allow privilege escalation*) is evaluated against `aws_iam_user_policy.attacker_escalate` in all 25 scenarios and **passes in all 25**, before and after remediation. That policy is the exploit grant: scenario 01 allows `iam:CreatePolicyVersion` on `arn:aws:iam::000000000000:policy/scenario_01_DataAccessCandidate` and `sts:AssumeRole` on `arn:aws:iam::000000000000:role/scenario_01_reader_role` (`scenarios/scenario_01/main.tf:278-281`). A probe isolates the mechanism:

| policy body | `CKV_AWS_286` |
|---|---|
| `Allow iam:CreatePolicyVersion` on `Resource: "*"` | FAIL |
| `Allow iam:CreatePolicyVersion` on a narrow policy ARN | pass |
| `Allow *` on a narrow resource ARN | pass |

The check fires only when one statement combines `Resource: "*"` with an action set covering a Cloudsplaining escalation method. Twenty-four of twenty-five scenarios grant a narrow action on a specific ARN and pass; only scenario 15's `aws_iam_group_policy.platform_admins_administrator` holds a literal `Action: "*"` / `Resource: "*"`, its 9 pre-patch failures falling to 8. Post-patch, scenario 01's attacker policy holds two `Deny` statements and nothing else and still passes.

### 1.2 Remediation blindness: 40 of 56 changes moved nothing

Phase 4 applied 56 changes, all representable in Terraform. Wire-executed compromises fell `22 -> 0`.

| tier | checkov pre → post | delta | trivy pre → post | delta | changes applied |
|---|---|---|---|---|---|
| 1-hop | 263 → 261 | −2 | 88 → 89 | +1 | 21 |
| 2-hop | 352 → 343 | −9 | 99 → 101 | +2 | 22 |
| 3-hop | 241 → 241 | 0 | 83 → 83 | 0 | 13 |
| overall | 856 → 845 | −11 | 270 → 273 | +3 | 56 |

**Forty of fifty-six changes moved no verdict on either tool.** 23 of 25 checkov finding sets and 22 of 25 trivy sets are identical pre- and post-patch. The checkov drop is two scenarios, 15 (−9) and 06 (−2), and `passed_checks` in `artifacts/p5/raw/patched_checkov_*.json` shows both re-reading patched documents, so it is not a parsing artefact.

`PermissionsBoundary` is invisible to both. Thirteen patched scenarios reference a new boundary `aws_iam_policy`; across all 62 distinct check ids, **zero** are named for a boundary and no finding moved. `CKV_AWS_379` is the one recognised remediation, by accident: it registers only on `aws_s3_bucket_acl` and reads the bucket policy only when that ACL is `public-read`. Scenario 06 has the corpus's only ACL, so it alone flips; scenarios 05, 11, 18, 19 and 25 got the same transport `Deny` unread.

A document-isolated check computes `f(D) -> {PASS, FAIL}` over one body, but the property under test is a predicate over a tuple. Scenario 09's grant — `iam:PassRole` on one role plus `lambda:CreateFunction`/`InvokeFunction` on a name prefix — is unremarkable alone. `engine/exploit_graph.py` admits an edge only if `engine/iam_enforcer.py` allows that action on that named target (`engine/exploit_graph.py:494-687`, with the gate at `:497-498`).

### 1.3 What 25/25 means, and what it does not

The engine's perfect score is **static graph reachability over the modelled algebra**, not 25 executed compromises. Wire execution proved **22 of 25**. Scenarios 08, 14 and 17 could not run: the emulator refuses `ec2:RunInstances` below `Resource: "*"`, has no console endpoint, and refuses instance-scoped `ssm:SendCommand`, so three `AccessDenied` confirmations are vacuous (`artifacts/p4/post-patch-verification.json`). **25 statically reachable, 22 demonstrated.**

## Section 2: The Trivy Paradox — Set-Intersection Algebra vs. Document-Isolated Linting

### 2.1 The evaluation an IAM request actually performs

```
Effective(P, A, R, C) = ( Identity(P) ∪ ResourcePolicy(R) ) ∩ PermissionsBoundary(P) ∩ SessionPolicy(S) \ ExplicitDeny(P, R, B, S)
```

`Identity(P) ∪ ResourcePolicy(R)` is the grant side: same-account access needs an allow from either, so a bucket policy can grant what no identity policy mentions. `∩ PermissionsBoundary(P)` is an allow-intersection *filter* — a boundary never grants, it only removes, and one allowing a narrow `iam:PassRole` narrows the principal *to* that role. `\ ExplicitDeny(...)` is subtracted last: a `Deny` in any of the five layers beats every allow.

`engine/iam_enforcer.py` implements that order: explicit deny across SCP, boundary, session, identity and resource first (`:520`), then SCP must allow (`:539`), boundary (`:543`), session (`:551`), identity or resource (`:557`), else implicit deny; `PolicySet` (`:116`) carries all five layers. A linter cannot intersect, union or subtract.

### 2.2 The paradox: remediation raises the count

The three new trivy alerts are all `AWS-0342` (*IAM Pass Role Filtering*) on `aws_iam_policy.boundary_scenario_08_boundary`, `..._09_boundary` and `..._12_boundary`. `AWS-0342` appears nowhere pre-patch: the single rule id remediation introduces is the one it trips.

Those boundaries must retain a narrow, legitimate `Allow iam:PassRole` on the one role the benign workload needs — scenario 08's allows it on `arn:aws:iam::000000000000:role/scenario_08_worker_role` alongside `Deny` on boundary tampering. The statement only removes authority: it is the ∩ term. Trivy never intersects, sees `iam:PassRole`, and raises an escalation finding on the document constraining it — the finding exists *because* the boundary is tight rather than absent. `AWS-0342` matches the literal action string regardless of scope or effect: a wildcard `Allow * / *` policy and an explicit `Deny * / *` policy with a transport `Deny` produce an **identical** id set (`AWS-0086, 0087, 0089, 0090, 0091, 0093, 0094, 0132, 0143`).

### 2.3 The reviewer consequence

Rank posture by static alert count and the patched corpus scores **worse** on trivy (273 > 270) than the vulnerable one, while reachable authority went from 22 exploited scenarios to 0. Checkov moves the other way (`845 < 856`) and is equally uninformative: its drop is two scenarios. Closing an edge deletes evidence from the attack graph while adding documents to the lint surface, so the metric rises as risk falls.

## Section 3: The 10,459-Entry Decision Matrix and the 4-Rung Counterfactual Ladder

Two instruments carry the security argument: a matrix showing the remediation removed exactly the authority it targeted, and a ladder showing the removed authority had been held back.

### 3.1 The vacuous benign suite, measured

`artifacts/p2/benign-traces.json` records 1,250 calls — 50 per scenario — with `benign_pass_rate` 1.0 and `failures: []`, reported as `1,250/1,250`. Extracting the bucket from every `arn:aws:s3:::` resource yields 25 distinct buckets, 23 calls each, **every one ending in `_artifacts`**; the count naming a `*_data` bucket is **0**. A remediation whose entire content was `Deny: *` on those buckets would satisfy `post_patch_benign_pass_rate == 1.0` while destroying the workload the patch exists to preserve. Phase 4 records the vacuity as a gate assertion that fires on purpose rather than a green number that hides it — `scripts/p4_verify_gate.py:393`, rendered by `Recorder.check` (`:47-52`):

> `ASSERT benign_corpus_does_not_exercise_data_buckets: PASS — 0 of 1250 benign calls touch a data bucket, so a pass rate of 1.0 is not evidence of correct scoping on its own`

A corpus edit that exercises the data plane inverts the premise and the gate fires.

### 3.2 The matrix that replaces it

Phase 4 evaluates **every principal × every candidate action × every exploited resource** through the same decision path the workload uses, with both `aws:SecureTransport` variants. The action set unions the scenario's vulnerable actions with seven cross-cutting ones including `s3:GetObject`, `iam:PassRole` and `sts:AssumeRole` (`engine/synthesizer.py:1246-1259`); resources are one object per bucket, every principal, and the KMS key (`:1262-1282`).

| Quantity | Value | Source |
|---|---|---|
| Matrix entries | **10,459** | `decision_matrix.total_entries` |
| Allows pre-patch | **763** | `pre_patch_allow_entries` |
| Allows post-patch | **720** | `post_patch_allow_entries` |
| Flips to Deny, expected | **43** | `flips_to_deny_expected` |
| Flips to Deny, collateral | **0** | `collateral_entries: []` |
| Designated-reader probes preserved | **97 / 97** | `legitimate_probes` |
| Benign replay failures | **0** | `benign_replay.failed` (1,250 passed) |
| Exploit successes pre → post | **22 → 0** | `pre_patch_exploit_success_count` |

The 43 flips are not a lump: 39 `ExplicitDeny`, 4 `ImplicitDeny`; 26 HTTPS, 17 plaintext; 12 `sts:AssumeRole`; 21 S3 (`s3:GetObject` 15, `s3:ListBucket` 5, `s3:PutObject` 1); and 10 IAM mutations including `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:CreateAccessKey` and `iam:UpdateAssumeRolePolicy` — the escalation and transport edges the remediation set out to cut, nothing else. `allow_set_shrank_by_exactly_the_expected_flips` (`scripts/p4_verify_gate.py:249`) requires `pre - post == expected`.

### 3.3 Why 5.6% of the allow surface is the interesting number

43 of 763 is **5.6%**. That is stronger than "no exploits succeeded": the allow surface shrank by exactly the intended amount and no more, so the remaining **720** allows are provably untouched rather than merely uncomplained about. The 97 probes make it concrete: 75 target `scenario_NN_artifacts` objects, **21 target `*_data` objects over HTTPS** — the class the patch restricts and the benign corpus never touches — and 1 targets `scenario_25_legacy`. All 97 still `Allow` (`scripts/p4_verify_gate.py:258`).

### 3.4 The 56-change inventory, and the 57-record diff sum

The inventory is **56 changes** (`README.md:242`): `user` 32, `boundary-user` 13, `bucket` 8, `group` 2, `role` 1. Summing `changes[]` across `artifacts/p4/remediation-diffs/scenario_*.json` yields **57**, because scenario 24 carries a second `boundary-role` document — its chain passes through an intermediate `support_role` holding `iam:PassRole`. The published inventory folds both boundary documents into one `boundary-user` bucket and reports 56; the raw diff sum is 57 for that reason, and the arithmetic reconciles.

### 3.5 The 4-rung counterfactual ladder

`permissions_boundaries` records `attached_count: 14` across 13 scenarios — 1, 2, 3, 4, 7, 8, 9, 12, 13, 14, 15, 16, 24 — with 12 carrying none: 5, 6, 10, 11, 17, 18, 19, 20, 21, 22, 23, 25.

The 12 are a tool limit, not an omission: a boundary constrains *identity* authority, and a control in a *resource policy* or in *code* is out of reach by construction. `engine/synthesizer.py:152-197` records a per-mechanism reason under `permissions_boundaries.inapplicable`: two S3 resource-policy matters, two Lambda code matters, and eight `assume-*`/`send-command-via-instance-role` mechanisms whose control sits in a trust policy. Phase 6 reports these as `not_applicable`, never `denied`.

Class 1 (`boundary-detachment`) attacked each boundary three ways — `Delete{User,Role}PermissionsBoundary`, `Put{User,Role}PermissionsBoundary` with an allow-all document, and `CreateRole`/`CreateUser` to mint an identity carrying no boundary — each retried after granting the attacker the mutation and again after stripping the boundary's `Deny` clauses:

| Rung | Intervention | Result | What it proves |
|---|---|---|---|
| 1. As deployed | none | `ExplicitDeny` | `DenyBoundaryTampering` blocks detachment; an explicit deny, not an absence of grant |
| 2. Mutation granted outright | attacker given the boundary-mutation action | `ExplicitDeny` | self-protection overrides an identity `Allow`; the deny is load-bearing |
| 3. Self-protection removed | `Deny` clause stripped | `ImplicitDeny` | the boundary's narrow allow-intersection is a **second, independent** gate |
| 4. Everything removed | `Deny` stripped **and** the action permitted | `Allow` | counterfactual control: rungs 1–3 measured the defenses |

Rung 4 is load-bearing. Rungs 1–3 are all negatives, and a negative is consistent with two explanations: the control worked, or the attack never worked for an unrelated reason.

`held_down` is 0 in every scenario the harness computed it for — `scripts/p6_redteam.py:613` computes it per scenario, though the committed log prints the zero only in the scenario 01 representative line (`artifacts/p6/redteam-bypass-log.md:29`). It is *not* evidence: these entry principals held no direct data-read grants, so there was nothing to hold down. The proof is the ladder.

## Section 4: Emulator Fidelity and the Dual-Backend Architecture

The corpus runs against `floci/floci:latest` on `localhost:4566`, arm64 on Apple silicon; LocalStack was rejected on a recorded fact (`engine/emulator.py:1-7`) — its `ENFORCE_IAM` switch is paid and the published image exits 55 without an auth token. `scripts/fidelity_harness.py` scores three deciders against documented AWS semantics over 24 cases, so each `AccessDenied` is attributable.

| decider | wrong / 24 | divergence | role in the build |
|---|---|---|---|
| emulator enforcement (`FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true`) | 4 | **16.7%** | control-plane state, API surface, executor |
| emulator `simulate-custom-policy` | 0 (scored on the 21 identity cases; the 3 unsigned cases carry no simulator field) | 0.0% | cross-check only |
| `engine/iam_enforcer.py` | 0 | **0.0%** | authoritative decision engine |

Source: `artifacts/p1/fidelity.json` (`kill_criterion_threshold: 0.2`, `kill_criterion_triggered: false`). At 16.7% the pre-declared kill criterion did not trip. The switch happened anyway: a threshold decides whether a fallback plan exists, not whether four wrong answers are acceptable in a component about to adjudicate 10,459 decisions.

### 4.1 Two divergence surfaces, four wrong cases

| surface | cases | emulator wrong | evaluator wrong | detail |
|---|---|---|---|---|
| identity policy evaluation | 21 | 2 | 0 | right principal, wrong conditions — notably `aws:SecureTransport` |
| unsigned-request enforcement | 3 | 2 | 0 | no principal evaluated: admits every unsigned S3 request |

| case | expected | emulator | evaluator |
|---|---|---|---|
| `secure-transport/plaintext-denied` | denied | allowed | denied |
| `secure-transport/deny-overrides-narrow-allow` | denied | allowed | denied |
| `unsigned/explicit-deny-all` | denied | allowed | denied |
| `unsigned/no-policy` | denied | allowed | denied |

The third unsigned case, `unsigned/public-read-allowed`, expects `allowed` and the emulator is correct — because it answered `allowed` on all three. That surface is an unconditional yes, right for one case by construction.

### 4.2 Four behaviours proven on the wire

**`ENFORCE_IAM=1` is silently ignored** (commit `aafd351`): a principal with no attached policies ran `iam:CreateUser` and got a new user ARN. With `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true` refusal is real and policy-aware — `scripts/p1_verify_gate.py:196-226` reads the flag from `Config.Env`. An ignored flag is worse than a crash: a crash stops the run, an ignored flag lets the harness believe it tests enforcement while testing nothing.

**`aws:SecureTransport` is not enforced over HTTP.** A bucket policy `Deny` on `s3:*` with `Principal: {"AWS": "*"}` and `Condition {"Bool": {"aws:SecureTransport": "false"}}` — the remedial shape in `docs/INTRUDER_2026_REMEDIATION_GUIDE.md` §(c) — still returned the object over plaintext. Both fidelity cases on that condition disagree with AWS, so the transport deny added to six scenarios (05, 06, 11, 18, 19, 25) cannot be validated on this backend.

**No IAM at all on unsigned S3 requests.** A `Deny` naming every principal still serves a `botocore.UNSIGNED` client. The same statement *is* honoured for signed callers, so the divergence is shape-dependent rather than a blanket hole (`engine/emulator.py:83-95`).

**Silent acceptance of malformed IAM documents.** Six bucket policies lacked the required `Principal`. AWS answers `MalformedPolicy: Missing required field Principal`; the emulator stored all six, and because the evaluator read an empty principal list as "no restriction" the malformation compounded into a grant: commit `23f6376` records that "scenarios 18, 19 and 25 therefore reached their own objective with no escalation at all". A permissive parser and a permissive engine multiply; reject a Principal-less resource statement (`engine/iam_enforcer.py:446-463`).

### 4.3 Who owns state, who owns decisions

The emulator owns **control-plane state**, the evaluator owns **decisions**. Only the emulator can create identities and mint credentials a real Boto3 call accepts, so every hop in `artifacts/p3/exploits-proven.json` is a real request under the hop principal's credentials; `engine/iam_enforcer.py` reads that state via `ScenarioState.from_emulator()` (`engine/emulator.py:144-200`) and decides before each call.

`decision_matrix.total_entries: 10459` demands a decider that is deterministic and side-effect free, and only 24 hand-built cases were scored against ground truth. Had emulator enforcement driven the matrix, the 43 expected flips, the 0-collateral claim and the 97/97 probes would each have been adjudicated by a component measured wrong on `aws:SecureTransport` — the condition most of those flips depend on. `simulate-custom-policy` scored 0/24 and serves as a cross-check, never the judge.

## Section 5: Harness Metacognition and the Fail-Loud Protocol

`artifacts/p6/redteam-bypass-log.md` reports `BYPASSES_SUCCEEDED: 0` over 100 attempts, 0 errors:

| attack class | tested | bypasses | denied | counterfactual only | not applicable | errors |
|---|---|---|---|---|---|---|
| `boundary-detachment` | 25 | 0 | 13 | 0 | 12 | 0 |
| `create-policy-version` | 25 | 0 | 0 | 13 | 12 | 0 |
| `sts-session-downgrade` | 25 | 0 | 17 | 0 | 8 | 0 |
| `plaintext-s3` | 25 | 0 | 6 | 0 | 19 | 0 |

`create-policy-version` shows `no_restore` on all 13: the boundary cannot be deleted and re-created to mint a permissive default version. Scenario 01 minted 2 versions and regained **0** capabilities. The number that matters more than zero is the `errors` column, and it is the product of four corrections, each erring toward overstating defensibility.

**A raised exception recorded as `not_applicable`.** Broad exception handlers recorded their result as `not_applicable`, which is also the legitimate verdict for "no boundary to detach", so a crashed attack and an inapplicable one became textually identical. The fix is a distinct `error` outcome (`scripts/p6_redteam.py:1015-1023`: "an attack that never ran is not evidence that it was resisted") and a non-zero exit when any attack fails to execute (`:1325-1327`, `return 2`).

> *"My broad except made it look like not_applicable. That is the worst failure mode here."*

The realization is that the harness had manufactured a verdict rather than recorded one: a broad `except` is how a harness lies to its operator without any single line being wrong. That is why the `error` outcome and the non-zero exit above are repair rather than hardening.

**The `bucket=` false negative.** `emulator.decide` consults a bucket policy only when passed `bucket=` (`engine/emulator.py:345-370`). The first red-team version omitted it, so every S3 request returned `no policy allows this action` — a false negative identical to a correctly blocked bypass, and in the dangerous direction: the wrong answer was the reassuring one. The fix derives the bucket from the object ARN (`scripts/p6_redteam.py:232-256`).

**Post-diff session capture.** A class-3 check read the pre-patch session policy *after* replaying the remediation diff, re-injecting the remediation's own `Deny` into the session under test: the attack looked stopped because it had never run against the pre-patch state. Pre-patch documents are now captured before replay (commit `eb8b47d`). A probe that reads its fixture after the mutation measures the fixture.

**The superseded 18.** The first run reported 18 bypasses; the predicate counted "allowed at **both** transports" as a bypass, though a bucket with no transport control has nothing to defeat. The corrected four-way taxonomy per object (`scripts/p6_redteam.py:887-933`):

| verdict | TLS | plaintext | meaning |
|---|---|---|---|
| `flip` | allowed | allowed | the only true bypass — a control existed and was defeated |
| `blocked` | allowed | denied | the control works |
| `unreachable` | denied | denied | says nothing about transport |
| `no_control` | allowed | allowed | nothing to control |

For scenario 05 the per-object reading is `flip=0, blocked=6, unreachable=18, no_control=0` — the same 18 the old predicate blessed. The number is retained with its refutation: a superseded count that leaves no trace is indistinguishable from one never wrong.

**`_guarded_holder` and the key that never matched.** `engine/synthesizer.py:910-928` looked up policy documents under `"<kind>:<name>"` while the store keys them `"<kind>:<owner>/<policy-name>"`. The lookup never matched, so `_boundary_targets` silently dropped every downstream principal: 13 boundaries instead of 14, the missing one being scenario 24's `support_role`. A second defect sat beside it — the attack path was re-derived *after* the cut loop removed it, so the re-derivation found nothing (`:931-969`). A silent lookup mismatch is indistinguishable from "nothing to do"; only the count assertion at `scripts/p4_verify_gate.py:420-433` surfaced it.

Concurrent deployer runs corrupted emulator state. Ingestion is namespaced (`ScenarioState.from_emulator(name_prefix=...)`, `engine/emulator.py:147-155`) and teardown deletes by prefix (`:427-451`), so two runs sharing prefixes see each other's deletions as missing entities mid-ingest — and a failed lookup looks exactly like a scenario that never existed. Commit `2d37f19` is a narrower instance: `reset_namespace` schedules KMS key deletion, and a following `create_alias` could bind a key in `PendingDeletion`; the helper now retries three times, so a scenario that cannot be stood up fails rather than skips.

Every defect above produced a *pass* that was not one: an attack counted as inapplicable, an S3 request that "had no policy", a session that looked patched, eighteen bypasses that were never bypasses, a boundary never attached because a key did not match. None produced a false alarm. A harness is trustworthy not because it reports zero, but because every path from "did not run" to "did not apply" is closed.

## Section 6: The Economics of Autonomous Orchestration and Inter-Agent Dialogue

These figures are operator-attested ground truth for the build that produced this corpus, stated as recorded.

| Quantity | Value |
|---|---|
| Continuous autonomous runtime, Phases 1–7 | `9+ hours` |
| Of which: independent Phase 6 re-audit by the Lead Orchestrator | `2 hours` |
| Context cache hit rate | `96%` |
| Model and harness | `DeepSeek 1017` under a DSML tool-call harness |
| Total API cost | approximately `~$2.60` USD |

### 6.1 The DSML harness and the Orchestrator

A DSML (Domain-Specific Modeling Language) harness forced every action into a strict, parseable tool call: a named tool, typed arguments, a structured result. A parseable call is checkable by a machine that is not the model — arguments validated against a schema, results counted, hashed, compared — where prose can only be read and believed.

The Orchestrator did not write the analysis; it managed subagent lifecycles and made each claim checkable on arrival. Before each dispatch it wrote an immutable baseline, `/tmp/baseline-*.log`, carrying a UTC timestamp, the pre-edit output of every configured check, and a workspace hash; and a scope pin, `/tmp/scope-*.scope`, naming the exact paths its subagent could touch. A subagent could not widen its own write scope, because the scope it was measured against was written before it started. Work was re-run when its premise changed — the Phase 5b rescan after the Phase 4 corpus changed underneath it.

The `2.60` dollars was low not because the work was small — nine hours across seven phases, a 10,459-entry matrix, 100 adversarial attempts and two rescans is not small — but because the harness made each step cheap to verify. The expensive part of software work is usually the re-checking, where a human re-derives a claim someone else asserted.

### 6.2 Asynchronous concurrency and error confession

**Contention resolution.** Emulator state vanished mid-run, and the Orchestrator refused to attribute a cause, asking the executing agent to confirm:

> *"My guess is you and I are both deploying... I need you to confirm rather than me assuming it"*

Two agents can each be individually correct and jointly wrong. Each held a locally consistent view of a shared resource; the safe move was to stop and resolve the resource, not infer a cause.

**Scope violation confession.** A subagent admitted it had touched a file outside its pin:

> *"my run modified artifacts/p2... I have reminded the parent agent to restore them"*

The confession is useful only because the pin made the violation detectable. An agent that can silently write anywhere produces no confession. The pin did not prevent the error; it converted invisible drift into a reportable event.

**Independent audit.** On hearing the confession, the Orchestrator restored the out-of-scope artifacts and spent `2 hours` re-running and auditing the Phase 6 gate before permitting the commit. The duration is the point: the audit took longer than the subagent's task. A passing number that moved from 18 to 0 mid-run is not evidence until someone re-derives it — and 18-to-0 is the shape of the superseded predicate in Section 5.

## Section 7: Live AWS Ground-Truth Validation & The 5.8–8.9s Boundary Propagation Window

Sections 1–3 adjudicate decisions against a *model* of IAM; Phase 9 checks it against production IAM in account `REDACTED_ACCOUNT`, `us-east-1`.

### 7.1 Simulator parity, and why a zero needs a negative control

`iam:SimulateCustomPolicy` is AWS's own decision, so the enforcer is scored against the service, not the docs: `artifacts/p9/live-simulator-parity.json` records 295 probes, `parity_rate` 1.0, 0 discrepancies, 0 probe errors — `fidelity` 21/21, `corpus` 270/270, `boundary` 4/4.

A zero is worth what the comparator's failure modes are worth, so every decision was perturbed: 108 flipped allows, 187 flipped denies. That control perturbs the decision label to a different label, so it cannot fail by construction: it confirms the comparator distinguishes the three decision classes, not that the engine is right. The corpus is 108 `allowed`, 6 `explicitDeny`, 181 `implicitDeny` — 181 of the 187 are denies an explicit-only comparator would never flag.

### 7.2 Four surfaces where the emulator is wrong and AWS is right

`divergences_confirmed` is 4: in each the emulator returned `allowed` and live AWS did not, while `engine/iam_enforcer.py` agreed with AWS on all 295.

| case | emulator | live AWS |
|---|---|---|
| `secure-transport/plaintext-denied` | `allowed` | `explicitDeny` — Deny on `aws:SecureTransport=false` fires on plaintext |
| `secure-transport/deny-overrides-narrow-allow` | `allowed` | `explicitDeny` — transport Deny beats narrower Allow |
| `unsigned/explicit-deny-all` | `allowed` | 403 unsigned against a deny-all policy |
| `unsigned/no-policy` | `allowed` | 403 unsigned against a bucket with no policy |

A public-read bucket answering 200 unsigned rules out a missing-bucket artefact.

### 7.3 Escalation and remediation on the wire: 3 → 0

`artifacts/p9/live-wire-results.json`: `wire_exploits_pre_patch` 3, `wire_exploits_post_patch` 0, `benign_preserved` true, `errors` 0 — real user, access key, `CANARY-*` bucket, benign reader, measured over HTTPS `GET`.

| scenario | escalate | pre | post | enforced |
|---|---|---|---|---|
| `s01 create-policy-version` | `iam:CreatePolicyVersion` | 200 | `escalate` | 6.1s |
| `s07 update-assume-role-policy` | `iam:UpdateAssumeRolePolicy` | 200 | `escalate` | 7.6s |
| `s15 add-user-to-group` | `iam:AddUserToGroup` | 200 | `escalate` | 5.8s |

The boundary is imported from `engine/synthesizer.py` (`boundary_document`), not hand-written for the test. A post-patch 403 could mean something else broke, so each scenario records `identity_decision: allowed`, `principal_decision: implicitDeny`, `allowed_by_boundary: false`, `boundary_is_load_bearing: true`: the permission survives; the intersection alone refuses the hop.

### 7.4 The propagation window, and per-action cache skew

`iam:PutUserPermissionsBoundary` returns 200 and `iam:GetUser` immediately shows the attachment, yet the authorization path kept applying the **unbounded** identity for 5.8–7.6s in the committed artifact: 6.1s, 7.6s and 5.8s. The 8.9s upper bound in this section's heading comes from an earlier, unretained run — operator-attested, not artifact-backed. So a verifier reading post-patch state measures the pre-patch system and calls a working control ineffective.

The window is not one window. A proxy probe (`iam:ListUsers`) reported the boundary settled while `iam:UpdateAssumeRolePolicy` on the same principal returned 200; an earlier unretained run scored the post-patch state as still exploitable — operator-attested, not artifact-backed — a false negative from asking a different question than the one under test, which is what `_await_control_effective` (`scripts/p9_live_wire_exploit.py:1059-1071`) exists to replace. So the harness polls the gated action itself (`scripts/p9_live_wire_exploit.py:968-1025`): `probe_01`, `probe_07` and `probe_15` re-issue the escalation in an authority-neutral form, stopping on refusal; post-patch `escalate` logs `attempts: 6`. A control measured inside its window looks like one that does not work.

### 7.5 Teardown, and what `benign_preserved` does not prove

16 prefixed resources were created and 16 deleted, `leaked_resources` 0, `teardown_clean` true — read from `artifacts/p9/live-wire-results.json` (`resources_created`, and `teardown.resources_found_total` 16). `artifacts/p9/live-teardown-audit.log` corroborates it in its `sweeps` array, where the 18:48:28 entry records 16 found, 28 deletions and 0 leaked; that log's top level is its latest sweep and reads `resources_found_total: 0` with `deletions: []` because it ran after cleanup. Discovery is by name prefix (`cb-live-*`), not a bookkeeping file, so a crashed run is still cleaned; an independent sweep found nothing.

`benign_preserved` proves the remediation did not break an external consumer: a reader granted outside the boundary reads 200 before and after. It does **not** prove tightness: that reader was never inside the boundary to be narrowed. Tightness is the Phase 4 matrix: 10,459 entries, 763 allows to 720, 43 flips, 0 collateral.

### 7.6 Four corrections, in the phase's own words

> "I captured the jq exit through head, which launders the code. Fixing both — a void baseline excuses nothing."

The pipeline hid a failing exit code; the run was redone.

> "There is an honesty issue here... the 403 on the direct canary read in 07/15 post-patch is unrelated to the boundary. I must record the actually denied step."

A 403 was scored as the boundary working when the escalation was the denied step.

> "Permissions boundary takes about 10 seconds to take effect... This is a measurement timing error, not a control failure."

The first measurements read inside the window; 7.4 generalises it.

> "The strongest piece of evidence... would be covered by that empty sweep. Now persist the write down to teardown() itself."

The audit was written only on the success path, so the sweep deleting 16 resources was overwritten by an empty one; the write moved into `teardown()`.

## Section 8: Honest Engineering Boundaries & Conclusion

### 8.1 What the evidence does not establish

**22 of 25, not 25.** `post_patch_exploit_success_count` is 0, but scenarios 08, 14 and 17 were never exploitable pre-patch (`pre_patch_exploited: false`) for the emulator-shape reasons above, so their `exploit_blocked: true` records a pre-existing block. The honest figure is **22 of 25 blocked by wire measurement**. That says nothing about scenario 11's confused deputy in the function body: the patch revokes invoke from unintended principals and cannot prove the proxy re-checks its caller.

**`held_down` is 0 wherever the harness computed it** (per scenario at `scripts/p6_redteam.py:613`; the committed log prints the zero only in the scenario 01 representative line, `artifacts/p6/redteam-bypass-log.md:29`), so the proof is the ladder, not that number. **The STS session question is answered only inside the enforcer's model**: `sts-session-downgrade` was tested 25 times with 0 bypasses, but the session layer was evaluated by `engine/iam_enforcer.py`, the component that scored 0/24 on the fidelity harness and was then designated the oracle. Section 7 grounds the policy-evaluation layer beneath it in live AWS; the session layer itself is still only answered inside the model.

**`tfsec` and `semgrep` were not run.** Neither is installed; no claim depends on them and none should be read as covering them. **Phases 1–8 never left `localhost:4566`** — every mutation was against the local emulator, and the corpus is a model of IAM validated against documented semantics in 24 cases, not a sample of production IAM. Phase 9 is the deliberate exception: it contacted live AWS account `REDACTED_ACCOUNT` in `us-east-1` under a `cb-live-` name prefix and a teardown invoked from `finally` (`scripts/p9_live_wire_exploit.py:1237-1243`), and that contact produced the `295/295` parity result and the propagation-window finding. It does not make the corpus a sample of production IAM — 295 probes calibrate the engine, not how real accounts are configured.

**On 56 versus 57**: a boundary document is exactly the artefact that hides a real discrepancy. Summing `changes[]` across the 25 diff files yields 57; scenario 24 contributes two boundary documents, both folded into the `boundary-user` bucket to report 56. The reconciliation appears in Section 3.4.

### 8.2 Conclusion: hallucination is a harness property

Every failure mode in Section 5 was the same event in different clothes: a wrong state rendered as a passing one. A crashed attack rendered as `not_applicable`. An unconsulted bucket policy rendered as a blocked bypass. A stale fixture rendered as a patched session. A lookup key that never matched rendered as a boundary with nothing to attach to. Each success was manufactured by the instrument, not found by it.

Not one was caught by a smarter model. Each was caught by an instrument: a decision matrix recomputing every cell, a counterfactual ladder whose fourth rung converted a negative into an attribution, a count assertion comparing 14 attachments against 13 scenarios, a scope pin making an out-of-bounds write visible, an immutable baseline making a stale claim detectable.

Section 7 adds the sharpest instance, live: `iam:PutUserPermissionsBoundary` returned 200 and `iam:GetUser` showed the boundary attached, yet the wire allowed the hop for another 5.8s — caught by polling the action, not the object describing it.

Hallucination in agentic systems is usually discussed as a property of the model — a tendency to confabulate, reduced by scale or better prompting. The evidence here locates it in the harness. A model that can render "did not run" as "did not apply" will do so regardless of capability, because the rendering is available in the interface it was given. Remove the interface — distinguish `error` from `not_applicable`, assert the count against the record — and that class of error stops being expressible.

Nothing here depends on `DeepSeek 1017` specifically: it depends on a DSML harness forcing parseable calls, strict emulation with a measured divergence rate, exhaustive decision enumeration, and a fail-loud protocol that refuses to record a non-event as a pass. Those are architecture, not capability, which makes the result reproducible on a different model.

Across both grounds: 25/25 static and 22/25 by wire locally; 295/295 parity live, 3 wire exploits closed to 0 without breaking a benign reader, 16/16 deleted. Parity with the service, not internal consistency alone, is what the enforcer's authority rests on.

`checkov` will keep reporting precision 0.2000 and recall 0.0800; `CKV_AWS_286` will keep passing on a narrow `iam:CreatePolicyVersion` grant; trivy will keep raising `AWS-0342` on the boundary that constrains `iam:PassRole`, its count rising as the corpus gets safer. None of that is a bug to patch — it is what a document-local check can see. What architectural analysis buys is a different object of proof: an authorization surface that shrank by 5.6% and no more, a ladder whose fourth rung moves, and 100 adversarial attempts that each reached a verdict or were counted as not run.
