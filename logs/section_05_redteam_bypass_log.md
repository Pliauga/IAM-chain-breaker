# Phase 6 — red-team bypass log

Adversarial replay of the 25 Phase 4 remediations.

Each scenario is redeployed from scratch, its recorded remediation diff is replayed through the same path `scripts/p4_verify_gate.py` uses, and the four contract attack classes are then run against the patched state.

**BYPASSES_SUCCEEDED: 0**

```
BYPASSES_SUCCEEDED: 0
```

## Summary per attack class

| Attack class | Scenarios tested | Bypasses | Denied | Counterfactual only | Not applicable | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| `boundary-detachment` | 25 | **0** | 13 | 0 | 12 | 0 |
| `create-policy-version` | 25 | **0** | 0 | 13 | 12 | 0 |
| `sts-session-downgrade` | 25 | **0** | 17 | 0 | 8 | 0 |
| `plaintext-s3` | 25 | **0** | 6 | 0 | 19 | 0 |

### `boundary-detachment`

Tested on 25 scenario(s); the attack reached a decision in 13 and was structurally inapplicable in 12; 0 succeeded. Judge: iam_enforcer.

- **Method attempted:** Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses
- **Method attempted:** delete / replace / route around the permissions boundary
- **Observed:** 13 × `denied`, 12 × `not_applicable`
- **Representative result (scenario 01):** 1 boundary holder(s); user/scenario_01_attacker[attached=True; as-deployed delete=ExplicitDeny (explicit deny in permissions-boundary policy), put=ExplicitDeny; granted the mutation: real-boundary=ExplicitDeny, Deny-stripped=ImplicitDeny, Deny-stripped-and-permitted=Allow]; as-deployed prerequisites refused: delete 1/1, put-allow-all 1/1, unbounded-mint refused; counterfactual (attacker granted the mutation outright): with the boundary attached the swap was denied in 1/1 case(s); removing only the boundary's Deny clause still left it denied in 1/1 (the narrow allow-list is a second gate); removing the Deny *and* permitting the action -- i.e. the boundary the attacker wants -- admitted the swap in 1/1; performing the allow-all swap restored the removed capability in 0/1; unbounded-mint when granted: real boundary=ExplicitDeny, permitted boundary=Allow; runtime capabilities the boundary narrowed away (probe-visible): 0; minted role+user -> created

### `create-policy-version`

Tested on 25 scenario(s); the attack reached a decision in 13 and was structurally inapplicable in 12; 0 succeeded. Judge: iam_enforcer (authorization) + Prover (exploit restoration).

- **Method attempted:** CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy
- **Method attempted:** mint a permissive default version of a namespace managed policy
- **Observed:** 13 × `no_restore`, 12 × `not_applicable`
- **Representative result (scenario 01):** 4/4 prerequisite call(s) denied (e.g. explicit deny in identity policy); counterfactual: minted 2 version(s), regained 0 capability(ies), exploit restored=False

### `sts-session-downgrade`

Tested on 25 scenario(s); the attack reached a decision in 17 and was structurally inapplicable in 8; 0 succeeded. Judge: iam_enforcer.

- **Method attempted:** hold a credential issued before the patch and exercise the removed hop
- **Method attempted:** replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot)
- **Observed:** 17 × `denied`, 8 × `not_applicable`
- **Representative result (scenario 01):** 1 removed hop(s); current-identity reading: 1/1 denied (explicit deny in identity policy); frozen-snapshot reading: 1/1 still allowed (model divergence, not counted as a bypass)

### `plaintext-s3`

Tested on 25 scenario(s); the attack reached a decision in 6 and was structurally inapplicable in 19; 0 succeeded. Judge: iam_enforcer.

- **Method attempted:** s3:GetObject with aws:SecureTransport=false, as entry user and as every role
- **Observed:** 6 × `denied`, 19 × `not_applicable`
- **Representative result (scenario 05):** 24 (principal, object) read(s) at both transports: flip(TLS allow -> plaintext allow)=0, blocked by the transport Deny itself=6, denied for another reason (transport control did not fire)=18, allowed at both (bucket carries no transport control)=0; deny reasons: ['explicit deny in resource policy', 'no policy allows this action (TLS also denied)']

## Attempt table

| Scenario | Attack class | Method | Judge | Outcome | Note |
| --- | --- | --- | --- | --- | --- |
| 01 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 01 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 01 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 01 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 02 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 02 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 02 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 02 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 03 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 03 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 03 | `sts-session-downgrade` | hold a credential issued before the patch and exercise the removed hop | iam_enforcer | **not_applicable** |  |
| 03 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 04 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 04 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 04 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 04 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 05 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 05 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 05 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 05 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **denied** |  |
| 06 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 06 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 06 | `sts-session-downgrade` | hold a credential issued before the patch and exercise the removed hop | iam_enforcer | **not_applicable** |  |
| 06 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **denied** |  |
| 07 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 07 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 07 | `sts-session-downgrade` | hold a credential issued before the patch and exercise the removed hop | iam_enforcer | **not_applicable** |  |
| 07 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 08 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 08 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 08 | `sts-session-downgrade` | hold a credential issued before the patch and exercise the removed hop | iam_enforcer | **not_applicable** |  |
| 08 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 09 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 09 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 09 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 09 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 10 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 10 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 10 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 10 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 11 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 11 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 11 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 11 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **denied** |  |
| 12 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 12 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 12 | `sts-session-downgrade` | hold a credential issued before the patch and exercise the removed hop | iam_enforcer | **not_applicable** |  |
| 12 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 13 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 13 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 13 | `sts-session-downgrade` | hold a credential issued before the patch and exercise the removed hop | iam_enforcer | **not_applicable** |  |
| 13 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 14 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 14 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 14 | `sts-session-downgrade` | hold a credential issued before the patch and exercise the removed hop | iam_enforcer | **not_applicable** |  |
| 14 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 15 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 15 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 15 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 15 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 16 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 16 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 16 | `sts-session-downgrade` | hold a credential issued before the patch and exercise the removed hop | iam_enforcer | **not_applicable** |  |
| 16 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 17 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 17 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 17 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 17 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 18 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 18 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 18 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 18 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **denied** |  |
| 19 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 19 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 19 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 19 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **denied** |  |
| 20 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 20 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 20 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 20 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 21 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 21 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 21 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 21 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 22 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 22 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 22 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 22 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 23 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 23 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 23 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 23 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 24 | `boundary-detachment` | Delete{Prefix}PermissionsBoundary, Put{Prefix}PermissionsBoundary(allow-all) and CreateRole/CreateUser without a boundary, each retried after granting the attacker the mutation and after stripping the boundary's own Deny clauses | iam_enforcer | **denied** |  |
| 24 | `create-policy-version` | CreatePolicyVersion(allow-all) + SetDefaultPolicyVersion on every namespace managed policy | iam_enforcer (authorization) + Prover (exploit restoration) | **no_restore** |  |
| 24 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 24 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **not_applicable** |  |
| 25 | `boundary-detachment` | delete / replace / route around the permissions boundary | iam_enforcer | **not_applicable** |  |
| 25 | `create-policy-version` | mint a permissive default version of a namespace managed policy | iam_enforcer | **not_applicable** |  |
| 25 | `sts-session-downgrade` | replay removed hop with a pre-patch session policy (and with a frozen pre-patch identity snapshot) | iam_enforcer | **denied** |  |
| 25 | `plaintext-s3` | s3:GetObject with aws:SecureTransport=false, as entry user and as every role | iam_enforcer | **denied** |  |

## Notable observations

- scenario 01: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 02: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 04: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 05: under frozen-snapshot semantics 3 of 3 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 09: under frozen-snapshot semantics 2 of 2 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 10: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 11: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 15: under frozen-snapshot semantics 2 of 2 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 17: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 18: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 19: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 20: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 21: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 22: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 23: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 24: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass
- scenario 25: under frozen-snapshot semantics 1 of 1 removed hop(s) would still be authorized; counted as a model divergence, not a bypass

## Corrections made while building this log

Three defects in this harness were found and fixed before the final run. An earlier intermediate run printed a non-zero bypass count; that count was wrong and is superseded by the numbers above.

1. **Plaintext reads were counted as bypasses when the bucket had no transport control at all.** The first predicate treated any `s3:GetObject` allow under `aws:SecureTransport=false` as a bypass, which counted principals that could read the object over TLS *and* plaintext. That is not a defeat of a TLS control; there was no control. The first run reported 18 on this basis. Corrected: the only bypass condition is a deny→allow flip between transports.

2. **The bucket policy was never consulted for S3 requests.** `emulator.decide` only looks up a bucket policy when it is passed `bucket=`, and the first version omitted it, so every S3 request returned `no policy allows this action`. That is a false *negative* that is textually identical to a blocked bypass, and it is the more dangerous direction of error. Corrected before the final run.

3. **The pre-patch session policy was read after the remediation was replayed**, so the class 3 test re-injected the remediation's own `Deny` into the session it was supposed to be testing. Corrected: pre-patch documents are captured before the diff is applied.

The emulator also died partway through one intermediate run; those attempts were recorded as `error`, not as `not_applicable`, and the harness now exits non-zero when any attack fails to run. A fourth defect — `not_applicable` used for a raised exception — was removed for the same reason: an attack that never ran is not evidence that it was resisted.

## What this does not prove

**Class 1 is no longer vacuous, but it is also not a boundary-only test.** 13 of the 25 remediations now attach a real `PermissionsBoundary` -- 14 attachments, because scenario 24 bounds both the entry user and the `support_role` that carries `iam:PassRole` on the chain. Class 1 attacked every attached boundary and was denied in all 13 scenarios (0 succeeded). The other 12 scenarios carry no boundary because their control is not an identity-authority control -- an S3 bucket-policy transport `Deny`, a public-ACL scope, a lambda-body edit, or a trust-policy narrowing cannot be expressed as a permissions boundary, and `engine/synthesizer.py`'s `BOUNDARY_INAPPLICABLE` records the reason per scenario. Class 1 reports those as `not_applicable`, not as `denied`, because an attack that had nothing to bite is not evidence of resistance.

**What class 1 actually established.** Each attachment was attacked three ways: `Delete{User,Role}PermissionsBoundary`, `Put{User,Role}PermissionsBoundary` with an allow-all document, and `CreateRole`/`CreateUser` to mint an identity that never carried a boundary. As deployed, the first two are refused by the boundary's own `DenyBoundaryTampering` clause -- the decision is `ExplicitDeny` with the reason `explicit deny in permissions-boundary policy`, not an `ImplicitDeny` from an identity policy that simply never granted the action. That distinction is the whole point: it means the control is the boundary, and it was tested rather than assumed.

**The counterfactual, and what it shows.** Because most attackers do not hold the boundary-mutation action at all, `denied` alone would be a weak claim. So the attacker is granted the mutation outright and the request is re-judged. With the real boundary attached the swap is still `ExplicitDeny`. Strip only the `Deny` clauses and it becomes `ImplicitDeny` -- the narrow allow-list is a second, independent gate. Strip the `Deny` *and* add an `Allow` for the action, i.e. build the boundary the attacker is trying to install, and the swap is `Allow`. The gap between the last two is exactly the self-protection clause, so the clause is load-bearing, not decorative. Both the as-built and the counterfactual results are in the attempt table below.

**Counterfactual attacks are labelled as such.** For classes 1 and 2 the prerequisite mutating call is refused by the enforcer; the mutation is then performed anyway to learn whether the remediation's `Deny` is load-bearing. An `outcome` of `restored` means the exploit returns *if* the prerequisite were granted -- it is not a bypass, and it is reported separately from `succeeded`.

**The emulator is not the judge for classes 1, 3, and 4, and it disagrees with the enforcer.** It applies no IAM to unsigned S3 requests and evaluates no `aws:SecureTransport` condition (measured divergence 16.7% in Phase 1). Every authorization verdict in this log is `engine/iam_enforcer.py`; the emulator is used only to perform mutations that are then re-ingested and re-judged. A bypass would have to be one the enforcer recognises as an `Allow`, and an enforcer bug would therefore cancel out a real bypass rather than create a false one.

**The STS-session question is answered only inside the enforcer's model.** `iam_enforcer.evaluate` treats a session as *current identity policy ∧ session policy*, which matches AWS's documented behaviour that permission changes take effect almost immediately for long-term-credential-derived sessions. Under the alternative frozen-snapshot reading -- where a session issued before the patch carries its own copy of the old permissions -- the removed hops come back for every scenario with a pre-patch grant (see Notable observations). That reading is not counted as a bypass because AWS does not grant it, but it is also not *disproved* here: no real STS endpoint is involved, `sts:GetFederationToken` is exercised only for its shape, and session lifetime was never actually elapsed. Whether a session survives a mid-life policy edit is **untested** against real AWS.

**The boundary's allow-list was measured, not guessed, but measurement has a horizon.** It is the union of the post-patch decision-matrix allows for that principal and the literal `Allow` statements that survived the patch. The matrix samples a fixed action/resource cross-product, so an action outside it that the principal legitimately performs would not appear in the allow-list. That is why the boundary also re-emits each surviving identity `Allow` verbatim: the identity statement, not the sample, is the backstop. Five boundaries (scenarios 7, 8, 9, 12, 15) carry a non-empty allow-list for that reason; the eight identities that keep no `Allow` statement at all get an empty allow-list, which is correct for an identity that has nothing left to permit.

**A boundary that narrowed too far would show up as collateral, and none did.** The decision matrix re-ran with the boundaries attached: 10,459 entries, 763 allows pre-patch, 720 post-patch, 43 expected flips, 0 collateral, and all 97 designated-reader probes still `Allow`. The boundary is attached to the principal that holds the mechanism primitive, never to the scenario's `service` or `reporter` principals, so the reader the contract protects is outside its scope by construction.

**Known emulator limits that were not treated as bypasses:** `ec2:RunInstances` is authorized only for `Resource:"*"`, there is no console endpoint, and instance-scoped `ssm:SendCommand` is refused. Scenarios 08, 14, and 17 were never exploitable pre-patch, so their remediations had nothing to break.

**Untested, explicitly:** (a) the console-session path in scenario 14 -- no console endpoint exists, so the second hop of that chain has no executor; (b) real STS session expiry and revocation latency; (c) `iam:CreatePolicyVersion` against a policy attached to a role the attacker cannot assume but whose trust policy already names a third party; (d) proxy-lambda plaintext reads where the lambda's execution role is outside the scenario namespace -- every role tested here belongs to the scenario; (e) S3 resource-policy paths for principals that are not enumerated in the deployed state, such as anonymous or cross-account callers, because the corpus declares no such principal; (f) whether a boundary attached to a *group* narrows its members the way a user boundary does -- no scenario attaches one to a group; (g) the `DenyUnboundedPrincipalMint` clause was judged but its created identities were never used to escalate, because the emulator's `create_role` does not enforce trust round-trips.

This log is generated by `scripts/p6_redteam.py`; the counts above are measured, not asserted.
