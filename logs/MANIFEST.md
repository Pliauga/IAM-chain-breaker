# Artifact Manifest — `logs/`

This directory is a read-only mirror of the raw artifacts underpinning `WHITEPAPER.md`. Files are copied verbatim from `artifacts/` at commit `HEAD`; each filename is prefixed by the whitepaper section it supports. The originals remain in `artifacts/` unmodified. Every SHA-256 below is computed from the **current** bytes on disk, so the table stays self-consistent regardless of any later redaction pass.

Five files carry authorised redactions and therefore do not hash equal to their `artifacts/` originals: `section_03_exploits_proven.json` (one mock credential), plus `section_07_live_aws_simulator_parity.json`, `section_07_live_aws_wire_exploits.json`, `section_07_live_aws_teardown_audit.log` and `section_08_whitepaper_audit.json` (account identifier and caller ARN — see the Redaction Log below). The remaining five top-level files and all 100 raw scanner JSONs are byte-identical. `section_03_exploits_proven.json` is additionally summarised in [SANITIZATION.md](./SANITIZATION.md).

For a mechanically checkable verification, use the sibling [SHA256SUMS](./SHA256SUMS) file, which is a plain `sha256sum` manifest over all 110 mirrored files with no prose: `cd logs && sha256sum -c SHA256SUMS`. The fenced block further down shows the same commands applied to this document's table, but note that `sha256sum -c` requires a bare checksum list and will warn about any file containing prose — hence the separate file.

## Mapping

| Whitepaper section | Claim supported | File | SHA-256 |
|---|---|---|---|
| §1 (scanner table) | Checkov / Trivy / engine precision, recall, F1 per hop tier | `section_01_scanner_comparison.csv` | `1a2ba9bb106b5383cde4ae5aa1b5b8704b97c20265e213ca12e0087c4d49b191` |
| §1, §1.2 | 856 → 845 checkov and 270 → 273 trivy total findings; per-scenario deltas; `CKV_AWS_286` and `AWS-0342` behaviour | `section_01_raw_scanner_output/` (100 JSON) | `0a450bb2a1cb09831c46f7e4cf8c0cbb3d1dea1d934c0413c4977d0283cb3f89` (SHA-256 of the 100 per-file hashes in `ls` order) |
| §3.1 | 1,250/1,250 benign calls pass; per-scenario counts sum to the declared 1,250 | `section_03_benign_traces.json` | `a7c9d509d8e2b40964aef72f486d43385f5e84698e0104fa079282ae0393d089` |
| §1.3, §3 | 22/25 scenarios exploited by execution (08, 14, 17 never exploitable) | `section_03_exploits_proven.json` | `7f794d492ee12e3e19b6caa8b028ebb260a85210fd34f887aa13d3935127f104` |
| §3.2 | 10,459 matrix entries; 763 → 720 allows; 43 expected flips; 0 collateral; 97/97 legitimate probes retained | `section_03_decision_matrix_10459.json` | `3d7143eb00ea14c706351f3213d7920bb8d84b06f3bc5dbff72de40775b6af8c` |
| §4, §4.1 | 4 wrong of 24 = 16.7% emulator divergence; two surfaces; `selected_backend: iam_enforcer` | `section_04_emulator_fidelity.json` | `844beefa8eefb4eec176ae790569d99f8181eb18442c68b0d597bb05efc8b212` |
| §5, §3.5 | `BYPASSES_SUCCEEDED: 0`; four attack classes; the four-rung counterfactual ladder; the five metacognition corrections | `section_05_redteam_bypass_log.md` | `408222d2df1e471722155ee7e0b13d2a60ac720cc7ced2ce5796efa6d0007603` |
| §7.1, §7.2 | 295/295 parity with live `iam:SimulateCustomPolicy`; 4 confirmed divergences; negative controls 108 allow / 187 deny | `section_07_live_aws_simulator_parity.json` | `2f16890dcf9bfd9588573471904a3afca584f42a47e466e5cc6a3e473b73dbd7` |
| §7.3, §7.5 | 3 → 0 wire exploits; 16 resources created; `benign_preserved: true`; per-scenario propagation 6.1 / 7.6 / 5.8 s | `section_07_live_aws_wire_exploits.json` | `835e815b39e53d4a8e547f5e1626893d71b18d0efdf4079adcf3ea6e30ad6e5d` |
| §7.5 | `sweeps[]` entries 3, 5 and 6 each read: 16 found, 28 deletions, 0 leaked, `teardown_clean: true` | `section_07_live_aws_teardown_audit.log` | `8b30515bb945d0a49823599376e2337094aea15a15cd13ac46c3691f49c7e9c5` |
| §8 | Red Team's verdict trail: 215 claims, 0 unbacked, 0 contradictions, 14 findings all resolved | `section_08_whitepaper_audit.json` | `f22a44b3326c099c18e8ba2363d421dce5a0be8fd71888de4c589d68cfdbcacd` |
| §8 supporting | The whitepaper source this mirror annotates | `../WHITEPAPER.md` | `b791b5a95dd09ab3edc1e777402cad92b280ce1377f3a6df637ab002bde2b6b8` |

## Verification

The mechanically checkable form is the sibling [SHA256SUMS](./SHA256SUMS), a bare checksum list over the same 110 files. From inside `logs/`:

```
$ cd logs
$ sha256sum -c SHA256SUMS
section_01_scanner_comparison.csv: OK
section_03_benign_traces.json: OK
section_03_decision_matrix_10459.json: OK
section_03_exploits_proven.json: OK
section_04_emulator_fidelity.json: OK
section_05_redteam_bypass_log.md: OK
section_07_live_aws_simulator_parity.json: OK
section_07_live_aws_teardown_audit.log: OK
section_07_live_aws_wire_exploits.json: OK
section_08_whitepaper_audit.json: OK
section_01_raw_scanner_output/checkov_01.json: OK
... 98 more raw files, all OK ...
section_01_raw_scanner_output/trivy_25.json: OK
```

That is 10 top-level files plus 100 raw files: 110 `OK` lines, zero `FAILED`. To assert it mechanically rather than by eye, filtering out the success lines leaves nothing behind:

```
# still inside logs/; prints nothing and exits 1 when every file matches
$ sha256sum -c SHA256SUMS 2>&1 | grep -v ': OK$'
$ echo $?
1
```

Note that `sha256sum -c` must be pointed at a bare checksum list, not at this document: given a Markdown file it still verifies the hash lines it recognises but emits `WARNING: N lines are improperly formatted` for the prose, which is why `SHA256SUMS` exists as a separate file.

The per-file hashes can also be recomputed one at a time from the repository root:

```
$ sha256sum logs/section_01_scanner_comparison.csv
$ sha256sum logs/section_03_benign_traces.json
$ sha256sum logs/section_03_decision_matrix_10459.json
$ sha256sum logs/section_03_exploits_proven.json
$ sha256sum logs/section_04_emulator_fidelity.json
$ sha256sum logs/section_05_redteam_bypass_log.md
$ sha256sum logs/section_07_live_aws_simulator_parity.json
$ sha256sum logs/section_07_live_aws_teardown_audit.log
$ sha256sum logs/section_07_live_aws_wire_exploits.json
$ sha256sum logs/section_08_whitepaper_audit.json
$ sha256sum WHITEPAPER.md
```

## Notes on what is and is not here

The 100 `artifacts/p5/raw/*.err` files are all zero-length and are omitted from the mirror; their emptiness is the signal. It confirms both scanners produced no stderr output on any of the 25 scenarios, in either the pre-patch or the patched corpus.

`AGENTS.md`, `JOB.md`, `engine/`, and `scripts/` are intentionally excluded because they are the orchestration harness, not the results it produced.

`artifacts/` itself is not mirrored wholesale: only the eleven files a reader of `WHITEPAPER.md` needs to check a specific claim. Per-phase raw JSON that the whitepaper does not cite (for example `artifacts/p5/raw/*.err`) stays behind.

### Two claims in the whitepaper that this mirror annotates but cannot fully re-derive

Stated plainly, because a reader who tries to reproduce every number from `logs/` alone will hit both walls:

1. **`0 of 1,250 benign calls touch a data bucket`** (`WHITEPAPER.md:95`, section `02` line 31). The assertion text is quoted in `section_08_whitepaper_audit.json` (`citations_checked[23].found`) and `section_03_benign_traces.json` confirms the corpus size, since per-scenario `benign_calls` sum to 1,250 with all 1,250 passing. But the `0 of` count is computed at `scripts/p4_verify_gate.py:380-399` by intersecting each benign operation's bucket and resource against the vulnerable `*_data` bucket set drawn from `scenarios/`. Neither `scripts/` nor `scenarios/` is in this mirror, and `section_03_decision_matrix_10459.json` stores only the resulting `benign_replay` totals, not the bucket-intersection intermediate. So the pass rate is verifiable here; the zero-touch claim is corroborated by an audit citation but is not independently recomputable from `logs/`.

2. **The five metacognition quotes** in §5 come from operator-attested session transcript (`section_08_whitepaper_audit.json` `attested[]`), not from a machine-written artifact under `artifacts/`. They are attested evidence by design, and no file in `logs/` can regenerate them.

Both limitations are properties of the original artifact set, not of this copy.

## Redaction Log

Two identifier classes were removed from public-facing text. The original bytes remain in `artifacts/`, which is local-only; the `logs/` copies carry the substitutions.

| # | Placeholder | Occurrences in `logs/` | Files affected |
|---|---|---|---|
| 1 | `REDACTED_ACCOUNT` | 283 + 61 + 17 + 2 = 363 | `section_07_live_aws_simulator_parity.json` (283), `section_07_live_aws_wire_exploits.json` (61), `section_07_live_aws_teardown_audit.log` (17), `section_08_whitepaper_audit.json` (2) |
| 2 | `REDACTED_USER` | 1 + 1 = 2 | `section_07_live_aws_simulator_parity.json` (1), `section_07_live_aws_wire_exploits.json` (1) |

The first substitution replaced a twelve-digit AWS account number wherever it appeared, including inside ARNs such as `arn:aws:iam::<account>:role/...` and inside bucket names of the form `<prefix>-<account>-s01-<suffix>-data`. It was applied to `README.md` and `WHITEPAPER.md` as well, which is why those two hashes are recorded above rather than compared to a pre-redaction copy. The second substitution replaced the IAM caller name in the `caller_arn` and `principal_arn` fields of the two Phase 9 wire artifacts.

Within `logs/`, the same substitution was applied to the four files listed in the table. **All other bytes are byte-identical to the `artifacts/` originals** — the five remaining top-level files (`section_01_scanner_comparison.csv`, `section_03_benign_traces.json`, `section_03_decision_matrix_10459.json`, `section_04_emulator_fidelity.json`, `section_05_redteam_bypass_log.md`) and all 100 raw scanner JSONs hash equal to their sources.

This document does not contain either replaced string, by construction: writing it into the manifest would defeat the purpose of redacting it.

See [SANITIZATION.md](./SANITIZATION.md) for the initial AKIA redaction, which predates these two substitutions and accounts for the fifth redacted file, `section_03_exploits_proven.json`.

