# Specification traceability matrix

Maps each mandatory requirement from the project specification
(*Project 1: Security Patch Validation and Regression Testing in CI/CD*) to
its implementation and its verification.

Status is recorded honestly. **"Complete" means implemented *and* verified by
an executed test**, not that a file or class exists. Where something is
partial or missing, this document says so.

Legend: ✅ complete · 🟡 partial · ❌ not implemented

---

## §2 — Scope and baseline requirements

| # | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| 2.1 | Target is a compiled C/C++ ELF on Linux x86_64 | `infra/elf.py` rejects non-ELF and non-x86-64 | `test_infra.py::test_non_elf_input_is_rejected` | ✅ |
| 2.2 | Input via stdin, file or argv | `infra/runner.py` `_build_argv`, `InputDelivery` | `test_e2e.py` (stdin); manifest supports all three | 🟡 stdin exercised end to end; file/argv implemented and unit-covered, not exercised by a fixture |
| 2.3 | Dynamic execution mandatory; no SAST-only | Whole pipeline executes real binaries | `test_e2e.py` compiles and runs real C | ✅ |
| 2.4 | Generalisable; new target by configuration only | `config/schema.py`; profiles via `CFLAGS`/`LDFLAGS` | `docs/developer-guide.md`; `confparse` added with zero code changes | ✅ |
| 2.5 | Correctness oracle independent of the patched version | `config/testsuite.py::has_independent_oracle`; `targets/confparse/SPEC.md` | `test_analysis.py::test_regression_needs_an_independent_oracle` | ✅ |
| 2.6 | Oracle approved by the instructor at design time | — | — | ❌ Outside the tool. `SPEC.md` is written and ready for review |

## §3.1 — Patch validation and linking findings to changes

| # | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| 3.1.1 | Accept base, patched and the diff | `infra/source.py` (3 modes), `infra/diffing.py` computes the diff | `test_infra.py::test_unified_diff_parsing_tracks_line_numbers` | ✅ |
| 3.1.2 | Correlate findings with patch changes | `app/correlate.py` | `test_analysis.py` (4 verdict cases), `test_e2e.py::test_correlation_links_the_fix_to_the_changed_function` | ✅ |
| 3.1.3 | Use stack traces and file/function matching | `infra/sanitizer.py` frame parsing; `diffing.find_functions` | `test_analysis.py::test_project_frame_skips_sanitizer_and_libc_internals` | ✅ |
| 3.1.4 | Compare execution of both versions as evidence | `app/compare.py`; `SIGNATURE_APPEARED`/`DISAPPEARED` evidence | `test_analysis.py::test_comparison_classifies_fixed_remaining_and_new` | ✅ |
| 3.1.5 | Failure need not be on a changed line; changed caller counts | `CALLER_CHANGED` evidence in `app/correlate.py` | `test_analysis.py::test_changed_caller_gives_an_indirect_relationship` | ✅ |
| 3.1.6 | Mere adjacency is insufficient → report unknown | `_decide()` thresholds; file-level overlap weighted 0.75 | `test_analysis.py::test_file_level_overlap_alone_is_not_sufficient_evidence` | ✅ |
| 3.1.7 | Four classes: Fixed / Incomplete / New / Functional regression | `FindingStatus`; `app/compare.py`, `app/oracle.py` | `test_e2e.py` scenarios 2–4 | ✅ |
| 3.1.8 | Inconclusive state for insufficient evidence | `FindingStatus.INCONCLUSIVE`; `CorrelationVerdict.UNKNOWN` | `test_decision.py::test_unclassified_crash_alone_does_not_confirm_a_vulnerability` | ✅ |
| 3.1.9 | A new finding does not by itself prove the patch caused it | Correlation separate from status; rationale states relationship ≠ root cause | `app/correlate.py` docstring; `test_analysis.py::test_without_frames_the_relationship_is_unknown` | ✅ |
| 3.1.10 | Every error-producing input runs on both versions | `pipeline._stage_execute` iterates version × profile × test | `test_e2e.py::test_profiles_are_observed_and_reported_separately` | ✅ |
| 3.1.11 | Regression must show base met the reference and patched violated it | `oracle.detect_regressions` requires base PASS + patched FAIL | `test_analysis.py::test_regression_requires_base_pass_and_patched_fail` | ✅ |

## §3.2 — Dynamic testing and precise error reporting

| # | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| 3.2.1 | Test valid, boundary and invalid inputs | `TestCategory`; 14 tests in `targets/confparse/tests/manifest.yaml` | `test_e2e.py` (56 executions per run) | ✅ |
| 3.2.2 | Record error type | `ErrorType` (24 values); `infra/sanitizer.py` | `test_analysis.py::test_asan_report_is_parsed` | ✅ |
| 3.2.3 | Record detection mechanism (signal / canary / sanitizer) | `DetectionMechanism`; `parse_glibc_hardening` detects `__stack_chk_fail` | `test_analysis.py::test_ubsan_and_glibc_reports_are_parsed` | ✅ |
| 3.2.4 | Record exit code, signal, stdout and stderr separately | `ExecutionResult` fields; artifacts per stream | `test_e2e.py::test_every_finding_references_real_evidence` | ✅ |
| 3.2.5 | Report timeouts and resource limits; not automatically a vulnerability | `ErrorType.TIMEOUT` → `Severity.RESOURCE`, excluded from code 10 | `test_analysis.py::test_timeout_is_recorded_but_is_resource_severity` | ✅ |
| 3.2.6 | Release and instrumented builds never mixed | Separate source tree per profile; profile in every comparison key | `test_e2e.py::test_profiles_are_observed_and_reported_separately` (asserts 4 distinct binary hashes) | ✅ |
| 3.2.7 | Compare matching builds before/after | `compare_findings` groups by `(signature, profile)` | `test_analysis.py::test_profiles_are_compared_separately` | ✅ |
| 3.2.8 | Same suite, settings and limits on both versions and builds | One `TestCaseSpec` set, one `ExecutionConfig` | `pipeline._stage_execute` | ✅ |

## §3.3 — Reproducibility, minimisation, regression generation

| # | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| 3.3.1 | Reproducer bundle: input, commit, build settings, env, command | `app/reproduce.py` writes `input.bin`, `metadata.json`, `reproduce.sh` | `test_e2e.py::test_reproduction_minimisation_and_regression_generation` | ✅ |
| 3.3.2 | At least 3 replays; unstable cases identified | `AnalysisConfig.replay_count` (min 3); `stable` flag | Same test (asserts `total_attempts >= 3`) | ✅ |
| 3.3.3 | Automatic minimisation (delta debugging or similar) | `app/minimize.py` (ddmin over bytes) | `test_infra.py::test_ddmin_shrinks_while_preserving_the_predicate` | ✅ |
| 3.3.4 | Predicate preserves the same error type and location | `app/signature.py`; `FindingSignature.matches` | `test_e2e.py` asserts `minimization.verified` | ✅ |
| 3.3.5 | A non-zero exit code is not a sufficient criterion | `signature.preserves_signature` compares full signatures | `app/signature.py`; `test_analysis.py::test_nonzero_exit_is_not_a_finding` | ✅ |
| 3.3.6 | Store both original and minimised inputs | `evidence/minimized/<finding>/{original,minimized}.bin` | `MinimizationResult.original_artifact` / `minimized_artifact` | ✅ |
| 3.3.7 | Add minimised input to the regression suite automatically | `app/regression.py` writes a real dynAn manifest | `test_e2e.py::test_generated_suite_feeds_the_next_run` | ✅ |
| 3.3.8 | Generated test reveals the error on base, absent on patched | `regression.verify_generated_test` executes both | `test_e2e.py` asserts `verified_fails_on_base` and `verified_passes_on_patched` | ✅ |

## §3.4 — Binary hardening

| # | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| 3.4.1 | Check NX, PIE, RELRO, Stack Canary with evidence | `infra/elf.py`, native ELF parsing | `test_infra.py::test_elf_hardening_matches_the_requested_flags` (validated against `readelf`) | ✅ |
| 3.4.2 | RELRO reported as none / partial / full | `RelroLevel`; `PT_GNU_RELRO` + `BIND_NOW` | Same test | ✅ |
| 3.4.3 | Detect unintended weakening between versions | `pipeline.compare_hardening` | `test_infra.py::test_hardening_comparison_detects_weakening` | ✅ |
| 3.4.4 | PIE does not prove ASLR is active | Stated in `BinaryHardening.caveats` | `test_e2e.py::test_hardening_is_compared_between_versions` | ✅ |
| 3.4.5 | Canary presence ≠ all functions protected | Stated in `caveats` and in the property detail | Same test | ✅ |

## §3.5 — CI/CD execution and exit codes

| # | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| 3.5.1 | Runnable from the command line | `cli/main.py`, `dynan` console script | `test_e2e.py::test_cli_exit_code_matches_the_decision` | ✅ |
| 3.5.2 | Readable developer summary | `cli/render.py` | Produced on every `dynan validate` | ✅ |
| 3.5.3 | Structured JSON output | `results.json`, `--json-out`, schema-versioned | `test_e2e.py::test_cli_json_output_matches_the_stored_run` | ✅ |
| 3.5.4 | Code 0 conditions | `decision.evaluate` + `assess_completeness` | `test_decision.py::test_clean_run_passes` | ✅ |
| 3.5.5 | Code 10; unclassified stop insufficient | `_confirmed_remaining` / `_confirmed_new_issue` | `test_decision.py` (3 tests) | ✅ |
| 3.5.6 | Code 20, recorded independently of security | `FunctionalStatus` kept separate | `test_decision.py::test_functional_regression_is_twenty_and_independent_of_security` | ✅ |
| 3.5.7 | Code 30; never counted as a security finding | Rule `build.failed`; security forced to `not_assessed` | `test_decision.py::test_failed_build_is_thirty_and_never_a_security_claim` | ✅ |
| 3.5.8 | Code 40 for incomplete checks or weak evidence | `assess_completeness` gaps | `test_decision.py` (3 tests) | ✅ |
| 3.5.9 | Precedence 30 → 10 → 20 → 40 → 0 | `EXIT_CODE_PRECEDENCE` | `test_decision.py::test_precedence_follows_the_specification_order` | ✅ |
| 3.5.10 | All findings and independent statuses retained in JSON | `ValidationRun` keeps every list | `test_e2e.py::test_cli_run_is_visible_in_the_web_ui_without_re_execution` | ✅ |

> **Note on 3.5.9.** The specification PDF states the order *30, 10, 20, 40, 0*.
> The accompanying product brief stated *40, 20, 10, 30, 0*. The brief says to
> follow the PDF on conflict, so the PDF order is implemented, encoded once in
> `EXIT_CODE_PRECEDENCE`, and quoted in that constant's docstring.

## §4 — Evaluation scenarios

| # | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| 4.1 | Vulnerable base with a reproducible memory error | `targets/confparse/base` | `test_e2e.py` (3/3 stable replays) | ✅ |
| 4.2 | Correct patch → exit 0 | `targets/confparse/correct` | `test_e2e.py::test_correct_patch_passes` | ✅ |
| 4.3 | Incomplete patch → exit 10 | `targets/confparse/incomplete` | `test_e2e.py::test_incomplete_patch_reports_vuln_remains` | ✅ |
| 4.4 | Regression patch → exit 20 | `targets/confparse/regression` | `test_e2e.py::test_regression_patch_reports_functional_regression` | ✅ |
| 4.5 | Build/config failure → exit 30 | — | `test_e2e.py::test_broken_build_is_a_configuration_error` | ✅ |
| 4.6 | Inconclusive → exit 40 | — | `test_decision.py` (3 tests) | 🟡 Verified at the decision layer; no end-to-end fixture yet |
| 4.7 | **Two independent C/C++ programs** | One target (`confparse`) | — | ❌ **Only one target exists** |
| 4.8 | **At least one real, non-toy program or library** | `confparse` is a purpose-built fixture | — | ❌ **Not satisfied** |
| 4.9 | Answers must not depend on filename or patch identity | No path, name or variant is consulted anywhere in `decision.py` or `compare.py` | Config-driven; same code produced 0/10/20 from identical settings | ✅ |
| 4.10 | Day-zero unseen patches evaluated live | Supported by design (4.9); nothing is hardcoded | — | 🟡 Mechanism in place, not demonstrated on an unseen patch |

> **4.7 / 4.8 are the main outstanding gap.** The product brief directed that
> during development only "a small, simple, self-contained C/C++ program" be
> used, which `confparse` is. A second target, and a real-world library for at
> least one of the two, must still be onboarded before final delivery. No code
> change is required — see `docs/developer-guide.md`.

## §5 — Execution and delivery rules

| # | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| 5.1 | Isolated execution environment with resource limits | `infra/sandbox/` (bwrap, container); `infra/process.py` rlimits | `doctor` self-test; `test_e2e.py` runs under bwrap | ✅ |
| 5.2 | Never silently fall back to unsandboxed execution | `SandboxUnavailable` is fatal; `none` needs explicit opt-in | `test_infra.py::test_unsandboxed_execution_must_be_explicit` | ✅ |
| 5.3 | LLM may assist, but validation logic must be deterministic | `decision.py` never reads `extension_results` | `test_e2e.py::test_disabled_llm_extension_makes_no_requests` | ✅ |
| 5.4 | Consistent, reproducible results | Immutable runs; atomic writes; replay stability | `test_e2e.py::test_generated_suite_feeds_the_next_run` | ✅ |
| 5.5 | Deliver sources, config, versions, tests, bundles, reports, pipeline, guide | This repository | `README.md`, `docs/`, `.github/workflows/validate.yml` | ✅ |
| 5.6 | All members master the architecture | — | — | ❌ Outside the tool |

## §6 — Grading-weighted capabilities

| Weight | Area | Status |
|---|---|---|
| 25 | Patch validation, version comparison, diff correlation | ✅ Implemented and tested |
| 25 | Dynamic testing, boundary inputs, build separation, error classification | ✅ Implemented and tested |
| 15 | Reproducibility, minimisation, regression generation | ✅ Implemented and tested |
| 15 | Two independent programs + unseen patches | 🟡 One target; mechanism for unseen patches in place |
| 10 | CI/CD, JSON output, exit codes | ✅ Implemented and tested |
| 5 | Binary hardening and change detection | ✅ Implemented and validated against `readelf` |
| 5 | Documentation, contract design, independent execution | ✅ |

---

## Summary of what is NOT done

1. **Only one target program exists.** The specification requires two
   independent programs (§4.7).
2. **No real-world, non-toy target.** `confparse` is a purpose-built fixture
   (§4.8).
3. **Exit code 40 has no end-to-end fixture.** The rules are unit-tested, but
   no target variant produces an inconclusive full run (§4.6).
4. **Unseen-patch evaluation is undemonstrated.** The design forbids
   identity-based answers and the code honours that, but no unseen patch has
   been run through it (§4.10).
5. **File and argv input delivery are not exercised end to end.** Both are
   implemented and the manifest supports them; the fixture uses stdin (§2.2).
6. **Instructor approval of targets and oracles has not happened** (§2.6).

Items 1–4 are target-authoring work and need no changes to dynAn itself.

## Beyond the specification

These are not PDF requirements. They are listed so a reviewer can tell
optional work apart from mandatory work, and so that nothing optional is
mistaken for a graded capability.

| Capability | Implementation | Verification | Status |
| ---------- | -------------- | ------------ | ------ |
| Optional LLM advisor, disabled by default | `ext/llm/` | `test_e2e.py::test_disabled_llm_extension_makes_no_requests` | ✅ |
| Optional fuzzing, disabled by default | `ext/fuzz/` | `test_fuzz.py` (42 tests) | ✅ |
| Grammar-based input generation | `ext/fuzz/grammar.py`, schema tokeniser | `test_fuzz.py::test_escaped_braces_expand_correctly`, `::test_malformed_braces_are_rejected` | ✅ |
| Fuzz crash triage: confirm, minimise, attribute | `ext/fuzz/triage.py` | `test_fuzz.py::test_only_confirmed_patched_only_crashes_are_promotable` | ✅ |
| Fuzz findings excluded from the verdict | `decision.py` never reads `extension_results` | `test_fuzz.py::test_extension_results_cannot_change_the_verdict` | ✅ |

The fuzzer deliberately does **not** influence the exit code. PDF §3.5 judges
a patch within the agreed test scope, and a fuzzer generates inputs outside
it; a verdict that shifted with the random seed would not be reproducible,
which §6.1 requires. Confirmed patched-only crashes are instead promoted into
the regression suite, so a later run evaluates them in scope.

Verified end to end on the incomplete patch: 800 generated inputs across both
versions found the `store_value` overflow, minimised it from 182 to 18 bytes,
correctly attributed it as `pre_existing` (the base build crashes the same
way), promoted nothing, and left the exit code at 10.

## Reproducing this matrix

```bash
pytest -q                         # 113 tests
dynan validate --config configs/confparse-correct.yaml      # exit 0
dynan validate --config configs/confparse-incomplete.yaml   # exit 10
dynan validate --config configs/confparse-regression.yaml   # exit 20
```

Optional, with fuzzing enabled — the verdict must be unchanged at 10:

```bash
dynan validate --config configs/confparse-incomplete-fuzz.yaml
```
