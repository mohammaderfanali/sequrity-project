# Architecture

## Why it is shaped this way

Two constraints drove every structural decision:

1. **One authoritative implementation of the validation workflow.** The CLI,
   the web UI and CI must agree about a run because they read the same
   objects, not because three implementations happen to be consistent.
2. **Every conclusion must be traceable to real evidence.** The data model is
   built so that a finding cannot exist without pointing at the execution that
   produced it.

## Layers

```
          ┌──────────────────────────────────────────┐
          │  presentation      cli/        web/      │
          └───────────────────┬──────────────────────┘
                              │ calls services only
          ┌───────────────────▼──────────────────────┐
          │  application       app/                  │
          │  pipeline, services, analysis, events    │
          └──────┬────────────────────────┬──────────┘
                 │                        │
     ┌───────────▼─────────┐   ┌──────────▼──────────┐
     │  domain             │   │  infrastructure     │
     │  models, decision   │   │  infra/             │
     │  (no I/O at all)    │   │  processes, git,    │
     └─────────────────────┘   │  build, ELF, store  │
                               └─────────────────────┘
                 ┌──────────────────────────┐
                 │  extensions   ext/       │  optional, advisory
                 └──────────────────────────┘
```

Dependency rule: **domain depends on nothing**. Infrastructure may import
domain. Application may import both. Presentation imports application and
domain models for rendering, never infrastructure. Extensions may read a run
but cannot influence the verdict.

### `domain/` — meaning

Pure data and rules, no I/O, no imports from other layers.

| Module | Responsibility |
| ------ | -------------- |
| `enums.py` | The entire status vocabulary, and `EXIT_CODE_PRECEDENCE`. |
| `models.py` | Canonical models: `ValidationRun` and everything it holds. |
| `decision.py` | The only place a verdict is produced. |

Because it is I/O-free, every rule is testable by constructing a run in
memory. `tests/test_decision.py` does exactly that.

### `infra/` — contact with the outside world

| Module | Responsibility |
| ------ | -------------- |
| `process.py` | The only place dynAn spawns a process. Timeouts, rlimits, capture. |
| `sandbox/` | `bwrap`, container and null backends behind one interface. |
| `git.py` | Revision resolution, worktrees, diff generation, content hashing. |
| `source.py` | Three acquisition modes converging on one representation. |
| `diffing.py` | Unified-diff parsing and C/C++ function-span attribution. |
| `build.py` | Build execution per version and profile. |
| `runner.py` | Target execution with stdin / file / argv delivery. |
| `sanitizer.py` | Parsing ASan, UBSan, glibc and assertion output. |
| `elf.py` | Native ELF hardening inspection. |
| `store.py` | Run persistence, artifacts, events. |

### `app/` — use cases

| Module | Responsibility |
| ------ | -------------- |
| `service.py` | Public surface. Everything a front end can ask for. |
| `pipeline.py` | The staged workflow. |
| `classify.py` | Observation → normalised finding. |
| `compare.py` | Differential status across versions, within a profile. |
| `correlate.py` | Finding ↔ diff relationship, with evidence. |
| `oracle.py` | Independent correctness checks and regression detection. |
| `signature.py` | The shared failure-preservation predicate. |
| `minimize.py` | ddmin over bytes. |
| `reproduce.py` | Replay stability and reproducer bundles. |
| `regression.py` | Promoting minimised inputs into a managed suite. |
| `doctor.py` | Environment readiness. |
| `events.py` | Structured progress, persisted and broadcast. |

### `cli/` and `web/` — adapters

Both call `ValidationService`. Neither classifies a finding, decides a verdict
or runs a process. `cli/render.py` and the Jinja templates map canonical enum
values to labels and colours; that is the full extent of their logic.

The CLI does **not** make HTTP requests to the local server — it calls the
services directly, so it works with no server running.

## Data flow

```
config ──> SourceResolver ──> PreparedSources ─┬─> diffing ──> StructuredDiff
                                               │
                                               └─> BuildExecutor ──> BuildResult × 4
                                                          │
 TestCaseSpec (manifest) ──────────────────────────> TargetRunner
                                                          │
                                                   ExecutionResult
                                                     │        │
                                           classify ─┘        └─ oracle
                                                │                   │
                                            Finding             OracleCheck
                                                │                   │
                                     compare ───┤                   ├── detect_regressions
                                                │                   │
                                      FindingComparison      FunctionalRegression
                                                │                   │
                             correlate ─────────┤                   │
                                                │                   │
                            reproduce / minimize / regression       │
                                                │                   │
                                                └──────┬────────────┘
                                                       ▼
                                               decision.evaluate()
                                                       ▼
                                                   Decision
```

`ExecutionResult` is deliberately interpretation-free. The runner records exit
status, signal, output and timing; deciding whether that constitutes a
vulnerability happens in `classify.py`, against rules that are unit-tested
independently of any process.

## Validation lifecycle

Stages, in order, from `STAGE_ORDER`:

| Stage | Produces | On failure |
| ----- | -------- | ---------- |
| `preflight` | `DoctorReport` | Aborts: environment error (30) |
| `source` | `SourcePair` | Aborts: configuration error (30) |
| `diff` | `StructuredDiff` | Aborts |
| `build` | 4 × `BuildResult` | Aborts: build error (30) |
| `execute` | `ExecutionResult[]` | Recorded, analysis continues |
| `analyze` | `Finding[]`, `OracleCheck[]`, comparisons, regressions | — |
| `correlate` | `FindingCorrelation[]` | Blocked without a diff |
| `reproduce` | `ReproductionResult[]` | Unstable findings → incomplete |
| `minimize` | `MinimizationResult[]` | Skippable by configuration |
| `regression` | `GeneratedRegressionTest[]` | Skippable by configuration |
| `hardening` | `HardeningComparison` | Missing → incomplete analysis |
| `extensions` | advisory output | Never fatal |
| `decide` | `Decision` | Always runs |

`decide` and persistence run in a `finally` block, so an aborted run still
produces a stored, explainable report — which the specification requires.

### Why four builds

The specification forbids mixing release and instrumented observations, and
requires base/patched comparisons between matching profiles.

Each build gets **its own copy of the source tree**. Targets normally build to
a fixed output path, so building both profiles in one tree would leave the
sanitized binary overwriting the release one — and every "release" observation
would silently come from the instrumented binary. The isolation is structural
rather than a convention the target has to honour. The end-to-end test asserts
all four binary hashes are distinct.

## Decision rules

`domain/decision.py` is the single authority. It reads a `ValidationRun` and
returns a `Decision` carrying:

- one exit code, chosen by `EXIT_CODE_PRECEDENCE`;
- the independent security, functional and completeness statuses;
- every candidate code that applied before precedence;
- a list of `DecisionReason`, each naming the rule that fired.

Guards that exist specifically because the specification demands them:

- A non-zero exit code produces no finding at all.
- An unclassified stop is `UNCONFIRMED` and routes to `INCONCLUSIVE`, never
  to code 10.
- Code 10's "new issue" clause requires a confirmed **memory** error; its
  "previous error still occurs" clause also accepts confirmed undefined
  behaviour.
- `PASS` requires a reproduced baseline, stable replays for confirmed
  findings, four successful builds and a completed hardening inspection.

## Persistence

Filesystem-backed. The access pattern is write-once, read-by-id, list-recent,
which the filesystem serves directly; a database would add an operational
dependency without removing work.

- `results.json` and `manifest.json` are written atomically (temp + rename).
- `events.jsonl` is append-only and tailable while a run is in flight.
- Artifact paths are resolved against the run root and refuse to escape it —
  a security boundary, since the web API serves artifact downloads.
- Run ids are validated against a pattern before touching the filesystem.
- A run directory is never reused.

## Extension boundary

```python
class Extension(Protocol):
    name: str
    def diagnose(self, config) -> list[Diagnostic]: ...
    def run(self, context: ExtensionContext) -> dict: ...
```

The registry imports an extension's implementation only when it is enabled, so
a disabled extension costs nothing — no dependency import, no network traffic,
no blocking diagnostics. Extension output is stored under
`run.extension_results` and the decision engine never reads it.

The PDF's mandatory capabilities — reproduction, minimisation, regression
generation, correlation, hardening — are **core pipeline stages**, not
extensions, so they cannot be disabled into irrelevance.

## Deliberate omissions

- **No separate HTML report generator.** The web UI is the report viewer; a
  second template system rendering the same data would be duplicated
  presentation logic.
- **No dependency-injection framework.** Construction is explicit; the
  pipeline receives its sandbox, store and emitter as arguments.
- **No plugin discovery via entry points.** A name-to-factory table is
  sufficient and keeps failure modes obvious.
