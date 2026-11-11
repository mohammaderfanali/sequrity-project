# dynAn

Dynamic security-patch validation and regression testing for compiled C/C++
ELF targets on Linux x86_64.

dynAn takes a vulnerable base version and a patched version of a program,
builds both in a release and an instrumented profile, runs a test suite
against all four binaries, collects real execution evidence, links what it
observes to the source changes, and emits a verdict with a stable exit code
suitable for CI.

It answers two questions by **executing the program**, not by reading it:

1. Does the security defect that was reproduced on the base version still
   occur in the patched version, within the defined test scope?
2. Did the patch preserve the program's expected behaviour on valid input?

---

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[web,dev]'
```

Check the environment before anything else:

```bash
dynan doctor --config configs/confparse-correct.yaml
```

Validate a patch:

```bash
dynan validate --config configs/confparse-correct.yaml
```

Open the results in a browser:

```bash
dynan ui
```

---

## What a validation does

```
source resolution → diff → build (4 profiles) → execution → classification
→ differential comparison → correlation → reproduction → minimisation
→ regression-test generation → binary hardening → decision
```

Every stage is recorded. A run that fails part way through still produces a
persisted report and a verdict.

### Exit codes

| Code | Meaning | Condition |
| ---- | ------- | --------- |
| `0`  | `PASS` | The reproduced baseline defect is gone, no other confirmed security finding, all functional tests satisfied the independent oracle, and every mandatory check completed. |
| `10` | `VULN_REMAINS` / `NEW_ISSUE` | The baseline defect still occurs, or a new memory error was confirmed with valid evidence. |
| `20` | `FUNC_REGRESSION` | A valid functional test passed on base and failed after the patch. |
| `30` | `BUILD_OR_CONFIG_ERROR` | The target did not build, the configuration is incomplete, or the environment is broken. |
| `40` | `INCONCLUSIVE` | A mandatory check did not complete, or the evidence is insufficient. |

When several apply at once, the precedence is **30 → 10 → 20 → 40 → 0**.

> The build/config code outranks everything deliberately: if the target did
> not build, no security or functional claim derived from that run is
> trustworthy. `INCONCLUSIVE` sits above `PASS` so incomplete analysis is
> never reported as success.

Security status, functional status and analysis completeness are tracked
**independently** and all three stay in the JSON, whichever single code is
emitted. A patch can fix a vulnerability and introduce a regression at the
same time; that run exits `20` while still recording `security=pass`.

---

## CLI

```bash
dynan doctor [--config FILE] [--json]      # environment readiness
dynan validate --config FILE               # run a validation
dynan show-diff --config FILE [--raw]      # computed diff, no build
dynan runs list [--artifacts DIR]          # recorded runs
dynan runs show <run-id|latest> [--json]   # inspect a stored run
dynan runs events <run-id|latest>          # recorded progress events
dynan ui [--host H] [--port P]             # local web interface
```

Useful flags for `validate`:

| Flag | Effect |
| ---- | ------ |
| `--quiet` | Suppress progress output; for CI logs. |
| `--verbose` | Also print the stage timeline. |
| `--json-out PATH` | Write the full structured result. |
| `--no-minimize` | Skip input minimisation. |
| `--no-regression` | Do not generate regression tests. |
| `--sandbox BACKEND` | Override the sandbox backend. |
| `--artifacts DIR` | Override where runs are stored. |

The CLI never starts or contacts the web server. The web UI and the CLI both
call the same application services, so a run created by either is fully
inspectable in the other.

---

## Source modes

dynAn computes the diff itself; you do not supply one.

**Two directories**

```yaml
source:
  mode: directories
  base_path: ../targets/confparse/base
  patched_path: ../targets/confparse/correct
```

Directories are copied before use, so your sources are never modified. A
directory is identified by a **content hash**, which dynAn reports as such and
never presents as a commit identifier.

**A local repository**

```yaml
source:
  mode: local_git
  repo_path: ../my-project
  base_commit: v1.2.0
  patched_commit: fix/overflow
```

Each revision is materialised as a detached worktree. Your checkout and
working tree are untouched.

**A remote repository**

```yaml
source:
  mode: remote_git
  repo_url: https://github.com/example/project.git
  base_commit: 8f3a1c2
  patched_commit: 9b7e4d5
  # patched_repo_url:   # optional, when the patch lives in another fork
```

Clones are cached under `<artifacts.root>/cache` and refetched only when a
required commit is missing.

You may also pass `source.patch_file`. dynAn still computes its own diff and
reports any disagreement rather than trusting the supplied file.

---

## Adding a new target

No code changes are required — this is a configuration-only operation.

1. Make the build read `CFLAGS` / `CXXFLAGS` / `LDFLAGS` from the environment
   (a `?=` assignment in a Makefile is enough). dynAn parameterises the
   release and sanitized profiles through those variables.
2. Write a behavioural specification for the program, **before** looking at
   the patch. This is the independent oracle.
3. Write a test manifest whose expectations cite that document in
   `expect.provenance`.
4. Write a configuration pointing at the sources, the build commands, the
   binary path and the manifest.

See [docs/developer-guide.md](docs/developer-guide.md) for a worked example and
[docs/configuration.md](docs/configuration.md) for the full schema.

---

## Isolation

Target build scripts and target binaries are both untrusted, and both run
inside a sandbox with resource limits, no network, a read-only filesystem view
and an explicit writable allow-list.

| Backend | Notes |
| ------- | ----- |
| `bwrap` | Default. Rootless user namespaces, no daemon. |
| `container` | Podman if present, otherwise Docker. Honours `--pids-limit`. |
| `none` | Requires `allow_unsandboxed: true`. For debugging trusted fixtures only. |

**dynAn never falls back to unsandboxed execution.** If the configured backend
is unavailable the run ends as a build/configuration error, because silently
dropping isolation while still reporting a confident verdict would be worse
than failing.

`dynan doctor` verifies the sandbox by actually creating one.

---

## Reports and evidence

Everything lives under `artifacts.root` (default `.dynan`):

```
.dynan/runs/<run-id>/
  manifest.json          # listing projection
  results.json           # the full run, schema-versioned
  events.jsonl           # progress events
  diff.patch             # computed unified diff
  logs/build/            # per-profile build output
  evidence/exec/         # stdin, stdout, stderr per execution
  evidence/findings/     # raw sanitizer reports
  evidence/minimized/    # original and minimised inputs
  reproducers/<finding>/ # input.bin, metadata.json, reproduce.sh
  sources/               # prepared trees, one per version and profile
```

Completed runs are immutable; nothing overwrites a previous run.

Reporting is provided by the readable CLI summary, the structured JSON, the
stored artifacts, and the web UI. There is deliberately **no separate HTML
report generator** — the UI is the report viewer, for live and historical runs
alike.

---

## Web UI

```bash
dynan ui --port 8723
```

Binds to `127.0.0.1` by default. It has no authentication, so do not expose it
on a public address.

- **Runs** — every recorded run with its verdict and independent statuses.
- **New validation** — pick a configuration, validate it, run environment
  checks, start a run and watch real progress over Server-Sent Events.
- **Run detail** — overview, tests, findings, side-by-side diff, evidence.
- **Environment** — the same diagnostics `dynan doctor` prints.

The UI renders the canonical models the pipeline produced. It never recomputes
a status, a severity or a verdict.

---

## Optional LLM assistance

Disabled by default. The core workflow runs with no network access, no API key
and no LLM SDK installed.

```yaml
extensions:
  enabled: [llm]
  llm:
    enabled: true
    provider: openai
    model: gpt-4o-mini
    api_key_env: OPENAI_API_KEY     # the key itself is never stored in config
    allow_source_upload: false      # source leaves the machine only on opt-in
```

```bash
export OPENAI_API_KEY=...
dynan validate --config my-target.yaml
```

The model is an advisor. It explains findings and summarises diffs; it cannot
change the verdict, which is produced solely by the deterministic engine in
`dynan/domain/decision.py`. Its output is stored separately and labelled
unverified.

---

## CI/CD

See [.github/workflows/validate.yml](.github/workflows/validate.yml) for a
working pipeline. The essentials:

```yaml
- run: pip install -e .
- run: dynan doctor --config configs/target.yaml
- run: dynan validate --config configs/target.yaml --quiet --json-out report.json
- uses: actions/upload-artifact@v4
  if: always()                      # keep evidence when validation fails
  with:
    name: dynan-report
    path: |
      report.json
      .dynan/runs/
```

The job's exit status is dynAn's exit code, so the pipeline can branch on it
directly.

---

## Troubleshooting

**`bwrap: Creating new namespace failed: Resource temporarily unavailable`**
Usually `RLIMIT_NPROC`. That limit counts every process owned by your user, not
just this run's children, so a low `execution.limits.processes` makes the
sandbox's own setup fail. It is off by default; leave it off unless you are
using the container backend's per-container `--pids-limit`.

**`AddressSanitizer failed to allocate ... (errno: 12)`**
ASan reserves a very large virtual address range for shadow memory, so
`RLIMIT_AS` kills it at startup. dynAn disables the address-space limit for
sanitized runs and bounds them with ASan's `hard_rss_limit_mb` instead. If you
see this, something is applying an external `ulimit -v`.

**The release build does not reproduce a defect the sanitized build finds**
This is expected and informative, not a bug. Optimisation can legally delete
code whose behaviour is undefined. It is exactly why the specification
requires both profiles, and dynAn reports them separately.

**`no reproducer bundle for ...` in an INCONCLUSIVE verdict**
A confirmed finding could not be replayed stably. Check the `reproductions`
section of `results.json` for the per-attempt results.

**Verdict is `INCONCLUSIVE` with "no security finding was reproduced"**
The base version never failed under your tests, so there is nothing to prove
fixed. Add a test that triggers the defect on the base version.

---

## Documentation

| Document | Contents |
| -------- | -------- |
| [docs/architecture.md](docs/architecture.md) | Layers, data flow, lifecycle, extension points |
| [docs/configuration.md](docs/configuration.md) | Full configuration and manifest schema |
| [docs/developer-guide.md](docs/developer-guide.md) | Adding targets, tests and adapters |
| [docs/requirements-matrix.md](docs/requirements-matrix.md) | Specification traceability with honest status |

## Tests

```bash
pytest                      # everything
pytest -m "not slow"        # unit tests only
pytest tests/test_e2e.py    # real compiled fixtures
```

Integration tests compile and execute real C programs. No finding in the test
suite is mocked.

## Scope and limitations

- Linux x86_64 ELF targets only; the target must be buildable from source.
- Function attribution for correlation is a brace-matching heuristic over
  C/C++ source. It is used as supporting evidence and never as proof.
- Absence of a finding is not proof that no vulnerability exists. dynAn
  reports what it observed within the configured test scope, and says so.
