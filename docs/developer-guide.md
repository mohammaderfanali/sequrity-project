# Developer guide

## Adding a new target

Adding a program must not require changing dynAn's code. It is a
configuration-only operation, and the `confparse` fixture is a worked example
of every step.

### 1. Make the build profile-aware

dynAn drives the release and sanitized profiles through environment variables.
Your build only has to let the environment win:

```make
CC      ?= cc
CFLAGS  ?= -O2 -g
LDFLAGS ?=

build/myprog: src/*.c | build
	$(CC) $(CFLAGS) -o $@ src/*.c $(LDFLAGS)
```

`?=` is the important part — it assigns only when the variable is unset, so
`CFLAGS` from the environment takes precedence. CMake equivalents work too,
since CMake reads `CFLAGS` on first configure.

### 2. Write the behavioural specification first

This is the single most important step, and the easiest to get wrong.

The specification is your **independent oracle**. Write it from the program's
documentation or its intended contract, *before* looking at the patch. If you
derive expectations by running the patched program, you have no oracle — you
have a tautology, and dynAn cannot detect a regression that the patch itself
introduced.

See [`targets/confparse/SPEC.md`](../targets/confparse/SPEC.md). It states the
input grammar, the validity rules, the exact output format, every error
message and every exit code, plus worked examples.

### 3. Write the test manifest

```yaml
version: 1
oracle:
  provenance: "targets/myprog/SPEC.md"
defaults:
  delivery: stdin
tests:
  - id: valid_basic
    category: valid
    input_file: inputs/basic.txt
    expect:
      exit_code: 0
      stdout_exact: "ok\n"
      provenance: "SPEC.md section 4"
```

Cover all four categories. In particular:

- **valid** — must include a case near, but inside, each limit. This is what
  catches a patch that fixes an overflow by tightening a bound below what the
  specification allows.
- **boundary** — the largest accepted and smallest rejected value for every
  limit.
- **invalid** — each distinct error path.
- **security** — inputs that trigger the defect. Give them the *correct*
  expectation (what a conforming program does), not the crash. The base
  version will fail them; that is the point.

### 4. Write the configuration

```yaml
version: 1
target:
  name: myprog
source:
  mode: directories
  base_path: ../targets/myprog/base
  patched_path: ../targets/myprog/patched
build:
  binary: build/myprog
  env: {CC: gcc}
tests:
  manifests: [../targets/myprog/tests/manifest.yaml]
  regression_suite: ../regression-suite/myprog
artifacts:
  root: ../.dynan
```

### 5. Check before running

```bash
dynan doctor --config configs/myprog.yaml
dynan show-diff --config configs/myprog.yaml
dynan validate --config configs/myprog.yaml
```

`doctor` verifies sources, commits, build tools, manifests, input files, the
artifacts directory and the sandbox — and tells you how many tests carry a
usable independent oracle.

---

## Designing the four patch variants

The specification requires four versions per target. The `confparse` fixture
shows what makes each one a genuine test rather than a demonstration.

| Variant | Must be | Expected |
| ------- | ------- | -------- |
| **base** | Reproducibly memory-unsafe | — |
| **correct** | Fixes it; all functional tests still pass | `0` |
| **incomplete** | Fixes *one* path; another input still reaches the defect | `10` |
| **regression** | Memory-safe, but breaks valid behaviour | `20` |

Two design points worth copying:

**Give the defect two reachable paths.** `confparse` accepts both `key=value`
and `key:value`, and both reach the same unchecked copy. The incomplete patch
guards only the `=` path, so the `:` test still triggers it. This is what
makes "incomplete" a real category rather than a relabelled "unfixed".

**Make the regression subtle.** `confparse`'s regression patch is genuinely
memory-safe; it just caps values at 12 characters when the specification
allows 15. Basic inputs still work. Only `valid_twelve_char_value` and
`boundary_value_15` fail — which is exactly why those tests exist. A
regression that breaks everything proves nothing about detection.

Keep diffs minimal. A small diff is a much harder test of the correlation
engine than a rewrite.

---

## Implementing a new sandbox backend

```python
from dynan.infra.sandbox.base import Sandbox, SandboxProbe
from dynan.infra.process import ExecSpec

class MySandbox(Sandbox):
    name = "mine"

    def probe(self) -> SandboxProbe:
        """Cheap availability check, no payload executed."""

    def selftest(self) -> SandboxProbe:
        """Actually run something trivial through the backend."""

    def wrap(self, spec: ExecSpec) -> ExecSpec:
        """Return a spec whose argv runs the original inside isolation."""
```

Register it in `dynan/infra/sandbox/__init__.py` and add the name to the
`backend` literal in `config/schema.py`.

`selftest` must execute a real command. An installed binary that cannot create
namespaces passes a `which` lookup and then fails inside the first build,
which is a far worse experience than an absent one.

Honour `spec.writable_paths`, `spec.readable_paths` and `spec.network`.
Keeping host paths identical inside the sandbox is strongly preferred: it
makes every command line recorded in evidence directly reusable by a human.

---

## Adding an optional extension

```python
class MyExtension:
    name = "myext"
    description = "..."

    def diagnose(self, config) -> list[Diagnostic]:
        """Readiness, shown by dynan doctor. Must never block unrelated work."""

    def run(self, context: ExtensionContext) -> dict:
        """Advisory output, stored under run.extension_results."""
```

Register a **factory** in `dynan/ext/registry.py`:

```python
def _load_myext():
    from .myext.extension import MyExtension   # import inside the factory
    return MyExtension()
```

Importing inside the factory is what keeps a disabled extension free: no
dependency import, no network traffic, no diagnostics.

Rules for extensions:

- They cannot change the verdict. `decision.evaluate()` never reads
  `extension_results`.
- Anything they produce is labelled unverified.
- Any new evidence they suggest must be executed through the real testing
  engine before it counts.
- A crashing extension must not fail the run; the pipeline catches and records
  it as a warning.

---

## Extending finding classification

To recognise a new diagnostic format, add a parser in
`infra/sanitizer.py` and register it in `parse_output`, ordered by evidence
strength. Then map its error type in `domain/enums.py`, adding it to
`MEMORY_SAFETY_ERRORS` or `UNDEFINED_BEHAVIOR_ERRORS` as appropriate — those
sets are what the decision engine consults.

Test against **captured real output**, not output you wrote by hand. The
constants at the top of `tests/test_analysis.py` are verbatim GCC 13
libasan/libubsan text; that is how the parser's handling of interleaved
libsanitizer, glibc and project frames was validated.

---

## Testing conventions

```bash
pytest                   # everything (~2 minutes)
pytest -m "not slow"     # unit tests only (~1 second)
pytest tests/test_e2e.py # real compiled fixtures
```

- Domain rules are tested by constructing a `ValidationRun` in memory —
  `tests/test_decision.py` needs no filesystem and no compiler.
- Anything that claims a program misbehaved must compile and run a real
  program. **Never assert an end-to-end security result from a mocked
  finding**: for a dynamic-analysis tool that proves nothing.
- Integration tests use `config_factory`, which writes an isolated
  configuration into the test's own `tmp_path`, so tests never touch the
  repository's `.dynan` or each other's runs.
- Skip conditions call dynAn's own doctor checks, so a skip reason matches
  what a user would be told.

Test the states that are easy to forget: interrupted runs, failed builds,
missing dependencies, unstable findings, empty results.

---

## Code conventions

- Python 3.11+, type annotations throughout, `src/` layout.
- The domain layer imports nothing from other layers and performs no I/O.
- Presentation maps enum values to labels; it never recomputes a status.
- All processes go through `infra/process.py` so limits and isolation cannot
  be bypassed by accident.
- Comments explain *why*. The compiler already shows what.
