# Configuration reference

One schema serves the CLI, the web UI and CI. It is validated before any
expensive work starts, and an invalid file produces a list of problems rather
than a stack trace.

## Strict YAML

Configuration files and test manifests are parsed with duplicate mapping keys
**rejected**. Standard YAML silently keeps the last of a repeated key, which
in a configuration file is a trap: writing `build:` twice, or repeating a rule
name in a grammar, would discard half of what you wrote with no diagnostic.

```
Configuration is not valid YAML.
  - duplicate key 'version'; the later definition would silently replace the
    earlier one
```

## Path resolution

**Every path in a configuration file resolves relative to the directory
containing that file**, unless already absolute.

The exception is paths that describe locations *inside the target source
tree* — `build.working_dir`, `build.binary`, `execution.working_dir`. Those
stay relative, because the tree does not exist when the file is loaded.

| Field | Resolved against |
| ----- | ---------------- |
| `source.base_path`, `source.patched_path`, `source.repo_path`, `source.patch_file` | the config file |
| `tests.manifests`, `tests.regression_suite` | the config file |
| `artifacts.root`, `sandbox.ro_binds` | the config file |
| `build.working_dir`, `build.binary`, `execution.working_dir` | the prepared source tree |
| `input_file` in a manifest | the manifest file |

## Minimal example

```yaml
version: 1

target:
  name: myprog

source:
  mode: directories
  base_path: ../src/vulnerable
  patched_path: ../src/fixed

build:
  binary: build/myprog

tests:
  manifests: [../tests/manifest.yaml]
```

Everything else has a safe default.

---

## `version`

Required, currently `1`. A mismatch is rejected rather than guessed at.

## `target`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `name` | string | required | Short identifier, shown in listings. |
| `description` | string | `""` | Free text. |
| `language` | `c` \| `cpp` | `c` | Informational. |

## `source`

| Key | Type | Required for | Meaning |
| --- | ---- | ------------ | ------- |
| `mode` | `directories` \| `local_git` \| `remote_git` | always | Acquisition mode. |
| `base_path`, `patched_path` | path | `directories` | Source trees; copied, never modified. |
| `repo_path` | path | `local_git` | Repository to take worktrees from. |
| `repo_url` | string | `remote_git` | Clone URL. |
| `patched_repo_url` | string | optional | Second origin, when the patch is in another fork. |
| `base_commit`, `patched_commit` | string | both git modes | Any revision expression; resolved to a full SHA. |
| `fetch_depth` | int | optional | Shallow clone depth. |
| `patch_file` | path | optional | External diff, checked for consistency against the computed one. |

A `directories` source is identified by a content hash. dynAn labels it as a
content hash and never presents it as a commit identifier.

## `build`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `working_dir` | path | `"."` | Where commands run, inside the tree. |
| `commands` | list of argv arrays | `[["make","clean"],["make"]]` | Ordered build steps. |
| `binary` | path | required | Built executable, relative to `working_dir`. |
| `env` | map | `{}` | Extra environment, e.g. `CC: gcc`. |
| `timeout_s` | float | `600` | Per-command wall-clock limit. |
| `network` | bool | `false` | Network during the build. |
| `profiles` | map | release + sanitized | See below. |

Commands are **argv arrays**, not shell strings: no implicit shell, no quoting
ambiguity.

### `build.profiles`

Both `release` and `sanitized` must exist. Each profile supports:

| Key | Type | Meaning |
| --- | ---- | ------- |
| `cflags` | list | Exported as `CFLAGS`. |
| `cxxflags` | list | Exported as `CXXFLAGS`; defaults to `cflags`. |
| `ldflags` | list | Exported as `LDFLAGS`. |
| `env` | map | Extra environment for this profile. |
| `commands` | list | Overrides `build.commands` entirely. |
| `binary` | path | Overrides `build.binary`. |

dynAn also exports `DYNAN_PROFILE=release|sanitized`.

Defaults:

```yaml
profiles:
  release:
    cflags: ["-O2", "-g"]
  sanitized:
    cflags: ["-O1", "-g", "-fno-omit-frame-pointer",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    ldflags: ["-fsanitize=address,undefined"]
```

`-fno-sanitize-recover=all` matters: without it UBSan prints a warning and
exits `0`, making undefined behaviour invisible to a dynamic tool.

> Your build must take `CFLAGS`/`LDFLAGS` from the environment. In a Makefile,
> `CFLAGS ?= -O2 -g` is enough — `?=` lets the environment win.

## `execution`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `argv` | list | `["{binary}"]` | Command template; must reference `{binary}`. |
| `delivery` | `stdin` \| `file` \| `argv` \| `none` | `stdin` | Default input mechanism. |
| `timeout_s` | float | `10` | Per-execution limit. |
| `env` | map | `{}` | Extra environment. |
| `working_dir` | path | `"."` | `"."` means a fresh scratch directory per execution. |
| `limits` | object | see below | Resource limits. |
| `max_output_bytes` | int | `1000000` | Captured output cap per stream. |

Placeholders: `{binary}`, `{input}`, `{workdir}`. `{input}` is required when
`delivery: file`.

### `execution.limits`

| Key | Default | Notes |
| --- | ------- | ----- |
| `memory_mb` | `2048` | `RLIMIT_AS` for release; ASan `hard_rss_limit_mb` for sanitized. |
| `cpu_s` | `30` | `RLIMIT_CPU`. |
| `file_size_mb` | `256` | `RLIMIT_FSIZE`. |
| `processes` | `null` | **Off by default.** See warning. |
| `core_dump` | `false` | `RLIMIT_CORE`. |

> **`processes`**: `RLIMIT_NPROC` counts every process owned by your *user*,
> not just this execution's children. On a desktop session, any value below
> your existing process count makes the first fork fail with `EAGAIN` —
> including the sandbox's own namespace setup. Use the container backend's
> per-container `--pids-limit` instead.

> **`memory_mb` and ASan**: AddressSanitizer reserves tens of terabytes of
> virtual address space for shadow memory, so `RLIMIT_AS` kills it at startup.
> dynAn applies the address-space limit to release runs only and bounds
> sanitized runs with ASan's own RSS limit.

## `tests`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `manifests` | list of paths | required, non-empty | Test manifests. |
| `regression_suite` | path | `regression` | Where generated tests are written. |
| `include_generated` | bool | `true` | Load the generated suite in future runs. |

The regression suite is **project-owned**. dynAn never writes into the target's
repository: mutating the code under validation would corrupt the measurement
and make the next run's diff meaningless.

## `sandbox`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `backend` | `bwrap` \| `container` \| `podman` \| `docker` \| `none` | `bwrap` | Isolation backend. |
| `image` | string | `docker.io/library/gcc:13` | Container backends only. |
| `network` | bool | `false` | Network inside the sandbox. |
| `ro_binds` | list of paths | `[]` | Extra read-only host paths. |
| `allow_unsandboxed` | bool | `false` | Required to select `none`. |

`container` picks Podman when available and falls back to Docker.

With the container backend, build *and* execution happen inside the image, so
the binary runs against the libc it was linked against.

## `analysis`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `replay_count` | int ≥ 3 | `3` | Replays per confirmed finding. |
| `minimize` | bool | `true` | Run input minimisation. |
| `minimization_max_iterations` | int | `400` | Candidate executions budget. |
| `minimization_timeout_s` | float | `120` | Wall-clock budget. |
| `generate_regression_tests` | bool | `true` | Promote minimised inputs. |
| `verify_generated_tests` | bool | `true` | Execute them on both versions. |
| `correlate` | bool | `true` | Link findings to the diff. |
| `hardening` | bool | `true` | Inspect ELF protections. |
| `profiles` | list | `[release, sanitized]` | Profiles the suite runs on. |

## `artifacts`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `root` | path | `.dynan` | Run storage root. |
| `keep_worktrees` | bool | `false` | Keep Git worktree registrations. |

## `extensions`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `enabled` | list | `[]` | Extension names to activate. |
| `llm` | object | disabled | See below. |
| `fuzz` | object | disabled | See below. |

An unknown name is a configuration error, not silently ignored. Setting
`<name>.enabled: true` without also listing `<name>` in `enabled` is rejected,
so an extension cannot be half-switched-on.

### `extensions.llm`

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `enabled` | bool | `false` | Master switch. |
| `provider` | `openai` \| `openai_compatible` \| `local` | `openai` | Provider family. |
| `base_url` | string | provider default | Required for non-OpenAI providers. |
| `model` | string | `gpt-4o-mini` | Model identifier. |
| `api_key_env` | string | `OPENAI_API_KEY` | **Name** of the env var holding the key. |
| `timeout_s` | float | `60` | Request timeout. |
| `max_retries` | int | `2` | Retries on transport and 5xx/429 errors only. |
| `allow_source_upload` | bool | `false` | Permits sending source/diff externally. |
| `max_prompt_chars` | int | `24000` | Truncation bound. |

API keys are never stored in configuration, never logged and never returned by
the API.

### `extensions.fuzz`

Grammar- and mutation-based fuzzing of the built targets.

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `enabled` | bool | `false` | Master switch. |
| `iterations` | int | `300` | Inputs to execute per version. |
| `time_budget_s` | float | `120` | Wall-clock ceiling per campaign. |
| `max_findings` | int | `10` | Stop after this many distinct signatures. |
| `seed` | int \| null | `1337` | PRNG seed. Fixed by default so a campaign is reproducible; `null` for a fresh corpus each run. |
| `strategy` | `grammar` \| `mutation` \| `both` | `both` | Generation strategy. |
| `grammar` | object | none | Required for `grammar`; optional for `both`. |
| `max_input_bytes` | int | `8192` | Size cap on generated inputs. |
| `versions` | list | `[base, patched]` | Which builds to fuzz. |
| `profile` | `release` \| `sanitized` | `sanitized` | Build profile to fuzz. |
| `confirm_replays` | int | `3` | Replays required to call a crash confirmed. |
| `minimize` | bool | `true` | Minimise confirmed crashes. |
| `minimization_max_iterations` | int | `150` | Minimisation budget. |
| `promote_to_regression` | bool | `true` | Emit confirmed patched-only crashes into the regression suite. |
| `delivery` | `stdin` \| `file` \| `argv` \| null | suite default | How generated inputs reach the target. |
| `argv` | list | `[]` | Extra arguments for generated inputs; needed to place `{input}` when `delivery` is `file` or `argv`. |

By default the fuzzer uses the suite's own `execution.delivery`, so generated
inputs arrive exactly as hand-written ones do. Override it to fuzz a different
surface — a target that reads both stdin and a named file has two attack
surfaces, and fuzzing only one tests only half the program:

```yaml
    delivery: file
    argv: ["{input}"]
```

#### Fuzz findings never change the exit code

This is deliberate. The specification judges a patch *within the agreed test
scope*, and a fuzzer invents inputs outside that scope by construction — if it
could move the verdict, the same patch would pass or fail depending on a
random seed.

The promotion path is the honest alternative. A crash that is

1. **confirmed** — reproduced `confirm_replays` times in a row,
2. **minimised** — under the same signature-preserving predicate the core
   pipeline uses, and
3. **patched-only** — verified *not* to reproduce on the base build,

is written into `tests.regression_suite`. The next run then evaluates it
in scope, where it does affect the verdict — and by then it is a named,
reviewable test rather than a lucky draw.

A crash that also reproduces on the base version is reported as
`pre_existing` and never promoted: it did not come from the patch. Fuzzing
only the patched version makes that distinction impossible, so the doctor
warns when `versions` omits `base`.

#### `extensions.fuzz.grammar`

Random bytes are rejected by a parser's first validity check, so they only
ever exercise the error path. A grammar produces structurally plausible
inputs that reach the deeper code a security patch usually touches.

| Key | Type | Default | Meaning |
| --- | ---- | ------- | ------- |
| `start` | string | — | Non-terminal to start from. Must have a rule. |
| `rules` | map | — | Non-terminal → list of alternatives. |
| `max_depth` | int | `12` | Depth after which only cheapest-terminating alternatives are chosen. |

Inside an alternative:

| Syntax | Meaning |
| ------ | ------- |
| `{name}` | Expand rule `name`. |
| `{{` | A literal `{`. |
| `}}` | A literal `}`. |

**A malformed reference is an error, not literal text.** `{ name }` (spaces),
`{na-me}` (invalid character), `{name` (unterminated) and a stray `}` are all
rejected at load time. Silently treating them as literals would mean a typo
produces a fuzzer that quietly explores nothing.

Recursion is fine and expected:

```yaml
grammar:
  start: document
  max_depth: 10
  rules:
    document:
      - "{line}\n"
      - "{line}\n{document}"      # recursive: safe
    line:
      - "{key}={value}"
      - "{key}:{value}"
      - "# {value}"
      - ""
    key: ["host", "port", "{ident}"]
    ident: ["a", "k", "_"]
    value:
      - ""
      - "localhost"
      - "123456789012345"         # at the specified limit
      - "1234567890123456"        # one past it
      - "{chunk}{value}"          # recursive: safe
    chunk: ["A", "AAAAAAAA", "0123456789abcdef"]
```

dynAn proves the grammar terminates **before** running it, by a fixpoint
analysis over the rules. A rule needs no literal alternative of its own as
long as it can reach literal text through others — `document → {line}`
terminates because `line` does. Only a genuinely circular set, such as
`a → {b}` with `b → {a}`, is rejected:

```
grammar rule(s) 'a', 'b' can never terminate: every alternative leads back
into an endlessly recursive rule.
```

Past `max_depth` the generator restricts itself to the cheapest-terminating
alternatives, so expansion always closes — termination is deterministic, not
a matter of luck.

`dynan doctor --config FILE` generates sample inputs from the grammar and
reports them, so a grammar that cannot vary its output is caught before a
campaign spends its budget on it.

A complete worked example ships as
[`configs/confparse-incomplete-fuzz.yaml`](../configs/confparse-incomplete-fuzz.yaml).

---

# Test manifest schema

Test definitions live outside the main configuration so a suite can grow
without touching tool settings, and so the generated regression suite is just
another manifest.

```yaml
version: 1

oracle:
  provenance: "targets/confparse/SPEC.md"   # default for all tests below

defaults:
  delivery: stdin
  timeout_s: 10

tests:
  - id: valid_basic
    category: valid
    description: "Both separators in one input."
    input_file: inputs/valid_basic.txt
    expect:
      exit_code: 0
      stdout_exact: |
        host=localhost
        ok 1
      provenance: "SPEC.md section 4"
```

### Test fields

| Key | Required | Meaning |
| --- | -------- | ------- |
| `id` | yes | Matches `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; used in paths and URLs. |
| `category` | no | `valid` \| `boundary` \| `invalid` \| `security`. Default `valid`. |
| `description` | no | Free text. |
| `delivery` | no | Overrides the manifest default. |
| `input_file` | one of | Path, relative to the manifest. |
| `input` | one of | Inline UTF-8 text. |
| `input_hex` | one of | Inline binary as hex. |
| `input_base64` | one of | Inline binary as base64. |
| `argv` | no | Extra arguments appended to `execution.argv`. |
| `timeout_s` | no | Overrides the execution timeout. |
| `expect` | no | The oracle expectation. |
| `expect_baseline_signature` | no | Signature the base version is expected to exhibit. |

### `expect`

| Key | Meaning |
| --- | ------- |
| `exit_code` | Required exit status. |
| `stdout_exact` | Byte-for-byte stdout. |
| `stdout_contains` | String or list of required substrings. |
| `stdout_regex` | Pattern searched with `MULTILINE`. |
| `stderr_contains` | String or list of required substrings. |
| `must_not_crash` | Default `true`. Signals and timeouts violate it. |
| `max_duration_s` | Upper bound on runtime. |
| `provenance` | Where the expectation came from. |

### Input delivery

A test receives its input through one of three mechanisms. `delivery` may be
set per test, overriding `execution.delivery`.

| `delivery` | How the input reaches the program |
| ---------- | --------------------------------- |
| `stdin` | Written to the process's standard input. |
| `file` | Written to a file in the working directory; `{input}` in the command line expands to its path. |
| `argv` | Decoded as text; `{input}` expands to it as a single argument. |
| `none` | Nothing is delivered. |

`file` and `argv` both work by substituting `{input}`, which must appear in
`execution.argv` **or** in the test's own `argv`:

```yaml
  - id: delivery_file_input
    delivery: file
    argv: ["{input}"]            # the program takes a filename
    input_file: inputs/valid_basic.txt

  - id: delivery_argv_input
    delivery: argv
    argv: ["-c", "{input}"]      # the program takes the text inline
    input: "host = localhost\n"
```

A `file` or `argv` test with no reachable `{input}` is a configuration error.
Without that check the input would silently never arrive and the test would
"fail" for a reason unrelated to the patch. `dynan doctor` reports it too.

Binary inputs work with every mechanism; `argv` decodes them as UTF-8 with
replacement, since a command-line argument cannot carry a NUL byte.

### Checking files the program writes

Many programs report their result through an output file rather than stdout.
`output_file` (one entry) or `output_files` (a list) asserts on those.

```yaml
  - id: output_file_written
    argv: ["-o", "result.txt"]
    input_file: inputs/valid_basic.txt
    expect:
      exit_code: 0
      stdout_exact: ""
      output_file:
        path: result.txt
        exact: |
          host=localhost
          ok 1
      provenance: "SPEC.md section 8"
```

| Key | Meaning |
| --- | ------- |
| `path` | Relative to the execution working directory. Absolute paths and `..` are rejected. |
| `exists` | Default `true`. `false` asserts the file must **not** be there. |
| `exact` | Full expected content. `exact: ""` means "exists and is empty" — distinct from absent. |
| `contains` | String or list of required substrings. |
| `regex` | Pattern searched with `MULTILINE`. |

A bare string is shorthand for "must exist": `output_file: result.txt`.

Declared files are read immediately after the process exits and stored as run
artifacts, so the bytes the oracle checked are preserved as evidence and are
visible in the web UI.

Where to write: the working directory is a fresh per-execution scratch
directory, so a relative path like `result.txt` is usually right. `{workdir}`
expands to its absolute path if the program needs one.

### The independence rule

An expectation counts as an **independent correctness oracle** only when it
has both:

1. a non-empty `provenance`, and
2. at least one concrete assertion — `exit_code`, `stdout_exact`,
   `stdout_contains`, `stdout_regex`, `stderr_contains`, or an output file
   with asserted content (`exact`, `contains`, `regex`) or asserted absence
   (`exists: false`).

`must_not_crash` alone is a safety check, not a functional criterion. So is a
bare `output_file: result.txt`: "the file was created" says nothing about what
the program computed, so it does not license a regression claim either.

This matters because **a functional regression can only be claimed against an
independent oracle**. The specification forbids treating the patched program's
own output as the correctness reference, so a test without provenance is
skipped by regression detection — it is still executed, and still contributes
security findings.

`dynan doctor --config FILE` reports how many of your tests carry a usable
oracle, and warns when none do.
