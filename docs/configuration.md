# Configuration reference

One schema serves the CLI, the web UI and CI. It is validated before any
expensive work starts, and an invalid file produces a list of problems rather
than a stack trace.

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

An unknown name is a configuration error, not silently ignored.

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

### The independence rule

An expectation counts as an **independent correctness oracle** only when it
has both:

1. a non-empty `provenance`, and
2. at least one concrete assertion (`exit_code`, `stdout_exact`,
   `stdout_contains`, `stdout_regex` or `stderr_contains`).

`must_not_crash` alone is a safety check, not a functional criterion.

This matters because **a functional regression can only be claimed against an
independent oracle**. The specification forbids treating the patched program's
own output as the correctness reference, so a test without provenance is
skipped by regression detection — it is still executed, and still contributes
security findings.

`dynan doctor --config FILE` reports how many of your tests carry a usable
oracle, and warns when none do.
