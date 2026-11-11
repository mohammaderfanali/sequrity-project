# `confparse` - behavioural specification

This document is the **independent correctness oracle** for the `confparse`
target. It was written before the patches were produced and does not describe
any particular implementation; the tests in `tests/manifest.yaml` cite it by
section through their `expect.provenance` field.

The project specification requires the correctness criterion to be defined
independently of the patched program. Concretely: if a patched build disagrees
with this document, the document is right and the build is wrong.

## 1. Purpose

`confparse` reads configuration entries from standard input, one entry per
line, validates them, and writes the normalised entries to standard output.

## 2. Input grammar

Each line is one of:

| Form        | Meaning                                  |
| ----------- | ---------------------------------------- |
| *(empty)*   | ignored                                  |
| `# ...`     | comment, ignored                         |
| `key=value` | an entry                                 |
| `key:value` | an entry; `:` and `=` are equivalent     |

The separator is the **first** occurrence of `=` or `:` in the line, whichever
comes first.

Whitespace immediately around the key and the value is removed.

## 3. Validity rules

1. The key must be non-empty and at most **31** characters.
2. The key must consist only of `A-Z`, `a-z`, `0-9` and `_`.
3. The value must be at most **15** characters after trimming.
4. The value may be empty.
5. A line containing neither `=` nor `:` is invalid.

## 4. Output

For every valid entry, in input order, exactly one line on standard output:

```
key=value
```

Note that a `key:value` input is normalised to `key=value` on output.

After the last entry, one final line on standard output:

```
ok N
```

where `N` is the decimal count of accepted entries.

## 5. Errors

On the **first** invalid line, the program writes one line to standard error:

```
error: line L: REASON
```

where `L` is the 1-based line number and `REASON` is exactly one of:

| Reason            | Condition                              |
| ----------------- | -------------------------------------- |
| `missing separator` | rule 5 violated                      |
| `empty key`       | rule 1 violated, key empty             |
| `key too long`    | rule 1 violated, key over 31 chars     |
| `invalid key`     | rule 2 violated                        |
| `value too long`  | rule 3 violated                        |

It then stops processing and exits.

## 6. Exit codes

| Code | Condition                      |
| ---- | ------------------------------ |
| `0`  | every line was valid           |
| `2`  | an invalid line was found      |

No other exit code is specified. The program must not terminate abnormally
(signal, abort) for any input, including malformed or oversized input.

## 7. Worked examples

Input:

```
# database settings
host = localhost
port:8080

name=main_db
```

Standard output:

```
host=localhost
port=8080
name=main_db
ok 3
```

Exit code `0`.

---

Input:

```
host=localhost
this_value_is_far_too_long_to_fit=x
```

The key on line 2 is 33 characters, violating rule 1.

Standard output:

```
host=localhost
```

Standard error:

```
error: line 2: key too long
```

Exit code `2`.

---

Input:

```
level=0123456789abcdefghij
```

The value is 20 characters, violating rule 3.

Standard error:

```
error: line 1: value too long
```

Exit code `2`.
