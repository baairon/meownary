# Driving meownary from an agent

This guide is the operating manual for scripts, CI jobs and AI agents that run
meownary without a person at the keyboard. It covers how to invoke each command,
how to read its output, what every exit code means, and which workflows are safe
to chain. The [README](../README.md) explains what meownary removes and why; this
page explains how to drive it and check the results.

Everything here describes the shipped binary. When in doubt, ask the binary:
`meownary capabilities --json` and `meownary schema <name> --json` are the
source of truth, and the JSON schemas in [schemas/](schemas) are compiled into
it unchanged.

## Contents

- [Ground rules](#ground-rules)
- [Two command families](#two-command-families)
- [Reading output](#reading-output)
- [Exit codes](#exit-codes)
- [Choosing a command](#choosing-a-command)
- [Argument rules](#argument-rules)
- [Precision command reference](#precision-command-reference)
- [Legacy command reference](#legacy-command-reference)
- [Workflows](#workflows)
- [Rules files](#rules-files)
- [Edit specs and plans](#edit-specs-and-plans)
- [Verification reports](#verification-reports)
- [Limits](#limits)
- [Errors and fixes](#errors-and-fixes)
- [Safety guarantees](#safety-guarantees)

## Ground rules

1. **Always pass `--json`.** Every non-interactive command supports it, and the
   human output is not a stable interface.
2. **Trust the exit code, then the `done` event.** The process exit code always
   equals the `exit` field of the final `done` event.
3. **Never run the bare `meownary` or `meownary <path>` without a verb.** Those
   open the interactive view and wait for keys.
4. **Prefer copies.** Deattribution and byte edits write a new file by default.
   Only `clean --category`/`--signature`, `bytes ... --in-place` and
   `apply --in-place` change an original, and all three can be undone.
5. **Plan, then apply.** Save a plan with `--plan-out`, inspect it, apply it with
   `apply`, then confirm it with `verify`. Plans refuse to run against an input
   that changed after planning.
6. **Treat exit 75 as "not done".** It means coverage, verification or I/O fell
   short. Do not report success on 75.
7. **Use `--` before untrusted paths.** Everything after `--` is a path, even if
   it starts with a dash.
8. **meownary makes no network requests**, needs no credentials, and never
   executes the files it reads.

## Two command families

meownary has two command-line surfaces with different JSON dialects. Know which
one you are calling before you parse its output.

| | Legacy commands | Precision commands |
|---|---|---|
| Verbs | `scan`, `clean`, `undo` | `deattribute`, `inspect`, `inventory`, `hash`, `bytes`, `find`, `strings`, `diff`, `plan`, `apply`, `verify`, `archive`, `capabilities`, `schema` |
| Input | one file or a folder, walked recursively | one regular file (`inventory` and `archive pack` take a folder) |
| JSON line shape | flat: `{"event":"finding","path":...}` | enveloped: `{"version":1,"event":"match","data":{...}}` |
| Last line | `{"event":"done",...,"exit":N}` | `{"version":1,"event":"done","exit":N,"complete":bool}` |
| Errors | `error` field on `done` | an `error` event, then `done` |
| Without `--json` | aligned text for people | each event's `data` as pretty JSON, no envelope, no `done` |
| Help | `meownary --help` | `meownary bytes --help` (any precision verb with `--help`) |

**Routing rule.** `clean` becomes the precision `deattribute` command when it
carries `--deattribute` plus any of `--rules`, `--verify`, `--max-scan`,
`--max-matches`, `--plan-out` or `--output` (before `--`). That form takes one
regular file, not a folder, and speaks the enveloped dialect. Without
`--deattribute`, those options make `clean` exit 2 with
`policy options on clean require --deattribute`.

## Reading output

### Precision commands

With `--json`, stdout carries JSON Lines, one object per line. Each line is one
of three shapes, as defined by `meownary schema events`:

```json
{"version":1,"event":"<name>","data":{}}
{"version":1,"event":"error","error":"<message>","exit":2}
{"version":1,"event":"done","exit":0,"complete":true}
```

- Result events carry `data`. Their names are listed per command below.
- An `error` event appears only when the command stopped early. It is always
  followed by `done`.
- `done` is always the last line. `complete` is `true` exactly when `exit` is 0.
- A command can finish with `complete: false` and no `error` event: that is an
  incomplete result (exit 75), such as a search that hit its byte budget or a
  verification that failed. Read the preceding result events to see why.
- Without `--json`, errors go to stderr as `meownary: <message>`.

A minimal reader:

```python
import json, subprocess

proc = subprocess.run(
    ["meownary", "find", "sample.bin", "--text", "North Star", "--json"],
    capture_output=True, text=True,
)
events = [json.loads(line) for line in proc.stdout.splitlines() if line]
done = events[-1]
assert done["event"] == "done" and done["exit"] == proc.returncode
matches = [e["data"] for e in events if e["event"] == "match"]
errors = [e["error"] for e in events if e["event"] == "error"]
```

### Legacy commands

`scan --json`, `clean --json` and `undo --json` print flat objects, one per
line, ending with a `done` object that carries `exit`. Field tables for `clean`
and `undo` are in the README's [JSON output](../README.md#json-output) section;
`scan` is described under [Legacy command reference](#legacy-command-reference).

## Exit codes

| Code | Legacy commands | Precision commands | What an agent should do |
|---|---|---|---|
| 0 | success | complete success | continue |
| 1 | `scan --fail-on` met; `clean` matched but changed nothing; `undo` failed | never used | read the events; for `scan`, act on the findings |
| 2 | bad command, flag or value; missing path | bad command, flag or value; invalid rules or spec; stale plan; search selection problems; symbolic link or non-regular input | fix the arguments or re-plan; retrying unchanged will fail the same way |
| 73 | state store unavailable or held by another meownary; nothing edited | not used (state-store failures surface as 75) | wait for the other meownary to exit, then retry |
| 75 | some files not fully read; a copy not written or verified | incomplete coverage or verification, or an operational error such as a missing file, an existing output without `--overwrite`, or a staged copy that failed verification | inspect the events; do not treat as success |
| 101 | internal error | internal error | report it; the message says where |
| 130 | interrupted (Windows reports `0xC000013A`) | same | rerun if the interruption was not intended |

Two precision details that differ from the legacy commands:

- A path that does not exist is an I/O error in the precision family, so it
  exits **75**, not 2.
- "Already exists" errors for binary outputs and plans exit **75**; the
  archive `--manifest` existence check exits **2**.

## Choosing a command

| Goal | Command |
|---|---|
| List what a file or folder carries | `scan <path> --json` |
| Identify a file's format, layout and protected spans | `inspect <file> --json` |
| Hash one file (size, BLAKE3, SHA-256) | `hash <file> --json` |
| Hash every file under a folder | `inventory <dir> --json` |
| Deattribute one file with policy control and a saved plan | `deattribute <file> ... --json` |
| Deattribute a whole folder or archive tree | `clean <path> --deattribute [--deep] --json` |
| Remove selected metadata from originals | `clean <path> --category <slug> --json` or `--signature <id>` |
| Delete files that carry a finding | `clean <path> --category <slug> --file --force --json` |
| Revert scrubs, deletes and in-place byte edits | `undo [--last \| --all] --json` |
| Read raw bytes | `bytes read <file> --offset N --length N --json` |
| Search text or hex | `find <file> --text T --json` or `--hex H` |
| List embedded strings | `strings <file> --encoding E --json` |
| Compare two files byte by byte | `diff <a> <b> --json` |
| Patch bytes at an offset or at search hits | `bytes replace\|fill\|insert\|delete\|truncate ...` |
| Apply several exact edits at once | `plan <file> --spec S --output P`, then `apply P` |
| Check a written copy against its plan | `verify <plan> <output> --json` |
| List, extract, repack or verify ZIP and TAR | `archive list\|extract\|pack\|verify ...` |
| Read MSI installer tables | `archive msi <file> --json` |
| Discover features and schemas | `capabilities --json`, `schema <name> --json` |

## Argument rules

These apply to every precision command:

- Options may appear before or after paths. `--flag value` and `--flag=value`
  are both accepted. A value option always consumes the next argument, even one
  that starts with `-`, so `--text --json` searches for the text `--json`.
- Switches reject a value: `--dry-run=yes` exits 2.
- Repeating an option exits 2 (`duplicate option`). An option the subcommand
  does not use exits 2 (`does not apply to this command`).
- `--` ends options. Every later argument is a path.
- Numbers accept decimal or `0x` hexadecimal, never negative.
- Hex strings accept pairs of hex digits with optional spaces, such as
  `"4e 6f 72"`. Search patterns (not payloads) may use `?` for a wildcard nibble.
- `--help` or `-h` anywhere (outside option values, before `--`) prints the
  precision help and exits 0.
- Paths are passed through as raw OS strings, so non-UTF-8 file names work.
- Inputs must be regular files. An input, an existing output or a pack folder
  that is itself a symbolic link is refused with exit 2. Links in parent
  folders resolve like any other path, so macOS `/tmp` and `/var` and Windows
  junctions work.
- Paths are compared in one resolved spelling, so two names for the same place
  (`/var` and `/private/var`, or a Windows 8.3 short name and its long name)
  count as the same file in every collision check.

Legacy commands use a stricter parser: option values may not start with `-`,
and unknown options exit 2.

## Precision command reference

Each entry lists the exact options the command accepts, the events it prints in
order, and when it counts as complete. `--json` is accepted everywhere and is
omitted from the option lists.

### `capabilities`

```sh
meownary capabilities --json
```

- **Options**: none. **Events**: `capabilities`. **Complete**: always.
- `data` lists `schema_version`, deattribute modes (`normal`, `deep`),
  verification policies, byte operations, encodings, hashes, default limits and
  archive formats. Check `schema_version` before relying on field names.

### `schema`

```sh
meownary schema [plan|rules|spec|events] --json
```

- **Options**: none; one optional name, default `plan`. **Events**: `schema`,
  whose `data` is the JSON Schema object. **Complete**: always.
- The same files are in [docs/schemas](schemas).

### `hash`

```sh
meownary hash <file> --json
```

- **Options**: none. **Events**: `hash` with `{"size","blake3","sha256"}`.
- Hex digests are lowercase.

### `inventory`

```sh
meownary inventory <dir> --json
```

- **Options**: none. Walks the folder in file-name order without following
  symbolic links.
- **Events**: one `entry` per file, `{"path","hashes"}`, or
  `{"path","status":"symlink skipped"}` for a link; then `inventory` with
  `{"files": N}` counting hashed files.
- **Complete**: false (exit 75) when any symbolic link was skipped.

### `inspect`

```sh
meownary inspect <file> [--details] --json
```

- **Options**: `--details` is accepted and currently adds nothing.
- **Events**: `inspection` with `path`, `hashes`, `layout`, `partial` and
  `findings` (`[{"category","signature"}]`). PE files add `architecture`
  (`pe32` or `pe64`), `checksum` and `signature_present`.
- `layout` has `size`, `format`, `regions` (`[{"span","category"}]`),
  `protected`, `linkage`, `fields` and `valid`. Region `category` labels are
  what rules files match with `regions` globs.
- **Complete**: false (exit 75) when the scan could not read the whole file.

### `bytes read`

```sh
meownary bytes read <file> [--offset N] [--length N] [--encoding E] [--details] --json
```

- Defaults: offset 0, length 256 (or less at the end of the file). At most
  1 MiB per call; a range past the end exits 2.
- **Events**: `bytes` with `{"offset","len","hex"}`; `--details` adds `text`,
  the bytes decoded with `--encoding` (default `utf8`), or null when they do
  not decode.

### `find`

```sh
meownary find <file> (--text TEXT | --hex HEX) [--encoding E] [--boundary B]
  [--ignore-case] [--offset N] [--length N] [--max-scan N] [--max-matches N]
  [--details] --json
```

- Exactly one of `--text` or `--hex`. `--encoding`, `--boundary` and
  `--ignore-case` apply to `--text` only; with `--hex` they exit 2.
- Defaults: encoding `utf8`, boundary `substring`, case-sensitive, whole file.
- Hex patterns need at least one exact byte; `?` matches one nibble.
- **Events**: one `match` per hit, `{"pattern":0,"offset","len","encoding"}`
  (`encoding` is null for hex); `--details` adds `bytes_hex`. Then `coverage`
  with `{"complete","examined","unexamined","matches"}`; the range lists are
  `[{"offset","len"}]`.
- **Complete**: false (exit 75) when `--max-scan` or `--max-matches` stopped the
  search. Zero matches with full coverage is exit 0.

### `strings`

```sh
meownary strings <file> [--encoding E] [--min-length N] [--limit N]
  [--offset N] [--length N] [--max-scan N] [--details] --json
```

- Defaults: encoding `utf8`, minimum 4 characters, at most 1,000 strings.
- **Events**: one `string` per run, `{"offset","len","encoding","truncated"}`
  in encoded bytes; `--details` adds `text`. Then `coverage`.
- A run longer than 64 KiB keeps its offset and reports `truncated: true`.
- **Complete**: false (exit 75) when `--limit` or `--max-scan` cut the walk;
  `coverage.unexamined` says where it stopped.

### `diff`

```sh
meownary diff <before> <after> [--limit N] [--max-scan N] [--details] --json
```

- **Events**: one `diff` with `before_size`, `after_size`, `ranges`
  (`[{"offset","len"}]` of differing bytes, compared by position) and
  `complete`. `--details` adds `details`: per range, `before_hex`, `after_hex`
  and `sample_bytes`, at most 64 bytes each.
- Bytes past the end of the shorter file count as different.
- **Complete**: false (exit 75) when `--limit` (default 1,000 ranges) or
  `--max-scan` stopped the comparison.

### `deattribute`

```sh
meownary deattribute <file> [--deep] [--rules FILE] [--verify strict|protected]
  [--plan-out FILE] [--output FILE] [--overwrite] [--dry-run]
  [--max-scan N] [--max-matches N] [--details] --json
```

- One regular file. For folders and archive trees use
  `clean <path> --deattribute`.
- `--rules` reads a [rules file](#rules-files) (or `-` for stdin).
  `--verify` defaults to `strict`.
- **What gets written**:

  | Flags | Plan file | Binary copy |
  |---|---|---|
  | none | no | `<name>.deattributed.<ext>` beside the input |
  | `--output F` | no | `F` |
  | `--plan-out P` | `P` | no |
  | `--plan-out P --output F` | `P` | `F` |
  | `--dry-run` (with or without `--plan-out`) | only if `--plan-out` | no |

  Existing files need `--overwrite`. The plan and the copy must be different
  files, and a plan may not replace the input.
- **Events**:
  1. `planned`: `{"input","operations","affected_bytes","coverage_complete","skipped"}`,
     where `skipped` lists skip reasons such as `functional name kept`.
  2. `audit` (with `--details` only): the identities learned, their patterns,
     the parsed layout and allowances. This can contain identity text.
  3. Then one of:
     - nothing more, for `--dry-run` or a plan-only run;
     - `verification`, when there was nothing to change: the original itself is
       checked against the policy;
     - `saved`, an apply report `{"output","operations","undo_id","verified"}`.
- **Complete**:
  - dry run or plan only: `coverage_complete`;
  - nothing to change: the verification passed;
  - copy written: always, because a copy that fails verification is never
    published and the run ends with an `error` event and exit 75 instead.
- Coverage is incomplete when any skip reason is `io error`,
  `changed since scan`, `malformed metadata` or `deep scan budget reached`.

### `bytes replace | fill | insert | delete | truncate`

```sh
meownary bytes <op> <file>
  (--offset N [--length N] | --find-text TEXT | --find-hex HEX)
  [--hex HEX | --text TEXT | --data-file FILE | --fill BYTE]
  [--encoding E] [--boundary B] [--ignore-case] [--max-scan N] [--max-matches N]
  [--expect N] [--occurrence N] [--resize] [--pad BYTE]
  [--plan-out FILE] [--output FILE | --in-place] [--overwrite] [--dry-run] [--raw] --json
```

Selection is either an explicit range or a search:

- **Range**: `--offset` (required) and `--length`. `truncate` takes only
  `--offset` and removes everything after it. `insert` takes only `--offset`.
- **Search**: `--find-text` or `--find-hex`, never with `--offset`/`--length`.
  Every match becomes one operation. `--expect N` refuses unless exactly N
  matches were found; `--occurrence N` keeps only the Nth (from 1). A search
  must complete and find at least one match, or the command exits 2.

Payloads per operation:

| Operation | Needs | Removes | Notes |
|---|---|---|---|
| `replace` | one of `--hex`, `--text`, `--data-file` | the selected range | same length unless `--resize`; `--pad BYTE` pads a shorter `--hex`/`--text` value to the range; without `--length` (or with `--length 0`), replaces as many bytes as the payload holds |
| `fill` | `--fill BYTE` and a length or search | the selected range | writes BYTE over the whole range |
| `insert` | one of `--hex`, `--text`, `--data-file` | nothing | the payload lands at `--offset`, ahead of the byte that was there |
| `delete` | a length or search | the selected range | no payload allowed |
| `truncate` | `--offset` | the tail | no payload allowed |

- `--encoding` encodes `--text` and `--find-text`; it is rejected otherwise.
- `--data-file` payloads are pinned by hash inside the plan.
- `--raw` is required to resize a recognized format or to touch its protected
  or unverified regions. Raw plans verify bytes only.
- **Output**: a copy at `<file>.edited` by default, `--output` elsewhere, or
  `--in-place` to replace the input with an undo snapshot. `--plan-out` alone
  writes only the plan; add `--output` or `--in-place` to also apply.
  `--dry-run` writes no binary (it still writes a requested plan).
- **Events**: `planned` with `{"operations","before","after","raw"}` (hashes
  of the input and the expected output), then `applied` with an apply report
  unless nothing was applied.
- **Complete**: always when it gets that far.

### `plan`

```sh
meownary plan <file> --spec SPEC [--output PLAN] [--overwrite] [--raw] --json
```

- Reads an [edit spec](#edit-specs-and-plans) (or `-` for stdin) and pins it
  to the current input. `--output` saves the plan.
- **Events**: `plan`, the full plan object.

### `apply`

```sh
meownary apply <plan> [--output FILE | --in-place] [--overwrite] [--raw] --json
```

- Checks that the input, every affected range and every payload file still
  match the plan, writes a temporary sibling, verifies it, then publishes it.
- Default output is `<input>.edited`. Writing to the input path requires
  `--in-place`; `--in-place` requires the input path.
- A raw plan needs `--raw` again here.
- **Events**: `applied` with `{"output","operations","undo_id","verified"}`.
  `undo_id` is set only for `--in-place`.

### `verify`

```sh
meownary verify <plan> <output> --json
```

- **Options**: none.
- Re-checks the original (or, after an in-place apply, its undo snapshot),
  then checks the output. See [Verification reports](#verification-reports).
- **Events**: `verification`. **Complete**: when every check passed; a failed
  check is exit 75 with no `error` event.

### `archive`

```sh
meownary archive list <archive> [--manifest FILE] [--overwrite] [limits] --json
meownary archive extract <archive> --output DIR [--manifest FILE] [--overwrite] [limits] --json
meownary archive pack <dir> --output ARCHIVE [--format zip|tar|tar.gz]
  [--manifest FILE] [--overwrite] [--normalize-metadata] [limits] --json
meownary archive verify <archive> --manifest FILE [limits] --json
meownary archive msi <installer.msi> [--limit N] --json
```

`[limits]` is `--limit N` (entries, default 100,000), `--max-entry N` (bytes,
default 256 MiB) and `--max-total N` (bytes, default 1 GiB).

- Formats: ZIP and ZIP64, TAR, TAR.GZ. `pack` defaults to `zip`.
- `extract` needs a destination that does not exist yet; it stages the folder
  and publishes it whole.
- `--manifest` must sit outside the input tree and the output. An existing
  manifest needs `--overwrite` (exit 2 otherwise).
- **Events**: `list`, `extract` and `pack` print `archive` with the manifest,
  `{"version":1,"entries":[{"path","directory","hashes"}]}` (directories have
  null `hashes`). `verify` prints `archive_verification` with
  `{"verified": bool}`; false is exit 75.
- `msi` prints `msi` with `tables` (rows of `File`, `Component`, `Directory`,
  `Media` and `Property`, binary cells as `{"binary_stream":true}`),
  `complete`, `payloads_extracted: false` and a `note`. `--limit` caps the
  total number of rows; hitting it makes the run incomplete (exit 75).
- Nested archives are ordinary files here. Links, special files, absolute or
  traversing paths, duplicates and case collisions are refused.

## Legacy command reference

### `scan`

```sh
meownary scan <path> [--fail-on info|notice|warn|alert] [--no-color] --json
```

Events, in walk order:

- `identify` per file: `{"event","path","format","size","partial","error"?}`.
  `error` appears only when `partial` is true.
- `finding` per finding: `{"event","path","category","confidence","severity",
  "signature","title","offset","note","removable","category_detail","marker"}`.
  `marker` is null or `{"op","offset","len","container"}`.
- `done`: `{"event","files","partial_files","findings","by_severity",
  "worst","exit"}`, where `by_severity` counts `info`, `notice`, `warn` and
  `alert`.

Categories are `identity`, `brand`, `integrity`, `tamper`, `deception`,
`bundleware` and `junk`; these are also the `--category` slugs for `clean`.
The `signature` value is what `clean --signature` takes.

### `clean` and `undo`

See the README for [deattribute](../README.md#deattribute),
[scrub](../README.md#scrub), [delete](../README.md#delete),
[undo](../README.md#undo) and their [JSON fields](../README.md#json-output).
Agent-relevant points:

- Always run `clean ... --dry-run --json` first. It plans every edit, runs the
  safety checks and writes nothing.
- Scrub skips weak and warn-level edits unless `--force` is given; only pass
  `--force` after reading the dry run.
- One `clean` run is one undo group. `undo --last` reverts the newest group.
- The state store allows one writer. A second concurrent meownary exits 73
  without editing.

## Workflows

### Deattribute one binary with a reviewable plan

```sh
# 1. Look before touching anything.
meownary inspect app.dll --json
meownary deattribute app.dll --deep --dry-run --details --json

# 2. Save the plan without writing a binary.
meownary deattribute app.dll --deep --verify protected --plan-out app.plan.json --json

# 3. Apply it to a copy, then verify the copy independently.
meownary apply app.plan.json --output app.clean.dll --json
meownary verify app.plan.json app.clean.dll --json
```

Stop at step 1 when `planned.coverage_complete` is false: the plan would leave
part of the file unexamined. Under `strict`, any surviving learned identity
fails verification; switch to `protected` only when the retained names are
load-bearing (imports, linkage, explicit exclusions) and that is acceptable.

### Deattribute a folder

```sh
meownary clean ./vendor --deattribute --deep --dry-run --json
meownary clean ./vendor --deattribute --deep --json
```

Read `saved` events for each copy and its `verified` flag, and `skipped`
events for reasons. Exit 75 means at least one copy was not written or not
verified.

### Add identities the engine cannot infer

```sh
meownary schema rules --json > rules.schema.json
meownary deattribute app.dll --rules identities.json --dry-run --details --json
```

Use `expected_matches` in each rule to fail fast when a name appears more or
fewer times than expected.

### Patch bytes at every match of a string

```sh
meownary find app.bin --text "North Star" --json
meownary bytes replace app.bin --find-text "North Star" --text "South Star" \
  --expect 2 --plan-out patch.json --json
meownary apply patch.json --output app.patched.bin --json
meownary verify patch.json app.patched.bin --json
```

`--expect` turns a silent over- or under-match into exit 2 before any write.

### Apply several exact edits from a spec

```sh
meownary schema spec --json
meownary plan app.bin --spec edits.spec.json --output edits.plan.json --json
meownary apply edits.plan.json --output app.edited.bin --json
```

### Edit in place and undo

```sh
meownary bytes fill app.bin --offset 0x200 --length 16 --fill 0 --in-place --json
meownary undo --last --json
```

`applied.undo_id` identifies the journal record. A later `verify` of an
in-place plan needs that undo snapshot, so verify before undoing or clearing
state.

### Repack an archive reproducibly

```sh
meownary archive extract bundle.zip --output ./bundle --manifest bundle.json --json
meownary archive pack ./bundle --format zip --normalize-metadata \
  --output rebuilt.zip --manifest rebuilt.json --json
meownary archive verify rebuilt.zip --manifest rebuilt.json --json
```

### Gate CI on findings

```sh
meownary scan ./dist --fail-on warn --json > scan.jsonl
```

Exit 1 means a finding at `warn` or above; 75 means some files could not be
fully read.

## Rules files

A rules file adds identities for `deattribute --rules`. Schema:
`meownary schema rules`.

```json
{
  "version": 1,
  "identities": [
    {
      "id": "publisher",
      "scope": "publisher",
      "names": ["North Star Labs", "NorthStar"],
      "encodings": ["utf8", "utf16le"],
      "boundary": "identifier",
      "ignore_ascii_case": true,
      "replacement": "Nobody Labs",
      "pad": " ",
      "files": ["bin/*.dll"],
      "regions": ["PE data"],
      "expected_matches": 3
    }
  ],
  "exclusions": [
    {"kind": "text", "value": "NorthStarRequiredABI"},
    {"kind": "hex", "value": "4e 53 ?? 00"}
  ]
}
```

| Field | Required | Default | Meaning |
|---|---|---|---|
| `version` | yes | | must be `1` |
| `identities[].id` | yes | | unique, nonempty |
| `identities[].scope` | yes | | `publisher`, `product`, `toolchain`, `third_party`, `credits` or `build_paths` |
| `identities[].names` | yes | | 1 to 65,536 bytes each |
| `identities[].encodings` | no | `utf8`, `utf16le`, `utf16be`, `windows1252` | how names are encoded before matching |
| `identities[].boundary` | no | `identifier` | `substring`, `word` or `identifier` |
| `identities[].ignore_ascii_case` | no | `true` | ASCII-only case folding |
| `identities[].replacement` | no | spaces | must fit the encoded field |
| `identities[].pad` | no | none | one character; required when `replacement` is shorter |
| `identities[].files` | no | all files | `*`/`?` globs on the input path as given, `/` separators; a plan saves that path and matches it again on `apply` |
| `identities[].regions` | no | all regions | globs on `inspect` region labels |
| `identities[].expected_matches` | no | unchecked | distinct selected ranges required in the input before editing; the output is judged by the audit |
| `exclusions[]` | no | none | text or hex patterns whose every occurrence is retained |

The `files` glob above selects an input given as `bin/<name>.dll`, so run
`deattribute bin/app.dll --rules identities.json` from the folder above `bin`.
Exclusion text patterns default to `utf8`, `substring` and case-sensitive,
unlike identities. At most 1,000 identities and 1,000 exclusions; globs are at
most 4,096 characters.

## Edit specs and plans

An edit spec lists operations in original-input coordinates. Schema:
`meownary schema spec`.

```json
{
  "version": 1,
  "operations": [
    {"kind": "replace", "offset": 256, "remove": 4,
     "data": {"kind": "hex", "value": "00 01 02 03"}},
    {"kind": "fill", "offset": 512, "remove": 16,
     "data": {"kind": "fill", "byte": 0, "len": 16}},
    {"kind": "insert", "offset": 1024, "remove": 0,
     "data": {"kind": "file", "path": "payload.bin",
              "hashes": {"size": 8, "blake3": "...", "sha256": "..."}}},
    {"kind": "truncate", "offset": 4096, "remove": 1024,
     "data": {"kind": "empty"}}
  ]
}
```

| `kind` | `remove` | `data` | Constraint |
|---|---|---|---|
| `replace` | > 0 | `hex` or `file` | same length unless `"resize": true` |
| `fill` | > 0 | `fill` with `len == remove` | |
| `insert` | 0 | nonempty `hex` or `file` | |
| `delete` | > 0 | `empty` | |
| `truncate` | the whole tail | `empty` | `offset + remove` must equal the file size |

Operations may not overlap, two inserts may not share an offset, and a plan
holds at most 100,000 operations. A `file` payload's `hashes` must match the
file when the plan is created and when it is applied.

A plan (`meownary schema plan`) is what `plan`, `bytes --plan-out` and
`deattribute --plan-out` write. It pins `input`, `before` and `after` hashes,
each operation with the BLAKE3 of the bytes it removes, the `raw` flag, and,
for deattribution, the mode, policy, options, learned audit and `logical`, the
input path as it was given, which `apply` and `verify` match the rules' `files`
globs against. Treat plans as read-only: any edit makes `apply` refuse it.

## Verification reports

`verify`, `deattribute` and every apply report carry the same object:

| Field | Meaning |
|---|---|
| `byte_integrity` | the output's size and hashes equal the plan's `after` |
| `structure_valid` | for deattribution: the format is unchanged and, for PE, the layout parses and imports match the original; null for byte plans |
| `coverage_complete` | every region was examined, during planning and on the output |
| `policy_satisfied` | the verification policy holds on the output |
| `raw` | the plan was raw: bytes were checked, structure was not |
| `hashes` | the output's size, BLAKE3 and SHA-256 |
| `audit` | deattribution only: `complete`, `clean`, `policy_satisfied`, `residuals` and `unexamined`; the patterns cover every identity the original carried, learned or planned, so a credit an exclusion kept is a residual retained as `explicit exclusion` |

A report passes when `byte_integrity`, `coverage_complete` and
`policy_satisfied` are true and `structure_valid` is not false.

Each `audit.residuals` entry is a learned identity still present in the output:
`{"rule","offset","len","encoding","region","retained"}`. Under `strict`, any
residual fails. Under `protected`, a residual passes only when `retained`
names a reason recorded in the plan, such as a parsed import, a structural
record or an exclusion.

## Limits

| Limit | Default | Override |
|---|---|---|
| Streaming scan budget per pass | 1,073,741,824 bytes | `--max-scan` |
| Matches per search | 100,000 | `--max-matches` |
| Deep string candidates per sweep | 500,000 | none; past it coverage is incomplete |
| `bytes read` length | 256 bytes, at most 1 MiB | `--length` |
| `strings` results | 1,000 | `--limit` |
| `strings` minimum length | 4 characters | `--min-length` |
| `diff` ranges | 1,000 | `--limit` |
| JSON input (plans, specs, rules) | 32 MiB | none |
| Operations per plan | 100,000 | none |
| `--pad` field | 16 MiB | none |
| Archive entries | 100,000 | `--limit` |
| Archive entry size | 256 MiB | `--max-entry` |
| Archive total payload | 1 GiB | `--max-total` |
| ZIP expansion ratio | 1,000 | none |

## Errors and fixes

Common precision messages. All exit 2 unless noted.

| Message | Cause | Fix |
|---|---|---|
| `unknown option: --x` | option not part of the precision surface | check `bytes --help` |
| `--x does not apply to this command` | option belongs to another verb | drop it |
| `duplicate option: --x` | option given twice | pass it once |
| `expected N positional path(s)` | wrong number of paths | `diff` and `verify` take two; others take one |
| `symbolic links are not followed` | the input or an existing output is itself a link | pass the link's target instead |
| `expected a regular file` | a folder or device was given | use `inventory` or `clean` for folders |
| `choose exactly one --text or --hex` | zero or both patterns | pass one |
| `text matching options do not apply to hex search` | `--encoding`/`--boundary`/`--ignore-case` with hex | drop them |
| `search incomplete; no edits planned` | `--max-scan` or `--max-matches` too small for a search edit | raise the limit |
| `expected match count differs from N` | `--expect` mismatch | re-run `find` and fix the pattern or count |
| `no matches` | a search edit found nothing | check encoding and boundary |
| `replacement changes length; specify resize` | payload length differs from the range | pad, change the payload, or `--resize` |
| `resizing a recognized format requires --raw` | resize on PE, ELF, Mach-O and similar | use same-length edits, or `--raw` and accept byte-only verification |
| `this plan needs an explicit --raw override` | applying a raw plan without `--raw` | add `--raw` |
| `input changed since planning` | the input's hashes moved | re-plan against the current file |
| `affected range changed since planning` | bytes under an operation moved | re-plan |
| `replacement file changed since planning` | a `--data-file` payload changed | re-plan |
| `deattribution plan differs from the current rules and original file` | rules, mode or engine output changed | re-plan with the same rules |
| `use --in-place to replace the input` | `--output` names the input | use `--in-place` or another path |
| `plan and binary output must be different files` | `--plan-out` equals `--output` | pick two paths |
| `output exists; use --overwrite` (exit 75) | destination exists | add `--overwrite` or pick a new path |
| `staged output failed verification: ...` (exit 75) | the temporary copy failed its own checks; nothing was published | read the embedded report |
| `matching original undo snapshot is unavailable` | verifying an in-place edit after undo or state cleanup | verify before undoing, or keep the state directory |
| `rule X needs explicit padding` | `replacement` is shorter than the field | add `pad` |
| `conflicting identity replacements overlap` | two rules replace the same bytes differently | narrow `files`/`regions` or merge rules |

Publishing without `--overwrite` uses a hard link so it can never replace a
file that appeared in the meantime. On file systems without hard links, such
as FAT and exFAT, pass `--overwrite` or write to another drive.

## Safety guarantees

What a driver can rely on:

- **Originals are untouched** by `deattribute`, `apply` without `--in-place`,
  `bytes` without `--in-place`, `archive` and every read-only command.
- **Writes are staged.** Copies, plans, manifests and extracted folders are
  written beside their destination and published only after they verify. A
  failure leaves the previous destination as it was.
- **Plans are pinned.** Input, expected output, affected ranges and payload
  files are hashed. A plan never applies to bytes it was not made for.
- **In-place edits are journaled.** The original is snapshotted to the undo
  journal before replacement, and `meownary undo` restores it.
- **Coverage is explicit.** Budgets that stop a scan are reported as
  `unexamined` ranges and exit 75; nothing silently counts as clean.
- **Identity text stays out of ordinary output.** Only `--details` prints
  decoded text, matched bytes or learned identities.
- **Nothing runs.** meownary parses files; it never executes them, installs
  MSI packages or follows symbolic links.
