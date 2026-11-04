# Working on meownary

Notes for coding agents and contributors changing this repository. To run
meownary rather than change it, read [docs/agents.md](docs/agents.md).

## Where things are documented

| Document | Owns |
|---|---|
| [README.md](README.md) | what meownary does, every user-facing behavior, legacy JSON fields, exit codes |
| [docs/agents.md](docs/agents.md) | driving the CLI from scripts and agents: options per command, events, errors, workflows |
| [docs/schemas/](docs/schemas) | JSON Schemas for plans, rules, specs and precision events |
| [SECURITY.md](SECURITY.md) | how to report vulnerabilities |
| `HELP_TEXT` in `src/cli/args.rs`, `HELP` in `src/cli/precision.rs` | `--help` output |

The schema files are compiled into the binary with `include_str!` and printed by
`meownary schema <name>`. Editing one changes CLI output; changing a serialized
type in `src/edit/precision/` or `src/edit/deattribute/policy.rs` means editing
the matching schema.

A behavior change is complete when the README section, `docs/agents.md`, any
affected schema and the help text all agree with the code.

## Checks

CI runs these on every push: `.github/workflows/ci.yml` on GitHub, and
`.forgejo/workflows/ci.yml` on the forge, which runs the same commands on Linux
only. Run them all before calling work done:

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --locked --no-default-features -- -D warnings
cargo test --locked
cargo test --locked --no-default-features
cargo package --locked --allow-dirty --no-verify
```

- **MSRV** is Rust 1.88: CI also runs `cargo check --all-targets --locked` on
  1.88.0, so avoid newer language and library features. Locked dependencies
  count too: run `cargo +1.88.0 check --all-targets --locked` before pushing,
  and when a crate's new release raises its `rust-version`, pin the last
  compatible one with `cargo update <crate> --precise <version>` (uuid is held
  at 1.26.1 for this reason).
- **Features**: `tui` is the only feature and is on by default. Everything
  outside `src/tui/` must build and pass tests with `--no-default-features`.
- **Tests on all three platforms**: the GitHub test job runs on Linux, macOS
  and Windows. Path handling, permissions and hard links differ; do not assume
  Unix semantics.
- **Windows shells**: from Git Bash, coreutils `link` can shadow the MSVC
  `link.exe`. Use the GNU toolchain (`RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-gnu`)
  or a Developer PowerShell when MSVC linking fails with `extra operand`.
- CI and local runs use `cargo test --no-fail-fast`, which reports every
  failing target at once; plain `cargo test` stops after the first failing
  test binary and hides the rest.
- **Path aliases**: macOS temp folders sit behind the `/var` symlink and
  Windows CI temp paths use 8.3 short names (`RUNNER~1`). Reproduce both before
  pushing path code: run the suite with `TMPDIR` pointing through a symlinked
  folder on Linux, and with `TMP` and `TEMP` set to a short-name path on
  Windows (`cygpath -d` prints one).

## Source map

| Path | Role |
|---|---|
| `src/main.rs` | entry point: parses arguments and dispatches |
| `src/cli/args.rs` | strict parser for the view and legacy commands; routes precision verbs |
| `src/cli/headless.rs` | `scan`, `clean`, `undo` and their flat JSON events |
| `src/cli/precision.rs` | every precision command and its enveloped JSON events |
| `src/model/` | shared types: findings, markers, categories, reports |
| `src/catalog/` | the signature catalog (`catalog.ron`), its schema and validator |
| `src/scan/` | walking, identification, per-file probes and guards |
| `src/parsers/` | format parsers (PE, ELF, Mach-O, archives, documents, images, media) |
| `src/edit/engine.rs`, `journal.rs`, `trash.rs`, `lock.rs` | edits, the undo journal, trash and the state-store lock |
| `src/edit/fsio.rs` | staged writes, hashing, canonical paths |
| `src/edit/deattribute/` | deattribution planning, deep mode, rules, audit, layout, ZIP and tar rewriters |
| `src/edit/precision/` | byte patterns, edit plans, archive helpers |
| `src/tui/` | the interactive view (feature `tui`) |
| `tests/cli.rs`, `tests/deattribute_cli.rs`, `tests/precision_cli.rs` | end-to-end tests against the built binary |
| `tests/fixtures/pe.rs` | PE builders shared by integration tests and, through `#[path]` in `src/lib.rs`, by unit tests |

## Invariants

- `unsafe_code` is forbidden crate-wide.
- No network access, no execution of scanned files, no following of symbolic
  links as inputs, outputs or archive entries. Parent folders resolve
  normally.
- Compare paths only after `plan::resolved` (in `src/edit/precision/plan.rs`),
  never an absolute spelling against a canonical one.
- Originals are changed only by journaled operations (scrub, delete,
  `--in-place`), and the journal record is synced before the file changes.
- Copies, plans and manifests are written to a temporary sibling, verified, and
  then published. A failed check must leave the destination untouched.
- Every budget that stops a scan is reported as incomplete coverage, never as
  clean.
- Version 1 JSON shapes are a public interface. Add fields rather than rename
  or remove them, and document each change.
- Help text lines stay within 80 columns; `help_lines_fit_80_columns` enforces
  it.

## Writing conventions

- Commits use Conventional Commits.
- Docs and comments avoid em and en dashes; use commas, colons or parentheses.
- Test fixtures use invented names such as `North Star Labs`, never real
  vendors, people or libraries.
