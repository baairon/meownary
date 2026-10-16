# Changelog

All notable changes to meownary are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Folders in the view**: the files pane shows one folder at a time, its
  subfolders first, instead of every scanned file in one list. Rows stay put
  while a scan fills them in, each folder shows its own progress, file count
  and findings, and a folder can be picked for scrub or deattribute.
- **Progress for every action**: plans, copies, scrubs, deletes and undo run
  off the input thread with a thin progress bar naming the file in work, and
  `esc` stops after the current file.
- **Picker**: browses with keys like the view (`enter` opens, `left` goes up,
  `s` scans, `/` filters or takes a path), reads folders in the background,
  counts each folder's files, and keeps its layout still.
- **Previews**: the README images draw seamless borders with rounded corners,
  rounded chips and gradient progress bars.

### Fixed

- The highlight no longer moves when a file appears or disappears above it,
  such as a `.deattributed` copy sorting before its original.
- Columns line up for file names with wide characters.

## [0.1.0] - unreleased

The first release.

### Added

- **Identify**: names a file's true format from its bytes, independent of its
  name, and reports an `identity.ext_mismatch` finding when the content
  contradicts the extension. An executable behind a document, image, or media
  extension is an `alert`.
- **Probes by family**: executables (PE, ELF, Mach-O), archives and compression
  (ZIP and the JAR, APK, and Office Open XML formats built on it, RAR, 7z, gzip,
  xz, zstd, bzip2, tar), media (MP4, Matroska and WebM, MP3, FLAC, Ogg, WAV,
  AVI), images (JPEG, PNG, GIF, WebP, BMP), documents (PDF, Office Open XML, OLE
  compound files and MSI), and cross-format deception checks. Findings fall into
  the brand, integrity, tamper, deception, bundleware, and junk categories, each
  with a confidence and a severity.
- **Catalog**: detection data in `src/catalog/catalog.ron`, where every entry
  cites a source and strong-confidence entries name their corroborating
  evidence.
- **Clean and undo**: `meownary clean` scrubs markers by category or signature
  id, or deletes whole files with `--file --force`. Every edit is snapshotted to
  a trash store and journaled first, so `meownary undo` (or `undo --all`)
  restores the original bytes. Risky edits need `--force`, corrupting ones are
  refused, and `--dry-run` reports the same decisions without writing.
- **Interactive view**: `meownary <path>` opens a terminal view over a
  streaming scan, with details, buckets, bulk actions, and undo.
- **Headless scan**: `meownary scan` streams results in a stable order, with one
  line per file, aligned finding rows, a summary line, severity color on a
  terminal (respecting `NO_COLOR` and `--no-color`), and a progress counter on
  stderr.
- **JSON output**: `--json` on `scan`, `clean`, and `undo` prints JSON Lines
  events (`identify`, `finding`, `would_clean`, `cleaned`, `skipped`, `undone`,
  `done`), with finding detail, marker regions, skip reasons, and the exit code.
- **Exit codes**: 0 ok, 1 threshold met or nothing applied, 2 usage error,
  73 state store unavailable, 75 partial results, 101 internal error, and 130
  interrupted.
- **Prebuilt binaries**: archives for x86_64 and ARM64 Linux (static musl),
  Apple silicon and Intel macOS, and x86_64 Windows, with a `SHA256SUMS` file
  per release.

[Unreleased]: https://github.com/baairon/meownary/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/baairon/meownary/releases/tag/v0.1.0
