# Changelog

All notable changes to meownary are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
