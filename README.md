# meownary

A lean terminal tool that identifies what any file really is, labels how it was
built and signed, flags tampered or mislabeled binaries, and removes the markers
and metadata it finds. It works on a single file or a whole directory, and every
change it makes is reversible.

meownary reads files locally and never connects to the network. It reports what
it observes; it does not assert that a file is safe or malicious.

## Status

Early development. The scanning engine, identification, the headless CLI, and the
reversible edit engine are in place. Format-specific parsers and the interactive
view are being filled in.

## Install

Prebuilt binaries are published on the Releases page:

    https://github.com/baairon/meownary/releases

Download the one for your platform and put it on your PATH. There is nothing else
to install; the binary is self-contained.

To build from source you need Rust 1.85 or newer:

    git clone https://github.com/baairon/meownary
    cd meownary
    cargo build --release

The binary is written to `target/release/meownary`.

## Quick start

Open the interactive view on the current directory:

    meownary

Scan a file or folder and print a report, with no interactive view:

    meownary scan ./downloads

Emit one JSON object per line, for scripts and pipelines:

    meownary scan ./downloads --json

## What it looks at

meownary identifies a file from its bytes, not its extension, then runs a set of
probes over a bounded window of the file. Findings fall into these categories:

| Category    | What it means                                                        |
|-------------|----------------------------------------------------------------------|
| identity    | The true format, and whether it contradicts the extension.           |
| brand       | Who or what produced it: vendor, code signer, toolchain, packer, installer. |
| integrity   | The state of any signature or checksum the format carries.           |
| tamper      | Evidence the artifact was altered after it was built or signed.      |
| deception   | Patterns meant to mislead, such as a hidden extension or an impersonated vendor. |
| bundleware  | A wrapper or adware installer around some inner payload.             |
| junk        | Removable metadata, such as EXIF, build paths, or archive comments.  |

Each finding carries a confidence of `strong`, `moderate`, or `weak`. Strong
findings require corroborating evidence, not a single generic marker, so the
default actions never hinge on a lone weak guess. Each finding also carries a
severity of `info`, `notice`, `warn`, or `alert`.

## Interactive view

Running `meownary` with no subcommand opens a terminal view over the scan.

| Key            | Action                          |
|----------------|---------------------------------|
| up / down, j k | move the selection              |
| tab            | switch pane                     |
| enter          | open the detail and hex view    |
| esc            | go back                         |
| space          | select for a bulk action        |
| d              | scrub the selected marker bytes |
| D or x         | delete the whole file           |
| e              | open the file in your editor    |
| b              | group findings into buckets     |
| /              | filter                          |
| u              | undo the last action            |
| ?              | key reference                   |
| q              | quit                            |

## Cleaning

Cleaning removes a detected marker from a file. By default it scrubs only the
marker bytes and leaves the rest of the file intact; it can also delete whole
files when that is what you want.

Before any change, meownary copies the original into its own trash store and
writes an entry to an undo journal, so a single `undo` puts things back. A
length-preserving scrub stores only the bytes it overwrote, so undo stays cheap
even on very large files.

Preview what a clean would do without touching anything:

    meownary clean ./downloads --category junk --dry-run

Scrub every marker in a category, or by exact signature id:

    meownary clean ./downloads --category junk
    meownary clean ./downloads --signature packer.upx

Delete whole files that carry a match, rather than scrubbing bytes:

    meownary clean ./downloads --signature identity.ext_mismatch --file

Undo the last clean, or everything recorded in the journal:

    meownary undo
    meownary undo --all

Some edits are gated. An edit that could corrupt a file, such as erasing a
format's magic bytes, is refused. An edit that is allowed but consequential,
such as truncating an executable that may carry an appended signature, is a
warning and needs `--force` on the command line. The interactive view asks for
confirmation instead.

The trash store and journal live under your platform's application data
directory. Set `MEOWNARY_STATE_DIR` to redirect them, which is also how the test
suite keeps off real data.

## JSON output

With `--json`, `scan` prints one object per line. Fields are only ever added, so
a consumer can rely on the ones it reads:

    {"event":"identify","path":"a.exe","format":"pe","size":51200,"partial":false}
    {"event":"finding","path":"a.exe","category":"brand","confidence":"moderate","severity":"info","signature":"packer.upx","title":"UPX-packed executable","offset":1024,"removable":false}
    {"event":"done","files":1,"partial_files":0}

`clean --json` emits `would_clean`, `cleaned`, and `skipped` events and a final
`done` with counts.

## Auditing a folder of downloads

meownary pairs well with any workflow that pulls files from elsewhere. For a
post-download check, gate a script on severity:

    meownary scan ./incoming --fail-on warn

That exits non-zero when any finding reaches `warn`, so a script can hold a file
for review. To pull out only the loudest findings:

    meownary scan ./incoming --json | jq "select(.event==\"finding\" and .severity==\"alert\")"

## Exit codes

| Code | Meaning                                                      |
|------|--------------------------------------------------------------|
| 0    | ok                                                           |
| 1    | `scan --fail-on` threshold was met                           |
| 2    | the command was wrong                                        |
| 73   | the trash store could not be created (no edit was attempted) |
| 75   | some files could not be fully scanned (partial results)      |
| 130  | interrupted                                                  |

## How it works

meownary opens each file once and reads a small window from the front and the
back, seeking to specific structural points only when a parser needs them. A
multi-gigabyte file is identified from a few kilobytes, so a scan is fast and
uses little memory regardless of file size. A directory is walked in parallel.
Each file is processed under a guard, so one malformed or hostile file yields a
partial result for that file alone and never takes down the scan.

## Supported formats

Executables and code: PE, ELF, Mach-O (including universal binaries), Java class,
WebAssembly, shell scripts, Windows shortcuts.

Archives and compression: ZIP (and ZIP-based formats such as JAR, APK, and Office
Open XML), RAR, 7z, gzip, xz, zstd, bzip2, tar.

Media and images: MP4 and ISO base media, Matroska and WebM, Ogg, FLAC, MP3, WAV,
AVI, PNG, JPEG, GIF, BMP, WebP.

Documents: PDF, OLE compound files (legacy Office and MSI).

## Privacy

Everything happens on your machine. meownary does not make network requests, and
the only state it writes is its trash store and undo journal, under your
application data directory.

## Contributing

Build and test with a recent stable Rust:

    cargo test
    cargo clippy
    cargo build --release

The detection catalog lives in `src/catalog/catalog.ron` as reviewable data. Each
entry cites a source, and strong-confidence entries must name their corroborating
evidence; a test enforces this.

## License

MIT. Copyright (c) 2026 bairon.dev.
