<h1 align="center">meownary</h1>

<p align="center">
  Deattributes software and scrubs files to prepare them for reverse engineering. Writes clean copies without the brand labels and patch credits that name who made them, and strips the metadata you pick.
</p>

<p align="center">
  <a href="#what-it-does">What it does</a> ·
  <a href="#deattribute">Deattribute</a> ·
  <a href="#scrub">Scrub</a> ·
  <a href="#undo">Undo</a> ·
  <a href="#interactive-view">Interactive view</a> ·
  <a href="#json-output">JSON output</a> ·
  <a href="#install">Install</a> ·
  <a href="#exit-codes">Exit codes</a>
</p>

<p align="center"><img src="assets/preview.svg" width="960" alt="The meownary interactive view after a scan of 16 files. Left: the file list, one row per file with a severity dot, its detected type and a finding count. Right: the five findings of the highlighted executable, each with severity, title, confidence and signature id, removable ones tagged and one picked. Under them a peek box for the highlighted finding: kind tamper: appended data, action cut the file at 0x9c400, verdict warn, truncating may remove an appended code signature. Footer: key hints including d scrub and a deattribute, and 1 selected."></p>

## What it does

meownary scans a file or a folder, names each file's real format, and lists
what each file carries as findings. Two actions act on them:

- **Deattribute** is for software. It writes a copy of each file beside the
  original with brand labels, toolchain stamps and `patched by` credits blanked
  at the same length. The original is never touched.
- **Scrub** is for files. It removes the metadata you select, such as EXIF,
  document properties, build paths or archive comments, from the file itself.
  Every scrub can be undone.

Each finding has a category, a confidence, a severity and a signature id, and
may carry a removable marker: a byte range plus the method that removes it.
meownary makes no network requests.

## Deattribute or scrub

Deattribute is a fixed, quiet pass that writes clean copies; scrub edits the
findings you select in place.

| | Deattribute | Scrub |
|---|---|---|
| For | software: who made it and with what | files: the metadata they carry |
| Command | `clean <path> --deattribute` | `clean <path> --category <slug>` or `--signature <id>` |
| Key in the view | `a` | `d` |
| Writes | a `.deattributed` copy beside the original | the original file |
| Removes | `brand` labels and `patch` credits | any finding with a removable marker |
| Occurrences | every match | the reported one |
| Method | same-length blank | blank, truncate or structural rewrite |
| File length | unchanged | may shrink |
| Weak findings | included | skipped unless `--force`, or scrubbed alone in the view |
| Warn-level edits | never run | run with `--force`, or after the view's confirm |
| Output names | paths, kinds, generic reasons | paths, signature ids, methods, reasons |
| Afterwards | the copy is rescanned to verify | `meownary undo` reverts it |

## Commands

The interactive view, `scan` and `clean` each take one path: a file, or a
folder they walk once, recursively.

```sh
meownary [<path>]
meownary scan <path> [--json] [--no-color] [--fail-on <severity>]
meownary clean <path> --deattribute [--dry-run] [--json]
meownary clean <path> --category <slug> [--marker | --file] [--dry-run] [--force] [--json]
meownary clean <path> --signature <id> [--marker | --file] [--dry-run] [--force] [--json]
meownary undo [--last | --all] [--json]
```

- **Paths**: `scan` and `clean` need a path; `meownary` without one opens a
  file and folder picker. Hidden files are included, symbolic links are never
  followed, and meownary's state directory is never scanned.
- **Cloud-only files**: placeholders for files that are not stored locally are
  never opened, so nothing is downloaded. They are reported as partial with
  `cloud-only file, not downloaded`.
- **`scan`**: prints each file's findings with severity, confidence, title and
  signature id; a trailing `*` marks a removable marker. `--fail-on` takes
  `info`, `notice`, `warn` or `alert` and exits 1 once a finding reaches it.
- **`--dry-run`**: plans every edit and runs the safety checks, prints what
  would change, and writes nothing.
- **Flags**: go in any order, and a value follows its flag or joins it with
  `=`. `--` ends options, so later arguments are paths.
- **Environment**: `MEOWNARY_STATE_DIR` moves the state directory. `NO_COLOR`
  turns color off and `MEOWNARY_NO_ANIM` stills the view's wordmark, each when
  set and not empty.

## Deattribute

Deattribute writes a copy of each file with brand labels and `patched by`
credits blanked at the same length, and never prints what it removed.

```sh
meownary clean <path> --deattribute [--dry-run] [--json]
```

In the view, `a` plans with the same rules. It blanks vendor and copyright
strings along with toolchain credits, so it is meant for software you build or
are entitled to change.

### What it removes

Every blank is one of two kinds, `brand` or `patch`.

| Format | Value | Fill |
|---|---|---|
| PE | Rich header, from the masked `DanS` through the key after `Rich` | `0x00` |
| PE | CompanyName, ProductName, FileDescription, OriginalFilename, FileVersion and LegalCopyright strings | `0x00` |
| ELF | `.comment` strings that hold no file path | `0x00` |
| PE, ELF, Mach-O | `patched by` text, kind `patch` | `0x00` |
| Executables, MSI | `/rustc/`, `Mingw-w64 runtime failure`, `Inno Setup`, `InstallShield` | `0x00` |
| PDF | Info Producer and Creator values | `0x20`; `0` in hex strings |
| PDF | `Acrobat Distiller`, `Skia/PDF`, `Quartz PDFContext` outside Info | `0x20` |
| MP4 | encoder tag in `udta/meta/ilst` | `0x20` |
| Matroska, WebM | MuxingApp and WritingApp, unless Info has a CRC-32 | `0x20` |
| FLAC | Vorbis comment vendor string | `0x20` |
| WAV, AVI | `INFO/ISFT` software string | `0x20` |
| Audio, video | `Lavf`, `Lavc`, `x264 - core`, `x265 (build`, `HandBrake` | `0x00` |

- Catalog text credits are matched only in the first and last 64 KiB of a file,
  in the formats their catalog entry lists, weak matches included. Every match
  is blanked, though the scan lists a catalog entry once per file.
- `patched by` and the executable and media credits are blanked from the match
  to the end of its printable ASCII run, when that run ends within 80 bytes.
- Other version keys, the numeric file version and every key name stay.

### Archives

A ZIP, tar or tar.gz carries no attribution of its own, so deattribute cleans
the files inside it and writes `name.deattributed.zip`, `.tar` or `.tar.gz`
beside the original.

- Each file inside is identified and planned like a file on disk. Files with
  nothing to blank are copied byte for byte.
- Office documents, JAR and APK files are ZIP containers but are treated as
  single files, not as archives.
- Archives inside an archive are not opened.
- Encrypted entries, entries over 256 MiB and unsupported compression methods
  are skipped with a reason; an archive over 1 GiB uncompressed is refused.
- A tar.gz copy is written as one gzip member without the original's stored
  file name or comment.
- An archive with nothing to blank inside gets no copy and reports
  `nothing to blank inside the archive`.

### How it writes

- The copy is named after the original with `.deattributed` before the last
  extension, in the same folder, so it still opens and runs the same way.
- The original is read, never written. Each region is hashed when planned and
  checked again on the bytes copied, or the file is skipped.
- The copy is written to a temporary file, synced, then renamed into place. A
  copy from an earlier run is replaced, never stacked, and files that are
  already `.deattributed` copies are never deattributed again.
- Every edit is a raw blank, so the copy keeps the original's size, layout and
  offsets. Only blanks the safety check rates safe are planned, and none is
  forced.
- A file with nothing to blank gets no copy. Deattribute never opens the state
  directory, so there is nothing to undo: delete the copy to discard it.

### What it skips

A skip names one of five generic reasons: `load-bearing`,
`no removable marker`, `unsafe edit`, `changed since scan` or `io error`.

<details>
<summary>What each reason covers</summary>

| Reason | When |
|---|---|
| `load-bearing` | the stamp is needed to load, unpack, install or play the file |
| `no removable marker` | the label has no safe blank, or a text credit runs past 80 bytes |
| `unsafe edit` | the blank is not rated safe, or it overlaps a blank with another fill |
| `changed since scan` | the original's size or bytes changed after planning |
| `io error` | the original could not be read or the copy could not be written |

Load-bearing stamps: packer markers and PE packer section names, .NET metadata
and its runtime imports, Go build info and build ids, PyInstaller, Nuitka,
Electron, Qt and Delphi runtimes, installer stubs (NSIS, WiX Burn, 7-Zip and
WinRAR self-extractors, Squirrel), the LAME header in MP3, MP4 brand boxes, the
Office Open XML package, 7z, RAR and xz headers, and Mach-O build version and
encryption info.

</details>

### What it reports

- Each copy prints one line, `saved` with the copy's path, the original's name
  and its counts of `brand` and `patch` blanks, or `would save` in a dry run.
  A skip prints the path and its reason.
- The summary counts the copies saved beside their originals and the skips by
  reason. Offsets appear only in JSON.
- Nothing printed names matched text, titles, notes, evidence or signature ids.
- After writing, each copy is scanned and planned again. A partial scan or a
  blank still planned prints `verification incomplete for an edited file` and
  exits 75.
- Exit 1 means something matched and no copy was written.

### What it never does

- Write to the original, delete a file, or change the copy's length.
- Touch junk, tamper, integrity, identity, deception or bundleware findings,
  other than `patched by`, so other metadata stays in the copy.
- Accept `--force`, `--file`, `--category` or `--signature`; each is a usage
  error.
- Run a warn-level edit, or one the safety check refuses.
- Re-sign an executable or update its PE checksum. The copy of a signed file
  carries an invalid signature.

## Scrub

Scrub removes the findings you select from the file itself, in any category,
each through the method its marker names.

```sh
meownary clean <path> --category <slug> [--dry-run] [--force] [--json]
meownary clean <path> --signature <id> [--dry-run] [--force] [--json]
```

In the view, `d` scrubs the highlighted finding, a file's findings, your picks
or a bucket, as [Interactive view](#interactive-view) lists.

### What it removes

- **`--category <slug>`**: every finding in one category: `identity`,
  `brand`, `integrity`, `tamper`, `deception`, `bundleware` or `junk`, in any
  letter case.
- **`--signature <id>`**: every finding with that exact signature id, as
  `scan` and the view print it.

Only findings with a removable marker change anything; the rest are skipped.

<details>
<summary>Which findings carry which method</summary>

- **Raw blank, `0x00`**: `pe.pdb_path`, `pe.rich_header`,
  `pe.version_info.junk`, `elf.comment.junk`, `elf.rpath`, `macho.rpath`,
  `jpeg.iptc`, `gif.app` (IPTC), `mp3.id3v2` (frames; the header stays),
  `cfb.summary` (UTF-16 text).
- **Raw blank, `0x20`** (`0` in PDF hex strings): `jpeg.comment`,
  `gif.comment`, `pdf.producer`, `pdf.creator`, `pdf.info`, `cfb.summary`
  (8-bit text), `zip.comment` (when data follows the end record),
  `gzip.fname`, `gzip.fcomment`, `rar.comment`, `flac.vendor`, `flac.tags`,
  `mkv.muxing_app`, `mkv.writing_app`, `mkv.title`, `mp4.encoder`,
  `mp4.metadata`, `riff.software`, `riff.info`,
  `catalog.producer.distiller`, `catalog.producer.skia`,
  `catalog.producer.quartz`.
- **Truncate**: `pe.overlay`, `pe.overlay_bloat`, `jpeg.trailing_data`,
  `png.trailing_data`, `zip.trailing_data`, `mp3.id3v1`.
- **Structural rewrite**: `jpeg.exif`, `jpeg.xmp`, `png.exif`, `png.text`,
  `png.time`, `webp.exif`, `webp.xmp`, `zip.comment` (when the end record ends
  the file), `tar.owner` (names cleared, length kept).
- **C2PA Content Credentials**: `jpeg.c2pa` (APP11 segments), `png.c2pa`
  (caBX and JUMBF chunks), `webp.c2pa`, and `mp4.c2pa` in MP4, HEIC and AVIF,
  where the box is zeroed and turned into free space so nothing moves.
- **HEIC and AVIF items**: `mp4.exif_item` and `mp4.xmp_item`; `mp4.xmp` turns
  its box into free space the same way.
- **Hidden text**: `text.invisible` (zero-width, tag and private-use
  characters), `text.spaces` (exotic spaces become plain spaces), `text.bidi`
  (bidi controls) and `text.ai_comment` (AI provenance comments in Markdown and
  HTML). Agent config files such as `CLAUDE.md`, `AGENTS.md`, `SKILL.md` and
  anything under `.git` are never touched.

Every other finding has no marker.

</details>

### How it edits

Each marker names one of three methods.

| Method | Effect on the bytes | Length |
|---|---|---|
| Raw blank | overwrites the region in place with one fill byte | unchanged |
| Truncate | cuts the file at the marker and drops the rest | shorter |
| Structural rewrite | rebuilds the container without the region and replaces the file atomically, up to 256 MiB | shorter, except tar owner names |

Every edit is rated before it runs:

| Rating | Runs | When |
|---|---|---|
| safe | yes | anything not listed below |
| warn | with `--force`, or after the view's confirm | truncating PE or Mach-O; dropping over 256 MiB; rewriting any container but a ZIP comment, PNG chunk, JPEG segment, RIFF chunk or tar header; deleting a file; a one-way marker |
| refuse | never | blanking offset 0 or the first 16 bytes of a structured format; an empty region or one past the end; truncating to 0 bytes or into the first 16 bytes; a symbolic link or anything but a regular file |

Edits that keep the length run first, then the others from the end of the file
backward, so earlier offsets stay valid. Before writing, the file size must
still match the scan.

### What it skips

A skip names its reason, with detail after a colon where one applies:
`no removable marker`, `weak confidence`, `needs --force`, `refused`,
`changed since scan`, `unsupported`, `io error` or `error`.

<details>
<summary>What each reason covers</summary>

| Reason | When |
|---|---|
| `no removable marker` | the finding has no marker |
| `weak confidence` | a weak finding without `--force` |
| `needs --force` | a warn-level edit without `--force` |
| `refused` | the safety check refuses the edit; `--force` does not change it |
| `changed since scan` | the file's size changed, or an earlier edit in the run removed the bytes |
| `unsupported` | no structural remover fits, it found nothing to change, or the file is over 256 MiB |
| `io error` | a read or write failed |
| `error` | any other failure |

</details>

### What it reports

- Each finding acted on prints one line: `would clean`, `cleaned` or
  `skipped`, the path, and the signature id in brackets. A dry run adds the
  method, length and offset; a skip adds its reason.
- A summary line counts skips by reason, and a run that changed files ends with
  a reminder that `meownary undo` reverts them.
- Exit 1 means findings matched and nothing was applied. Exit 75 means some
  files could not be fully read; when both apply, the run exits 1.

### What it never does

- Act on a finding outside the selection, or one without a marker.
- Run an edit the safety check refuses, even with `--force`.
- Remove a weak finding without `--force`, or as part of a bulk scrub in the
  view.
- Re-sign an executable or update its PE checksum. Scrubbing signed bytes
  invalidates the signature.

## Delete

Delete moves whole files to meownary's trash, and `meownary undo` moves them
back.

```sh
meownary clean <path> --category <slug> --file --force [--dry-run] [--json]
meownary clean <path> --signature <id> --file --force [--dry-run] [--json]
```

- Every file that carries a match moves once. Without `--force` it is skipped
  with `needs --force: removes the whole file`.
- In the view, `D` or `x` deletes the picked files, or the highlighted file,
  after a confirm.

## Undo

Scrub and delete save the original bytes before the file changes, so a run can
be put back.

```sh
meownary undo [--last | --all] [--json]
```

- **Groups**: one `clean` run, or one confirmed batch in the view, is one
  group. `undo`, `undo --last` and `u` revert the newest group; `--all`
  reverts every edit in the journal, newest first.
- **Order**: the original is saved and a journal record with fingerprints of
  the file before and after is synced to disk, then the file changes.
- **Storage**: blanks up to 4096 bytes keep the original bytes in the journal.
  Larger blanks, cut tails, whole-file snapshots of rewrites and deleted files
  go to the trash.
- **Changed files**: undo restores a file only while it matches what the edit
  left. Otherwise it stops and exits 1, and what it already reverted stays so.
- **Retention**: originals stay until undone, removed metadata included.
  Nothing expires.
- **One writer**: another meownary holding the state store makes scrub, delete
  and `undo` exit 73, and the view shows a notice instead of editing.

The state directory holds `trash/`, `undo-journal.jsonl` and `recent.json`, the
picker's last five picks, written only when you pick something in the picker.
`MEOWNARY_STATE_DIR` overrides the default:

| Platform | Default state directory |
|---|---|
| Linux | `$XDG_DATA_HOME/meownary`, else `~/.local/share/meownary` |
| macOS | `~/Library/Application Support/dev.bairon.meownary` |
| Windows | `%APPDATA%\bairon\meownary\data` |

## Interactive view

`meownary <path>` opens a terminal view that lists files as the walk finds
them; `meownary` alone opens a picker first.

<p align="center"><img src="assets/picker.svg" width="960" alt="The meownary picker on first run: the wordmark, one line saying nothing is changed until you confirm an action, an empty path input, and a list of places to start from: Downloads, Desktop, Documents, Pictures, the current folder, drive C: and home. Footer: up/dn move, right open, left back, enter scan, tab complete, esc quit."></p>

- **Picker**: the path line is also a live filter for the folder it points at.
  Letters always type; arrows move, `right` or `tab` opens a folder, `left`
  goes up, and `enter` scans the highlighted file or folder. Recent picks come
  first, then common folders, drives and home. It asks before scanning a whole
  home folder, the folder that holds every user's home, or a drive.
- **Reopen**: `o` brings the picker back over the view; `esc` returns to the
  view unchanged.
- **Saved marks**: a file you scrub, or the copy deattribute writes, gets a
  `scrubbed` or `deattributed` chip in the list, and the status line names
  what was saved.

| | `d` scrub | `a` deattribute | `D` or `x` delete |
|---|---|---|---|
| Picks made with `space` | picked findings, and the filtered findings of picked files | picked files, and the files of picked findings | picked files, else the highlighted file |
| Findings pane or detail | the highlighted finding | the highlighted file | the highlighted file |
| Files pane | the highlighted file's filtered findings | the highlighted file | the highlighted file |
| Buckets screen | every removable finding in the bucket | picks, else every file in the bucket | not available |

- **Confirm**: before anything is written, a prompt lists each edit with a
  `safe`, `warn` or `refuse` chip, the path, the signature id or kind, and the
  action with its size and offset. `y` goes ahead and `n` or `esc` cancels.
  Refused items never run.
- **Force**: for scrub and delete the confirm stands in for `--force`;
  deattribute never forces.
- **Undo**: `u` reverts the newest scrub or delete group, a `clean` run
  included.
- **Editor**: `e` opens the highlighted file in `$VISUAL` or `$EDITOR`, else
  `notepad` on Windows and `vi` elsewhere. A change is journaled like a scrub.
- **Browse**: `enter` opens a finding's detail with the bytes around it, `b`
  groups findings, and `/` filters by path, format, signature id or title.
  `left`, `right` or `tab` switch panes.

<details>
<summary>Key reference</summary>

<p align="center"><img src="assets/keys.svg" width="960" alt="The meownary key reference, the ? sheet, drawn over the dimmed interactive view. Move: up/dn or j/k move, pgup/pgdn page, home/end or g/G top or bottom, tab, left/right or h/l switch pane, enter open, esc back. Act: space select, d scrub markers, a deattribute, D or x delete file, e open in editor, u undo last. View: b buckets, / filter, o open file or folder, ? keys, q or ctrl+c quit. Confirm: y confirm, n or esc cancel. Filter: backspace erase, enter keep, esc clear. Press any key to close."></p>

</details>

## JSON output

With `--json`, `scan`, `clean` and `undo` print one JSON object per line,
ending with a `done` event that carries the exit code. `scan --json` prints
`identify`, `finding` and `done` events.

<details>
<summary><code>clean --deattribute</code> fields</summary>

| Field | Events | Value |
|---|---|---|
| `event` | all | `would_clean`, `cleaned`, `would_save`, `saved`, `skipped` or `done` |
| `path` | per file | the original, as walked |
| `output` | `would_clean`, `cleaned`, `would_save`, `saved` | the copy's path |
| `kind` | `would_clean`, `cleaned`, `skipped` | `brand` or `patch` |
| `op`, `offset`, `len` | `would_clean`, `cleaned` | `raw_blank` and the blanked region |
| `edits` | `would_save`, `saved` | blanks in the copy |
| `entries` | `would_save`, `saved` | for an archive, files inside that were cleaned |
| `entry` | `skipped` | for an archive, the path inside it |
| `reason` | `skipped` | one of the five reasons |
| `cleaned`, `skipped`, `saved` | `done` | counts; a dry run counts what it would do |
| `dry_run` | `done` | whether nothing was written |
| `files`, `partial_files` | `done` | files walked, and files not fully read or verified |
| `exit` | `done` | the exit code |

No event carries `title`, `note`, `signature`, `evidence` or `label`.

</details>

<details>
<summary><code>clean --category</code> and <code>--signature</code> fields</summary>

| Field | Events | Value |
|---|---|---|
| `event` | all | `would_clean`, `cleaned`, `skipped` or `done` |
| `path` | per finding | the file, as walked |
| `label` | per finding | the journal label: the signature id, or `delete file` |
| `signature`, `category`, `severity` | per finding | from the finding |
| `op` | per finding | `raw_blank`, `truncate`, `structural_remove`, `delete_file`, or null |
| `offset`, `len` | per finding | bytes touched; null without a marker |
| `undo_id` | `cleaned` | the journal record id |
| `reason` | `skipped` | the reason, with any detail |
| `cleaned`, `skipped`, `dry_run` | `done` | counts, and whether nothing was written |
| `by_reason` | `done` | skip counts keyed by reason |
| `files`, `partial_files`, `exit` | `done` | files walked, files not fully read, the exit code |
| `error` | `done` | why the run stopped, when the state store failed |

</details>

<details>
<summary><code>undo</code> fields</summary>

| Field | Events | Value |
|---|---|---|
| `event` | all | `undone` or `done` |
| `count` | `undone` | edits reverted |
| `undone`, `exit` | `done` | edits reverted, the exit code |
| `error` | `done` | why undo failed, when it did |

</details>

## Install

Prebuilt archives for Linux, macOS and Windows are on the
[releases page](https://github.com/baairon/meownary/releases).

| Platform | Targets |
|---|---|
| Linux (static) | `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` |
| macOS | `aarch64-apple-darwin`, `x86_64-apple-darwin` |
| Windows | `x86_64-pc-windows-msvc` |

Archives are named `meownary-<version>-<target>.tar.gz`, or `.zip` on Windows.
Each has a `.sha256` file, and `SHA256SUMS` lists them all.

Building from source needs Rust 1.88 or newer:

```sh
git clone https://github.com/baairon/meownary
cd meownary
cargo build --release --locked
```

The binary lands at `target/release/meownary`.

## Exit codes

Every command exits with one of seven codes.

<details>
<summary>Codes 0, 1, 2, 73, 75, 101 and 130</summary>

| Code | Meaning |
|------|---------|
| 0    | success |
| 1    | `scan --fail-on` was met; `clean` matched but changed nothing; `undo` failed; the view failed |
| 2    | bad command, flag or value, a missing path, or a path that does not exist |
| 73   | the state store could not be opened, or another meownary holds it; nothing was edited |
| 75   | some files could not be fully read, or a deattributed copy could not be verified |
| 101  | internal error; meownary prints where to report it |
| 130  | interrupted with Ctrl-C (Windows reports 0xC000013A instead) |

</details>

## License

MIT. Copyright (c) 2026 bairon.dev.
