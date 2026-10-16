# Security policy

## Reporting a vulnerability

Please report security issues privately, not in public issues or pull
requests. Either:

- open a private report through GitHub's vulnerability reporting at
  https://github.com/baairon/meownary/security/advisories/new, or
- email hi@bairon.dev.

Include the meownary version (`meownary --version`), your platform, and the
smallest file or steps that reproduce the problem. If the trigger is a file,
attach it or describe how to build it; do not publish it. Fixes ship in a patch
release.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

Fixes land on the latest 0.1 release.

## Scope

meownary reads hostile files by design, so these are in scope:

- **Parsing untrusted files**: a crafted file that crashes the process, hangs a
  scan, makes it allocate or read without bound, or reads outside the file's
  own bytes. One bad file is meant to yield a partial result for that file
  alone.
- **The edit and undo engine**: an edit that changes bytes outside its marker,
  writes outside the target file or the state directory, or cannot be undone;
  an `undo` that does not restore the original bytes exactly, or overwrites a
  file that changed after the edit; a trash store or journal entry that can be
  made to point somewhere else.
- **Path handling**: following a symbolic link the walk should not follow,
  scanning or cleaning meownary's own state directory, editing through a link,
  or a file name that injects terminal escape sequences into the output.

Out of scope: findings that are wrong or missing (open a normal issue), and
anything that needs an attacker who can already write to the state directory.

## Network

meownary never connects to the network. It reads the files you point it at and
writes only its trash store and undo journal, so there is no server, telemetry,
or update channel to report on.
