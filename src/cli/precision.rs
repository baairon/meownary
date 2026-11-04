//! Scriptable deattribution and byte editing. Every successful JSON result is
//! followed by a versioned done event; usage and operational failures differ.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::edit::deattribute::{
    self, Mode,
    policy::{Options, Rules, VerificationPolicy},
};
use crate::edit::precision::archive;
use crate::edit::precision::{
    pattern::{Boundary, Encoding, Limits, Matcher, Pattern, Span, invalid, parse_hex, read_exact},
    plan::{self, EditPlan, EditSpec, OperationKind, Payload, Request},
};
use crate::scan::{FileView, WindowedFile};

pub fn is_command(name: &str) -> bool {
    matches!(
        name,
        "deattribute"
            | "inspect"
            | "inventory"
            | "hash"
            | "bytes"
            | "strings"
            | "find"
            | "diff"
            | "plan"
            | "apply"
            | "verify"
            | "capabilities"
            | "schema"
            | "archive"
    )
}

const HELP: &str =
    "meownary deattribute <input> [--deep] [--rules FILE] [--verify strict|protected]
  [--plan-out FILE] [--output FILE] [--dry-run] [--max-scan N] [--max-matches N]
meownary inspect|inventory|hash <path> [--json] [--details]
meownary bytes read <file> [--offset N] [--length N] [--encoding utf8] [--details]
meownary find <file> (--text TEXT|--hex HEX) [--encoding utf8] [--boundary word]
meownary strings <file> [--encoding utf8] [--min-length N] [--details]
meownary diff <before> <after> [--limit N] [--details]
meownary bytes replace|fill|insert|delete|truncate <file> [--offset N] [--length N]
  [--hex HEX|--text TEXT|--data-file FILE|--fill BYTE] [--resize] [--pad BYTE]
  [--find-text TEXT|--find-hex HEX] [--expect N] [--occurrence N]
  [--plan-out FILE] [--output FILE|--in-place] [--dry-run] [--overwrite] [--raw]
meownary plan <file> --spec FILE [--output PLAN] [--raw]
meownary apply <plan> [--output FILE|--in-place] [--overwrite] [--raw]
meownary verify <plan> <output>
meownary archive list|extract|pack|verify|msi <path> [--output PATH]
  [--format zip|tar|tar.gz] [--manifest FILE] [--max-total N] [--max-entry N]
  [--normalize-metadata] [--limit N]
meownary capabilities|schema [plan|rules|spec|events]

All commands accept --json. Plans and rules accept - for stdin.
Offsets and lengths accept decimal or 0x hexadecimal. All edit offsets refer
to the original input. Read/search output is bounded; --details includes text.
--encoding: ascii, utf8, utf16le, utf16be, windows1252.
--boundary: substring, word, identifier. --ignore-case folds ASCII only.
--max-scan is a byte budget (default 1073741824). --max-matches defaults to 100000.
Copies are the default. --in-place records an undo snapshot. --raw permits
protected edits and resizing recognized formats, with byte verification only.
";

#[derive(Default)]
struct Args {
    pos: Vec<OsString>,
    flags: BTreeMap<String, OsString>,
}

impl Args {
    fn parse(args: &[OsString], values: &[&str], switches: &[&str]) -> io::Result<Self> {
        let mut out = Self::default();
        let mut i = 0;
        let mut ended = false;
        while i < args.len() {
            let arg = &args[i];
            i += 1;
            if arg == "--" && !ended {
                ended = true;
                continue;
            }
            let text = arg.to_string_lossy();
            if ended || !text.starts_with("--") {
                out.pos.push(arg.clone());
                continue;
            }
            let (key, inline) = text
                .split_once('=')
                .map_or((text.as_ref(), None), |(a, b)| (a, Some(b)));
            let value = if values.contains(&key) {
                match inline {
                    Some(v) => OsString::from(v),
                    None => {
                        let next = args
                            .get(i)
                            .ok_or_else(|| invalid(format!("{key} needs a value")))?;
                        i += 1;
                        next.clone()
                    }
                }
            } else if switches.contains(&key) {
                if inline.is_some() {
                    return Err(invalid(format!("{key} takes no value")));
                }
                OsString::new()
            } else {
                return Err(invalid(format!("unknown option: {key}")));
            };
            if out.flags.insert(key.into(), value).is_some() {
                return Err(invalid(format!("duplicate option: {key}")));
            }
        }
        Ok(out)
    }
    fn has(&self, flag: &str) -> bool {
        self.flags.contains_key(flag)
    }
    fn only(&self, accepted: &[&str]) -> io::Result<()> {
        for key in self.flags.keys() {
            if key != "--json" && !accepted.contains(&key.as_str()) {
                return Err(invalid(format!("{key} does not apply to this command")));
            }
        }
        Ok(())
    }
    fn text(&self, flag: &str) -> io::Result<Option<&str>> {
        self.flags
            .get(flag)
            .map(|s| {
                s.to_str()
                    .ok_or_else(|| invalid(format!("{flag} needs Unicode text")))
            })
            .transpose()
    }
    fn path(&self, flag: &str) -> Option<PathBuf> {
        self.flags.get(flag).map(PathBuf::from)
    }
    fn number(&self, flag: &str, default: u64) -> io::Result<u64> {
        self.text(flag)?
            .map(number)
            .transpose()
            .map(|v| v.unwrap_or(default))
    }
    fn paths(&self, count: usize) -> io::Result<Vec<PathBuf>> {
        if self.pos.len() != count {
            return Err(invalid(format!("expected {count} positional path(s)")));
        }
        Ok(self.pos.iter().map(PathBuf::from).collect())
    }
    fn limits(&self) -> io::Result<Limits> {
        Ok(Limits {
            max_scan_bytes: self.number("--max-scan", Limits::default().max_scan_bytes)?,
            max_matches: usize::try_from(self.number("--max-matches", 100000)?)
                .map_err(|_| invalid("max-matches is too large"))?,
        })
    }
    fn encoding(&self) -> io::Result<Encoding> {
        match self.text("--encoding")?.unwrap_or("utf8") {
            "ascii" => Ok(Encoding::Ascii),
            "utf8" | "utf-8" => Ok(Encoding::Utf8),
            "utf16le" | "utf-16le" => Ok(Encoding::Utf16le),
            "utf16be" | "utf-16be" => Ok(Encoding::Utf16be),
            "windows1252" | "windows-1252" => Ok(Encoding::Windows1252),
            _ => Err(invalid("unknown encoding")),
        }
    }
    fn pattern(&self, text_flag: &str, hex_flag: &str) -> io::Result<Pattern> {
        match (self.text(text_flag)?, self.text(hex_flag)?) {
            (Some(value), None) => Ok(Pattern::Text {
                value: value.into(),
                encoding: self.encoding()?,
                ignore_ascii_case: self.has("--ignore-case"),
                boundary: match self.text("--boundary")?.unwrap_or("substring") {
                    "substring" => Boundary::Substring,
                    "word" => Boundary::Word,
                    "identifier" => Boundary::Identifier,
                    _ => return Err(invalid("unknown boundary")),
                },
            }),
            (None, Some(value)) => Ok(Pattern::Hex {
                value: value.into(),
            }),
            _ => Err(invalid(format!(
                "choose exactly one {text_flag} or {hex_flag}"
            ))),
        }
    }
}

fn number(value: &str) -> io::Result<u64> {
    let result = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    };
    result.map_err(|_| invalid(format!("invalid unsigned integer: {value}")))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let reader: Box<dyn Read> = if path == Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(path)?)
    };
    let mut bytes = Vec::new();
    reader.take(32 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(invalid("JSON exceeds 32 MiB"));
    }
    serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))
}

pub fn run(argv: &[OsString]) -> i32 {
    let (json_output, help) = global_flags(argv);
    if help {
        let _ = io::stdout().write_all(HELP.as_bytes());
        return 0;
    }
    let mut stdout = io::stdout().lock();
    let result = dispatch(argv, &mut stdout, json_output);
    let code = match &result {
        Ok(complete) => {
            if *complete {
                0
            } else {
                75
            }
        }
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => 2,
        Err(_) => 75,
    };
    if let Err(error) = result {
        if json_output {
            let _ = writeln!(
                stdout,
                "{}",
                json!({"version":1,"event":"error","error":error.to_string(),"exit":code})
            );
        } else {
            let _ = writeln!(io::stderr(), "meownary: {error}");
        }
    }
    if json_output {
        let _ = writeln!(
            stdout,
            "{}",
            json!({"version":1,"event":"done","exit":code,"complete":code==0})
        );
    }
    code
}

fn global_flags(argv: &[OsString]) -> (bool, bool) {
    const VALUES: &[&str] = &[
        "--rules",
        "--verify",
        "--max-scan",
        "--max-matches",
        "--plan-out",
        "--output",
        "--spec",
        "--offset",
        "--length",
        "--text",
        "--hex",
        "--data-file",
        "--fill",
        "--pad",
        "--find-text",
        "--find-hex",
        "--encoding",
        "--boundary",
        "--expect",
        "--occurrence",
        "--min-length",
        "--limit",
        "--format",
        "--manifest",
        "--max-total",
        "--max-entry",
    ];
    let (mut json, mut help, mut value) = (false, false, false);
    for arg in argv {
        if value {
            value = false;
            continue;
        }
        if arg == "--" {
            break;
        }
        let text = arg.to_string_lossy();
        if VALUES.contains(&text.as_ref()) {
            value = true;
            continue;
        }
        json |= arg == "--json";
        help |= arg == "--help" || arg == "-h";
    }
    (json, help)
}

fn emit(
    out: &mut dyn Write,
    json_output: bool,
    event: &str,
    value: impl serde::Serialize,
) -> io::Result<()> {
    if json_output {
        writeln!(out, "{}", json!({"version":1,"event":event,"data":value}))
    } else {
        writeln!(out, "{}", serde_json::to_string_pretty(&value)?)
    }
}

fn dispatch(argv: &[OsString], out: &mut dyn Write, json_output: bool) -> io::Result<bool> {
    let command = argv
        .first()
        .and_then(|s| s.to_str())
        .ok_or_else(|| invalid("missing command"))?;
    match command {
        "capabilities" => {
            Args::parse(&argv[1..], &[], &["--json"])?.paths(0)?;
            emit(out, json_output, "capabilities", capabilities())?;
            Ok(true)
        }
        "schema" => {
            let a = Args::parse(&argv[1..], &[], &["--json"])?;
            if a.pos.len() > 1 {
                return Err(invalid("schema accepts at most one name"));
            }
            let name = a.pos.first().and_then(|s| s.to_str()).unwrap_or("plan");
            emit(out, json_output, "schema", schema(name)?)?;
            Ok(true)
        }
        "deattribute" | "clean" => {
            if command == "clean"
                && !argv
                    .iter()
                    .take_while(|a| *a != "--")
                    .any(|a| a == "--deattribute")
            {
                return Err(invalid("policy options on clean require --deattribute"));
            }
            deattribute_command(&argv[1..], out, json_output)
        }
        "bytes" => bytes_command(&argv[1..], out, json_output),
        "plan" | "apply" | "verify" => plan_command(command, &argv[1..], out, json_output),
        "find" | "strings" | "diff" | "inspect" | "inventory" | "hash" => {
            inspect_command(command, &argv[1..], out, json_output)
        }
        "archive" => archive_command(&argv[1..], out, json_output),
        _ => Err(invalid("unknown command")),
    }
}

fn deattribute_command(
    argv: &[OsString],
    out: &mut dyn Write,
    json_output: bool,
) -> io::Result<bool> {
    let a = Args::parse(
        argv,
        &[
            "--rules",
            "--verify",
            "--max-scan",
            "--max-matches",
            "--plan-out",
            "--output",
        ],
        &[
            "--deep",
            "--dry-run",
            "--overwrite",
            "--json",
            "--details",
            "--deattribute",
        ],
    )?;
    let paths = a.paths(1)?;
    let path = &paths[0];
    plan::regular(path)?;
    let policy = match a.text("--verify")?.unwrap_or("strict") {
        "strict" => VerificationPolicy::Strict,
        "protected" => VerificationPolicy::Protected,
        _ => return Err(invalid("--verify expects strict or protected")),
    };
    let options = Options {
        limits: a.limits()?,
        rules: a
            .path("--rules")
            .map(|p| read_json::<Rules>(&p))
            .transpose()?,
        verification: policy,
    };
    let view = WindowedFile::open(path)?;
    let report = crate::scan::scan_file_detailed(path, &crate::parsers::registry());
    let mode = if a.has("--deep") {
        Mode::Deep
    } else {
        Mode::Basic
    };
    let planned = deattribute::plan_with_options(&report.report, &view, mode, &options)?;
    let edit = EditPlan::from_deattribute(path, &planned, mode == Mode::Deep, policy)?;
    distinct_outputs(
        a.path("--plan-out").as_deref(),
        a.path("--output").as_deref(),
    )?;
    if let Some(output) = a.path("--plan-out") {
        write_plan(&output, &edit, a.has("--overwrite"))?;
    }
    emit(
        out,
        json_output,
        "planned",
        json!({"input":path,"operations":edit.operations.len(),"affected_bytes":planned.targets.iter().map(|t|t.marker.region.len).sum::<u64>(),
        "coverage_complete":edit.deattribute.as_ref().is_some_and(|d|d.coverage_complete),
        "skipped":planned.skipped.iter().map(|s|s.reason.slug()).collect::<Vec<_>>() }),
    )?;
    if a.has("--details") {
        emit(out, json_output, "audit", &planned.audit)?;
    }
    if a.has("--dry-run") || (a.has("--plan-out") && !a.has("--output")) {
        return Ok(edit
            .deattribute
            .as_ref()
            .is_some_and(|d| d.coverage_complete));
    }
    if edit.operations.is_empty() {
        let verified = edit.verify(path)?;
        let ok = verified.ok();
        emit(out, json_output, "verification", verified)?;
        return Ok(ok);
    }
    let output = a
        .path("--output")
        .unwrap_or_else(|| deattribute::deattributed_name(path));
    let result = edit.apply(&output, a.has("--overwrite"), false, false)?;
    emit(out, json_output, "saved", result)?;
    Ok(true)
}

fn plan_command(
    command: &str,
    argv: &[OsString],
    out: &mut dyn Write,
    json_output: bool,
) -> io::Result<bool> {
    let a = Args::parse(
        argv,
        &["--spec", "--output"],
        &["--json", "--raw", "--overwrite", "--in-place"],
    )?;
    a.only(match command {
        "plan" => &["--spec", "--output", "--raw", "--overwrite"],
        "apply" => &["--output", "--raw", "--overwrite", "--in-place"],
        _ => &[],
    })?;
    if command == "plan" {
        let paths = a.paths(1)?;
        let spec: EditSpec = read_json(
            &a.path("--spec")
                .ok_or_else(|| invalid("plan needs --spec"))?,
        )?;
        if spec.version != 1 {
            return Err(invalid("unsupported spec version"));
        }
        let plan = EditPlan::create(&paths[0], spec.operations, a.has("--raw"))?;
        if let Some(output) = a.path("--output") {
            write_plan(&output, &plan, a.has("--overwrite"))?;
        }
        emit(out, json_output, "plan", &plan)?;
        return Ok(true);
    }
    let paths = a.paths(if command == "verify" { 2 } else { 1 })?;
    if a.has("--output") && a.has("--in-place") {
        return Err(invalid("choose output or in-place"));
    }
    let plan: EditPlan = read_json(&paths[0])?;
    if command == "verify" {
        let result = plan.verify(&paths[1])?;
        let ok = result.ok();
        emit(out, json_output, "verification", result)?;
        return Ok(ok);
    }
    let output = if a.has("--in-place") {
        plan.input.clone()
    } else {
        a.path("--output")
            .unwrap_or_else(|| edited_name(&plan.input))
    };
    distinct_outputs(Some(&paths[0]), Some(&output))?;
    emit(
        out,
        json_output,
        "applied",
        plan.apply(
            &output,
            a.has("--overwrite"),
            a.has("--in-place"),
            a.has("--raw"),
        )?,
    )?;
    Ok(true)
}

fn edited_name(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".edited");
    path.with_file_name(name)
}

fn distinct_outputs(plan_path: Option<&Path>, output: Option<&Path>) -> io::Result<()> {
    if let (Some(p), Some(o)) = (plan_path, output)
        && plan::output_path(p)? == plan::output_path(o)?
    {
        return Err(invalid("plan and binary output must be different files"));
    }
    Ok(())
}

fn write_plan(output: &Path, edit: &EditPlan, overwrite: bool) -> io::Result<()> {
    let destination = plan::output_path(output)?;
    if destination == edit.input
        || edit
            .operations
            .iter()
            .any(|op| matches!(&op.edit.data, Payload::File { path, .. } if *path == destination))
    {
        return Err(invalid(
            "plan output cannot replace an input or payload file",
        ));
    }
    plan::write_json(output, edit, overwrite)
}

fn bytes_command(argv: &[OsString], out: &mut dyn Write, json_output: bool) -> io::Result<bool> {
    let verb = argv
        .first()
        .and_then(|s| s.to_str())
        .ok_or_else(|| invalid("bytes needs an operation"))?;
    if verb == "read" {
        return inspect_command("read", &argv[1..], out, json_output);
    }
    let kind = match verb {
        "replace" => OperationKind::Replace,
        "fill" => OperationKind::Fill,
        "insert" => OperationKind::Insert,
        "delete" => OperationKind::Delete,
        "truncate" => OperationKind::Truncate,
        _ => return Err(invalid("unknown byte operation")),
    };
    let a = Args::parse(
        &argv[1..],
        &[
            "--offset",
            "--length",
            "--text",
            "--hex",
            "--data-file",
            "--fill",
            "--pad",
            "--find-text",
            "--find-hex",
            "--encoding",
            "--boundary",
            "--max-scan",
            "--max-matches",
            "--expect",
            "--occurrence",
            "--plan-out",
            "--output",
        ],
        &[
            "--json",
            "--dry-run",
            "--raw",
            "--resize",
            "--ignore-case",
            "--in-place",
            "--overwrite",
        ],
    )?;
    let paths = a.paths(1)?;
    let path = &paths[0];
    if a.has("--output") && a.has("--in-place") {
        return Err(invalid("choose output or in-place"));
    }
    let searching = a.has("--find-text") || a.has("--find-hex");
    if !searching
        && ["--boundary", "--ignore-case", "--max-scan", "--max-matches"]
            .iter()
            .any(|f| a.has(f))
    {
        return Err(invalid("matching options require a search selector"));
    }
    if a.has("--encoding") && !a.has("--text") && !a.has("--find-text") {
        return Err(invalid("encoding requires a text payload or selector"));
    }
    if a.has("--find-hex") && (a.has("--boundary") || a.has("--ignore-case")) {
        return Err(invalid(
            "text matching options do not apply to hex selection",
        ));
    }
    if !searching && (a.has("--expect") || a.has("--occurrence")) {
        return Err(invalid("expect and occurrence require a search selector"));
    }
    if matches!(kind, OperationKind::Insert | OperationKind::Truncate)
        && (searching || a.has("--length"))
    {
        return Err(invalid(
            "insert and truncate take an offset, without a length or search selector",
        ));
    }
    if matches!(kind, OperationKind::Fill | OperationKind::Delete)
        && !searching
        && !a.has("--length")
    {
        return Err(invalid("fill and delete need a length"));
    }
    if a.has("--pad") && kind != OperationKind::Replace {
        return Err(invalid("padding applies only to replacement"));
    }
    plan::regular(path)?;
    let view = WindowedFile::open(path)?;
    let mut spans = if a.has("--find-text") || a.has("--find-hex") {
        if a.has("--offset") || a.has("--length") {
            return Err(invalid(
                "search selection cannot be combined with offset or length",
            ));
        }
        let pattern = a.pattern("--find-text", "--find-hex")?;
        let found = Matcher::new(&[pattern])?.search(
            &view,
            Span {
                offset: 0,
                len: view.size(),
            },
            &a.limits()?,
        )?;
        if !found.complete {
            return Err(invalid("search incomplete; no edits planned"));
        }
        if a.has("--expect") && a.number("--expect", 0)? != found.matches.len() as u64 {
            return Err(invalid(format!(
                "expected match count differs from {}",
                found.matches.len()
            )));
        }
        if found.matches.is_empty() {
            return Err(invalid("no matches"));
        }
        found
            .matches
            .into_iter()
            .map(|m| Span {
                offset: m.offset,
                len: m.len,
            })
            .collect::<Vec<_>>()
    } else {
        if !a.has("--offset") {
            return Err(invalid("an offset or search selector is required"));
        }
        let offset = a.number("--offset", 0)?;
        let len = if kind == OperationKind::Truncate {
            view.size()
                .checked_sub(offset)
                .ok_or_else(|| invalid("truncate is past EOF"))?
        } else {
            a.number("--length", 0)?
        };
        vec![Span { offset, len }]
    };
    if a.has("--occurrence") {
        let n = a.number("--occurrence", 0)?;
        spans = vec![
            spans
                .get(
                    usize::try_from(
                        n.checked_sub(1)
                            .ok_or_else(|| invalid("occurrences start at 1"))?,
                    )
                    .map_err(|_| invalid("occurrence is too large"))?,
                )
                .ok_or_else(|| invalid("occurrence is out of range"))?
                .clone(),
        ];
    }
    let payload_count = ["--text", "--hex", "--data-file", "--fill"]
        .iter()
        .filter(|f| a.has(f))
        .count();
    if matches!(kind, OperationKind::Delete | OperationKind::Truncate) && payload_count > 0 {
        return Err(invalid("this operation takes no replacement bytes"));
    }
    if matches!(
        kind,
        OperationKind::Replace | OperationKind::Insert | OperationKind::Fill
    ) && payload_count != 1
    {
        return Err(invalid("choose exactly one replacement payload"));
    }
    if kind == OperationKind::Fill && !a.has("--fill") {
        return Err(invalid("fill requires --fill BYTE"));
    }
    if a.has("--fill") && kind != OperationKind::Fill {
        return Err(invalid("--fill applies only to fill"));
    }
    let mut requests = Vec::new();
    for span in spans {
        let mut payload = if let Some(path) = a.path("--data-file") {
            Payload::from_file(&path)?
        } else if let Some(hex) = a.text("--hex")? {
            Payload::from_bytes(&parse_hex(hex, false)?.0)
        } else if let Some(text) = a.text("--text")? {
            Payload::from_bytes(&a.encoding()?.encode(text)?)
        } else if a.has("--fill") {
            Payload::Fill {
                byte: u8::try_from(a.number("--fill", 0)?)
                    .map_err(|_| invalid("fill must be a byte"))?,
                len: span.len,
            }
        } else {
            Payload::Empty
        };
        let remove = if kind == OperationKind::Insert {
            0
        } else if span.len == 0 && kind == OperationKind::Replace {
            payload.len()?
        } else {
            span.len
        };
        if a.has("--pad") {
            let pad =
                u8::try_from(a.number("--pad", 0)?).map_err(|_| invalid("pad must be a byte"))?;
            let Payload::Hex { value } = payload else {
                return Err(invalid("padding requires inline bytes"));
            };
            let mut bytes = parse_hex(&value, false)?.0;
            if remove > 16 * 1024 * 1024 || remove < bytes.len() as u64 {
                return Err(invalid("padding length is invalid"));
            }
            bytes.resize(remove as usize, pad);
            payload = Payload::from_bytes(&bytes);
        }
        requests.push(Request {
            kind,
            offset: span.offset,
            remove,
            data: payload,
            resize: a.has("--resize"),
        });
    }
    let plan = EditPlan::create(path, requests, a.has("--raw"))?;
    distinct_outputs(
        a.path("--plan-out").as_deref(),
        a.path("--output").as_deref(),
    )?;
    if let Some(output) = a.path("--plan-out") {
        write_plan(&output, &plan, a.has("--overwrite"))?;
    }
    emit(
        out,
        json_output,
        "planned",
        json!({"operations":plan.operations.len(),"before":plan.before,"after":plan.after,"raw":plan.raw}),
    )?;
    if a.has("--dry-run") || (a.has("--plan-out") && !a.has("--output") && !a.has("--in-place")) {
        return Ok(true);
    }
    if a.has("--output") && a.has("--in-place") {
        return Err(invalid("choose output or in-place"));
    }
    let output = if a.has("--in-place") {
        plan.input.clone()
    } else {
        a.path("--output").unwrap_or_else(|| edited_name(path))
    };
    emit(
        out,
        json_output,
        "applied",
        plan.apply(
            &output,
            a.has("--overwrite"),
            a.has("--in-place"),
            a.has("--raw"),
        )?,
    )?;
    Ok(true)
}

fn inspect_command(
    command: &str,
    argv: &[OsString],
    out: &mut dyn Write,
    json_output: bool,
) -> io::Result<bool> {
    let a = Args::parse(
        argv,
        &[
            "--offset",
            "--length",
            "--text",
            "--hex",
            "--encoding",
            "--boundary",
            "--max-scan",
            "--max-matches",
            "--min-length",
            "--limit",
        ],
        &["--json", "--ignore-case", "--details"],
    )?;
    a.only(match command {
        "read" => &["--offset", "--length", "--encoding", "--details"],
        "find" => &[
            "--offset",
            "--length",
            "--text",
            "--hex",
            "--encoding",
            "--boundary",
            "--max-scan",
            "--max-matches",
            "--ignore-case",
            "--details",
        ],
        "strings" => &[
            "--offset",
            "--length",
            "--encoding",
            "--max-scan",
            "--min-length",
            "--limit",
            "--details",
        ],
        "diff" => &["--max-scan", "--limit", "--details"],
        "inspect" => &["--details"],
        _ => &[],
    })?;
    let paths = a.paths(if command == "diff" { 2 } else { 1 })?;
    let path = &paths[0];
    if command == "inventory" {
        let mut count = 0;
        let mut complete = true;
        for entry in walkdir::WalkDir::new(path)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(io::Error::other)?;
            if entry.file_type().is_dir() {
                continue;
            }
            if entry.file_type().is_symlink() {
                complete = false;
                emit(
                    out,
                    json_output,
                    "entry",
                    json!({"path":entry.path(),"status":"symlink skipped"}),
                )?;
                continue;
            }
            emit(
                out,
                json_output,
                "entry",
                json!({"path":entry.path(),"hashes":plan::hash(entry.path())?}),
            )?;
            count += 1;
        }
        emit(out, json_output, "inventory", json!({"files":count}))?;
        return Ok(complete);
    }
    if command == "find"
        && a.has("--hex")
        && ["--encoding", "--boundary", "--ignore-case"]
            .iter()
            .any(|f| a.has(f))
    {
        return Err(invalid("text matching options do not apply to hex search"));
    }
    plan::regular(path)?;
    if command == "hash" {
        emit(out, json_output, "hash", plan::hash(path)?)?;
        return Ok(true);
    }
    let view = WindowedFile::open(path)?;
    let offset = a.number("--offset", 0)?;
    let length = a.number("--length", view.size().saturating_sub(offset))?;
    let range = Span {
        offset,
        len: length,
    };
    if range.end()? > view.size() {
        return Err(invalid("range is past EOF"));
    }
    match command {
        "inspect" => {
            let layout = deattribute::layout::inspect(&view);
            let scanned = crate::scan::scan_file_detailed(path, &crate::parsers::registry());
            let mut info = json!({"path":path,"hashes":plan::hash(path)?,"layout":layout,"partial":scanned.report.partial,
                "findings":scanned.report.findings.iter().map(|f|json!({"category":f.category.slug(),"signature":f.signature_id})).collect::<Vec<_>>()});
            if let Some(pe) = crate::parsers::pe::image::PeImage::parse(&view) {
                info["architecture"] = json!(if pe.is64 { "pe64" } else { "pe32" });
                info["checksum"] = json!(pe.checksum);
                info["signature_present"] = json!(pe.dir(4).is_some());
            }
            emit(out, json_output, "inspection", info)?;
            Ok(!scanned.report.partial)
        }
        "read" => {
            let len = a.number("--length", 256.min(view.size().saturating_sub(offset)))?;
            if len > 1024 * 1024 {
                return Err(invalid("read output is limited to 1 MiB"));
            }
            if offset.checked_add(len).is_none_or(|end| end > view.size()) {
                return Err(invalid("read range is past EOF"));
            }
            let bytes = read_exact(&view, offset, len as usize)?;
            let mut data = json!({"offset":offset,"len":len,"hex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>()});
            if a.has("--details") {
                data["text"] = json!(a.encoding()?.decode(&bytes));
            }
            emit(out, json_output, "bytes", data)?;
            Ok(true)
        }
        "find" => {
            let pattern = a.pattern("--text", "--hex")?;
            let found = Matcher::new(&[pattern])?.search(&view, range, &a.limits()?)?;
            for hit in &found.matches {
                let mut value = serde_json::to_value(hit)?;
                if a.has("--details") {
                    value["bytes_hex"] = json!(
                        read_exact(&view, hit.offset, hit.len as usize)?
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                }
                emit(out, json_output, "match", value)?;
            }
            emit(
                out,
                json_output,
                "coverage",
                json!({"complete":found.complete,"examined":found.examined,"unexamined":found.unexamined,"matches":found.matches.len()}),
            )?;
            Ok(found.complete)
        }
        "strings" => strings_command(&view, &a, range, out, json_output),
        "diff" => diff_command(&view, &paths[1], &a, out, json_output),
        _ => Err(invalid("unknown inspection command")),
    }
}

fn strings_command(
    view: &dyn FileView,
    a: &Args,
    range: Span,
    out: &mut dyn Write,
    json_output: bool,
) -> io::Result<bool> {
    let encoding = a.encoding()?;
    let width = if matches!(encoding, Encoding::Utf16le | Encoding::Utf16be) {
        2
    } else {
        1
    };
    let stop = range
        .end()?
        .min(range.offset.saturating_add(a.limits()?.max_scan_bytes));
    let minimum = usize::try_from(a.number("--min-length", 4)?)
        .map_err(|_| invalid("min-length is too large"))?;
    let limit = a.number("--limit", 1000)?;
    if minimum == 0 || limit == 0 {
        return Err(invalid("min-length and limit must be positive"));
    }
    let mut count = 0;
    let mut pos = range.offset;
    let mut start = pos;
    let mut pending = Vec::new();
    let mut overflow = false;
    while pos < stop {
        let len = (stop - pos).min(1024 * 1024) as usize;
        let bytes = read_exact(view, pos, len + (stop - pos - len as u64).min(4) as usize)?;
        let mut at = 0;
        while at < len {
            let scalar = encoding.scalar(&bytes[at..]);
            let consumed = scalar.map_or(width.min(bytes.len() - at), |(_, n)| n);
            let printable = scalar.is_some_and(|(c, _)| !c.is_control());
            let chunk = &bytes[at..at + consumed];
            if printable {
                if pending.is_empty() && !overflow {
                    start = pos;
                }
                if pending.len() + consumed <= 65536 {
                    pending.extend_from_slice(chunk);
                } else {
                    overflow = true;
                }
            } else {
                if let Some(text) = encoding
                    .decode(&pending)
                    .filter(|s| s.chars().count() >= minimum)
                {
                    let mut value = json!({"offset":start,"len":pending.len(),"encoding":encoding,"truncated":overflow});
                    if a.has("--details") {
                        value["text"] = json!(text);
                    }
                    emit(out, json_output, "string", value)?;
                    count += 1;
                }
                pending.clear();
                overflow = false;
            }
            pos += chunk.len() as u64;
            at += consumed;
            if count >= limit {
                emit(
                    out,
                    json_output,
                    "coverage",
                    json!({"complete":false,"unexamined":[{"offset":pos,"len":range.end()?.saturating_sub(pos)}]}),
                )?;
                return Ok(false);
            }
        }
    }
    if let Some(text) = encoding
        .decode(&pending)
        .filter(|s| s.chars().count() >= minimum)
    {
        let mut value = json!({"offset":start,"len":pending.len(),"encoding":encoding,"truncated":overflow || stop < range.end()?});
        if a.has("--details") {
            value["text"] = json!(text);
        }
        emit(out, json_output, "string", value)?;
    }
    emit(
        out,
        json_output,
        "coverage",
        json!({"complete":stop==range.end()?,"examined":{"offset":range.offset,"len":stop-range.offset}}),
    )?;
    Ok(stop == range.end()?)
}

fn diff_command(
    before: &dyn FileView,
    path: &Path,
    a: &Args,
    out: &mut dyn Write,
    json_output: bool,
) -> io::Result<bool> {
    plan::regular(path)?;
    let after = WindowedFile::open(path)?;
    let size = before.size().max(after.size());
    let stop = size.min(a.limits()?.max_scan_bytes);
    let mut pos = 0;
    let mut run = None;
    let mut ranges = Vec::new();
    let limit =
        usize::try_from(a.number("--limit", 1000)?).map_err(|_| invalid("limit is too large"))?;
    if limit == 0 {
        return Err(invalid("limit must be positive"));
    }
    while pos < stop {
        let len = (stop - pos).min(1024 * 1024) as usize;
        let left = read_exact(
            before,
            pos.min(before.size()),
            len.min(before.size().saturating_sub(pos) as usize),
        )?;
        let right = read_exact(
            &after,
            pos.min(after.size()),
            len.min(after.size().saturating_sub(pos) as usize),
        )?;
        let base = pos;
        for i in 0..len {
            let at = base + i as u64;
            if left.get(i) != right.get(i) {
                run.get_or_insert(at);
            } else if let Some(start) = run.take() {
                ranges.push(Span {
                    offset: start,
                    len: at - start,
                });
            }
            pos = at + 1;
            if ranges.len() >= limit {
                break;
            }
        }
        if ranges.len() >= limit {
            break;
        }
    }
    if let Some(start) = run {
        ranges.push(Span {
            offset: start,
            len: pos - start,
        });
    }
    let mut details = Vec::new();
    if a.has("--details") {
        for span in &ranges {
            let sample = span.len.min(64);
            let left = read_exact(
                before,
                span.offset.min(before.size()),
                sample.min(before.size().saturating_sub(span.offset)) as usize,
            )?;
            let right = read_exact(
                &after,
                span.offset.min(after.size()),
                sample.min(after.size().saturating_sub(span.offset)) as usize,
            )?;
            details.push(json!({"offset":span.offset,"before_hex":crate::edit::fsio::to_hex(&left),"after_hex":crate::edit::fsio::to_hex(&right),"sample_bytes":sample}));
        }
    }
    let mut value = json!({"before_size":before.size(),"after_size":after.size(),"ranges":ranges,"complete":pos==size});
    if a.has("--details") {
        value["details"] = json!(details);
    }
    emit(out, json_output, "diff", value)?;
    Ok(pos == size)
}

fn archive_command(argv: &[OsString], out: &mut dyn Write, json_output: bool) -> io::Result<bool> {
    let verb = argv
        .first()
        .and_then(|s| s.to_str())
        .ok_or_else(|| invalid("archive needs list, extract, pack, verify, or msi"))?;
    let a = Args::parse(
        &argv[1..],
        &[
            "--output",
            "--format",
            "--manifest",
            "--max-total",
            "--max-entry",
            "--limit",
        ],
        &["--overwrite", "--json", "--normalize-metadata"],
    )?;
    a.only(match verb {
        "list" => &[
            "--manifest",
            "--overwrite",
            "--max-total",
            "--max-entry",
            "--limit",
        ],
        "extract" => &[
            "--output",
            "--manifest",
            "--overwrite",
            "--max-total",
            "--max-entry",
            "--limit",
        ],
        "pack" => &[
            "--output",
            "--format",
            "--manifest",
            "--overwrite",
            "--max-total",
            "--max-entry",
            "--limit",
            "--normalize-metadata",
        ],
        "verify" => &["--manifest", "--max-total", "--max-entry", "--limit"],
        "msi" => &["--limit"],
        _ => return Err(invalid("unknown archive command")),
    })?;
    let paths = a.paths(1)?;
    if verb != "verify"
        && let Some(path) = a.path("--manifest")
    {
        let destination = plan::output_path(&path)?;
        let input = plan::resolved(&paths[0])?;
        let output = a.path("--output").map(|p| plan::resolved(&p)).transpose()?;
        if destination == input
            || (input.is_dir() && destination.starts_with(&input))
            || output.is_some_and(|o| destination == o || destination.starts_with(&o))
        {
            return Err(invalid("manifest must be separate from input and output"));
        }
        if destination.exists() && !a.has("--overwrite") {
            return Err(invalid("manifest already exists"));
        }
    }
    let limits = archive::Limits {
        total_bytes: a.number("--max-total", 1024 * 1024 * 1024)?,
        entry_bytes: a.number("--max-entry", 256 * 1024 * 1024)?,
        entries: usize::try_from(a.number("--limit", 100_000)?)
            .map_err(|_| invalid("limit is too large"))?,
    };
    if verb == "msi" {
        let info = archive::inspect_msi(&paths[0], limits.entries)?;
        let complete = info["complete"] == true;
        emit(out, json_output, "msi", info)?;
        return Ok(complete);
    }
    if verb == "verify" {
        let manifest = read_json(
            &a.path("--manifest")
                .ok_or_else(|| invalid("verify needs --manifest"))?,
        )?;
        let ok = archive::verify(&paths[0], &manifest, &limits)?;
        emit(
            out,
            json_output,
            "archive_verification",
            json!({"verified":ok}),
        )?;
        return Ok(ok);
    }
    let manifest = match verb {
        "list" => archive::inventory(&paths[0], &limits)?,
        "extract" => archive::extract(
            &paths[0],
            &a.path("--output")
                .ok_or_else(|| invalid("extract needs --output"))?,
            &limits,
        )?,
        "pack" => archive::pack_with_metadata(
            &paths[0],
            &a.path("--output")
                .ok_or_else(|| invalid("pack needs --output"))?,
            a.text("--format")?.unwrap_or("zip"),
            a.has("--overwrite"),
            &limits,
            a.has("--normalize-metadata"),
        )?,
        _ => return Err(invalid("unknown archive command")),
    };
    if let Some(path) = a.path("--manifest") {
        plan::write_json(&path, &manifest, a.has("--overwrite"))?;
    }
    emit(out, json_output, "archive", manifest)?;
    Ok(true)
}

fn capabilities() -> Value {
    json!({"schema_version":1,"deattribute":{"modes":["normal","deep"],"verification":["strict","protected"],"rules":true},
        "byte_operations":["read","replace","fill","insert","delete","truncate"],"encodings":["ascii","utf8","utf16le","utf16be","windows1252"],
        "hashes":["blake3","sha256"],"offsets":"original input","undo":"in-place edits","limits":Limits::default(),
        "archives":{"read_write":["zip","zip64","tar","tar.gz"],"msi":"read-only tables","automatic_nesting":false}})
}

fn schema(name: &str) -> io::Result<Value> {
    // Self-contained schemas ship in the crate for offline CLI discovery.
    let source = match name {
        "plan" => include_str!("../../docs/schemas/plan.json"),
        "rules" => include_str!("../../docs/schemas/rules.json"),
        "spec" => include_str!("../../docs/schemas/spec.json"),
        "events" => include_str!("../../docs/schemas/events.json"),
        _ => return Err(invalid("schema expects plan, rules, spec, or events")),
    };
    serde_json::from_str(source).map_err(io::Error::other)
}
