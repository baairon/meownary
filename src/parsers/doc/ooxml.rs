//! Office Open XML packages: the producing application from
//! `docProps/app.xml` and the author and date fields of
//! `docProps/core.xml`, read only when those parts are stored uncompressed
//! (method 0). Otherwise the package kind is reported from its entry names.
//! Nothing is decompressed.
//!
//! A stored part's bytes are covered by the entry's CRC-32, so blanking a
//! field in place would make the package fail its integrity check. The
//! fields are reported without a marker.

use crate::model::{BrandKind, Category, Confidence, Evidence, Finding, JunkKind, Severity};
use crate::scan::FileView;
use crate::util::bytes::find;

use crate::parsers::image::shared::{NOTE_CHARS, TITLE_CHARS, clip, excerpt, fetch, finding};
use crate::parsers::zip::{self, ZipArchive, ZipEntry};

/// Largest stored part read.
const MAX_PART: u64 = 1024 * 1024;
/// Most tags examined while looking for one element.
const MAX_TAGS: usize = 8192;

/// `docProps/core.xml` elements reported: local name and label.
const CORE_FIELDS: &[(&[u8], &str)] = &[
    (b"creator", "author"),
    (b"lastModifiedBy", "last modified by"),
    (b"title", "title"),
    (b"subject", "subject"),
    (b"keywords", "keywords"),
    (b"description", "description"),
    (b"created", "created"),
    (b"modified", "modified"),
    (b"lastPrinted", "last printed"),
];

/// `docProps/app.xml` elements reported as document info.
const APP_FIELDS: &[(&[u8], &str)] = &[(b"Company", "company"), (b"Manager", "manager")];

/// The kind of document a package holds, from its main part.
fn package_kind(z: &ZipArchive) -> &'static str {
    for (name, kind) in [
        ("word/document.xml", "Word document"),
        ("xl/workbook.xml", "Excel workbook"),
        ("ppt/presentation.xml", "PowerPoint presentation"),
        ("visio/document.xml", "Visio drawing"),
    ] {
        if z.entry(name).is_some() {
            return kind;
        }
    }
    "package"
}

/// A part's absolute data offset and bytes, when it is stored uncompressed,
/// unencrypted, and small enough to read.
fn stored_part(view: &dyn FileView, e: &ZipEntry) -> Option<(u64, Vec<u8>)> {
    if e.method != 0 || e.encrypted() || e.compressed != e.uncompressed || e.compressed > MAX_PART {
        return None;
    }
    let (start, len) = zip::entry_data_span(view, e)?;
    let bytes = fetch(view, start, usize::try_from(len).ok()?)?;
    Some((start, bytes))
}

/// The text content of the first element whose local name (the part after
/// any namespace prefix) is `local`: its offset in `xml`, its length, and the
/// text with the common entities decoded. Empty and self-closing elements
/// yield `None`.
fn element(xml: &[u8], local: &[u8]) -> Option<(usize, usize, String)> {
    let mut i = 0usize;
    for _ in 0..MAX_TAGS {
        let lt = i + find(xml.get(i..)?, b"<")?;
        let name_start = lt + 1;
        let mut j = name_start;
        while xml
            .get(j)
            .is_some_and(|&b| b != b'>' && b != b'/' && !b.is_ascii_whitespace())
        {
            j += 1;
        }
        let name = xml.get(name_start..j)?;
        let local_name = name.rsplit(|&b| b == b':').next().unwrap_or(name);
        if !name.is_empty() && local_name == local {
            let gt = j + find(xml.get(j..)?, b">")?;
            if gt > 0 && xml.get(gt - 1) == Some(&b'/') {
                return None;
            }
            let start = gt + 1;
            let end = start + find(xml.get(start..)?, b"<")?;
            let raw = xml.get(start..end)?;
            let text = unescape(&String::from_utf8_lossy(raw));
            if text.trim().is_empty() {
                return None;
            }
            return Some((start, end - start, text.trim().to_string()));
        }
        i = j.max(lt + 1);
    }
    None
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let Some(z) = zip::parse(view) else {
        return;
    };
    let Some(types) = z.entry("[Content_Types].xml") else {
        return;
    };
    let kind = package_kind(&z);
    let app = z.entry("docProps/app.xml");
    let core = z.entry("docProps/core.xml");
    let app_xml = app.and_then(|e| stored_part(view, e));
    let core_xml = core.and_then(|e| stored_part(view, e));

    let mut branded = false;
    if let Some((base, xml)) = &app_xml {
        if let Some((at, len, name)) = element(xml, b"Application") {
            let version = element(xml, b"AppVersion").map(|(_, _, v)| v);
            let label = match &version {
                Some(v) => format!("{name} {v}"),
                None => name.clone(),
            };
            out.push(finding(
                "ooxml.app",
                Category::Brand(BrandKind::DocProducer),
                Confidence::Moderate,
                Severity::Info,
                format!("OOXML application \"{}\"", clip(&label, TITLE_CHARS)),
                Evidence::at(base + at as u64)
                    .with_bytes(excerpt(xml.get(at..at + len).unwrap_or_default()))
                    .with_note(format!(
                        "{kind} written by \"{}\" (docProps/app.xml Application)",
                        clip(&label, NOTE_CHARS)
                    )),
                None,
            ));
            branded = true;
        }
        doc_info(*base, xml, "docProps/app.xml", APP_FIELDS, out);
    }
    if !branded {
        let why = match app {
            Some(_) => "docProps/app.xml is compressed, so the producing application is not read",
            None => "the package has no docProps/app.xml",
        };
        out.push(finding(
            "ooxml.package",
            Category::Brand(BrandKind::DocProducer),
            Confidence::Moderate,
            Severity::Info,
            format!("Office Open XML {kind}"),
            Evidence::at(types.central_offset)
                .with_bytes(excerpt(&types.name))
                .with_note(format!(
                    "[Content_Types].xml marks an Office Open XML {kind}; {why}"
                )),
            None,
        ));
    }
    if let Some((base, xml)) = &core_xml {
        doc_info(*base, xml, "docProps/core.xml", CORE_FIELDS, out);
    }
}

fn doc_info(base: u64, xml: &[u8], part: &str, fields: &[(&[u8], &str)], out: &mut Vec<Finding>) {
    for &(local, label) in fields {
        let Some((at, len, text)) = element(xml, local) else {
            continue;
        };
        out.push(finding(
            "ooxml.docinfo",
            Category::Junk(JunkKind::DocInfo),
            Confidence::Moderate,
            Severity::Notice,
            format!("OOXML {label} \"{}\"", clip(&text, TITLE_CHARS)),
            Evidence::at(base + at as u64)
                .with_bytes(excerpt(xml.get(at..at + len).unwrap_or_default()))
                .with_note(format!(
                    "{part} {} = \"{}\"; the part is covered by the entry's CRC-32, so it \
                     is not blanked in place",
                    String::from_utf8_lossy(local),
                    clip(&text, NOTE_CHARS)
                )),
            None,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::doc::probes;
    use crate::parsers::image::shared::testkit::{run, with_id};
    use crate::parsers::zip::tests::{Ent, build_zip};
    use crate::scan::MemView;

    const APP: &[u8] = b"<?xml version=\"1.0\"?><Properties xmlns=\"x\"><Template>Normal.dotm\
        </Template><Application>Microsoft Office Word</Application><Company>Example \
        &amp; Sons</Company><AppVersion>16.0000</AppVersion><TitlesOfParts/></Properties>";

    const CORE: &[u8] = b"<?xml version=\"1.0\"?><cp:coreProperties xmlns:cp=\"c\" \
        xmlns:dc=\"d\"><dc:title>Budget</dc:title><dc:subject/><dc:creator>Jane Doe\
        </dc:creator><cp:lastModifiedBy>John Roe</cp:lastModifiedBy><dcterms:created \
        xsi:type=\"dcterms:W3CDTF\">2024-01-02T03:04:05Z</dcterms:created></cp:coreProperties>";

    fn package(compress: bool) -> Vec<u8> {
        let ents = vec![
            Ent {
                name: "[Content_Types].xml",
                data: b"<Types/>",
                flags: 0,
            },
            Ent {
                name: "docProps/app.xml",
                data: APP,
                flags: 0,
            },
            Ent {
                name: "docProps/core.xml",
                data: CORE,
                flags: 0,
            },
            Ent {
                name: "word/document.xml",
                data: b"<w:document/>",
                flags: 0,
            },
        ];
        let mut data = build_zip(&ents, b"", b"");
        if compress {
            // Mark the docProps parts as deflated in both headers.
            let z = zip::parse(&MemView::new("", data.clone())).unwrap();
            for e in &z.entries[1..3] {
                data[e.local_offset as usize + 8] = 8;
                data[e.central_offset as usize + 10] = 8;
            }
        }
        data
    }

    fn scan(data: &[u8]) -> Vec<Finding> {
        run(probes(), "budget.docx", data, "ooxml")
    }

    #[test]
    fn stored_doc_props_are_read() {
        let data = package(false);
        let fs = scan(&data);
        let app = with_id(&fs, "ooxml.app");
        assert_eq!(app.len(), 1);
        assert_eq!(
            app[0].title,
            "OOXML application \"Microsoft Office Word 16.0000\""
        );
        assert!(with_id(&fs, "ooxml.package").is_empty());
        let info = with_id(&fs, "ooxml.docinfo");
        let titles: Vec<&str> = info.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "OOXML company \"Example & Sons\"",
                "OOXML author \"Jane Doe\"",
                "OOXML last modified by \"John Roe\"",
                "OOXML title \"Budget\"",
                "OOXML created \"2024-01-02T03:04:05Z\"",
            ]
        );
        for f in fs.iter() {
            assert!(f.marker.is_none());
            let at = f.evidence.offset as usize;
            assert_eq!(
                &data[at..at + f.evidence.matched.len()],
                &f.evidence.matched[..]
            );
        }
    }

    #[test]
    fn compressed_doc_props_fall_back_to_the_package_kind() {
        let fs = scan(&package(true));
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].signature_id, "ooxml.package");
        assert_eq!(fs[0].title, "Office Open XML Word document");
        assert_eq!(fs[0].confidence, Confidence::Moderate);
        assert!(
            fs[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("compressed")
        );
    }

    #[test]
    fn plain_zip_and_truncations_are_quiet() {
        let plain = build_zip(
            &[Ent {
                name: "docProps/app.xml",
                data: APP,
                flags: 0,
            }],
            b"",
            b"",
        );
        assert!(scan(&plain).is_empty());
        let data = package(false);
        for cut in 0..data.len() {
            assert!(scan(&data[..cut]).is_empty(), "prefix {cut}");
        }
        for i in 0..data.len() {
            for v in [0x00, b'<', b'>', b'/', 0xFF] {
                let mut m = data.clone();
                m[i] = v;
                let _ = scan(&m);
            }
        }
    }

    #[test]
    fn element_lookup() {
        assert_eq!(
            element(b"<a:x>v</a:x>", b"x").map(|e| e.2).as_deref(),
            Some("v")
        );
        assert!(element(b"<x/>", b"x").is_none());
        assert!(element(b"<xy>v</xy>", b"x").is_none());
        assert!(element(b"<x>  </x>", b"x").is_none());
        assert!(element(b"<x>unterminated", b"x").is_none());
        assert!(element(b"<<<<", b"x").is_none());
    }
}
