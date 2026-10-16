//! The undocumented MSVC "Rich" header: a XOR-masked table of the tools that
//! produced each object file, stored between the DOS stub and the PE header.

use crate::util::bytes::{rfind, u32_le};

/// "DanS" read as a little-endian dword.
const DANS: u32 = 0x536e_6144;
/// The Rich block never starts inside the 64-byte DOS header.
const DOS_HEADER: usize = 0x40;
/// Cap on decoded @comp.id entries.
const MAX_ENTRIES: usize = 256;

/// One @comp.id record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompId {
    pub product: u16,
    pub build: u16,
    pub count: u32,
}

/// A decoded Rich header.
#[derive(Debug, Clone)]
pub struct Rich {
    /// Absolute offset of the masked "DanS" dword.
    pub dans_off: usize,
    /// Absolute offset just past the XOR key that follows "Rich".
    pub end_off: usize,
    /// The three padding dwords decode to zero and the table is whole.
    pub clean: bool,
    pub entries: Vec<CompId>,
}

/// Find and decode the Rich header in `header`, which must start at file
/// offset 0. The block must end before the PE header at `e_lfanew`.
pub fn find(header: &[u8], e_lfanew: u64) -> Option<Rich> {
    let limit = usize::try_from(e_lfanew).ok()?.min(header.len());
    let region = header.get(DOS_HEADER..limit)?;
    let rich = DOS_HEADER + rfind(region, b"Rich")?;
    let end_off = rich.checked_add(8)?;
    if end_off > limit {
        return None;
    }
    let key = u32_le(header, rich + 4)?;

    let mut pos = rich;
    let dans_off = loop {
        if pos < DOS_HEADER + 4 {
            return None;
        }
        pos -= 4;
        if u32_le(header, pos)? ^ key == DANS {
            break pos;
        }
    };

    let table = dans_off + 16;
    if table > rich {
        return None;
    }
    let padding_zero =
        (1..=3).all(|i| u32_le(header, dans_off + 4 * i).map(|v| v ^ key) == Some(0));
    let whole = (rich - table).is_multiple_of(8);

    let mut entries = Vec::new();
    let mut at = table;
    while at + 8 <= rich && entries.len() < MAX_ENTRIES {
        let comp = u32_le(header, at)? ^ key;
        let count = u32_le(header, at + 4)? ^ key;
        entries.push(CompId {
            product: (comp >> 16) as u16,
            build: (comp & 0xffff) as u16,
            count,
        });
        at += 8;
    }

    Some(Rich {
        dans_off,
        end_off,
        clean: padding_zero && whole,
        entries,
    })
}

/// A short name for the well-known product ids. The 0x00ff to 0x010e range is
/// the MSVC 14.x family shared by Visual Studio 2015 and every release since.
pub fn product_name(product: u16) -> Option<&'static str> {
    Some(match product {
        0x0000 => "Unknown",
        0x0001 => "Import0",
        0x00ff => "CVTRES",
        0x0100 => "Export",
        0x0101 => "Implib",
        0x0102 => "Linker",
        0x0103 => "MASM",
        0x0104 => "C",
        0x0105 => "C++",
        0x0106 => "CVTCIL C",
        0x0107 => "CVTCIL C++",
        0x0108 => "LTCG C",
        0x0109 => "LTCG C++",
        0x010a => "LTCG MSIL",
        0x010b => "PGO instrumented C",
        0x010c => "PGO instrumented C++",
        0x010d => "PGO optimized C",
        0x010e => "PGO optimized C++",
        _ => return None,
    })
}

/// The Visual Studio release a 14.x-family build number belongs to.
pub fn vs_release(product: u16, build: u16) -> Option<&'static str> {
    if !(0x00ff..=0x010e).contains(&product) {
        return None;
    }
    Some(match build {
        0..25000 => "VS2015",
        25000..27500 => "VS2017",
        27500..30700 => "VS2019",
        _ => "VS2022 or later",
    })
}

/// Render one entry for the evidence note.
pub fn describe(e: &CompId) -> String {
    let name = match (product_name(e.product), vs_release(e.product, e.build)) {
        (Some(n), Some(r)) => format!("{n} ({r})"),
        (Some(n), None) => n.to_string(),
        _ => format!("prodid 0x{:04x}", e.product),
    };
    format!("{name} build {} x{}", e.build, e.count)
}

/// The release that best names the toolchain: the linker's when present,
/// otherwise any 14.x-family entry.
pub fn headline_release(entries: &[CompId]) -> Option<&'static str> {
    entries
        .iter()
        .find(|e| e.product == 0x0102)
        .or_else(|| {
            entries
                .iter()
                .find(|e| vs_release(e.product, e.build).is_some())
        })
        .and_then(|e| vs_release(e.product, e.build))
}
