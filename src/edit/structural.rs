//! Structure-aware removal: given a container kind and a region, return a new
//! valid file with that region dropped. Each container's remover lives in the
//! parser module that understands it; this file only dispatches. The engine
//! snapshots the original and writes the result atomically.

use crate::model::{ContainerKind, Region};
use crate::parsers::{archive, doc, elf, image, macho, media, pe, text, zip};

/// Rewrite `data` with `region` removed in a way that keeps `container` valid.
/// `None` means no structural remover exists for this container yet (the engine
/// then reports the edit unsupported, changing nothing).
pub fn remove(container: ContainerKind, data: &[u8], region: Region) -> Option<Vec<u8>> {
    use ContainerKind::*;
    match container {
        ZipComment => zip::structural_remove(data, region),
        JpegApp1 | JpegSegment | PngChunk | RiffChunk => image::structural_remove(data, region),
        Id3v1 | Id3v2 | IsoBox | EbmlElement => media::structural_remove(data, region),
        PdfObject | CfbStream => doc::structural_remove(data, region),
        GzipHeader | TarHeader | RarBlock => archive::structural_remove(data, region),
        PeOverlay | PeResource => pe::structural_remove(data, region),
        ElfSection => elf::structural_remove(data, region),
        MachoLoadCmd => macho::structural_remove(data, region),
        Raw => text::structural_remove(data, region),
        Generic => None,
    }
}
