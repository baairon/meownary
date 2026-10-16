//! Provenance comments in Markdown and HTML: `<!-- ... -->` blocks that name an
//! AI tool (see [`super::comment_is_provenance`]).
//!
//! In HTML the whole document is searched. In Markdown only the prose outside
//! fenced code blocks is, so a code sample showing such a comment is left
//! alone; an unclosed fence runs to the end of the document, as CommonMark
//! renders it. A comment is paired with the first `-->` (or `--!>`) after its
//! opening, and blocks never overlap.

use std::ops::Range;

use super::comment_is_provenance;

/// Which comment rule a file gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    Markdown,
    Html,
}

/// Byte ranges of the provenance comments in `text`, in order.
pub(crate) fn provenance_comments(text: &[u8], flavor: Flavor) -> Vec<Range<usize>> {
    let spans = match flavor {
        Flavor::Markdown => prose_spans(text),
        Flavor::Html => std::iter::once(0..text.len()).collect(),
    };
    let mut out = Vec::new();
    for span in spans {
        let seg = &text[span.clone()];
        for block in comment_blocks(seg) {
            let body = String::from_utf8_lossy(&seg[block.clone()]);
            if comment_is_provenance(&body) {
                out.push(span.start + block.start..span.start + block.end);
            }
        }
    }
    out
}

/// Every `<!--` ... `-->` block of `seg`, paired the way the upstream scan
/// pairs them: the first close that starts at or after the open's end.
fn comment_blocks(seg: &[u8]) -> Vec<Range<usize>> {
    let opens = matches_of(seg, |s, i| {
        s.get(i..i + 4).filter(|w| *w == b"<!--").map(|_| 4)
    });
    let closes = matches_of(seg, |s, i| {
        if s.get(i..i + 2) != Some(b"--") {
            return None;
        }
        match s.get(i + 2) {
            Some(b'>') => Some(3),
            Some(b'!') if s.get(i + 3) == Some(&b'>') => Some(4),
            _ => None,
        }
    });
    let mut blocks = Vec::new();
    let mut last_end = 0usize;
    let mut ci = 0usize;
    for (os, oe) in opens {
        if os < last_end {
            continue;
        }
        while closes.get(ci).is_some_and(|c| c.0 < oe) {
            ci += 1;
        }
        let Some(&(_, ce)) = closes.get(ci) else {
            break;
        };
        blocks.push(os..ce);
        last_end = ce;
    }
    blocks
}

/// Non-overlapping matches of `m` over `s`, as `(start, end)`.
fn matches_of(s: &[u8], m: impl Fn(&[u8], usize) -> Option<usize>) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < s.len() {
        match m(s, i) {
            Some(len) => {
                out.push((i, i + len));
                i += len;
            }
            None => i += 1,
        }
    }
    out
}

/// A fence line: where it starts and ends (without the newline), the marker
/// character and run length, and whether the text after the run is empty
/// apart from blanks.
struct Fence {
    start: usize,
    end: usize,
    marker: u8,
    run: usize,
    has_backtick: bool,
    blank_suffix: bool,
}

fn fence_lines(text: &[u8]) -> Vec<Fence> {
    let mut out = Vec::new();
    let mut line_start = 0usize;
    while line_start <= text.len() {
        let line_end = text[line_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(text.len(), |p| line_start + p);
        let line = &text[line_start..line_end];
        let indent = line
            .iter()
            .take(3)
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        if let Some(&marker) = line.get(indent)
            && (marker == b'`' || marker == b'~')
        {
            let run = line[indent..].iter().take_while(|&&b| b == marker).count();
            if run >= 3 {
                let suffix = &line[indent + run..];
                out.push(Fence {
                    start: line_start,
                    end: line_end,
                    marker,
                    run,
                    has_backtick: suffix.contains(&b'`'),
                    blank_suffix: suffix.iter().all(|b| matches!(b, b' ' | b'\t' | b'\r')),
                });
            }
        }
        if line_end >= text.len() {
            break;
        }
        line_start = line_end + 1;
    }
    out
}

/// The ranges of Markdown outside fenced code blocks.
fn prose_spans(text: &[u8]) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut open: Option<(u8, usize)> = None;
    let mut start = 0usize;
    for f in fence_lines(text) {
        match open {
            None => {
                if f.marker == b'`' && f.has_backtick {
                    continue;
                }
                spans.push(start..f.start);
                open = Some((f.marker, f.run));
            }
            Some((marker, run)) => {
                if f.marker == marker && f.run >= run && f.blank_suffix {
                    open = None;
                    start = f.end;
                }
            }
        }
    }
    if open.is_none() {
        spans.push(start..text.len());
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str, flavor: Flavor) -> Vec<&str> {
        provenance_comments(text.as_bytes(), flavor)
            .into_iter()
            .map(|r| &text[r])
            .collect()
    }

    #[test]
    fn html_comments_by_tool_name() {
        let html = "<p>a</p><!-- made with Claude --><!-- TOC --><!-- GPT-4 -->";
        assert_eq!(
            found(html, Flavor::Html),
            ["<!-- made with Claude -->", "<!-- GPT-4 -->"]
        );
        assert!(found("<!-- generated by hugo -->", Flavor::Html).is_empty());
        assert_eq!(
            found("<!-- Gemini --!>", Flavor::Html),
            ["<!-- Gemini --!>"]
        );
        assert!(found("<!-- Claude, never closed", Flavor::Html).is_empty());
    }

    #[test]
    fn markdown_skips_fenced_code() {
        let md = "intro <!-- ChatGPT -->\n```html\n<!-- Claude -->\n```\nafter <!-- Claude -->\n";
        let got = found(md, Flavor::Markdown);
        assert_eq!(got, ["<!-- ChatGPT -->", "<!-- Claude -->"]);
        let at = provenance_comments(md.as_bytes(), Flavor::Markdown);
        assert_eq!(at[0].start, 6);
        assert!(at[1].start > md.find("```\nafter").unwrap());
        let open = "<!-- ChatGPT -->\n~~~\n<!-- Claude -->\n";
        assert_eq!(found(open, Flavor::Markdown), ["<!-- ChatGPT -->"]);
        let both = "```\n<!-- Claude -->\n";
        assert!(found(both, Flavor::Markdown).is_empty());
    }

    #[test]
    fn fence_rules() {
        let longer = "````\n```\n<!-- Claude -->\n````\n<!-- Claude -->\n";
        assert_eq!(found(longer, Flavor::Markdown).len(), 1);
        let info_with_tick = "``` a`b\n<!-- Claude -->\n";
        assert_eq!(found(info_with_tick, Flavor::Markdown).len(), 1);
        let crlf = "```\r\ncode\r\n```\r\n<!-- Claude -->\r\n";
        assert_eq!(found(crlf, Flavor::Markdown).len(), 1);
        let indented = "    ```\n<!-- Claude -->\n";
        assert_eq!(found(indented, Flavor::Markdown).len(), 1);
    }

    #[test]
    fn blocks_do_not_overlap() {
        let text = "<!-- a <!-- Claude --> b -->";
        assert_eq!(found(text, Flavor::Html), ["<!-- a <!-- Claude -->"]);
        assert!(provenance_comments(b"", Flavor::Html).is_empty());
        assert!(provenance_comments(b"", Flavor::Markdown).is_empty());
    }
}
