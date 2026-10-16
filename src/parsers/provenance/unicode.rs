//! Invisible Unicode in text: the character sets and the keep-or-strip
//! decision of the upstream cleaner's default pass.
//!
//! Three kinds of change are made, each its own [`Class`]:
//!
//! * [`Class::Invisible`]: zero-width characters, soft hyphens, variation
//!   selectors, tag characters, fillers, noncharacters, reserved ignorables,
//!   private use, and other format controls are removed.
//! * [`Class::Space`]: exotic spaces (no-break, en, em, thin, ideographic and
//!   the like) become U+0020.
//! * [`Class::Bidi`]: bidirectional overrides and unpaired embeddings are
//!   removed. Directional marks and isolates, and paired embeddings, are
//!   legitimate in mixed-direction prose and are kept.
//!
//! Characters that carry meaning in context are kept: emoji joiners and
//! variation selectors after an emoji base, joiners between letters of one
//! complex script, complete flag tag sequences, same-script fillers and
//! selectors, and format controls next to their own script. Latin look-alikes
//! and NFKC folding are the upstream cleaner's opt-in extras and are not done.
//!
//! General categories are not in the standard library, so letter-or-mark
//! tests for the joining scripts use `char::is_alphabetic` plus the handful
//! of marks (viramas, nuktas, coeng) that it leaves out.

use std::ops::RangeInclusive;

/// Which kind of change a character gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Invisible,
    Space,
    Bidi,
}

/// What the cleaner does to one character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Keep,
    Strip(Class),
    /// Replace with this character.
    Replace(char, Class),
}

/// One decoded character with its place in the source bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Unit {
    pub ch: char,
    pub start: usize,
    pub len: usize,
}

/// Decode `bytes` as UTF-8. Each invalid byte becomes one U+FFFD unit, which
/// is never touched, so a file that is not clean UTF-8 keeps its bytes.
pub(crate) fn decode(bytes: &[u8]) -> Vec<Unit> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    while at < bytes.len() {
        match std::str::from_utf8(&bytes[at..]) {
            Ok(s) => {
                push_chars(s, at, &mut out);
                break;
            }
            Err(e) => {
                let good = e.valid_up_to();
                if let Ok(s) = std::str::from_utf8(&bytes[at..at + good]) {
                    push_chars(s, at, &mut out);
                }
                at += good;
                let bad = e.error_len().unwrap_or(bytes.len() - at).max(1);
                for i in 0..bad {
                    out.push(Unit {
                        ch: '\u{FFFD}',
                        start: at + i,
                        len: 1,
                    });
                }
                at += bad;
            }
        }
    }
    out
}

fn push_chars(s: &str, base: usize, out: &mut Vec<Unit>) {
    for (i, ch) in s.char_indices() {
        out.push(Unit {
            ch,
            start: base + i,
            len: ch.len_utf8(),
        });
    }
}

/// Soft hyphen, fillers, zero-width characters, directional controls,
/// invisible operators, the BOM, variation selectors, and interlinear
/// annotation anchors.
const STRIP: &[u32] = &[
    0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180E, 0x180F,
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2060, 0x2061,
    0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069, 0x206A, 0x206B, 0x206C, 0x206D, 0x206E,
    0x206F, 0xFEFF, 0xFE00, 0xFE01, 0xFE02, 0xFE03, 0xFE04, 0xFE05, 0xFE06, 0xFE07, 0xFE08, 0xFE09,
    0xFE0A, 0xFE0B, 0xFE0C, 0xFE0D, 0xFE0E, 0xFE0F, 0x3164, 0xFFA0, 0xFFF9, 0xFFFA, 0xFFFB,
];

/// Spaces that stand in for U+0020.
const SPACES: &[u32] = &[
    0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009,
    0x200A, 0x202F, 0x205F, 0x3000,
];

const VS_SUPPLEMENT: RangeInclusive<u32> = 0xE0100..=0xE01EF;
const TAGS_ALL: RangeInclusive<u32> = 0xE0001..=0xE007F;
const TAG_RANGE: RangeInclusive<u32> = 0xE0020..=0xE007F;

/// Bidirectional controls the default pass keeps: marks and isolates.
const PRESERVED_BIDI: &[u32] = &[0x061C, 0x200E, 0x200F, 0x2066, 0x2067, 0x2068, 0x2069];
const BIDI: &[u32] = &[
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
];

const MONGOLIAN_FVS: &[u32] = &[0x180B, 0x180C, 0x180D, 0x180F];
const KHMER_VOWELS: &[u32] = &[0x17B4, 0x17B5];
const HANGUL_FILLERS: &[u32] = &[0x115F, 0x1160, 0x3164, 0xFFA0];
const ORTHOGRAPHIC_CF: &[u32] = &[
    0x0600, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x06DD, 0x070F, 0x08E2, 0x110BD, 0x110CD,
];

/// Visible-layout format controls and the script block each belongs to.
const LAYOUT_CF: &[(RangeInclusive<u32>, RangeInclusive<u32>)] = &[
    (0x13430..=0x1343F, 0x13000..=0x143FF),
    (0x1BCA0..=0x1BCA3, 0x1BC00..=0x1BCA3),
    (0x1D173..=0x1D17A, 0x1D100..=0x1D1FF),
];

fn is_noncharacter(cp: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE
}

fn is_reserved_ignorable(cp: u32) -> bool {
    cp == 0x2065
        || cp == 0xE0000
        || (0xFFF0..=0xFFF8).contains(&cp)
        || (0xE0080..=0xE00FF).contains(&cp)
        || (0xE01F0..=0xE0FFF).contains(&cp)
}

fn is_private_use(cp: u32) -> bool {
    (0xE000..=0xF8FF).contains(&cp)
        || (0xF0000..=0xFFFFD).contains(&cp)
        || (0x100000..=0x10FFFD).contains(&cp)
}

/// Format controls (general category Cf).
fn is_cf(cp: u32) -> bool {
    matches!(
        cp,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

fn is_strip_cp(cp: u32) -> bool {
    STRIP.contains(&cp)
        || VS_SUPPLEMENT.contains(&cp)
        || TAGS_ALL.contains(&cp)
        || is_noncharacter(cp)
        || is_reserved_ignorable(cp)
        || is_private_use(cp)
}

/// The class of a character the pass strips.
fn strip_class(cp: u32) -> Class {
    if TAGS_ALL.contains(&cp)
        || is_noncharacter(cp)
        || is_reserved_ignorable(cp)
        || VS_SUPPLEMENT.contains(&cp)
        || (0xFE00..=0xFE0F).contains(&cp)
        || MONGOLIAN_FVS.contains(&cp)
    {
        Class::Invisible
    } else if BIDI.contains(&cp) {
        Class::Bidi
    } else {
        Class::Invisible
    }
}

fn is_emoji_glue(cp: u32) -> bool {
    matches!(cp, 0x200D | 0xFE0E | 0xFE0F)
}

fn is_variation_selector(cp: u32) -> bool {
    VS_SUPPLEMENT.contains(&cp) || (0xFE00..=0xFE0F).contains(&cp) || MONGOLIAN_FVS.contains(&cp)
}

fn is_emoji_base(cp: u32) -> bool {
    (0x1F000..=0x1FAFF).contains(&cp)
        || (0x2190..=0x25FF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || (0x2B00..=0x2BFF).contains(&cp)
        || matches!(
            cp,
            0x203C
                | 0x2049
                | 0x2139
                | 0x2934
                | 0x2935
                | 0x00A9
                | 0x00AE
                | 0x2122
                | 0x3030
                | 0x303D
                | 0x3297
                | 0x3299
                | 0x0023
                | 0x002A
        )
        || (0x0030..=0x0039).contains(&cp)
}

fn is_cjk_ideograph(cp: u32) -> bool {
    (0x3400..=0x4DBF).contains(&cp)
        || (0x4E00..=0x9FFF).contains(&cp)
        || (0xF900..=0xFAFF).contains(&cp)
        || (0x20000..=0x323AF).contains(&cp)
}

fn is_hangul_jamo(cp: u32) -> bool {
    (0x1100..=0x11FF).contains(&cp)
        || (0xA960..=0xA97C).contains(&cp)
        || (0xD7B0..=0xD7C6).contains(&cp)
        || (0x3131..=0x318E).contains(&cp)
        || (0xFFA1..=0xFFDC).contains(&cp)
}

/// Marks that are not `Alphabetic` but join letters: viramas, nuktas, the
/// Khmer coeng and signs, Myanmar asat, and a few accents.
fn is_extra_mark(cp: u32) -> bool {
    matches!(
        cp,
        0x0658
            | 0x0951..=0x0954
            | 0x093C
            | 0x094D
            | 0x09BC
            | 0x09CD
            | 0x0A3C
            | 0x0A4D
            | 0x0ABC
            | 0x0ACD
            | 0x0B3C
            | 0x0B4D
            | 0x0BCD
            | 0x0C4D
            | 0x0CBC
            | 0x0CCD
            | 0x0D3B
            | 0x0D3C
            | 0x0D4D
            | 0x0DCA
            | 0x0F84
            | 0x1037
            | 0x1039
            | 0x103A
            | 0x17C9..=0x17D3
    )
}

fn is_letter_or_mark(ch: char) -> bool {
    ch.is_alphabetic() || is_extra_mark(ch as u32)
}

/// The script group in which ZWJ and ZWNJ are orthographic, for a letter or
/// mark of that script.
fn joining_script(ch: char) -> Option<u8> {
    let cp = ch as u32;
    let group = match cp {
        0x0600..=0x08FF => 1,
        0x0900..=0x0DFF => 2,
        0x0F00..=0x109F => 3,
        0x1780..=0x17FF => 4,
        0x1800..=0x18AF => 5,
        _ => return None,
    };
    is_letter_or_mark(ch).then_some(group)
}

fn is_mongolian_letter(ch: char) -> bool {
    let cp = ch as u32;
    (0x1800..=0x18AF).contains(&cp) && ch.is_alphabetic() && !matches!(cp, 0x1885 | 0x1886 | 0x18A9)
}

fn is_khmer_letter(ch: char) -> bool {
    let cp = ch as u32;
    ((0x1780..=0x17B3).contains(&cp) || cp == 0x17DC) && ch.is_alphabetic()
}

/// Load-bearing invisibles do not advance the "previous kept" character, so
/// joiner chains and flag runs stay bound to their base.
fn is_glue(cp: u32) -> bool {
    is_emoji_glue(cp)
        || is_variation_selector(cp)
        || matches!(cp, 0x200C | 0x200D)
        || TAG_RANGE.contains(&cp)
        || MONGOLIAN_FVS.contains(&cp)
        || KHMER_VOWELS.contains(&cp)
        || HANGUL_FILLERS.contains(&cp)
}

/// Indices inside complete subdivision-flag tag sequences.
fn valid_flag_tags(units: &[Unit]) -> Vec<bool> {
    let mut valid = vec![false; units.len()];
    let mut i = 0usize;
    while i < units.len() {
        if units[i].ch as u32 != 0x1F3F4 {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while units
            .get(j)
            .is_some_and(|u| (0xE0020..=0xE007E).contains(&(u.ch as u32)))
        {
            j += 1;
        }
        if j > i + 1 && units.get(j).is_some_and(|u| u.ch as u32 == 0xE007F) {
            valid[i + 1..=j].fill(true);
            i = j + 1;
        } else {
            i += 1;
        }
    }
    valid
}

/// Indices of paired LRE/RLE ... PDF controls, overrides excluded.
fn valid_bidi_embeddings(units: &[Unit]) -> Vec<bool> {
    let mut valid = vec![false; units.len()];
    let mut stack: Vec<(u32, usize)> = Vec::new();
    for (i, u) in units.iter().enumerate() {
        let cp = u.ch as u32;
        match cp {
            0x202A | 0x202B | 0x202D | 0x202E => stack.push((cp, i)),
            0x202C => {
                if let Some((opener, at)) = stack.pop()
                    && matches!(opener, 0x202A | 0x202B)
                {
                    valid[at] = true;
                    valid[i] = true;
                }
            }
            _ => {}
        }
    }
    valid
}

/// Decide every unit of `units`, in order, with the upstream pass's context
/// rules. The result has one action per unit.
pub(crate) fn analyze(units: &[Unit]) -> Vec<Action> {
    let flag_tags = valid_flag_tags(units);
    let embeddings = valid_bidi_embeddings(units);
    let mut prev_kept: Option<char> = None;
    let mut out = Vec::with_capacity(units.len());
    for (i, u) in units.iter().enumerate() {
        let prev_input = i.checked_sub(1).map(|p| units[p].ch);
        let next_input = units.get(i + 1).map(|n| n.ch);
        let action = decide(
            u.ch,
            prev_kept,
            prev_input,
            next_input,
            flag_tags[i],
            embeddings[i],
        );
        match action {
            Action::Keep => {
                if !is_glue(u.ch as u32) {
                    prev_kept = Some(u.ch);
                }
            }
            Action::Replace(c, _) => prev_kept = Some(c),
            Action::Strip(_) => {}
        }
        out.push(action);
    }
    out
}

fn decide(
    ch: char,
    prev_kept: Option<char>,
    prev_input: Option<char>,
    next_input: Option<char>,
    valid_flag_tag: bool,
    valid_embedding: bool,
) -> Action {
    let cp = ch as u32;
    if valid_embedding || PRESERVED_BIDI.contains(&cp) {
        return Action::Keep;
    }
    if let Some(prev) = prev_input {
        let p = prev as u32;
        if (VS_SUPPLEMENT.contains(&cp) || (0xFE00..=0xFE0D).contains(&cp)) && is_cjk_ideograph(p) {
            return Action::Keep;
        }
        if MONGOLIAN_FVS.contains(&cp) && (0x1800..=0x18AF).contains(&p) {
            return Action::Keep;
        }
    }
    if is_emoji_glue(cp) {
        if matches!(cp, 0xFE0E | 0xFE0F) && prev_input.is_some_and(|p| is_emoji_base(p as u32)) {
            return Action::Keep;
        }
        if cp == 0x200D
            && prev_kept
                .zip(next_input)
                .is_some_and(|(a, b)| is_emoji_base(a as u32) && is_emoji_base(b as u32))
        {
            return Action::Keep;
        }
    }
    if matches!(cp, 0x200C | 0x200D)
        && let (Some(p), Some(n)) = (prev_input, next_input)
        && let (Some(a), Some(b)) = (joining_script(p), joining_script(n))
        && a == b
    {
        return Action::Keep;
    }
    if TAG_RANGE.contains(&cp) && valid_flag_tag {
        return Action::Keep;
    }
    if MONGOLIAN_FVS.contains(&cp) && prev_kept.is_some_and(is_mongolian_letter) {
        return Action::Keep;
    }
    if KHMER_VOWELS.contains(&cp) && prev_kept.is_some_and(is_khmer_letter) {
        return Action::Keep;
    }
    if HANGUL_FILLERS.contains(&cp) && prev_kept.is_some_and(|c| is_hangul_jamo(c as u32)) {
        return Action::Keep;
    }
    if ORTHOGRAPHIC_CF.contains(&cp) {
        return Action::Keep;
    }
    if let Some((_, script)) = LAYOUT_CF
        .iter()
        .find(|(controls, _)| controls.contains(&cp))
        && (prev_input.is_some_and(|p| script.contains(&(p as u32)))
            || next_input.is_some_and(|n| script.contains(&(n as u32))))
    {
        return Action::Keep;
    }
    if is_strip_cp(cp) {
        return Action::Strip(strip_class(cp));
    }
    if SPACES.contains(&cp) {
        return Action::Replace(' ', Class::Space);
    }
    if is_cf(cp) {
        return Action::Strip(Class::Invisible);
    }
    Action::Keep
}

/// The text of `bytes` with every change of `class` applied and all other
/// characters left exactly as they were. `None` when nothing changes.
pub(crate) fn clean(bytes: &[u8], class: Class) -> Option<Vec<u8>> {
    let units = decode(bytes);
    let actions = analyze(&units);
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    for (u, a) in units.iter().zip(&actions) {
        match *a {
            Action::Strip(c) if c == class => changed = true,
            Action::Replace(r, c) if c == class => {
                changed = true;
                let mut buf = [0u8; 4];
                out.extend_from_slice(r.encode_utf8(&mut buf).as_bytes());
            }
            _ => out.extend_from_slice(&bytes[u.start..u.start + u.len]),
        }
    }
    changed.then_some(out)
}

/// One change the pass would make, for reporting.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Hit {
    pub ch: char,
    pub class: Class,
    /// Byte offset of the character.
    pub start: usize,
    pub len: usize,
}

/// Every change the pass would make to `bytes`, in order.
pub(crate) fn hits(bytes: &[u8]) -> Vec<Hit> {
    let units = decode(bytes);
    let actions = analyze(&units);
    units
        .iter()
        .zip(actions)
        .filter_map(|(u, a)| match a {
            Action::Keep => None,
            Action::Strip(class) | Action::Replace(_, class) => Some(Hit {
                ch: u.ch,
                class,
                start: u.start,
                len: u.len,
            }),
        })
        .collect()
}

/// A name for a code point in notes: `U+200B zero width space`.
pub(crate) fn describe(ch: char) -> String {
    let cp = ch as u32;
    let name = match cp {
        0x00AD => "soft hyphen",
        0x034F => "combining grapheme joiner",
        0x061C => "Arabic letter mark",
        0x115F | 0x1160 | 0x3164 | 0xFFA0 => "Hangul filler",
        0x17B4 | 0x17B5 => "Khmer inherent vowel",
        0x180B..=0x180D | 0x180F => "Mongolian free variation selector",
        0x180E => "Mongolian vowel separator",
        0x200B => "zero width space",
        0x200C => "zero width non-joiner",
        0x200D => "zero width joiner",
        0x200E => "left-to-right mark",
        0x200F => "right-to-left mark",
        0x202A => "left-to-right embedding",
        0x202B => "right-to-left embedding",
        0x202C => "pop directional formatting",
        0x202D => "left-to-right override",
        0x202E => "right-to-left override",
        0x2060 => "word joiner",
        0x2061..=0x2064 => "invisible operator",
        0x2066..=0x2069 => "directional isolate",
        0x206A..=0x206F => "deprecated format control",
        0xFEFF => "zero width no-break space",
        0xFE00..=0xFE0F | 0xE0100..=0xE01EF => "variation selector",
        0xFFF9..=0xFFFB => "interlinear annotation",
        0xE0001..=0xE007F => "tag character",
        0x00A0 => "no-break space",
        0x1680 => "Ogham space mark",
        0x2000..=0x200A => "typographic space",
        0x202F => "narrow no-break space",
        0x205F => "medium mathematical space",
        0x3000 => "ideographic space",
        _ if is_private_use(cp) => "private use",
        _ if is_noncharacter(cp) => "noncharacter",
        _ if is_reserved_ignorable(cp) => "reserved ignorable",
        _ => "format control",
    };
    format!("U+{cp:04X} {name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actions(s: &str) -> Vec<Action> {
        analyze(&decode(s.as_bytes()))
    }

    fn cleaned(s: &str) -> String {
        let mut bytes = s.as_bytes().to_vec();
        for class in [Class::Invisible, Class::Space, Class::Bidi] {
            if let Some(next) = clean(&bytes, class) {
                bytes = next;
            }
        }
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn zero_width_tags_and_spaces() {
        assert_eq!(cleaned("a\u{200B}b\u{FEFF}c\u{00AD}d"), "abcd");
        assert_eq!(cleaned("x\u{E0041}\u{E0042}y"), "xy");
        assert_eq!(cleaned("a\u{00A0}b\u{2003}c\u{3000}d"), "a b c d");
        assert_eq!(cleaned("a\u{E000}b\u{FDD0}c\u{2065}d"), "abcd");
        assert_eq!(cleaned("a\u{0890}b"), "ab");
        assert_eq!(
            cleaned("plain ascii, 100% clean"),
            "plain ascii, 100% clean"
        );
    }

    #[test]
    fn classes_are_reported_apart() {
        let a = actions("a\u{200B}\u{00A0}\u{202E}b");
        assert_eq!(a[1], Action::Strip(Class::Invisible));
        assert_eq!(a[2], Action::Replace(' ', Class::Space));
        assert_eq!(a[3], Action::Strip(Class::Bidi));
        assert_eq!(a[0], Action::Keep);
    }

    #[test]
    fn bidi_marks_isolates_and_pairs_are_kept() {
        let kept = "a\u{200F}b\u{200E}c\u{2067}d\u{2069}e\u{202B}f\u{202C}g";
        assert_eq!(cleaned(kept), kept);
        assert_eq!(cleaned("a\u{202D}b\u{202C}c"), "abc");
        assert_eq!(cleaned("a\u{202A}b"), "ab");
        assert_eq!(cleaned("a\u{202C}b"), "ab");
    }

    #[test]
    fn emoji_sequences_survive() {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        assert_eq!(cleaned(family), family);
        let heart = "\u{2764}\u{FE0F}\u{200D}\u{1F525}";
        assert_eq!(cleaned(heart), heart);
        assert_eq!(cleaned("\u{2696}\u{FE0F}"), "\u{2696}\u{FE0F}");
        assert_eq!(cleaned("word\u{FE0F}"), "word");
        assert_eq!(cleaned("a\u{200D}b"), "ab");
    }

    #[test]
    fn flags_scripts_and_cjk_selectors() {
        let scotland = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        assert_eq!(cleaned(scotland), scotland);
        assert_eq!(cleaned("\u{1F3F4}\u{E0067}\u{E0062}"), "\u{1F3F4}");
        let persian = "\u{0645}\u{06CC}\u{200C}\u{0631}\u{0648}\u{0645}";
        assert_eq!(cleaned(persian), persian);
        let devanagari = "\u{0915}\u{094D}\u{200D}\u{0937}";
        assert_eq!(cleaned(devanagari), devanagari);
        let cjk = "\u{8FBB}\u{E0100}";
        assert_eq!(cleaned(cjk), cjk);
        let hangul = "\u{1100}\u{1160}";
        assert_eq!(cleaned(hangul), hangul);
        assert_eq!(cleaned("a\u{1160}"), "a");
        let mongolian = "\u{1820}\u{180B}";
        assert_eq!(cleaned(mongolian), mongolian);
        let hieroglyph = "\u{13000}\u{13430}\u{13001}";
        assert_eq!(cleaned(hieroglyph), hieroglyph);
        assert_eq!(cleaned("a\u{13430}b"), "ab");
        let arabic_sign = "\u{0600}12";
        assert_eq!(cleaned(arabic_sign), arabic_sign);
    }

    #[test]
    fn invalid_utf8_keeps_its_bytes() {
        let mut bytes = b"ok \xFF\xFE ".to_vec();
        bytes.extend_from_slice("\u{200B}z".as_bytes());
        let out = clean(&bytes, Class::Invisible).unwrap();
        assert_eq!(out, b"ok \xFF\xFE z");
        assert!(clean(b"\xC3(", Class::Invisible).is_none());
        assert_eq!(decode(b"a\xE2\x82").len(), 3);
    }

    #[test]
    fn clean_is_idempotent_and_exact() {
        let s = "a\u{200B}b\u{00A0}c\u{202E}d";
        let once = cleaned(s);
        assert_eq!(once, "ab cd");
        assert!(hits(once.as_bytes()).is_empty());
        let hs = hits(s.as_bytes());
        assert_eq!(hs.len(), 3);
        assert_eq!(hs[0].start, 1);
        assert_eq!(hs[0].len, 3);
        assert_eq!(describe(hs[0].ch), "U+200B zero width space");
        assert!(clean(b"nothing here", Class::Space).is_none());
    }
}
