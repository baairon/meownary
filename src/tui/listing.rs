//! One folder's contents, read from its directory listing alone, for the
//! views that browse folders.
//!
//! Nothing here opens an entry. On Windows the metadata comes with the
//! listing itself (`WIN32_FIND_DATAW`), which matters for cloud placeholders:
//! opening one makes its provider download it. Items are sorted by name with
//! [`natural_cmp`], with folders mixed in; each caller groups them its own
//! way.
//!
//! Links are marked the way the scan's walk sees them, so a caller can show
//! which entries a scan never enters.

#![cfg(feature = "tui")]

use std::cmp::Ordering;
use std::fs::DirEntry;
use std::io;
use std::iter::Peekable;
use std::path::{Path, PathBuf};

/// The usual cap on entries read from one folder.
pub const MAX_READ: usize = 10_000;

/// One folder's contents, read once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The folder that was read.
    pub location: PathBuf,
    /// Sorted by name with [`natural_cmp`], folders and files mixed.
    pub items: Vec<Item>,
    /// Why the folder could not be read, in plain words. There are no items
    /// then.
    pub error: Option<String>,
    /// The folder held more entries than the cap, so some are left out.
    pub truncated: bool,
}

impl Listing {
    /// Read `location`, keeping at most `cap` entries. An entry that cannot
    /// be read is skipped but still counts toward the cap, which also bounds
    /// a listing that keeps failing. A folder that cannot be opened gives no
    /// items and an [`error`](Self::error).
    pub fn read(location: &Path, cap: usize) -> Self {
        let mut items = Vec::new();
        let mut error = None;
        let mut truncated = false;
        match std::fs::read_dir(location) {
            Err(e) => error = Some(list_error(location, &e)),
            Ok(read) => {
                for (n, entry) in read.enumerate() {
                    if n == cap {
                        truncated = true;
                        break;
                    }
                    if let Ok(entry) = entry {
                        items.push(Item::from_entry(&entry));
                    }
                }
            }
        }
        // Lossy text can make two names look alike; their paths still
        // differ, so every read sorts the same way.
        items.sort_by(|a, b| natural_cmp(&a.name, &b.name).then_with(|| a.path.cmp(&b.path)));
        Self {
            location: location.to_path_buf(),
            items,
            error,
            truncated,
        }
    }
}

fn list_error(location: &Path, e: &io::Error) -> String {
    let at = location.display();
    match e.kind() {
        io::ErrorKind::NotFound => format!("No such folder: {at}"),
        io::ErrorKind::NotADirectory => format!("Not a folder: {at}"),
        io::ErrorKind::PermissionDenied => format!("Cannot open {at}: access denied."),
        _ => format!("Cannot open {at}: {e}"),
    }
}

/// One directory entry, described from the listing's own metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub name: String,
    pub path: PathBuf,
    /// A folder, or a link to one.
    pub dir: bool,
    /// A cloud placeholder whose content is not on disk, so it cannot be
    /// scanned. Only Windows marks these, and never on a folder.
    pub cloud: bool,
    /// A symbolic link, or on Windows a junction or another reparse point
    /// that names a different path. A scan skips these and never follows
    /// them. A synced cloud folder is not a link.
    pub link: bool,
    /// A dot-name, or on Windows an entry marked hidden or system.
    pub hidden: bool,
    /// Size in bytes, for files only.
    pub size: Option<u64>,
}

impl Item {
    /// On Windows the metadata comes from the directory listing itself
    /// (`WIN32_FIND_DATAW`), so this never opens the file. That matters for
    /// cloud placeholders, which download when opened.
    fn from_entry(entry: &DirEntry) -> Self {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let meta = entry.metadata().ok();
        let ty = entry.file_type().ok();
        // The scan's walk asks the same, so a link here is exactly what it
        // skips.
        let link = ty.is_some_and(|t| t.is_symlink());
        #[cfg(windows)]
        let (dir, cloud, marked) = {
            use std::os::windows::fs::MetadataExt;
            // Directory links and junctions carry the directory attribute too.
            let attrs = meta.as_ref().map_or(0, |m| m.file_attributes());
            let dir = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
            let marked = attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0;
            (dir, !dir && cloud_only(attrs), marked)
        };
        #[cfg(not(windows))]
        let (dir, cloud, marked) = {
            let dir = ty.is_some_and(|t| t.is_dir()) || (link && path.is_dir());
            (dir, false, false)
        };
        Self {
            hidden: marked || name.starts_with('.'),
            size: if dir { None } else { meta.map(|m| m.len()) },
            name,
            path,
            dir,
            cloud,
            link,
        }
    }
}

/// Compare two names the way a person reads them: ignoring case, with each
/// run of digits compared by its value, so `f2` sorts before `f10`. Names
/// that are equal that way, such as `File` and `file` or `x01` and `x1`, fall
/// back to their exact bytes, so the order is total and the same on every
/// run.
///
/// Digit runs are never parsed, so leading zeros and runs of any length are
/// fine. Only ASCII digits count as digits; every other character compares
/// by its lowercase form, so names without digits keep plain
/// case-insensitive order.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let mut x = a.chars().flat_map(char::to_lowercase).peekable();
    let mut y = b.chars().flat_map(char::to_lowercase).peekable();
    loop {
        let ord = match (x.peek().copied(), y.peek().copied()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                cmp_numbers(&mut x, &mut y)
            }
            (Some(c), Some(d)) => {
                x.next();
                y.next();
                c.cmp(&d)
            }
        };
        if ord.is_ne() {
            return ord;
        }
    }
}

/// Compare the digit runs `x` and `y` start with by value, consuming both.
fn cmp_numbers(
    x: &mut Peekable<impl Iterator<Item = char>>,
    y: &mut Peekable<impl Iterator<Item = char>>,
) -> Ordering {
    while x.next_if_eq(&'0').is_some() {}
    while y.next_if_eq(&'0').is_some() {}
    // Without leading zeros the longer run is the bigger number; between
    // runs of one length the first digit that differs decides.
    let mut first = Ordering::Equal;
    loop {
        match (
            x.next_if(char::is_ascii_digit),
            y.next_if(char::is_ascii_digit),
        ) {
            (None, None) => return first,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(p), Some(q)) => first = first.then(p.cmp(&q)),
        }
    }
}

/// Windows file attributes for a folder, and for an entry the user is not
/// meant to see.
#[cfg(windows)]
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
#[cfg(windows)]
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
#[cfg(windows)]
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;

/// Windows file attributes that mark a cloud placeholder (OneDrive and other
/// providers) whose content is not on disk. Matches the scan walk.
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

/// Whether these Windows file attributes mark a cloud-only placeholder.
#[cfg_attr(not(windows), allow(dead_code))]
fn cloud_only(attrs: u32) -> bool {
    attrs
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0
}

/// Whether a path outside a listing (a recent pick or a typed path) is a
/// cloud-only file. This asks for attributes only and reads no data.
#[cfg(windows)]
pub fn path_cloud_only(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_dir() && cloud_only(m.file_attributes()))
}

#[cfg(not(windows))]
pub fn path_cloud_only(_: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering::{Equal, Greater, Less};
    use std::fs;

    use super::*;

    fn check(cases: &[(&str, &str, Ordering)]) {
        for &(a, b, want) in cases {
            assert_eq!(natural_cmp(a, b), want, "{a:?} against {b:?}");
        }
    }

    fn names(listing: &Listing) -> Vec<&str> {
        listing.items.iter().map(|i| i.name.as_str()).collect()
    }

    fn item<'a>(listing: &'a Listing, name: &str) -> &'a Item {
        listing
            .items
            .iter()
            .find(|i| i.name == name)
            .unwrap_or_else(|| panic!("{name} is not listed"))
    }

    #[test]
    fn numbers_compare_by_value() {
        check(&[
            ("a2", "a10", Less),
            ("a10", "a2", Greater),
            ("a10", "a10", Equal),
            ("2", "10", Less),
            ("f9z", "f10a", Less),
            ("v1.10", "v1.9", Greater),
            ("a1b2", "a1b10", Less),
        ]);
    }

    #[test]
    fn ties_fall_back_to_exact_bytes() {
        check(&[
            ("File", "file", Less),
            ("file", "File", Greater),
            ("README", "Readme", Less),
            ("x01", "x1", Less),
            ("x1", "x01", Greater),
            ("x001", "x01", Less),
            ("x0", "x00", Less),
            // Case is ignored before the bytes are looked at.
            ("a", "B", Less),
            ("B", "a", Greater),
            ("x01", "X2", Less),
        ]);
    }

    #[test]
    fn digits_sort_before_letters() {
        check(&[
            ("a1", "ab", Less),
            ("a9", "aB", Less),
            ("ab", "a1", Greater),
            ("1", "a", Less),
            ("Z", "0", Greater),
            // Other characters keep their plain order around digits.
            ("a-1", "a1", Less),
            ("a_1", "a1", Greater),
        ]);
    }

    #[test]
    fn long_digit_runs_never_overflow() {
        let nines = format!("n{}", "9".repeat(400));
        let power = format!("n1{}", "0".repeat(400));
        assert_eq!(natural_cmp(&nines, &power), Less);
        assert_eq!(natural_cmp(&power, &nines), Greater);
        let padded = format!("{}7", "0".repeat(300));
        assert_eq!(natural_cmp(&padded, "7"), Less, "same value, bytes decide");
        assert_eq!(natural_cmp("8", &padded), Greater);
        let (one, two) = (
            format!("1{}1", "0".repeat(100)),
            format!("1{}2", "0".repeat(100)),
        );
        assert_eq!(natural_cmp(&one, &two), Less);
        check(&[("18446744073709551616", "18446744073709551615", Greater)]);
    }

    #[test]
    fn empty_and_non_ascii_names() {
        check(&[
            ("", "", Equal),
            ("", "a", Less),
            ("a", "", Greater),
            ("", "0", Less),
            ("\u{c4}rger", "\u{e4}rger", Less),
            ("\u{e4}rger", "Zebra", Greater),
            ("\u{d6}dland", "\u{f6}l", Less),
            ("\u{f6}2", "\u{f6}10", Less),
            ("\u{65e5}\u{672c}2", "\u{65e5}\u{672c}10", Less),
            // A fullwidth digit is a character, not part of a number.
            ("x\u{ff13}", "x10", Greater),
            // Lowercase `\u{130}` is two characters: `i` and a combining dot.
            ("\u{130}x", "ix", Greater),
        ]);
    }

    /// Sorting needs a total order: antisymmetric, transitive, and equal
    /// only for equal names. Names without digits keep the order the picker
    /// had before numbers counted.
    #[test]
    fn the_order_is_total() {
        let samples = [
            "",
            "0",
            "00",
            "007",
            "7",
            "a",
            "A",
            "a0",
            "a00",
            "a01",
            "a1",
            "a1b",
            "a01b",
            "a2",
            "a10",
            "a-1",
            "a_1",
            "a!",
            "a~",
            "ab",
            "aB",
            "Ab",
            "b",
            "\u{e9}",
            "\u{c9}",
            "z",
            "x\u{ff13}",
            "\u{130}",
            "i\u{307}",
            "1a",
            "01a",
        ];
        let digits = |s: &str| s.contains(|c: char| c.is_ascii_digit());
        for a in samples {
            for b in samples {
                let ab = natural_cmp(a, b);
                assert_eq!(ab, natural_cmp(b, a).reverse(), "{a:?} {b:?}");
                assert_eq!(ab == Equal, a == b, "{a:?} {b:?}");
                if !digits(a) && !digits(b) {
                    let plain = a.to_lowercase().cmp(&b.to_lowercase()).then(a.cmp(b));
                    assert_eq!(ab, plain, "{a:?} {b:?}");
                }
                for c in samples {
                    if ab.is_le() && natural_cmp(b, c).is_le() {
                        assert!(natural_cmp(a, c).is_le(), "{a:?} {b:?} {c:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_sorted_list_reads_like_a_person_would() {
        let mut sorted = vec![
            "img12.png",
            "IMG2.png",
            "img2.png",
            "img1.png",
            "img02.png",
            "img10.png",
            "Img1.png",
        ];
        sorted.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            sorted,
            [
                "Img1.png",
                "img1.png",
                "IMG2.png",
                "img02.png",
                "img2.png",
                "img10.png",
                "img12.png",
            ]
        );
    }

    /// tmp/
    ///   a.txt (3 bytes)
    ///   B2/
    ///   b10/ (inner.txt)
    ///   c1.bin (empty)
    #[test]
    fn read_lists_a_folder_in_natural_order() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join("b10")).unwrap();
        fs::write(root.join("b10").join("inner.txt"), b"x").unwrap();
        fs::create_dir(root.join("B2")).unwrap();
        fs::write(root.join("a.txt"), b"abc").unwrap();
        fs::write(root.join("c1.bin"), b"").unwrap();

        let listing = Listing::read(root, MAX_READ);
        assert_eq!(listing.location, root);
        assert_eq!(listing.error, None);
        assert!(!listing.truncated);
        assert_eq!(names(&listing), ["a.txt", "B2", "b10", "c1.bin"]);
        let shape: Vec<(bool, Option<u64>)> =
            listing.items.iter().map(|i| (i.dir, i.size)).collect();
        assert_eq!(
            shape,
            [
                (false, Some(3)),
                (true, None),
                (true, None),
                (false, Some(0))
            ]
        );
        for item in &listing.items {
            assert_eq!(item.path, root.join(&item.name));
            assert!(!item.cloud && !item.link && !item.hidden, "{item:?}");
        }
    }

    #[test]
    fn read_stops_at_the_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let empty = Listing::read(tmp.path(), 0);
        assert!(
            empty.items.is_empty() && !empty.truncated,
            "nothing was left out"
        );
        for i in 0..5 {
            fs::write(tmp.path().join(format!("f{i}")), b"").unwrap();
        }

        let capped = Listing::read(tmp.path(), 3);
        assert_eq!(capped.items.len(), 3);
        assert!(capped.truncated);
        assert_eq!(capped.error, None);
        let sorted = capped
            .items
            .windows(2)
            .all(|w| natural_cmp(&w[0].name, &w[1].name).is_lt());
        assert!(sorted, "{:?}", names(&capped));

        let exact = Listing::read(tmp.path(), 5);
        assert_eq!(names(&exact), ["f0", "f1", "f2", "f3", "f4"]);
        assert!(!exact.truncated);
        let none = Listing::read(tmp.path(), 0);
        assert!(none.items.is_empty() && none.truncated);
    }

    #[test]
    fn a_folder_that_cannot_be_read_gives_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing");
        let listing = Listing::read(&missing, MAX_READ);
        assert_eq!(listing.location, missing);
        assert!(listing.items.is_empty() && !listing.truncated);
        assert_eq!(
            listing.error,
            Some(format!("No such folder: {}", missing.display()))
        );

        let file = tmp.path().join("notes.txt");
        fs::write(&file, b"x").unwrap();
        let listing = Listing::read(&file, MAX_READ);
        assert!(listing.items.is_empty());
        assert!(listing.error.is_some());
    }

    #[test]
    fn error_texts_are_plain() {
        let at = Path::new("here");
        let text = |e: io::Error| list_error(at, &e);
        assert_eq!(text(io::ErrorKind::NotFound.into()), "No such folder: here");
        assert_eq!(
            text(io::ErrorKind::NotADirectory.into()),
            "Not a folder: here"
        );
        assert_eq!(
            text(io::ErrorKind::PermissionDenied.into()),
            "Cannot open here: access denied."
        );
        assert_eq!(text(io::Error::other("busy")), "Cannot open here: busy");
    }

    #[test]
    fn dot_names_are_hidden() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".config")).unwrap();
        fs::write(tmp.path().join(".env"), b"x").unwrap();
        fs::write(tmp.path().join("dot.in.middle"), b"x").unwrap();
        fs::write(tmp.path().join("shown.txt"), b"x").unwrap();
        let listing = Listing::read(tmp.path(), MAX_READ);
        let hidden: Vec<(&str, bool)> = listing
            .items
            .iter()
            .map(|i| (i.name.as_str(), i.hidden))
            .collect();
        assert_eq!(
            hidden,
            [
                (".config", true),
                (".env", true),
                ("dot.in.middle", false),
                ("shown.txt", false),
            ]
        );
        assert!(item(&listing, ".config").dir);
    }

    #[cfg(windows)]
    #[test]
    fn hidden_and_system_attributes_are_hidden() {
        use std::os::windows::fs::OpenOptionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let files = [
            ("marked.txt", FILE_ATTRIBUTE_HIDDEN),
            ("system.txt", FILE_ATTRIBUTE_SYSTEM),
            ("plain.txt", 0),
        ];
        for (name, attrs) in files {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .attributes(attrs)
                .open(tmp.path().join(name))
                .unwrap();
        }
        let listing = Listing::read(tmp.path(), MAX_READ);
        assert!(item(&listing, "marked.txt").hidden);
        assert!(item(&listing, "system.txt").hidden);
        assert!(!item(&listing, "plain.txt").hidden);
    }

    /// Links are marked the way the scan's walk sees them: never entered.
    #[test]
    fn folder_links_are_marked() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("inside.txt"), b"x").unwrap();
        let made = symlink_dir(&target, &tmp.path().join("linked"));
        if cfg!(windows) && made.is_err() {
            // Windows lets only an elevated user, or one in Developer Mode,
            // create a symbolic link, so there is nothing to check here.
            return;
        }
        made.expect("a symbolic link");
        let listing = Listing::read(tmp.path(), MAX_READ);
        let linked = item(&listing, "linked");
        assert!(linked.link && linked.dir, "{linked:?}");
        assert_eq!(linked.size, None);
        let target = item(&listing, "target");
        assert!(!target.link && target.dir, "{target:?}");
    }

    #[cfg(unix)]
    fn symlink_dir(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn symlink_dir(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    #[test]
    fn file_and_broken_links_are_links_but_not_folders() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("real.txt"), b"x").unwrap();
        symlink(tmp.path().join("real.txt"), tmp.path().join("to-file")).unwrap();
        symlink(tmp.path().join("gone"), tmp.path().join("broken")).unwrap();
        let listing = Listing::read(tmp.path(), MAX_READ);
        for name in ["to-file", "broken"] {
            let link = item(&listing, name);
            assert!(link.link && !link.dir, "{link:?}");
        }
        assert!(!item(&listing, "real.txt").link);
    }

    /// A junction needs no privilege, so this runs wherever `cmd` does.
    #[cfg(windows)]
    #[test]
    fn junctions_are_links() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir(&target).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(tmp.path().join("junction"))
            .arg(&target)
            .output()
            .is_ok_and(|out| out.status.success());
        if !made {
            return; // no cmd here, or a file system without junctions
        }
        let listing = Listing::read(tmp.path(), MAX_READ);
        let junction = item(&listing, "junction");
        assert!(junction.link && junction.dir, "{junction:?}");
        assert!(!junction.hidden && !junction.cloud);
        assert!(!item(&listing, "target").link);
    }

    #[test]
    fn cloud_only_attributes() {
        assert!(cloud_only(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS));
        assert!(cloud_only(FILE_ATTRIBUTE_RECALL_ON_OPEN));
        assert!(cloud_only(FILE_ATTRIBUTE_OFFLINE));
        assert!(cloud_only(0x0040_0000 | 0x0000_0400 | 0x0000_0020));
        assert!(!cloud_only(0));
        // Archive, pinned, unpinned: present on disk.
        for attrs in [0x20, 0x0008_0000, 0x0010_0000] {
            assert!(!cloud_only(attrs), "{attrs:#x}");
        }

        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("here.txt");
        fs::write(&file, b"x").unwrap();
        assert!(!path_cloud_only(&file));
        assert!(!path_cloud_only(tmp.path()));
        assert!(!path_cloud_only(&tmp.path().join("missing")));
        assert!(!item(&Listing::read(tmp.path(), MAX_READ), "here.txt").cloud);
    }
}
