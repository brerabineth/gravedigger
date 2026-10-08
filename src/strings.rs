use anyhow::{anyhow, Result};
use clap::Args;
use std::io::Write;
use std::path::PathBuf;

use crate::walk;
use crate::Ctx;

#[derive(Args, Debug)]
pub struct StringsArgs {
    /// file or directory to scan
    pub path: String,

    /// minimum string length
    #[arg(long, default_value_t = 4)]
    pub min_len: usize,

    /// also scan for utf-16le strings (ransom notes love this encoding)
    #[arg(long)]
    pub utf16: bool,

    /// emit json instead of grep-style lines
    #[arg(long)]
    pub json: bool,

    /// skip files larger than this many bytes
    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    pub max_size: u64,
}

#[derive(serde::Serialize)]
struct StringHit {
    file: String,
    offset: usize,
    kind: String,
    value: String,
}

/// printable ascii run extraction (space..tilde plus tab), classic strings(1) rules
pub fn extract_ascii(data: &[u8], min: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut buf = Vec::new();
    for (i, b) in data.iter().enumerate() {
        if is_printable(*b) {
            if buf.is_empty() {
                start = i;
            }
            buf.push(*b);
        } else if !buf.is_empty() {
            if buf.len() >= min {
                out.push((start, String::from_utf8_lossy(&buf).into_owned()));
            }
            buf.clear();
        }
    }
    if buf.len() >= min {
        out.push((start, String::from_utf8_lossy(&buf).into_owned()));
    }
    out
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

/// utf-16le run extraction, mirroring `strings -el`: each code unit stored
/// little-endian, second byte zero, printable first byte.
pub fn extract_utf16le(data: &[u8], min: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut buf: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let (lo, hi) = (data[i], data[i + 1]);
        if hi == 0 && is_printable(lo) {
            if buf.is_empty() {
                start = i;
            }
            buf.push(lo);
            i += 2;
        } else {
            flush_utf16(&mut buf, start, min, &mut out);
            i += if buf.is_empty() { 1 } else { 2 };
        }
    }
    flush_utf16(&mut buf, start, min, &mut out);
    out
}

fn flush_utf16(buf: &mut Vec<u8>, start: usize, min: usize, out: &mut Vec<(usize, String)>) {
    if buf.len() >= min {
        out.push((start, String::from_utf8_lossy(buf).into_owned()));
    }
    buf.clear();
}

pub fn run(a: &StringsArgs, ctx: &Ctx) -> Result<i32> {
    let root = PathBuf::from(&a.path);
    if !root.exists() {
        return Err(anyhow!("no such path: {}", a.path));
    }

    let mut targets: Vec<walk::Entry> = Vec::new();
    if root.is_file() {
        targets.push(single_entry(&root)?);
    } else {
        let (entries, _) = walk::walk(&root);
        targets.extend(
            entries
                .into_iter()
                .filter(|e| e.is_regular_file() && e.size <= a.max_size),
        );
    }
    targets.sort_by(|x, y| x.path.cmp(&y.path));

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if a.json {
        let mut all: Vec<StringHit> = Vec::new();
        for e in &targets {
            let data = match std::fs::read(&e.path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            for (off, val) in extract_ascii(&data, a.min_len) {
                all.push(hit(&e.path, off, "ascii", &val));
            }
            if a.utf16 {
                for (off, val) in extract_utf16le(&data, a.min_len) {
                    all.push(hit(&e.path, off, "utf16le", &val));
                }
            }
        }
        serde_json::to_writer(&mut out, &all)?;
        writeln!(out)?;
        if !ctx.quiet {
            eprintln!(
                "gravedigger: {} strings across {} files",
                all.len(),
                targets.len()
            );
        }
        return Ok(0);
    }

    let mut count = 0usize;
    for e in &targets {
        let data = match std::fs::read(&e.path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let file = e.path.to_string_lossy();
        for (off, val) in extract_ascii(&data, a.min_len) {
            writeln!(out, "{file}:{off}:{val}")?;
            count += 1;
        }
        if a.utf16 {
            for (off, val) in extract_utf16le(&data, a.min_len) {
                writeln!(out, "{file}:{off}:{val}")?;
                count += 1;
            }
        }
    }
    if !ctx.quiet {
        eprintln!(
            "gravedigger: {count} strings across {} files",
            targets.len()
        );
    }
    Ok(0)
}

fn hit(path: &std::path::Path, offset: usize, kind: &str, value: &str) -> StringHit {
    StringHit {
        file: path.to_string_lossy().into_owned(),
        offset,
        kind: kind.to_string(),
        value: value.to_string(),
    }
}

fn single_entry(path: &std::path::Path) -> Result<walk::Entry> {
    let md = std::fs::metadata(path)?;
    let (atime, mtime, ctime, crtime, mode, uid, gid, inode) = stat_of(&md);
    let ft = md.file_type();
    Ok(walk::Entry {
        path: path.to_path_buf(),
        size: md.len(),
        atime,
        mtime,
        ctime,
        crtime,
        mode,
        uid,
        gid,
        inode,
        is_dir: ft.is_dir(),
        is_symlink: ft.is_symlink(),
    })
}

#[cfg(unix)]
fn stat_of(md: &std::fs::Metadata) -> (i64, i64, i64, i64, u32, u32, u32, u64) {
    use std::os::unix::fs::MetadataExt;
    (
        md.atime(),
        md.mtime(),
        md.ctime(),
        0,
        md.mode(),
        md.uid(),
        md.gid(),
        md.ino(),
    )
}

#[cfg(not(unix))]
fn stat_of(md: &std::fs::Metadata) -> (i64, i64, i64, i64, u32, u32, u32, u64) {
    (0, 0, 0, 0, 0, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_basic() {
        let data = b"\x01xx--HELLO-DFIR--\x02yy";
        let hits = extract_ascii(data, 4);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "xx--HELLO-DFIR--");
        assert_eq!(hits[0].0, 1);
    }

    #[test]
    fn ascii_min_len_filters() {
        let hits = extract_ascii(b"ab\x00cdef\x00gh", 3);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "cdef");
    }

    #[test]
    fn utf16le_finds_note() {
        let mut data = vec![0xff, 0xfe]; // bom
        for b in "DECRYPT ALL FILES".bytes() {
            data.push(b);
            data.push(0);
        }
        let hits = extract_utf16le(&data, 4);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "DECRYPT ALL FILES");
    }

    #[test]
    fn utf16le_ignores_ascii_runs() {
        // plain ascii: every second byte is nonzero, so no utf16 run >= min
        let hits = extract_utf16le(b"just ascii text here", 4);
        assert!(hits.is_empty());
    }
}
