use crate::walk::Entry;

/// parse a user-supplied time bound. accepts a unix epoch or
/// YYYY-MM-DD / YYYY-MM-DD HH:MM[:SS]. returns epoch seconds (utc).
pub fn parse_when(s: &str) -> Option<i64> {
    if let Ok(v) = s.parse::<i64>() {
        return Some(v);
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(dt.and_utc().timestamp());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M") {
        return Some(dt.and_utc().timestamp());
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0)?.and_utc().timestamp());
    }
    None
}

/// "r/rrwxr-xr-x" — tsk type char, slash, nine permission bits
pub fn mode_string(e: &Entry) -> String {
    let mut s = String::with_capacity(11);
    s.push(crate::walk::type_char(e));
    s.push('/');
    let bits = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (bit, ch) in bits {
        s.push(if e.mode & bit != 0 { ch } else { '-' });
    }
    s
}

/// one line in the sleuthkit "body" format understood by mactime:
/// MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
pub fn body_line(e: &Entry, md5: Option<&str>) -> String {
    let name = e.path.to_string_lossy().replace('|', "%7C");
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        md5.unwrap_or("0"),
        name,
        e.inode,
        mode_string(e),
        e.uid,
        e.gid,
        e.size,
        e.atime,
        e.mtime,
        e.ctime,
        e.crtime
    )
}

/// csv cell quoting good enough for forensic exports
pub fn csv_cell(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fake_entry() -> Entry {
        Entry {
            path: PathBuf::from("/srv/case/invoice.pdf"),
            size: 4096,
            atime: 1_000_000,
            mtime: 2_000_000,
            ctime: 3_000_000,
            crtime: 0,
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            inode: 12345,
            is_dir: false,
            is_symlink: false,
        }
    }

    #[test]
    fn body_line_has_11_pipes() {
        let line = body_line(&fake_entry(), None);
        assert_eq!(line.split('|').count(), 11, "body line: {line}");
        assert!(line.starts_with("0|/srv/case/invoice.pdf|12345|r/rw-r--r--|"));
    }

    #[test]
    fn body_line_md5_column() {
        let line = body_line(&fake_entry(), Some("deadbeef"));
        assert!(line.starts_with("deadbeef|"));
    }

    #[test]
    fn parse_when_variants() {
        assert_eq!(parse_when("0"), Some(0));
        assert!(parse_when("2026-10-08").is_some());
        assert!(parse_when("2026-10-08 14:30").is_some());
        assert!(parse_when("2026-10-08 14:30:00").is_some());
        assert_eq!(parse_when("not a date"), None);
    }

    #[test]
    fn csv_cell_quotes_commas() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
