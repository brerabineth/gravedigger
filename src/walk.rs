use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Entry {
    pub path: PathBuf,
    pub size: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub crtime: i64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub inode: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
}

impl Entry {
    pub fn is_regular_file(&self) -> bool {
        !self.is_dir && !self.is_symlink
    }
}

/// lstat-style recursive walk. unreadable entries are counted, never fatal.
pub fn walk(root: &Path) -> (Vec<Entry>, u64) {
    let mut out = Vec::new();
    let mut skipped = 0u64;
    for dent in WalkDir::new(root).follow_links(false) {
        let dent = match dent {
            Ok(d) => d,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let md = match dent.metadata() {
            Ok(m) => m,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let ft = md.file_type();
        let (atime, mtime, ctime, crtime, mode, uid, gid, inode) = stat_times(&md);
        out.push(Entry {
            path: dent.path().to_path_buf(),
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
        });
    }
    (out, skipped)
}

#[cfg(unix)]
fn stat_times(md: &std::fs::Metadata) -> (i64, i64, i64, i64, u32, u32, u32, u64) {
    use std::os::unix::fs::MetadataExt;
    let crtime = {
        #[cfg(target_os = "macos")]
        {
            md.st_birthtime()
        }
        #[cfg(not(target_os = "macos"))]
        {
            0
        }
    };
    (
        md.atime(),
        md.mtime(),
        md.ctime(),
        crtime,
        md.mode(),
        md.uid(),
        md.gid(),
        md.ino(),
    )
}

#[cfg(not(unix))]
fn stat_times(md: &std::fs::Metadata) -> (i64, i64, i64, i64, u32, u32, u32, u64) {
    use std::time::UNIX_EPOCH;
    let secs = |t: std::io::Result<std::time::SystemTime>| {
        t.ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0)
    };
    (
        secs(md.accessed()),
        secs(md.modified()),
        secs(md.modified()),
        secs(md.created()),
        0,
        0,
        0,
        0,
    )
}

/// tsk-style type character for a body line
pub fn type_char(e: &Entry) -> char {
    if e.is_dir {
        'd'
    } else if e.is_symlink {
        'l'
    } else {
        match e.mode & 0o170000 {
            0o010000 => 'p',
            0o020000 => 'c',
            0o060000 => 'b',
            0o140000 => 's',
            _ => 'r',
        }
    }
}
