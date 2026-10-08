use anyhow::Result;
use clap::Args;

use crate::Ctx;

#[derive(Args, Debug)]
pub struct SweepArgs {
    /// directory to write the report into
    #[arg(long, default_value = ".")]
    pub out: String,

    /// collection profile: minimal, standard, full
    #[arg(long, value_enum, default_value_t = Profile::Standard)]
    pub profile: Profile,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Profile {
    Minimal,
    Standard,
    Full,
}

impl Profile {
    fn depth(&self) -> u8 {
        match self {
            Profile::Minimal => 0,
            Profile::Standard => 1,
            Profile::Full => 2,
        }
    }
}

#[cfg(not(unix))]
pub fn run(a: &SweepArgs, ctx: &Ctx) -> Result<i32> {
    let _ = (a, ctx);
    eprintln!("gravedigger: sweep is unix-only in this build");
    Ok(2)
}

#[cfg(unix)]
mod imp {
    use super::SweepArgs;
    use anyhow::{Context, Result};
    use chrono::Utc;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::Ctx;

    const TEXT_CAP: u64 = 2 * 1024 * 1024;

    #[derive(Serialize)]
    struct ManifestItem {
        source: String,
        file: String,
        bytes: u64,
        sha256: String,
        note: String,
    }

    #[derive(Serialize)]
    struct Manifest {
        started: String,
        host: String,
        kernel: String,
        profile: String,
        collected: Vec<ManifestItem>,
        skipped: Vec<String>,
    }

    struct Collector {
        dir: PathBuf,
        items: Vec<ManifestItem>,
        skipped: Vec<String>,
        seq: usize,
    }

    impl Collector {
        fn new(dir: PathBuf) -> Self {
            Collector {
                dir,
                items: Vec::new(),
                skipped: Vec::new(),
                seq: 0,
            }
        }

        /// copy a text artifact, capped, hashed, named after its source
        fn grab_text(&mut self, src: &Path, note: &str) {
            if !src.is_file() {
                return;
            }
            let raw = match fs::read(src) {
                Ok(r) => r,
                Err(e) => {
                    self.skipped.push(format!("{} ({e})", src.display()));
                    return;
                }
            };
            let truncated = raw.len() as u64 > TEXT_CAP;
            let bytes = if truncated {
                &raw[..TEXT_CAP as usize]
            } else {
                &raw[..]
            };
            let sha = hex::encode(Sha256::digest(bytes));
            self.seq += 1;
            let safe = src
                .to_string_lossy()
                .trim_start_matches('/')
                .replace(['/', '\\'], "_");
            let dest = self.dir.join(format!("{:03}_{safe}", self.seq));
            if fs::write(&dest, bytes).is_err() {
                self.skipped
                    .push(format!("{} (write failed)", src.display()));
                return;
            }
            self.items.push(ManifestItem {
                source: src.to_string_lossy().into_owned(),
                file: dest.file_name().unwrap().to_string_lossy().into_owned(),
                bytes: bytes.len() as u64,
                sha256: sha,
                note: if truncated {
                    format!("{note} (truncated at {TEXT_CAP} bytes)")
                } else {
                    note.to_string()
                },
            });
        }

        /// directory listing with size + mtime, filtered to a recency window
        fn grab_listing(&mut self, dir: &Path, note: &str, max_age_days: u64) {
            let mut lines = Vec::new();
            let cutoff = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .saturating_sub(max_age_days * 86400);
            let entries = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(e) => {
                    self.skipped.push(format!("{} ({e})", dir.display()));
                    return;
                }
            };
            for ent in entries.flatten() {
                let md = match ent.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|t| t.as_secs())
                    .unwrap_or(0);
                if max_age_days > 0 && mtime < cutoff {
                    continue;
                }
                lines.push(format!(
                    "{}\t{}\t{}",
                    chrono::DateTime::from_timestamp(mtime as i64, 0)
                        .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| mtime.to_string()),
                    md.len(),
                    ent.path().display()
                ));
            }
            if lines.is_empty() {
                return;
            }
            lines.sort();
            self.seq += 1;
            let safe = dir
                .to_string_lossy()
                .trim_start_matches('/')
                .replace(['/', '\\'], "_");
            let dest = self.dir.join(format!("{:03}_{safe}.listing", self.seq));
            if fs::write(&dest, lines.join("\n").as_bytes()).is_ok() {
                self.items.push(ManifestItem {
                    source: dir.to_string_lossy().into_owned(),
                    file: dest.file_name().unwrap().to_string_lossy().into_owned(),
                    bytes: 0,
                    sha256: String::new(),
                    note: note.to_string(),
                });
            }
        }

        fn grab_recent_files(&mut self, dir: &Path, max_age_hours: u64, note: &str) {
            let cutoff = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .saturating_sub(max_age_hours * 3600);
            let mut lines = Vec::new();
            for dent in walkdir::WalkDir::new(dir).max_depth(3).follow_links(false) {
                let dent = match dent {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let md = match dent.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if !md.is_file() {
                    continue;
                }
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|t| t.as_secs())
                    .unwrap_or(0);
                if mtime < cutoff {
                    continue;
                }
                lines.push(format!(
                    "{}\t{}\t{}",
                    chrono::DateTime::from_timestamp(mtime as i64, 0)
                        .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| mtime.to_string()),
                    md.len(),
                    dent.path().display()
                ));
            }
            if lines.is_empty() {
                return;
            }
            lines.sort();
            self.seq += 1;
            let dest = self.dir.join(format!(
                "{:03}_{}_recent.txt",
                self.seq,
                dir.to_string_lossy()
                    .trim_start_matches('/')
                    .replace('/', "_")
            ));
            if fs::write(&dest, lines.join("\n").as_bytes()).is_ok() {
                self.items.push(ManifestItem {
                    source: dir.to_string_lossy().into_owned(),
                    file: dest.file_name().unwrap().to_string_lossy().into_owned(),
                    bytes: 0,
                    sha256: String::new(),
                    note: note.to_string(),
                });
            }
        }
    }

    fn user_homes() -> Vec<PathBuf> {
        let mut homes = Vec::new();
        if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() >= 6 {
                    let uid: u32 = f[2].parse().unwrap_or(0);
                    // root plus real users; skip service accounts
                    if uid == 0 || uid >= 1000 {
                        let home = PathBuf::from(f[5]);
                        if home.starts_with("/home") || home == Path::new("/root") {
                            homes.push(home);
                        }
                    }
                }
            }
        }
        homes
    }

    fn run_cmd(cmd: &str, args: &[&str]) -> String {
        Command::new(cmd)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    pub fn run(a: &SweepArgs, ctx: &Ctx) -> Result<i32> {
        let stamp = Utc::now().format("%Y%m%d-%H%M%S");
        let out_dir = PathBuf::from(&a.out).join(format!("gravedigger_sweep_{stamp}"));
        fs::create_dir_all(&out_dir)
            .with_context(|| format!("create report dir {}", out_dir.display()))?;
        let depth = a.profile.depth();

        let mut c = Collector::new(out_dir.clone());

        // 00: host context
        let host = run_cmd("hostname", &[]);
        let kernel = run_cmd("uname", &["-sr"]);
        let host_report = format!(
            "host: {host}\nkernel: {kernel}\nprofile: {:?}\ntaken: {}\n",
            a.profile,
            Utc::now().to_rfc3339()
        );
        fs::write(out_dir.join("00_host.txt"), host_report)?;

        // 01: user activity
        for home in user_homes() {
            for hist in [".bash_history", ".zsh_history", ".sh_history"] {
                c.grab_text(&home.join(hist), "shell history");
            }
            c.grab_text(&home.join(".ssh/authorized_keys"), "authorized keys");
            c.grab_text(&home.join(".ssh/known_hosts"), "known hosts");
            if depth >= 2 {
                for rc in [".bashrc", ".profile", ".zshrc"] {
                    c.grab_text(&home.join(rc), "shell startup file");
                }
            }
        }

        // 02: cron
        c.grab_text(Path::new("/etc/crontab"), "system crontab");
        if let Ok(rd) = fs::read_dir("/etc/cron.d") {
            for ent in rd.flatten() {
                c.grab_text(&ent.path(), "cron drop-in");
            }
        }
        for spool in ["/var/spool/cron/crontabs", "/var/spool/cron"] {
            if let Ok(rd) = fs::read_dir(Path::new(spool)) {
                for ent in rd.flatten() {
                    c.grab_text(&ent.path(), "user crontab");
                }
            }
        }

        // 03: persistence
        c.grab_text(
            Path::new("/etc/ld.so.preload"),
            "ld preload (rootkit classic)",
        );
        c.grab_text(Path::new("/etc/rc.local"), "rc.local");
        if depth >= 1 {
            for wants in [
                "/etc/systemd/system/multi-user.target.wants",
                "/etc/systemd/system",
            ] {
                if let Ok(rd) = fs::read_dir(Path::new(wants)) {
                    for ent in rd.flatten() {
                        let p = ent.path();
                        if p.extension().map(|x| x == "service").unwrap_or(false) {
                            c.grab_text(&p, "systemd unit");
                        }
                    }
                }
            }
            for dir in ["/Library/LaunchDaemons", "/Library/LaunchAgents"] {
                if let Ok(rd) = fs::read_dir(Path::new(dir)) {
                    for ent in rd.flatten() {
                        c.grab_text(&ent.path(), "launchd plist");
                    }
                }
            }
        }

        // 04: temp directories
        if depth >= 1 {
            for tmp in ["/tmp", "/var/tmp", "/dev/shm"] {
                let p = Path::new(tmp);
                if p.is_dir() {
                    c.grab_listing(p, "recent temp entries", 7);
                }
            }
            c.grab_recent_files(Path::new("/etc"), 24, "etc files touched in last 24h");
        }

        // 05: kernel state
        c.grab_text(Path::new("/proc/modules"), "loaded kernel modules");

        // 06: logs (full only)
        if depth >= 2 {
            for log in [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/syslog",
                "/var/log/messages",
            ] {
                let p = Path::new(log);
                if p.is_file() {
                    c.grab_text(p, "log tail");
                }
            }
        }

        let manifest = Manifest {
            started: Utc::now().to_rfc3339(),
            host,
            kernel,
            profile: format!("{:?}", a.profile),
            collected: c.items,
            skipped: c.skipped,
        };
        let manifest_path = out_dir.join("manifest.json");
        let mf = fs::File::create(&manifest_path)?;
        serde_json::to_writer_pretty(&mf, &manifest)?;
        mf.sync_all()?;

        if !ctx.quiet {
            eprintln!(
                "gravedigger: sweep done — artifacts: {}, skipped: {} → {}",
                manifest.collected.len(),
                manifest.skipped.len(),
                out_dir.display()
            );
        }
        Ok(0)
    }
}

#[cfg(unix)]
pub fn run(a: &SweepArgs, ctx: &Ctx) -> Result<i32> {
    imp::run(a, ctx)
}
