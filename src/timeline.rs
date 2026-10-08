use anyhow::{anyhow, Result};
use clap::Args;
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use crate::body;
use crate::walk;
use crate::Ctx;

#[derive(Args, Debug)]
pub struct TimelineArgs {
    /// root path to walk
    pub path: String,

    /// output format: body (mactime), json, csv
    #[arg(long, value_enum, default_value_t = Format::Body)]
    pub format: Format,

    /// only entries with mtime >= this (epoch or YYYY-MM-DD[ HH:MM])
    #[arg(long)]
    pub since: Option<String>,

    /// only entries with mtime <= this
    #[arg(long)]
    pub until: Option<String>,

    /// fill the md5 column (reads every file, expect it to be slow)
    #[arg(long)]
    pub hash: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Format {
    Body,
    Json,
    Csv,
}

pub fn run(a: &TimelineArgs, ctx: &Ctx) -> Result<i32> {
    let root = PathBuf::from(&a.path);
    if !root.exists() {
        return Err(anyhow!("no such path: {}", a.path));
    }

    let since = bound(&a.since, "--since")?;
    let until = bound(&a.until, "--until")?;

    let (entries, skipped) = walk::walk(&root);

    let mut kept: Vec<_> = entries
        .iter()
        .filter(|e| since.is_none_or(|s| e.mtime >= s))
        .filter(|e| until.is_none_or(|u| e.mtime <= u))
        .collect();
    kept.sort_by_key(|e| (e.mtime, e.path.clone()));

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    match a.format {
        Format::Body => {
            let md5s: HashMap<PathBuf, String> = if a.hash {
                digest_all(&kept)
            } else {
                HashMap::new()
            };
            for e in &kept {
                let m = md5s.get(&e.path).map(String::as_str);
                writeln!(out, "{}", body::body_line(e, m))?;
            }
        }
        Format::Json => {
            serde_json::to_writer(&mut out, &kept)?;
            writeln!(out)?;
        }
        Format::Csv => {
            writeln!(
                out,
                "md5,name,inode,mode,uid,gid,size,atime,mtime,ctime,crtime"
            )?;
            for e in &kept {
                writeln!(
                    out,
                    ",{},{},{},{},{},{},{},{},{},{}",
                    body::csv_cell(&e.path.to_string_lossy()),
                    e.inode,
                    body::mode_string(e),
                    e.uid,
                    e.gid,
                    e.size,
                    e.atime,
                    e.mtime,
                    e.ctime,
                    e.crtime
                )?;
            }
        }
    }

    if !ctx.quiet {
        eprintln!(
            "gravedigger: {} entries ({} unreadable, skipped)",
            kept.len(),
            skipped
        );
    }
    Ok(0)
}

fn bound(v: &Option<String>, flag: &str) -> Result<Option<i64>> {
    match v {
        Some(s) => body::parse_when(s)
            .map(Some)
            .ok_or_else(|| anyhow!("cannot parse {flag} '{s}' (want epoch or YYYY-MM-DD[ HH:MM])")),
        None => Ok(None),
    }
}

fn digest_all(entries: &[&walk::Entry]) -> HashMap<PathBuf, String> {
    let files: Vec<&walk::Entry> = entries
        .iter()
        .copied()
        .filter(|e| e.is_regular_file() && e.size < 64 * 1024 * 1024)
        .collect();
    files
        .par_iter()
        .filter_map(|e| {
            crate::hashcmd::digest_file(&e.path, crate::hashcmd::Algo::Md5)
                .ok()
                .map(|h| (e.path.clone(), h))
        })
        .collect()
}
