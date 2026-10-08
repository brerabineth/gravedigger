use anyhow::{anyhow, Context, Result};
use clap::Args;
use md5::Md5;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::walk;
use crate::Ctx;

#[derive(Args, Debug)]
pub struct HashArgs {
    /// root path to walk
    pub path: String,

    /// digest algorithm
    #[arg(long, value_enum, default_value_t = Algo::Sha256)]
    pub algo: Algo,

    /// hash list to match against (one hex hash per line, # comments ok)
    #[arg(long)]
    pub against: Option<String>,

    /// output format
    #[arg(long, value_enum, default_value_t = HashFormat::Text)]
    pub format: HashFormat,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Algo {
    Sha256,
    Md5,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum HashFormat {
    Text,
    Json,
    Csv,
}

#[derive(serde::Serialize)]
struct HashRow {
    path: String,
    algo: String,
    hash: String,
    known_bad: bool,
}

pub fn digest_file(path: &Path, algo: Algo) -> Result<String> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(match algo {
        Algo::Sha256 => hex::encode(Sha256::digest(&data)),
        Algo::Md5 => hex::encode(Md5::digest(&data)),
    })
}

pub fn load_hashlist(path: &str) -> Result<HashSet<String>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read hash list {path}"))?;
    let mut set = HashSet::new();
    for line in raw.lines() {
        let line = line.split('#').next().unwrap_or("").trim().to_lowercase();
        if !line.is_empty() {
            set.insert(line);
        }
    }
    Ok(set)
}

pub fn run(a: &HashArgs, ctx: &Ctx) -> Result<i32> {
    let root = PathBuf::from(&a.path);
    if !root.exists() {
        return Err(anyhow!("no such path: {}", a.path));
    }
    let known = match &a.algo {
        Algo::Sha256 => "sha256",
        Algo::Md5 => "md5",
    };
    let bad = match &a.against {
        Some(list) => Some(load_hashlist(list)?),
        None => None,
    };

    let (entries, skipped) = walk::walk(&root);
    let files: Vec<&walk::Entry> = entries.iter().filter(|e| e.is_regular_file()).collect();

    let rows: Vec<HashRow> = files
        .par_iter()
        .filter_map(|e| {
            digest_file(&e.path, a.algo.clone()).ok().map(|hash| {
                let known_bad = bad.as_ref().is_some_and(|b| b.contains(&hash));
                HashRow {
                    path: e.path.to_string_lossy().into_owned(),
                    algo: known.to_string(),
                    hash,
                    known_bad,
                }
            })
        })
        .collect();

    let mut rows = rows;
    rows.sort_by(|x, y| x.path.cmp(&y.path));

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    match a.format {
        HashFormat::Text => {
            for r in &rows {
                writeln!(out, "{}  {}", r.hash, r.path)?;
            }
        }
        HashFormat::Json => {
            serde_json::to_writer_pretty(&mut out, &rows)?;
            writeln!(out)?;
        }
        HashFormat::Csv => {
            writeln!(out, "path,algo,hash,known_bad")?;
            for r in &rows {
                writeln!(
                    out,
                    "{},{},{},{}",
                    crate::body::csv_cell(&r.path),
                    r.algo,
                    r.hash,
                    r.known_bad
                )?;
            }
        }
    }

    let hits = rows.iter().filter(|r| r.known_bad).count();
    if !ctx.quiet {
        eprintln!(
            "gravedigger: {} files hashed ({known}), {hits} known-bad matches, {skipped} skipped",
            rows.len()
        );
    }
    Ok(if hits > 0 { 3 } else { 0 })
}
