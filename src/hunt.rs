use anyhow::{anyhow, Result};
use clap::Args;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::iocs::{self, Finding, Rule, Scope, Severity};
use crate::walk;
use crate::Ctx;

#[derive(Args, Debug)]
pub struct HuntArgs {
    /// root path to sweep
    pub path: String,

    /// extra rules file (json: [{"id","severity","scope","regex"}])
    #[arg(long)]
    pub rules: Option<String>,

    /// skip files larger than this many bytes during content scan
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    pub max_size: u64,

    /// emit json instead of text
    #[arg(long)]
    pub json: bool,

    /// only trip on high or medium severity (exit code 3)
    #[arg(long)]
    pub actionable_only: bool,
}

pub fn scan(root: &Path, rules: &[Rule], max_size: u64) -> Vec<Finding> {
    let (entries, _) = walk::walk(root);
    let mut findings = Vec::new();

    for e in &entries {
        let full = e.path.to_string_lossy();
        let name = e.path.file_name().map(|n| n.to_string_lossy().into_owned());

        // name / path scoped rules
        for r in rules {
            match r.scope {
                Scope::Filename => {
                    if let Some(n) = &name {
                        if r.re.is_match(n) {
                            findings.push(Finding {
                                rule: r.id.clone(),
                                severity: r.severity.label().to_string(),
                                path: full.clone().into_owned(),
                                offset: 0,
                                line: None,
                                snippet: format!("file name matches: {}", r.desc),
                            });
                        }
                    }
                }
                Scope::Path => {
                    if r.re.is_match(&full) {
                        findings.push(Finding {
                            rule: r.id.clone(),
                            severity: r.severity.label().to_string(),
                            path: full.clone().into_owned(),
                            offset: 0,
                            line: None,
                            snippet: format!("path matches: {}", r.desc),
                        });
                    }
                }
                Scope::Content => {}
            }
        }

        // content scoped rules
        if !e.is_regular_file() || e.size == 0 || e.size > max_size {
            continue;
        }
        let data = match std::fs::read(&e.path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let text = String::from_utf8_lossy(&data);
        for r in rules {
            if r.scope != Scope::Content {
                continue;
            }
            for m in r.re.find_iter(&text) {
                findings.push(Finding {
                    rule: r.id.clone(),
                    severity: r.severity.label().to_string(),
                    path: full.clone().into_owned(),
                    offset: m.start(),
                    line: Some(iocs::line_of(&text, m.start())),
                    snippet: iocs::snippet(&text, m.start(), m.end()),
                });
            }
        }
    }

    findings.sort_by(|a, b| {
        let sa = sev_rank(&a.severity);
        let sb = sev_rank(&b.severity);
        sb.cmp(&sa)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.offset.cmp(&b.offset))
    });
    findings
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "HIGH" => 3,
        "MEDIUM" => 2,
        _ => 1,
    }
}

pub fn run(a: &HuntArgs, ctx: &Ctx) -> Result<i32> {
    let root = PathBuf::from(&a.path);
    if !root.exists() {
        return Err(anyhow!("no such path: {}", a.path));
    }

    let mut rules: Vec<Rule> = iocs::PACK.clone();
    if let Some(file) = &a.rules {
        rules.extend(iocs::load_custom(file)?);
    }

    let findings = scan(&root, &rules, a.max_size);
    let high = findings.iter().filter(|f| f.severity == "HIGH").count();
    let med = findings.iter().filter(|f| f.severity == "MEDIUM").count();
    let info = findings.iter().filter(|f| f.severity == "INFO").count();

    if a.json {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        serde_json::to_writer_pretty(&mut out, &findings)?;
        writeln!(out)?;
    } else {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for f in &findings {
            let sev = Severity::parse(&f.severity.to_lowercase()).unwrap_or(Severity::Info);
            let tag = crate::output::paint(&f.severity, sev.code(), ctx.color);
            let loc = match f.line {
                Some(l) => format!("{}:{}", f.path, l),
                None => f.path.clone(),
            };
            writeln!(out, "{} [{}] {} — {}", tag, f.rule, loc, f.snippet)?;
        }
    }

    if !ctx.quiet {
        eprintln!(
            "gravedigger: {} findings ({high} high / {med} medium / {info} info)",
            findings.len()
        );
    }

    let actionable = high + med;
    Ok(if actionable > 0 { 3 } else { 0 })
}
