use gravedigger::hashcmd::{digest_file, load_hashlist, Algo};
use gravedigger::hunt;
use gravedigger::iocs::{self, Scope, Severity};
use std::io::Write;

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // ransom note with wallet
    let mut note = std::fs::File::create(root.join("RESTORE_FILES.txt")).unwrap();
    writeln!(
        note,
        "ALL YOUR FILES HAVE BEEN ENCRYPTED\nsend 0.35 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\npayment within 72 hours"
    )
    .unwrap();

    // encrypted file with double extension
    std::fs::write(
        root.join("invoice_2026.pdf.8x2q.locked"),
        [0x25u8, 0x50, 0x44, 0x46, 0xaa, 0xbb],
    )
    .unwrap();

    // utf-16le note (windows ransomware style)
    let mut u16note: Vec<u8> = vec![0xff, 0xfe];
    for b in "DECRYPT INSTRUCTIONS".bytes() {
        u16note.push(b);
        u16note.push(0);
    }
    std::fs::write(root.join("_HELP_RECOVER_DATA.txt"), u16note).unwrap();

    // benign file
    std::fs::write(
        root.join("meeting_notes.txt"),
        "q3 roadmap: ship the thing\n",
    )
    .unwrap();

    dir
}

#[test]
fn digest_known_vector() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("abc.txt");
    std::fs::write(&p, b"abc").unwrap();
    let sha = digest_file(&p, Algo::Sha256).unwrap();
    assert_eq!(
        sha,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let md5 = digest_file(&p, Algo::Md5).unwrap();
    assert_eq!(md5, "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn hashlist_parsing_skips_comments() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.hashes");
    std::fs::write(
        &p,
        "# known bad\nBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD\n\ndeadbeef # partial\n",
    )
    .unwrap();
    let set = load_hashlist(p.to_str().unwrap()).unwrap();
    assert_eq!(set.len(), 2);
    assert!(set.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

#[test]
fn hunt_finds_all_classes_in_fixture() {
    let dir = fixture();
    let findings = hunt::scan(dir.path(), &iocs::PACK, 4 * 1024 * 1024);

    let rules_hit: Vec<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(
        rules_hit.contains(&"RANSOM-NOTE"),
        "note name: {rules_hit:?}"
    );
    assert!(
        rules_hit.contains(&"RANSOM-NOTE2"),
        "underscore note: {rules_hit:?}"
    );
    assert!(rules_hit.contains(&"RANSOM-DOUBLE-EXT"), "{rules_hit:?}");
    assert!(rules_hit.contains(&"RANSOM-TEXT"), "{rules_hit:?}");
    assert!(rules_hit.contains(&"BTC-ADDR"), "{rules_hit:?}");

    // benign file clean
    assert!(findings
        .iter()
        .all(|f| !f.path.contains("meeting_notes.txt")));
}

#[test]
fn hunt_clean_directory_is_silent() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("ledger.csv"),
        "date,amount\n2026-01-01,42\n",
    )
    .unwrap();
    let findings = hunt::scan(dir.path(), &iocs::PACK, 4 * 1024 * 1024);
    assert_eq!(findings, vec![]);
}

#[test]
fn custom_rules_fire() {
    let dir = tempfile::tempdir().unwrap();
    let rules_p = dir.path().join("rules.json");
    std::fs::write(
        &rules_p,
        r#"[{"id":"CORP-MARK","severity":"high","scope":"content","regex":"project-apollo-internal"}]"#,
    )
    .unwrap();
    let custom = iocs::load_custom(rules_p.to_str().unwrap()).unwrap();
    assert_eq!(custom[0].severity, Severity::High);

    let case = tempfile::tempdir().unwrap();
    std::fs::write(
        case.path().join("deck.md"),
        "notes about project-apollo-internal roadmap",
    )
    .unwrap();
    let findings = hunt::scan(case.path(), &custom, 1024 * 1024);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, "CORP-MARK");
    assert_eq!(findings[0].line, Some(1));
}

#[test]
fn filename_rule_via_custom_scope() {
    let dir = tempfile::tempdir().unwrap();
    let rules_p = dir.path().join("rules.json");
    std::fs::write(
        &rules_p,
        r#"[{"id":"FIN-EXPORT","severity":"medium","scope":"filename","regex":"(?i)payroll.*\\.csv$"}]"#,
    )
    .unwrap();
    let custom = iocs::load_custom(rules_p.to_str().unwrap()).unwrap();
    assert!(matches!(custom[0].scope, Scope::Filename));

    let case = tempfile::tempdir().unwrap();
    std::fs::write(case.path().join("payroll_october.csv"), "a,b\n").unwrap();
    std::fs::write(case.path().join("innocuous.csv"), "x\n").unwrap();
    let findings = hunt::scan(case.path(), &custom, 1024 * 1024);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].path.ends_with("payroll_october.csv"));
}

#[test]
fn timeline_body_through_command_modules() {
    use gravedigger::body::{body_line, mode_string, parse_when};

    // epoch sanity
    assert_eq!(parse_when("1700000000"), Some(1700000000));

    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("evidence.bin");
    std::fs::write(&p, b"payload").unwrap();

    let (entries, skipped) = gravedigger::walk::walk(dir.path());
    assert_eq!(skipped, 0);
    assert!(entries.len() >= 2, "dir + file");

    for e in &entries {
        let line = body_line(e, None);
        assert_eq!(line.split('|').count(), 11);
        assert!(mode_string(e).contains('/'));
    }
}

#[test]
fn strings_utf16_in_fixture() {
    let dir = fixture();
    let p = dir.path().join("_HELP_RECOVER_DATA.txt");
    let data = std::fs::read(&p).unwrap();
    let hits = gravedigger::strings::extract_utf16le(&data, 4);
    assert!(hits.iter().any(|(_, v)| v.contains("DECRYPT INSTRUCTIONS")));
}
