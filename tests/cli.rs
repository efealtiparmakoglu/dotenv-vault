//! End-to-end CLI tests over real files in a temp dir.

use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_dotenv-vault")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("failed to spawn dotenv-vault")
}

fn env_file(dir: &std::path::Path, name: &str, content: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path.to_str().unwrap().to_string()
}

#[test]
fn full_lifecycle_encrypt_decrypt_diff_rotate() {
    let dir = std::env::temp_dir().join(format!("dv-e2e-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let key = dir.join("team.key");
    let key2 = dir.join("rotated.key");
    let env_v1 = env_file(&dir, ".env", "API_KEY=abc\nDB_URL=postgres://x\nDEBUG=0\n");
    let env_v2 = env_file(&dir, ".env2", "API_KEY=def\nDB_URL=postgres://x\nDEBUG=0\nNEW=1\n");
    let key_s = key.to_str().unwrap().to_string();
    let key2_s = key2.to_str().unwrap().to_string();
    let vault_a = dir.join("a.vault").to_str().unwrap().to_string();
    let vault_b = dir.join("b.vault").to_str().unwrap().to_string();
    let roundtrip = dir.join("roundtrip.env").to_str().unwrap().to_string();

    // keygen
    let out = run(&["keygen", "-o", &key_s]);
    assert!(out.status.success(), "keygen: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read(&key).unwrap().len(), 64);

    // keygen refuses overwrite
    let out = run(&["keygen", "-o", &key_s]);
    assert_eq!(out.status.code(), Some(1), "overwrite must fail");

    // encrypt both versions
    let out = run(&["encrypt", "-k", &key_s, "-i", &env_v1, "-o", &vault_a]);
    assert!(out.status.success(), "encrypt a");
    let out = run(&["encrypt", "-k", &key_s, "-i", &env_v2, "-o", &vault_b]);
    assert!(out.status.success(), "encrypt b");
    // same plaintext differs per nonce; different plaintexts obviously too
    let bytes_a = std::fs::read(&vault_a).unwrap();
    let bytes_b = std::fs::read(&vault_b).unwrap();
    assert_eq!(&bytes_a[..8], b"DENVLT01");
    assert_ne!(bytes_a, bytes_b);

    // diff shows changed + added keys
    let out = run(&["diff", "-k", &key_s, "-a", &vault_a, "-b", &vault_b]);
    assert!(out.status.success(), "diff");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("1 key(s) changed"), "summary: {}", stdout);
    assert!(stdout.contains("1 added"), "summary: {}", stdout);
    assert!(stdout.contains("+API_KEY=def"), "unified: {}", stdout);
    assert!(stdout.contains("-API_KEY=abc"), "unified: {}", stdout);

    // diff of identical vaults (same file on both sides) says identical
    let out = run(&["diff", "-k", &key_s, "-a", &vault_a, "-b", &vault_a]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("identical"));

    // decrypt round trip
    let out = run(&["decrypt", "-k", &key_s, "-i", &vault_a, "-o", &roundtrip]);
    assert!(out.status.success(), "decrypt");
    assert_eq!(
        std::fs::read_to_string(&roundtrip).unwrap(),
        "API_KEY=abc\nDB_URL=postgres://x\nDEBUG=0\n"
    );

    // rotate to a new key
    let out = run(&["keygen", "-o", &key2_s]);
    assert!(out.status.success(), "keygen 2");
    let rotated = dir.join("rotated.vault").to_str().unwrap().to_string();
    let out = run(&["rotate", "-k", &key_s, "-n", &key2_s, "-i", &vault_a, "-o", &rotated]);
    assert!(out.status.success(), "rotate: {}", String::from_utf8_lossy(&out.stderr));
    // old key no longer opens it; new key reads identical plaintext
    let out = run(&["decrypt", "-k", &key_s, "-i", &rotated, "-o", &roundtrip]);
    assert_eq!(out.status.code(), Some(1), "old key must fail after rotation");
    let out = run(&["decrypt", "-k", &key2_s, "-i", &rotated, "-o", &roundtrip]);
    assert!(out.status.success(), "new key must open rotated vault");
    assert_eq!(
        std::fs::read_to_string(&roundtrip).unwrap(),
        "API_KEY=abc\nDB_URL=postgres://x\nDEBUG=0\n"
    );
}

#[test]
fn tampered_vault_fails_authentication() {
    let dir = std::env::temp_dir().join(format!("dv-tamper-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    // raw 64-byte key file: 32 enc + 32 MAC bytes
    let key_path = dir.join("key.bin");
    std::fs::write(&key_path, vec![7u8; 64]).unwrap();
    let key_s = key_path.to_str().unwrap().to_string();
    let env = env_file(&dir, ".env", "SECRET=x\n");
    let vault = dir.join("s.vault").to_str().unwrap().to_string();
    assert!(run(&["encrypt", "-k", &key_s, "-i", &env, "-o", &vault]).status.success());

    let mut bytes = std::fs::read(&vault).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x80;
    std::fs::write(&vault, &bytes).unwrap();

    let out = run(&["decrypt", "-k", &key_s, "-i", &vault]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("authentication failed"), "stderr: {}", stderr);
}

#[test]
fn wrong_key_and_missing_files_exit_one() {
    let dir = std::env::temp_dir().join(format!("dv-wrong-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let k1 = dir.join("k1");
    let k2 = dir.join("k2");
    std::fs::write(&k1, vec![1u8; 64]).unwrap();
    std::fs::write(&k2, vec![2u8; 64]).unwrap();
    let env = env_file(&dir, ".env", "X=1\n");
    let vault = dir.join("s.vault").to_str().unwrap().to_string();
    run(&["encrypt", "-k", k1.to_str().unwrap(), "-i", &env, "-o", &vault]);

    let out = run(&["decrypt", "-k", k2.to_str().unwrap(), "-i", &vault]);
    assert_eq!(out.status.code(), Some(1));
    let out = run(&["decrypt", "-k", k1.to_str().unwrap(), "-i", "/nowhere/s.vault"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn usage_errors_exit_two() {
    let cases: [&[&str]; 5] = [
        &["--nope"],
        &["frobnicate"],
        &["encrypt", "-k"],
        &["encrypt"],
        &["keygen", "-o", "x", "y"],
    ];
    for argv in cases {
        let out = run(argv);
        assert_eq!(out.status.code(), Some(2), "argv: {:?}", argv);
        assert!(String::from_utf8_lossy(&out.stderr).starts_with("dotenv-vault:"));
    }
}

#[test]
fn help_and_version() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("USAGE"));
    let version = run(&["-V"]);
    assert!(String::from_utf8_lossy(&version.stdout).contains("1.0.0"));
}
