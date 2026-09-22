use std::path::Path;
use std::process::exit;

use dotenv_vault::diff::{diff_bytes, env_summary, render_unified};
use dotenv_vault::vault::{create_key, decrypt, encrypt, load_key, rotate, write_vault};

const USAGE: &str = r#"dotenv-vault v1.0.0 — local encrypted .env vault (AES-256-CTR + HMAC-SHA256)

USAGE
  dotenv-vault keygen  -o <keyfile>
  dotenv-vault encrypt -k <keyfile> -i <.env>    [-o <out.vault>]
  dotenv-vault decrypt -k <keyfile> -i <in.vault> [-o <out.env>]
  dotenv-vault diff    -k <keyfile> -a <a.vault> -b <b.vault>
  dotenv-vault rotate  -k <oldkey> -n <newkey> -i <in.vault> [-o <out.vault>]
  dotenv-vault (-h | --help | -V | --version)

COMMANDS
  keygen   write a fresh 64-byte key file (32 enc + 32 MAC bytes);
           refuses to overwrite an existing file
  encrypt  seal a plaintext env file into a vault file
  decrypt  open a vault file after verifying its HMAC tag
  diff     decrypt two vaults and show a unified diff plus a
           changed/added/removed key summary (the encrypted diff:
           ciphertexts differ per nonce, so this is how you compare)
  rotate   decrypt with the old key, re-encrypt with a new one

Vault format: "DENVLT01" | 12-byte nonce | AES-256-CTR ciphertext |
HMAC-SHA256 tag. Keys are read from raw key files; share them with your
team out-of-band (password manager), never in git.

Exit codes: 0 ok, 1 runtime failure (I/O, bad tag, wrong key), 2 usage error."#;

fn value_flag(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{} requires a value", flag))
}

struct Options {
    out: Option<String>,
    key: Option<String>,
    new_key: Option<String>,
    input: Option<String>,
    file_a: Option<String>,
    file_b: Option<String>,
    help: bool,
    version: bool,
    command: Option<String>,
}

fn parse_args(argv: &[String]) -> Result<Options, String> {
    let mut opts = Options {
        out: None,
        key: None,
        new_key: None,
        input: None,
        file_a: None,
        file_b: None,
        help: false,
        version: false,
        command: None,
    };
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        match arg {
            "-o" | "--out" => opts.out = Some(value_flag(argv, &mut i, arg)?),
            "-k" | "--key" => opts.key = Some(value_flag(argv, &mut i, arg)?),
            "-n" | "--new-key" => opts.new_key = Some(value_flag(argv, &mut i, arg)?),
            "-i" | "--in" => opts.input = Some(value_flag(argv, &mut i, arg)?),
            "-a" => opts.file_a = Some(value_flag(argv, &mut i, arg)?),
            "-b" => opts.file_b = Some(value_flag(argv, &mut i, arg)?),
            "-h" | "--help" => opts.help = true,
            "-V" | "--version" => opts.version = true,
            _ if arg.starts_with('-') => return Err(format!("unknown option \"{}\"", arg)),
            _ => {
                if opts.command.is_some() {
                    return Err(format!("unexpected extra argument \"{}\"", arg));
                }
                opts.command = Some(arg.to_string());
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn fail_usage(message: &str) -> ! {
    eprintln!("dotenv-vault: {}", message);
    eprintln!("dotenv-vault: run 'dotenv-vault --help' for usage");
    exit(2);
}

fn fail_runtime(message: String) -> ! {
    eprintln!("dotenv-vault: {}", message);
    exit(1);
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&argv) {
        Ok(o) => o,
        Err(m) => fail_usage(&m),
    };
    if opts.help {
        println!("{}", USAGE);
        return;
    }
    if opts.version {
        println!("dotenv-vault 1.0.0");
        return;
    }
    match opts.command.as_deref() {
        Some("keygen") => cmd_keygen(&opts),
        Some("encrypt") => cmd_encrypt(&opts),
        Some("decrypt") => cmd_decrypt(&opts),
        Some("diff") => cmd_diff(&opts),
        Some("rotate") => cmd_rotate(&opts),
        Some(other) => fail_usage(&format!("unknown command \"{}\"", other)),
        None => fail_usage("missing command"),
    }
}

fn cmd_keygen(opts: &Options) {
    let path = require(opts.out.as_deref(), "-o <keyfile>");
    match create_key(Path::new(&path)) {
        Ok(_) => println!("key written to {} (share out-of-band, never commit it)", path),
        Err(e) => fail_runtime(e),
    }
}

fn cmd_encrypt(opts: &Options) {
    let key_path = require(opts.key.as_deref(), "-k <keyfile>");
    let input = require(opts.input.as_deref(), "-i <.env file>");
    let out = opts.out.clone().unwrap_or_else(|| input.clone() + ".vault");
    let key = load_key(Path::new(&key_path)).unwrap_or_else(|e| fail_runtime(e));
    let plaintext = std::fs::read(&input)
        .unwrap_or_else(|e| fail_runtime(format!("cannot read {}: {}", input, e)));
    let vault = encrypt(&key, &plaintext).unwrap_or_else(|e| fail_runtime(e));
    write_vault(Path::new(&out), &vault).unwrap_or_else(|e| fail_runtime(e));
    println!("{} -> {} ({} bytes sealed)", input, out, plaintext.len());
}

fn cmd_decrypt(opts: &Options) {
    let key_path = require(opts.key.as_deref(), "-k <keyfile>");
    let input = require(opts.input.as_deref(), "-i <vault file>");
    let out = opts.out.clone().unwrap_or_else(|| {
        input.strip_suffix(".vault").map(|s| s.to_string()).unwrap_or_else(|| input.clone() + ".plain")
    });
    let key = load_key(Path::new(&key_path)).unwrap_or_else(|e| fail_runtime(e));
    let vault = std::fs::read(&input)
        .unwrap_or_else(|e| fail_runtime(format!("cannot read {}: {}", input, e)));
    let plaintext = decrypt(&key, &vault).unwrap_or_else(|e| fail_runtime(e));
    write_plaintext(&out, &plaintext);
    println!("{} -> {} (verified, {} bytes)", input, out, plaintext.len());
}

fn cmd_diff(opts: &Options) {
    let key_path = require(opts.key.as_deref(), "-k <keyfile>");
    let a = require(opts.file_a.as_deref(), "-a <a.vault>");
    let b = require(opts.file_b.as_deref(), "-b <b.vault>");
    let key = load_key(Path::new(&key_path)).unwrap_or_else(|e| fail_runtime(e));
    let plain_a = read_vault(&key, &a);
    let plain_b = read_vault(&key, &b);
    let changes = diff_bytes(&plain_a, &plain_b);
    if changes.iter().all(|l| matches!(l.op, dotenv_vault::diff::Op::Equal)) {
        println!("identical");
        return;
    }
    println!("{}", env_summary(&changes));
    print!("{}", render_unified(&a, &b, &changes));
}

fn cmd_rotate(opts: &Options) {
    let key_path = require(opts.key.as_deref(), "-k <old keyfile>");
    let new_path = require(opts.new_key.as_deref(), "-n <new keyfile>");
    let input = require(opts.input.as_deref(), "-i <vault file>");
    let out = opts.out.clone().unwrap_or_else(|| input.clone());
    let old_key = load_key(Path::new(&key_path)).unwrap_or_else(|e| fail_runtime(e));
    let new_key = load_key(Path::new(&new_path)).unwrap_or_else(|e| fail_runtime(e));
    let vault = std::fs::read(&input)
        .unwrap_or_else(|e| fail_runtime(format!("cannot read {}: {}", input, e)));
    let rotated = rotate(&old_key, &new_key, &vault).unwrap_or_else(|e| fail_runtime(e));
    write_vault(Path::new(&out), &rotated).unwrap_or_else(|e| fail_runtime(e));
    println!("{} -> {} re-encrypted under {}", input, out, new_path);
}

fn read_vault(key: &dotenv_vault::vault::VaultKey, path: &str) -> Vec<u8> {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| fail_runtime(format!("cannot read {}: {}", path, e)));
    decrypt(key, &bytes).unwrap_or_else(|e| fail_runtime(e))
}

fn write_plaintext(path: &str, data: &[u8]) {
    std::fs::write(path, data)
        .unwrap_or_else(|e| fail_runtime(format!("cannot write {}: {}", path, e)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

fn require(value: Option<&str>, what: &str) -> String {
    match value {
        Some(v) => v.to_string(),
        None => fail_usage(&format!("missing required option {}", what)),
    }
}
