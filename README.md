# dotenv-vault

Local encrypted vault for `.env` files — AES-256-CTR + HMAC-SHA256,
implemented from scratch, **zero crates**.

```console
$ dotenv-vault keygen -o team.key
key written to team.key (share out-of-band, never commit it)

$ dotenv-vault encrypt -k team.key -i .env -o .env.vault
.env -> .env.vault (40 bytes sealed)

$ dotenv-vault diff -k team.key -a .env.vault.old -b .env.vault
1 key(s) changed, 1 added, 0 removed
--- .env.vault.old
+++ .env.vault
@@ -1,3 +1,4 @@
-API_KEY=abc
+API_KEY=def
 DB_URL=postgres://x
 DEBUG=0
+NEW=1
```

## The model (git-crypt philosophy)

- `.env` files never enter git; their **`.env.vault`** counterparts do.
- The **key file** is 64 raw bytes (32 encryption + 32 MAC). It lives in
  your password manager / shared out-of-band — key distribution is a
  documentation problem, not a crypto one, so this tool keeps it dead
  simple: one file, zero prompts, no daemons.
- **Encrypted diff**: ciphertexts differ on every save (fresh nonce per
  encryption), so `git diff` on vault files is noise. Instead, `diff`
  decrypts two vaults in memory and shows a real unified diff plus a
  changed/added/removed key summary. Secrets never touch the terminal
  unless they changed.
- **Rotation** is one command: decrypt under the old key, re-encrypt
  under the new. Old keys stop working immediately after.

## Format

```
DENVLT01 | 12-byte random nonce | AES-256-CTR ciphertext | HMAC-SHA256 tag
```

The tag covers nonce + ciphertext and is **verified before any plaintext
is released**: a flipped bit anywhere fails with `authentication failed`
instead of silently decrypting garbage. Vault and plaintext outputs are
written with mode 0600 on Unix.

## Commands

```
dotenv-vault keygen  -o <keyfile>
dotenv-vault encrypt -k <keyfile> -i <.env>     [-o <out.vault>]
dotenv-vault decrypt -k <keyfile> -i <in.vault> [-o <out.env>]
dotenv-vault diff    -k <keyfile> -a <a.vault> -b <b.vault>
dotenv-vault rotate  -k <oldkey> -n <newkey> -i <in.vault> [-o <out.vault>]
```

`keygen` refuses to overwrite an existing key file, so a rotation never
clobbers the current key by accident.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | I/O error, authentication failure, wrong key, keygen overwrite |
| 2 | usage error |

## What is implemented from scratch

- **AES-256** block cipher per FIPS-197 (key expansion, SubBytes,
  ShiftRows, MixColumns, Paeth-free GF(2^8) arithmetic) with a known-answer
  test from the standard's appendix.
- **CTR mode** over a 96-bit nonce + 32-bit big-endian counter.
- **SHA-256** per FIPS 180-4 (tested against the published vectors,
  including one million `a`s) and **HMAC-SHA256** per RFC 2104/4231.
- **LCS diff** with a quadratic guard: beyond 4000 lines per side the
  result degrades to a wholesale replace.

Honest limits: CTR+HMAC gives you confidentiality and integrity but not
nonce-misuse resistance at stateStore scale — one random 96-bit nonce per
save is the whole scheme, the same trade git-crypt-era tooling made. There
is no key derivation: the key file *is* the key material. The tests cover
every single-byte tamper position of a real vault.

## Development

```console
$ cargo test     # 26 tests: crypto vectors, tamper matrix, CLI end-to-end
$ cargo clippy --all-targets -- -D warnings
```

## License

MIT — see [LICENSE](LICENSE).
