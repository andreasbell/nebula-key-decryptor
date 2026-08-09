# Nebula Key Decryption and Encryption tool

Small CLI tool for encrypting and decrypting [Nebula](https://github.com/slackhq/nebula) CA private keys.

## Install

Assuming you have [`uv`](https://docs.astral.sh/uv/) installed on your system the package can be run directly from the repository using:

```bash
uv run nebula-key-decryptor --help
```

## CLI Usage

The command supports two mutually exclusive modes:

- `-d`, `--decrypt`: decrypt an encrypted Nebula CA private key
- `-e`, `--encrypt`: encrypt a decrypted Nebula CA private key

The CLI accepts a passphrase and an optional key file. If no key file is provided, it reads from standard input.

### Decrypt an encrypted Nebula CA private key

```bash
uv run nebula-key-decryptor -d "your-passphrase" ca.key > decrypted.key
```

Or via stdin:

```bash
uv run nebula-key-decryptor -d "your-passphrase" < ca.key > decrypted.key
```

### Encrypt a decrypted Nebula CA private key

```bash
uv run nebula-key-decryptor -e "your-passphrase" ca.key > encrypted.key
```

Or via stdin:

```bash
uv run nebula-key-decryptor -e "your-passphrase" < ca.key > encrypted.key
```

## Notes

- The passphrase is used with Argon2id and AES-256-GCM.
- This tool is intended for working with the nebula CA private key format.
- The tool supports both the `ED25519` and `ECDSA P256` key formats. 
- Default Argon2 parameters are slightly differetnt than what nebula uses as default parameters. Use the optional CLI arguments to change the Argon2 parameters. 
