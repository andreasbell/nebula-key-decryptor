from .nebula_key import decrypt, encrypt
import argparse
import sys

def main() -> None:

    parser = argparse.ArgumentParser(description="Encrypt or decrypt a nebula CA private key.")
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the string")
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the string")

    parser.add_argument("passphrase", type=str, help="The passphrase to use")
    parser.add_argument("key", type=argparse.FileType('r', encoding='utf-8'), nargs="?", default=sys.stdin, help="The key file to process")
    parser.add_argument("--argon2-iterations", type=int, default=3, help="Argon2id time cost used when encrypting")
    parser.add_argument("--argon2-memory", type=int, default=64, help="Argon2id memory cost used when encrypting")
    parser.add_argument("--argon2-parallelism", type=int, default=4, help="Argon2id parallelism used when encrypting")

    args = parser.parse_args()

    if args.encrypt:
        with args.key as f:
            encrypted_key = f.read().strip()
        print(encrypt(
            encrypted_key,
            args.passphrase,
            args.argon2_iterations,
            args.argon2_memory,
            args.argon2_parallelism,
        ))
    elif args.decrypt:
        with args.key as f:
            encrypted_key = f.read().strip()
        print(decrypt(encrypted_key, args.passphrase))
    







