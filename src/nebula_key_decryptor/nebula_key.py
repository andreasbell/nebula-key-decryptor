from email import header

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from .proto_messages import EncryptedKey
import base64
import os

KEY_TYPES = ["ED25519", "ED25519 ENCRYPTED", "ECDSA P256", "ECDSA P256 ENCRYPTED"]
KEY_HEADER = "-----BEGIN NEBULA {} PRIVATE KEY-----"
KEY_FOOTER = "-----END NEBULA {} PRIVATE KEY-----"


def parse_pem_block(text: str) -> tuple[bool, str, str]:
    for key_type in KEY_TYPES:
        start = text.find(KEY_HEADER.format(key_type))
        if start < 0:
            continue
        end = text.find(KEY_FOOTER.format(key_type), start)
        if end < 0:
            continue
        body = text[start + len(KEY_HEADER.format(key_type)):end].strip()
        if key_type.endswith("ENCRYPTED"):
            return True, key_type[:-10], body
        return False, key_type, body
    raise RuntimeError("Incorrectly formated key could not be parsed")


def decrypt(encrypted_key: str, passphrase: str) -> str:
    # Parse protobuf encoded key from key file
    is_encrypted, key_type, b64_encrypted_key = parse_pem_block(encrypted_key)
    binary_encrypted_key = base64.b64decode(b64_encrypted_key)

    if not is_encrypted:
        raise RuntimeError("Key is not encrypted")

    # Deserialize protobuf encoded key
    data = EncryptedKey()
    data.ParseFromString(binary_encrypted_key)

    #print(data)

    # Compute aes encryption key from passphrase
    aes_key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=data.encryptionMetadata.argon2Parameters.salt,
        time_cost=data.encryptionMetadata.argon2Parameters.iterations,
        memory_cost=data.encryptionMetadata.argon2Parameters.memory,
        parallelism=data.encryptionMetadata.argon2Parameters.parallelism,
        hash_len=32,
        type=Type.ID
    )

    # Decrypt key using AES 
    aesgcm = AESGCM(aes_key)
    binary_decrypted_key = aesgcm.decrypt(
        data.ciphertext[0:12], 
        data.ciphertext[12:], 
        None
    )

    # Convert decrypted key to base 64 and add header and footer
    b64_decrypted_key = base64.b64encode(binary_decrypted_key).decode('utf-8')
    lines = [KEY_HEADER.format(key_type)]
    lines += [b64_decrypted_key[i:i+64] for i in range(0, len(b64_decrypted_key), 64)]
    lines += [KEY_FOOTER.format(key_type)   ]
    decrypted_key = "\n".join(lines)

    return decrypted_key


def encrypt(
    decrypted_key: str,
    passphrase: str,
    iterations: int = 3,
    memory: int = 64,
    parallelism: int = 4,
) -> str:
    # Parse key from key file
    is_encrypted, key_type, b64_decrypted_key = parse_pem_block(decrypted_key)
    binary_decrypted_key = base64.b64decode(b64_decrypted_key)

    if is_encrypted:
        raise RuntimeError("Key is already encrypted")

    data = EncryptedKey()
    data.encryptionMetadata.argon2Parameters.version = 19
    data.encryptionMetadata.argon2Parameters.salt = os.urandom(32)
    data.encryptionMetadata.argon2Parameters.iterations = iterations
    data.encryptionMetadata.argon2Parameters.memory = memory
    data.encryptionMetadata.argon2Parameters.parallelism = parallelism
    data.encryptionMetadata.encryptionAlgorithm = "AES-256-GCM"

    # Compute aes encryption key from passphrase
    aes_key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=data.encryptionMetadata.argon2Parameters.salt,
        time_cost=data.encryptionMetadata.argon2Parameters.iterations,
        memory_cost=data.encryptionMetadata.argon2Parameters.memory,
        parallelism=data.encryptionMetadata.argon2Parameters.parallelism,
        hash_len=32,
        type=Type.ID
    )

    # Encrypt key using AES 
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    binary_encrypted_data = aesgcm.encrypt(
        nonce, 
        binary_decrypted_key, 
        None
    )
    data.ciphertext = nonce
    data.ciphertext += binary_encrypted_data

    #print(data)

    # Convert encrypted key to base 64 and add header and footer
    binary_encrypted_key = data.SerializeToString()
    b64_encrypted_key = base64.b64encode(binary_encrypted_key).decode('utf-8')
    lines = [KEY_HEADER.format(key_type + " ENCRYPTED")]
    lines += [b64_encrypted_key[i:i+64] for i in range(0, len(b64_encrypted_key), 64)]
    lines += [KEY_FOOTER.format(key_type + " ENCRYPTED")]
    encrypted_key = "\n".join(lines)

    return encrypted_key