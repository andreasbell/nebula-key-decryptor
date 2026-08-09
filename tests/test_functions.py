def test_encrypt_ed25519():
    from nebula_key_decryptor import encrypt
    key = """
        -----BEGIN NEBULA ED25519 PRIVATE KEY-----
        super+secretkeydatahere+that+is+very+long+and+contains+multiple+lines
        and+is+base64+encoded+so+it+looks+like+this+12345==
        -----END NEBULA ED25519 PRIVATE KEY-----
    """
    passphrase = "test_passphrase"
    encrypted_key = encrypt(key, passphrase)

    print("Encrypted key:", encrypted_key)
    assert isinstance(encrypted_key, str)

def test_decrypt_ed25519():
    from nebula_key_decryptor import decrypt
    encrypted_key = """
        -----BEGIN NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
        CjkKC0FFUy0yNTYtR0NNEioIExBAGAMgBCoghRd5JTJJSOTwEvTUX9saW6KODX2J
        iSgrDtPC9Vx2egcSdC919G4iz4xgTePEfYv5yBCmpp9Wg2MaQw5GJ/rm4H2MSLXN
        +AbjBY0i987Zxa3jsrSVqBj2IVM1AKXvuKx8baBQS88LljyqERmziausAi9hTevE
        eE4rzvgTRkqAga4WtdM+wlicAFJn0bZkykXe2eF6blnv
        -----END NEBULA ED25519 ENCRYPTED PRIVATE KEY-----
    """
    passphrase = "test_passphrase"
    decrypted_key = decrypt(encrypted_key, passphrase)
    assert isinstance(decrypted_key, str)

def test_encrypt_decrypt_ed25519():
    from nebula_key_decryptor import decrypt, encrypt
    key = "-----BEGIN NEBULA ED25519 PRIVATE KEY-----\nshort+secret+key\n-----END NEBULA ED25519 PRIVATE KEY-----"
    passphrase = "test_passphrase"
    encrypted_key = encrypt(key, passphrase)
    decrypted_key = decrypt(encrypted_key, passphrase)
    assert decrypted_key == key

def test_encrypt_P256():
    from nebula_key_decryptor import encrypt
    key = """
        -----BEGIN NEBULA ECDSA P256 PRIVATE KEY-----
        super+secretkeydatahere+that+is+very+long+and+contains+multiple+lines
        and+is+base64+encoded+so+it+looks+like+this+12345==
        -----END NEBULA ECDSA P256 PRIVATE KEY-----
    """
    passphrase = "test_passphrase"
    encrypted_key = encrypt(key, passphrase)
    assert isinstance(encrypted_key, str)

def test_decrypt_P256():
    from nebula_key_decryptor import decrypt
    encrypted_key = """
        -----BEGIN NEBULA ECDSA P256 ENCRYPTED PRIVATE KEY-----
        CjkKC0FFUy0yNTYtR0NNEioIExBAGAMgBCoghRd5JTJJSOTwEvTUX9saW6KODX2J
        iSgrDtPC9Vx2egcSdC919G4iz4xgTePEfYv5yBCmpp9Wg2MaQw5GJ/rm4H2MSLXN
        +AbjBY0i987Zxa3jsrSVqBj2IVM1AKXvuKx8baBQS88LljyqERmziausAi9hTevE
        eE4rzvgTRkqAga4WtdM+wlicAFJn0bZkykXe2eF6blnv
        -----END NEBULA ECDSA P256 ENCRYPTED PRIVATE KEY-----
    """
    passphrase = "test_passphrase"
    decrypted_key = decrypt(encrypted_key, passphrase)
    assert isinstance(decrypted_key, str)

def test_encrypt_decrypt_P256():
    from nebula_key_decryptor import decrypt, encrypt
    key = "-----BEGIN NEBULA ECDSA P256 PRIVATE KEY-----\nshort+secret+key\n-----END NEBULA ECDSA P256 PRIVATE KEY-----"
    passphrase = "test_passphrase"
    encrypted_key = encrypt(key, passphrase)
    decrypted_key = decrypt(encrypted_key, passphrase)
    assert decrypted_key == key

def test_nebula_cert_compatibility():
    import os
    import subprocess
    import tempfile

    from nebula_key_decryptor import decrypt, encrypt

    passphrase = "SuperSecretPassphrase"

    with tempfile.TemporaryDirectory() as temp_dir:
        os.chdir(temp_dir)

        # Set environment passphrasevariable son that nebula-cert can use it
        os.environ["NEBULA_CA_PASSPHRASE"] = passphrase

        # Generate a new CA key using nebula-cert
        subprocess.run(["nebula-cert", "ca", "-name", "test", "-encrypt"], check=True)

        # Generate a new host certificate using the original encrypted CA key
        subprocess.run(["nebula-cert", "sign", "-name", "test1", "-networks", "192.168.1.0/24"], check=True)

        # Read the generated CA key
        with open("ca.key", "r") as f:
            ca_key = f.read()

        # Decrypt the CA key using our decrypt function
        decrypted_key = decrypt(ca_key, passphrase)

        # Write the decrypted key to a file
        with open("ca.key", "w") as f:  
            f.write(decrypted_key)  # Append "abc" to the decrypted key to simulate corruption

        # Generate a new host certificate using the decrypted CA key
        subprocess.run(["nebula-cert", "sign", "-name", "test2", "-networks", "192.168.1.0/24"], check=True)

        # Encrypt the CA key again using our encrypt function
        encrypted_key = encrypt(decrypted_key, passphrase)

        # Write the re-encrypted key to a file
        with open("ca.key", "w") as f:
            f.write(encrypted_key)

        # Generate a new host certificate using the re-encrypted CA key
        subprocess.run(["nebula-cert", "sign", "-name", "test3", "-networks", "192.168.1.0/24"], check=True)
