#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║         File Encryptor v2.0                 ║
║  AES-128 (Fernet) + PBKDF2 + SHA-256        ║
╚══════════════════════════════════════════════╝

Improvements over v1:
  - Password-based key derivation (PBKDF2HMAC + SHA-256)
  - Salt & IV embedded in .enc file header (no secret.key needed)
  - SHA-256 integrity check on decryption
  - Batch encrypt/decrypt multiple files (glob support)
  - Option to securely shred original after encryption
  - Colored terminal output
  - Persistent menu loop
  - Full error handling
"""

import os
import sys
import glob
import hashlib
import struct
import getpass
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    import base64
except ImportError:
    print("[-] Missing dependency: run  pip install cryptography")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN   = Fore.GREEN   + Style.BRIGHT
    RED     = Fore.RED     + Style.BRIGHT
    YELLOW  = Fore.YELLOW  + Style.BRIGHT
    CYAN    = Fore.CYAN    + Style.BRIGHT
    MAGENTA = Fore.MAGENTA + Style.BRIGHT
    RESET   = Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = CYAN = MAGENTA = RESET = ""

# ──────────────────────────────────────────────
# Header layout inside .enc file
#   [4 bytes]  magic "FENC"
#   [2 bytes]  version (0x0002)
#   [16 bytes] salt
#   [32 bytes] SHA-256 of original plaintext
#   [N bytes]  Fernet-encrypted ciphertext
# ──────────────────────────────────────────────
MAGIC   = b"FENC"
VERSION = struct.pack(">H", 2)
SALT_LEN = 16
HASH_LEN = 32
HEADER_LEN = len(MAGIC) + len(VERSION) + SALT_LEN + HASH_LEN
PBKDF2_ITERATIONS = 100_000  # NIST SP 800-132 minimum recommendation


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet-compatible key from a password + salt via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def shred_file(path: str, passes: int = 3):
    """Overwrite file with random bytes before deletion."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    os.remove(path)


def human_size(n_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n_bytes < 1024:
            return f"{n_bytes:.1f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.1f} TB"


# ──────────────────────────────────────────────
# Core operations
# ──────────────────────────────────────────────

def encrypt_file(filepath: str, password: str, shred_original: bool = False) -> bool:
    if not os.path.isfile(filepath):
        print(f"{RED}[-] File not found: {filepath}")
        return False
    if filepath.endswith(".enc"):
        print(f"{YELLOW}[!] Skipping already-encrypted file: {filepath}")
        return False

    try:
        with open(filepath, "rb") as f:
            plaintext = f.read()

        original_hash = hashlib.sha256(plaintext).digest()
        salt = os.urandom(SALT_LEN)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        ciphertext = fernet.encrypt(plaintext)

        out_path = filepath + ".enc"
        with open(out_path, "wb") as f:
            f.write(MAGIC)
            f.write(VERSION)
            f.write(salt)
            f.write(original_hash)
            f.write(ciphertext)

        orig_size = len(plaintext)
        enc_size  = os.path.getsize(out_path)
        print(f"{GREEN}[+] Encrypted  : {filepath}")
        print(f"    {CYAN}Output     : {out_path}")
        print(f"    {CYAN}Size       : {human_size(orig_size)} → {human_size(enc_size)}")
        print(f"    {CYAN}SHA-256    : {original_hash.hex()[:16]}…  (embedded in header)")

        if shred_original:
            shred_file(filepath)
            print(f"    {YELLOW}[~] Original shredded (3-pass overwrite)")

        return True

    except PermissionError:
        print(f"{RED}[-] Permission denied: {filepath}")
    except Exception as e:
        print(f"{RED}[-] Encryption failed for {filepath}: {e}")
    return False


def decrypt_file(filepath: str, password: str, shred_enc: bool = False) -> bool:
    if not os.path.isfile(filepath):
        print(f"{RED}[-] File not found: {filepath}")
        return False
    if not filepath.endswith(".enc"):
        print(f"{YELLOW}[!] File does not have .enc extension: {filepath}")

    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        # Validate header
        if len(raw) < HEADER_LEN:
            print(f"{RED}[-] File too small — possibly corrupt or not encrypted by this tool.")
            return False
        if raw[:4] != MAGIC:
            print(f"{RED}[-] Invalid magic bytes — file may not have been encrypted by this tool.")
            return False

        salt          = raw[6 : 6 + SALT_LEN]
        stored_hash   = raw[6 + SALT_LEN : HEADER_LEN]
        ciphertext    = raw[HEADER_LEN:]

        key    = derive_key(password, salt)
        fernet = Fernet(key)

        try:
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken:
            print(f"{RED}[-] Decryption failed — wrong password or corrupted file.")
            return False

        # Integrity check
        computed_hash = hashlib.sha256(plaintext).digest()
        if computed_hash != stored_hash:
            print(f"{RED}[-] INTEGRITY CHECK FAILED — file may be tampered!")
            return False

        out_path = filepath[:-4] if filepath.endswith(".enc") else filepath + ".dec"
        if os.path.exists(out_path):
            overwrite = input(f"    {YELLOW}[?] {out_path} already exists. Overwrite? [y/N]: ").strip().lower()
            if overwrite != "y":
                print(f"{YELLOW}[!] Skipped: {filepath}")
                return False

        with open(out_path, "wb") as f:
            f.write(plaintext)

        print(f"{GREEN}[+] Decrypted  : {filepath}")
        print(f"    {CYAN}Output     : {out_path}")
        print(f"    {CYAN}Size       : {human_size(len(plaintext))}")
        print(f"    {GREEN}[✓] Integrity check passed")

        if shred_enc:
            shred_file(filepath)
            print(f"    {YELLOW}[~] Encrypted file shredded")

        return True

    except PermissionError:
        print(f"{RED}[-] Permission denied: {filepath}")
    except Exception as e:
        print(f"{RED}[-] Decryption error for {filepath}: {e}")
    return False


# ──────────────────────────────────────────────
# Menu helpers
# ──────────────────────────────────────────────

def get_password(confirm: bool = False) -> str:
    while True:
        pwd = getpass.getpass(f"    {CYAN}Enter password: ")
        if not pwd:
            print(f"{YELLOW}    [!] Password cannot be empty.")
            continue
        if confirm:
            pwd2 = getpass.getpass(f"    {CYAN}Confirm password: ")
            if pwd != pwd2:
                print(f"{RED}    [-] Passwords do not match. Try again.")
                continue
        return pwd


def resolve_paths(raw_input: str) -> list[str]:
    """Expand wildcards and return a list of matching file paths."""
    paths = []
    for token in raw_input.split(","):
        token = token.strip()
        expanded = glob.glob(token)
        if expanded:
            paths.extend(expanded)
        elif token:
            paths.append(token)   # keep as-is (will fail gracefully later)
    return paths


def banner():
    print(f"""
{MAGENTA}╔══════════════════════════════════════════════╗
║  {GREEN}File Encryptor v2.0{MAGENTA}                         ║
║  {CYAN}AES-128-CBC (Fernet) · PBKDF2 · SHA-256{MAGENTA}     ║
╚══════════════════════════════════════════════╝{RESET}""")


def menu():
    banner()
    while True:
        print(f"""
{CYAN}  [1]{RESET} Encrypt file(s)
{CYAN}  [2]{RESET} Decrypt file(s)
{CYAN}  [3]{RESET} About / How it works
{CYAN}  [0]{RESET} Exit
""")
        choice = input(f"{CYAN}  >{RESET} ").strip()

        if choice == "1":
            raw = input(f"  {CYAN}File(s) to encrypt (comma-separated, wildcards OK): {RESET}")
            files = resolve_paths(raw)
            if not files:
                print(f"{YELLOW}[!] No matching files found.")
                continue
            print(f"  {CYAN}Found {len(files)} file(s): {', '.join(files)}")
            password = get_password(confirm=True)
            shred = input(f"  {YELLOW}Shred original file(s) after encryption? [y/N]: {RESET}").strip().lower() == "y"
            print()
            ok = sum(encrypt_file(fp, password, shred) for fp in files)
            print(f"\n{GREEN}[✓] Done — {ok}/{len(files)} file(s) encrypted successfully.")

        elif choice == "2":
            raw = input(f"  {CYAN}File(s) to decrypt (comma-separated, wildcards OK): {RESET}")
            files = resolve_paths(raw)
            if not files:
                print(f"{YELLOW}[!] No matching files found.")
                continue
            print(f"  {CYAN}Found {len(files)} file(s): {', '.join(files)}")
            password = get_password(confirm=False)
            shred = input(f"  {YELLOW}Delete encrypted file(s) after decryption? [y/N]: {RESET}").strip().lower() == "y"
            print()
            ok = sum(decrypt_file(fp, password, shred) for fp in files)
            print(f"\n{GREEN}[✓] Done — {ok}/{len(files)} file(s) decrypted successfully.")

        elif choice == "3":
            print(f"""
{CYAN}  How File Encryptor v2.0 works:
{RESET}
  Encryption:
    1. A random 16-byte salt is generated per file.
    2. Your password is stretched into a 256-bit key using
       PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS:,} iterations).
    3. The file is encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
    4. A SHA-256 hash of the original plaintext is stored in the
       file header for integrity verification on decryption.
    5. Output: [FENC magic][version][salt][sha256][ciphertext]

  Decryption:
    1. Salt is read from the header and used to re-derive the key.
    2. Fernet decrypts the ciphertext (HMAC verified automatically).
    3. SHA-256 of decrypted data is compared with the stored hash.
    4. File is written only if both checks pass.

  {YELLOW}Why no secret.key file?
{RESET}  The salt is stored inside the .enc file, so anyone with the
  correct password can decrypt — no key file to lose or leak.
""")

        elif choice == "0":
            print(f"\n{CYAN}  Goodbye. Stay encrypted. 🔐{RESET}\n")
            break

        else:
            print(f"{YELLOW}  [!] Invalid choice.")


if __name__ == "__main__":
    menu()