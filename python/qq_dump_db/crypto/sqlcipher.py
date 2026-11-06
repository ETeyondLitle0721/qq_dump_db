"""SQLCipher page verification and database decryption helpers."""
import hashlib
import hmac as hmac_mod
import os
import sqlite3
import struct
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

EXT_HEADER  = 1024
PAGE_SIZE   = 4096
SALT_SIZE   = 16
KEY_SIZE    = 32
IV_SIZE     = 16
HMAC_SIZE   = 20
RESERVE     = 48
HMAC_MASK   = 0x3a
KDF_ITER    = 4000
FAST_ITER   = 2

PRE_LOGIN_KEY = b"BD156D6710D54D8782F4"  # hardcoded in wrapper.node


def verify_key_hmac(page1_data, enc_key_bytes):
    """Validate enc_key against page 1 HMAC-SHA1."""
    salt = page1_data[:SALT_SIZE]
    hmac_salt = bytes(b ^ HMAC_MASK for b in salt)
    hmac_key = hashlib.pbkdf2_hmac('sha512', enc_key_bytes, hmac_salt, FAST_ITER, KEY_SIZE)
    data_end = PAGE_SIZE - RESERVE            # 4048
    # Page 1 HMAC skips the 16-byte salt prefix
    content  = page1_data[SALT_SIZE:data_end]
    iv       = page1_data[data_end:data_end + IV_SIZE]
    stored   = page1_data[data_end + IV_SIZE:data_end + IV_SIZE + HMAC_SIZE]
    # Page number is little-endian (not big-endian as RE doc states)
    computed = hmac_mod.new(hmac_key, content + iv + struct.pack('<I', 1), hashlib.sha1).digest()
    return hmac_mod.compare_digest(computed, stored)


def derive_enc_key(passphrase, salt):
    return hashlib.pbkdf2_hmac('sha512', passphrase, salt, KDF_ITER, KEY_SIZE)


def derive_hmac_key(enc_key_bytes, salt):
    hmac_salt = bytes(b ^ HMAC_MASK for b in salt)
    return hashlib.pbkdf2_hmac('sha512', enc_key_bytes, hmac_salt, FAST_ITER, KEY_SIZE)


def decrypt_page(page_data, enc_key, skip_salt=0):
    """Decrypt a single SQLCipher page (AES-256-CBC)."""
    data = page_data[skip_salt:]
    encrypted = data[:len(data) - RESERVE]
    iv = data[len(data) - RESERVE:len(data) - RESERVE + IV_SIZE]
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    dec = cipher.decryptor()
    return dec.update(encrypted) + dec.finalize()


def decrypt_db(input_path, output_path, enc_key_bytes):
    """Decrypt to a same-directory temporary file, validate, then replace atomically."""
    output_path = os.path.abspath(os.fspath(output_path))
    input_path = os.path.abspath(os.fspath(input_path))
    if os.path.normcase(input_path) == os.path.normcase(output_path):
        raise ValueError("Input and output database paths must be different.")
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    temp_path = None
    try:
        with open(input_path, "rb") as source:
            file_data = source.read()
        sc_data = file_data[EXT_HEADER:]
        if len(sc_data) < PAGE_SIZE:
            return False

        total_pages = len(sc_data) // PAGE_SIZE
        fd, temp_path = tempfile.mkstemp(prefix=".qq_dump_db_", suffix=".tmp", dir=os.path.dirname(output_path) or ".")
        with os.fdopen(fd, "wb") as destination:
            for pgno in range(1, total_pages + 1):
                page_start = (pgno - 1) * PAGE_SIZE
                page_raw = sc_data[page_start:page_start + PAGE_SIZE]
                skip = SALT_SIZE if pgno == 1 else 0
                decrypted = decrypt_page(page_raw, enc_key_bytes, skip_salt=skip)
                if pgno == 1:
                    full = bytearray(b"SQLite format 3\x00" + decrypted)
                    full[16:18] = struct.pack(">H", PAGE_SIZE)
                    full[20] = 0
                    full = full[:PAGE_SIZE]
                    if len(full) < PAGE_SIZE:
                        full.extend(b"\x00" * (PAGE_SIZE - len(full)))
                    destination.write(full)
                else:
                    destination.write(decrypted)
                    pad = PAGE_SIZE - len(decrypted)
                    if pad > 0:
                        destination.write(b"\x00" * pad)
            destination.flush()
            os.fsync(destination.fileno())

        # Open read-only and verify the system catalog before publishing.
        uri = Path(temp_path).as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cur.fetchall()
            if not tables:
                return False
        finally:
            conn.close()

        os.replace(temp_path, output_path)
        temp_path = None
        return True
    except (OSError, sqlite3.Error, ValueError):
        return False
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
