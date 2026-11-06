#include "qq_dump_db/crypto/sqlcipher.hpp"

namespace qq_dump_db {
// ── Crypto helpers (Windows BCrypt) ─────────────────────────────────────────

static bool pbkdf2_sha512(const uint8_t* password, size_t pw_len,
                           const uint8_t* salt, size_t salt_len,
                           int iterations,
                           uint8_t* derived, size_t dk_len)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA512_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st)) return false;

    st = BCryptDeriveKeyPBKDF2(
        hAlg,
        const_cast<PUCHAR>(password), static_cast<ULONG>(pw_len),
        const_cast<PUCHAR>(salt),     static_cast<ULONG>(salt_len),
        iterations, derived, static_cast<ULONG>(dk_len), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(st);
}

static bool hmac_sha1(const uint8_t* key, size_t key_len,
                       const uint8_t* data, size_t data_len,
                       uint8_t* output)
{
    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        return false;

    if (!BCRYPT_SUCCESS(BCryptCreateHash(
            hAlg, &hHash, nullptr, 0,
            const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    bool ok = BCRYPT_SUCCESS(BCryptHashData(
                  hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0)) &&
              BCRYPT_SUCCESS(BCryptFinishHash(hHash, output, HMAC_SIZE, 0));

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

 std::vector<uint8_t> aes256_cbc_decrypt(
    const uint8_t* key,        size_t key_len,
    const uint8_t* iv_in,      size_t iv_len,
    const uint8_t* ciphertext, size_t ct_len)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    std::vector<uint8_t> result;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                               const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);

    // IV is modified in-place by BCrypt – work on a copy
    std::vector<uint8_t> iv_copy(iv_in, iv_in + iv_len);

    // For AES-CBC without padding, output size == input size
    result.resize(ct_len);
    ULONG out_len = 0;
    BCryptDecrypt(hKey,
                  const_cast<PUCHAR>(ciphertext), static_cast<ULONG>(ct_len),
                  nullptr,
                  iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
                  result.data(),  static_cast<ULONG>(ct_len),
                  &out_len, 0);
    result.resize(out_len);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// ── Key derivation / verification ───────────────────────────────────────────

 std::vector<uint8_t> derive_enc_key(const uint8_t* passphrase,
                                            size_t pw_len,
                                            const uint8_t* salt)
{
    std::vector<uint8_t> key(KEY_SIZE);
    pbkdf2_sha512(passphrase, pw_len, salt, SALT_SIZE, KDF_ITER,
                  key.data(), KEY_SIZE);
    return key;
}

 bool verify_key_hmac(const uint8_t* page1, const uint8_t* enc_key)
{
    // Derive HMAC key
    uint8_t hmac_salt[SALT_SIZE];
    for (size_t i = 0; i < SALT_SIZE; ++i)
        hmac_salt[i] = page1[i] ^ HMAC_MASK;

    uint8_t hmac_key[KEY_SIZE];
    pbkdf2_sha512(enc_key, KEY_SIZE, hmac_salt, SALT_SIZE, FAST_ITER,
                  hmac_key, KEY_SIZE);

    const size_t data_end = PAGE_SIZE - RESERVE;          // 4048

    // HMAC input: content (after salt) + iv + page_number (LE u32)
    const size_t content_len   = data_end - SALT_SIZE;    // 4032
    const size_t hmac_in_len   = content_len + IV_SIZE + 4;
    std::vector<uint8_t> hmac_in(hmac_in_len);

    std::memcpy(hmac_in.data(),                        page1 + SALT_SIZE, content_len);
    std::memcpy(hmac_in.data() + content_len,          page1 + data_end,  IV_SIZE);
    uint32_t pgno = 1;                                   // little-endian
    std::memcpy(hmac_in.data() + content_len + IV_SIZE, &pgno, 4);

    uint8_t computed[HMAC_SIZE];
    hmac_sha1(hmac_key, KEY_SIZE, hmac_in.data(), hmac_in_len, computed);

    const uint8_t* stored = page1 + data_end + IV_SIZE;

    // Constant-time compare
    uint8_t diff = 0;
    for (size_t i = 0; i < HMAC_SIZE; ++i)
        diff |= computed[i] ^ stored[i];
    return diff == 0;
}

// ── Process helpers ─────────────────────────────────────────────────────────

} // namespace qq_dump_db
