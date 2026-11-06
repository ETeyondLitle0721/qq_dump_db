#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
std::vector<uint8_t> aes256_cbc_decrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* iv_in, size_t iv_len,
    const uint8_t* ciphertext, size_t ct_len);
std::vector<uint8_t> derive_enc_key(const uint8_t* passphrase, size_t pw_len,
                                    const uint8_t* salt);
bool verify_key_hmac(const uint8_t* page1, const uint8_t* enc_key);
}
