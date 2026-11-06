#include "qq_dump_db/services/decryptor.hpp"
#include "qq_dump_db/crypto/sqlcipher.hpp"
#include <sqlite3.h>

namespace qq_dump_db {
namespace {
std::vector<uint8_t> decrypt_page(const uint8_t* page_data,
                                  size_t page_len,
                                  const uint8_t* enc_key,
                                  size_t skip_salt = 0) {
    const uint8_t* data = page_data + skip_salt;
    const size_t data_len = page_len - skip_salt;
    const size_t enc_len = data_len - RESERVE;
    const uint8_t* iv = data + enc_len;
    return aes256_cbc_decrypt(enc_key, KEY_SIZE, iv, IV_SIZE, data, enc_len);
}

bool validate_sqlite_database(const fs::path& path) {
    sqlite3* db = nullptr;
    if (sqlite3_open16(path.wstring().c_str(), &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_stmt* statement = nullptr;
    const int prepare_rc = sqlite3_prepare_v2(
        db, "SELECT name FROM sqlite_master WHERE type='table'", -1, &statement, nullptr);
    int table_count = 0;
    if (prepare_rc == SQLITE_OK) {
        int step_rc = SQLITE_OK;
        while ((step_rc = sqlite3_step(statement)) == SQLITE_ROW) ++table_count;
        sqlite3_finalize(statement);
        sqlite3_close(db);
        return step_rc == SQLITE_DONE && table_count > 0;
    }
    if (statement) sqlite3_finalize(statement);
    sqlite3_close(db);
    return false;
}
}

bool decrypt_db(const fs::path& input_path,
                const fs::path& output_path,
                const uint8_t* enc_key) {
    try {
        std::ifstream input(input_path, std::ios::binary);
        if (!input) return false;
        input.seekg(0, std::ios::end);
        const std::streamoff end_position = input.tellg();
        if (end_position <= static_cast<std::streamoff>(EXT_HEADER + PAGE_SIZE)) return false;
        const size_t file_size = static_cast<size_t>(end_position);
        input.seekg(0, std::ios::beg);

        std::vector<uint8_t> file_data(file_size);
        input.read(reinterpret_cast<char*>(file_data.data()), static_cast<std::streamsize>(file_size));
        if (!input || static_cast<size_t>(input.gcount()) != file_size) return false;
        input.close();

        const uint8_t* encrypted_data = file_data.data() + EXT_HEADER;
        const size_t encrypted_length = file_size - EXT_HEADER;
        const size_t total_pages = encrypted_length / PAGE_SIZE;
        if (total_pages == 0) return false;

        std::vector<uint8_t> output;
        output.reserve(total_pages * PAGE_SIZE);
        for (size_t page_number = 1; page_number <= total_pages; ++page_number) {
            const uint8_t* raw_page = encrypted_data + (page_number - 1) * PAGE_SIZE;
            const size_t skip_salt = page_number == 1 ? SALT_SIZE : 0;
            const auto decrypted = decrypt_page(raw_page, PAGE_SIZE, enc_key, skip_salt);
            if (decrypted.empty()) return false;

            if (page_number == 1) {
                std::vector<uint8_t> first_page(PAGE_SIZE, 0);
                static const uint8_t sqlite_header[] = "SQLite format 3";
                std::memcpy(first_page.data(), sqlite_header, 16);
                std::memcpy(first_page.data() + 16, decrypted.data(),
                            std::min(decrypted.size(), PAGE_SIZE - 16));
                first_page[16] = static_cast<uint8_t>(PAGE_SIZE >> 8);
                first_page[17] = static_cast<uint8_t>(PAGE_SIZE & 0xFF);
                output.insert(output.end(), first_page.begin(), first_page.end());
            } else {
                output.insert(output.end(), decrypted.begin(), decrypted.end());
                if (decrypted.size() < PAGE_SIZE)
                    output.insert(output.end(), PAGE_SIZE - decrypted.size(), 0);
            }
        }

        const fs::path parent = output_path.parent_path();
        if (!parent.empty()) fs::create_directories(parent);
        fs::path temporary_path = output_path;
        temporary_path += L".tmp." + std::to_wstring(GetCurrentProcessId());
        {
            std::ofstream file(temporary_path, std::ios::binary | std::ios::trunc);
            if (!file) return false;
            file.write(reinterpret_cast<const char*>(output.data()),
                       static_cast<std::streamsize>(output.size()));
            file.flush();
            if (!file.good()) {
                file.close();
                fs::remove(temporary_path);
                return false;
            }
        }

        if (!validate_sqlite_database(temporary_path)) {
            fs::remove(temporary_path);
            return false;
        }
        const std::wstring temporary_wide = temporary_path.wstring();
        const std::wstring output_wide = output_path.wstring();
        if (!MoveFileExW(temporary_wide.c_str(), output_wide.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            fs::remove(temporary_path);
            return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}
} // namespace qq_dump_db
