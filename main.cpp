/*
 * Auto-dump NTQQ SQLCipher database keys from a running QQ process.
 *
 * Zero prior knowledge required - no hardcoded PIDs, keys, addresses, or salts.
 * Finds the QQ main process (wrapper.node), scans memory for x'key_salt' patterns.
 *
 * Usage (run as Administrator):
 *     qq_dump_db.exe --qq 10001
 *     qq_dump_db.exe --qq 10001 --pid 12345
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

#include "sqlite3.h"

#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;

// ── SQLCipher constants ─────────────────────────────────────────────────────

static constexpr size_t   EXT_HEADER = 1024;
static constexpr size_t   PAGE_SIZE  = 4096;
static constexpr size_t   SALT_SIZE  = 16;
static constexpr size_t   KEY_SIZE   = 32;
static constexpr size_t   IV_SIZE    = 16;
static constexpr size_t   HMAC_SIZE  = 20;
static constexpr size_t   RESERVE    = 48;
static constexpr uint8_t  HMAC_MASK  = 0x3a;
static constexpr int      KDF_ITER   = 4000;
static constexpr int      FAST_ITER  = 2;

static const uint8_t PRE_LOGIN_KEY[]   = "BD156D6710D54D8782F4";
static constexpr size_t PRE_LOGIN_KEY_LEN = sizeof(PRE_LOGIN_KEY) - 1; // 20

// ── Windows memory scan constants ───────────────────────────────────────────

static constexpr DWORD  MEM_COMMIT_FLAG = 0x1000;
static constexpr size_t MAX_REGION      = 256ULL * 1024 * 1024;

static const std::set<DWORD> READABLE_PROTS = {
    0x02, 0x04, 0x06, 0x08, 0x20, 0x40, 0x60, 0x80
};

// ── Hex utilities ───────────────────────────────────────────────────────────

static std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

static bool is_hex_char(uint8_t c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

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

static std::vector<uint8_t> aes256_cbc_decrypt(
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

static std::vector<uint8_t> derive_enc_key(const uint8_t* passphrase,
                                            size_t pw_len,
                                            const uint8_t* salt)
{
    std::vector<uint8_t> key(KEY_SIZE);
    pbkdf2_sha512(passphrase, pw_len, salt, SALT_SIZE, KDF_ITER,
                  key.data(), KEY_SIZE);
    return key;
}

static bool verify_key_hmac(const uint8_t* page1, const uint8_t* enc_key)
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

static std::vector<DWORD> find_qq_pids()
{
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring name(pe.szExeFile);
            std::transform(name.begin(), name.end(), name.begin(), ::towlower);
            if (name == L"qq.exe")
                pids.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}

static bool pid_has_module(DWORD pid, const wchar_t* module_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    std::wstring target(module_name);
    std::transform(target.begin(), target.end(), target.begin(), ::towlower);

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            std::wstring mod(me.szModule);
            std::transform(mod.begin(), mod.end(), mod.begin(), ::towlower);
            if (mod == target) { found = true; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

static DWORD find_qq_main_pid()
{
    auto pids = find_qq_pids();
    if (pids.empty()) return 0;

    std::cout << "QQ PIDs:";
    for (auto p : pids) std::cout << " " << p;
    std::cout << "\n";

    for (auto pid : pids) {
        if (pid_has_module(pid, L"wrapper.node")) {
            std::cout << "  PID " << pid << " has wrapper.node -> main process\n";
            return pid;
        }
    }
    std::cout << "  WARNING: wrapper.node not found, trying first PID "
              << pids[0] << "\n";
    return pids[0];
}

// ── DB discovery ────────────────────────────────────────────────────────────

struct DbInfo {
    std::string          account;
    fs::path             filepath;
    std::vector<uint8_t> page1;   // PAGE_SIZE bytes
};

static fs::path get_nt_db_base()
{
    wchar_t buf[MAX_PATH];
    ExpandEnvironmentStringsW(
        L"%USERPROFILE%\\Documents\\Tencent Files", buf, MAX_PATH);
    return fs::path(buf);
}

static std::pair<std::vector<DbInfo>,
                 std::map<std::string, std::vector<DbInfo>>>
find_and_collect_dbs(const std::string& qq_number,
                     const std::string& custom_db_dir = "")
{
    std::vector<DbInfo>                        global_dbs;
    std::map<std::string, std::vector<DbInfo>> pa_map;   // salt_hex -> DBs

    struct Dir { std::string account; fs::path path; };
    std::vector<Dir> dirs;

    if (!custom_db_dir.empty()) {
        // User-specified directory: scan it recursively for .db files
        fs::path custom(custom_db_dir);
        if (fs::is_directory(custom)) {
            dirs.push_back({qq_number, custom});
        } else {
            std::cerr << "ERROR: --db-dir path not found: " << custom << "\n";
        }
    } else {
        const fs::path base = get_nt_db_base();

        auto gdir = base / "nt_qq" / "global" / "nt_db";
        if (fs::is_directory(gdir))
            dirs.push_back({"global", gdir});

        auto adir = base / qq_number / "nt_qq" / "nt_db";
        if (fs::is_directory(adir))
            dirs.push_back({qq_number, adir});
        else
            std::cerr << "ERROR: DB dir not found: " << adir << "\n";
    }

    static const uint8_t SQLITE_HDR[] = "SQLite header 3";

    for (auto& [account, dir] : dirs) {
        for (auto& entry : fs::directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;
            auto ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext != ".db") continue;

            std::ifstream f(entry.path(), std::ios::binary);
            if (!f) continue;

            std::vector<uint8_t> hdr(EXT_HEADER + PAGE_SIZE);
            f.read(reinterpret_cast<char*>(hdr.data()),
                   static_cast<std::streamsize>(hdr.size()));
            if (static_cast<size_t>(f.gcount()) < EXT_HEADER + PAGE_SIZE)
                continue;

            if (std::memcmp(hdr.data(), SQLITE_HDR, 16) != 0)
                continue;

            DbInfo info;
            info.account  = account;
            info.filepath = entry.path();
            info.page1.assign(hdr.begin() + EXT_HEADER,
                              hdr.begin() + EXT_HEADER + PAGE_SIZE);

            std::string salt_hex = to_hex(info.page1.data(), SALT_SIZE);

            if (account == "global")
                global_dbs.push_back(std::move(info));
            else
                pa_map[salt_hex].push_back(std::move(info));
        }
    }
    return {global_dbs, pa_map};
}

// ── Memory scanner ──────────────────────────────────────────────────────────

struct ScanHit {
    uintptr_t   addr;
    std::string  key_hex;
};

static std::map<std::string, ScanHit>
scan_by_salt(HANDLE handle, const std::vector<std::string>& salt_hexes)
{
    std::map<std::string, ScanHit> results;
    std::set<std::string> remaining(salt_hexes.begin(), salt_hexes.end());

    size_t total = 0;
    auto t0 = std::chrono::steady_clock::now();

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;

    while (true) {
        if (VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(addr),
                           &mbi, sizeof(mbi)) == 0)
            break;

        auto base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        size_t size = mbi.RegionSize;

        if (mbi.State == MEM_COMMIT &&
            READABLE_PROTS.count(mbi.Protect & 0xFF) &&
            size > 0 && size <= MAX_REGION)
        {
            std::vector<uint8_t> data(size);
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(base),
                                  data.data(), size, &bytes_read) &&
                bytes_read > 0)
            {
                data.resize(bytes_read);
                total += bytes_read;

                for (auto it = remaining.begin(); it != remaining.end(); ) {
                    const std::string& sh = *it;
                    const auto* needle =
                        reinterpret_cast<const uint8_t*>(sh.c_str());
                    const size_t nlen = sh.size();   // 32

                    bool found = false;
                    size_t off = 0;
                    while (off + nlen <= bytes_read) {
                        auto pos = std::search(
                            data.begin() + off,
                            data.begin() + bytes_read,
                            needle, needle + nlen);
                        if (pos == data.begin() + static_cast<ptrdiff_t>(bytes_read))
                            break;

                        size_t idx = static_cast<size_t>(
                            pos - data.begin());

                        // Verify pattern: x'<64 hex key><32 hex salt>'
                        if (idx >= 66 && idx + 33 <= bytes_read &&
                            data[idx - 66] == 'x' &&
                            data[idx - 65] == '\'' &&
                            data[idx + 32] == '\'')
                        {
                            bool all_hex = true;
                            for (size_t j = idx - 64; j < idx; ++j) {
                                if (!is_hex_char(data[j])) {
                                    all_hex = false;
                                    break;
                                }
                            }
                            if (all_hex) {
                                std::string key_hex(
                                    data.begin() + idx - 64,
                                    data.begin() + idx);
                                std::transform(key_hex.begin(),
                                               key_hex.end(),
                                               key_hex.begin(), ::tolower);
                                results[sh] = {base + idx - 66, key_hex};
                                found = true;
                                break;
                            }
                        }
                        off = idx + 1;
                    }

                    if (found) it = remaining.erase(it);
                    else       ++it;
                }
            }
        }

        uintptr_t nxt = base + size;
        if (nxt <= addr || nxt >= 0x7FFFFFFFFFFF) break;
        addr = nxt;
    }

    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    std::cout << "  Scanned " << (total / 1048576) << " MB in "
              << std::fixed << std::setprecision(1) << elapsed << "s -> "
              << results.size() << "/" << salt_hexes.size()
              << " salts matched\n";
    return results;
}

// ── Page / DB decryption ────────────────────────────────────────────────────

static std::vector<uint8_t> decrypt_page(const uint8_t* page_data,
                                          size_t page_len,
                                          const uint8_t* enc_key,
                                          size_t skip_salt = 0)
{
    const uint8_t* data     = page_data + skip_salt;
    const size_t   data_len = page_len  - skip_salt;
    const size_t   enc_len  = data_len  - RESERVE;
    const uint8_t* iv       = data + enc_len;

    return aes256_cbc_decrypt(enc_key, KEY_SIZE, iv, IV_SIZE, data, enc_len);
}

static bool decrypt_db(const fs::path& input_path,
                        const fs::path& output_path,
                        const uint8_t*  enc_key)
{
    std::ifstream fin(input_path, std::ios::binary);
    if (!fin) return false;

    fin.seekg(0, std::ios::end);
    const auto file_size = static_cast<size_t>(fin.tellg());
    fin.seekg(0);
    if (file_size <= EXT_HEADER + PAGE_SIZE) return false;

    std::vector<uint8_t> file_data(file_size);
    fin.read(reinterpret_cast<char*>(file_data.data()),
             static_cast<std::streamsize>(file_size));
    fin.close();

    const uint8_t* sc_data = file_data.data() + EXT_HEADER;
    const size_t   sc_len  = file_size - EXT_HEADER;
    const size_t   total_pages = sc_len / PAGE_SIZE;

    std::vector<uint8_t> output;
    output.reserve(total_pages * PAGE_SIZE);

    for (size_t pgno = 1; pgno <= total_pages; ++pgno) {
        const uint8_t* page_raw = sc_data + (pgno - 1) * PAGE_SIZE;
        size_t skip = (pgno == 1) ? SALT_SIZE : 0;

        auto dec = decrypt_page(page_raw, PAGE_SIZE, enc_key, skip);

        if (pgno == 1) {
            // Rebuild the standard SQLite header
            std::vector<uint8_t> full(PAGE_SIZE, 0);
            static const uint8_t FMT_HDR[] = "SQLite format 3";
            std::memcpy(full.data(), FMT_HDR, 16);
            std::memcpy(full.data() + 16, dec.data(),
                        std::min(dec.size(), PAGE_SIZE - 16));
            // Page size (big-endian)
            full[16] = static_cast<uint8_t>(PAGE_SIZE >> 8);
            full[17] = static_cast<uint8_t>(PAGE_SIZE & 0xFF);
            // Preserve the original reserved-bytes-per-page value (byte 20).
            // NTQQ's SQLCipher uses reserved=80 for B-tree layout (usable=4016)
            // even though the crypto reserve (IV+HMAC) is only 48 bytes.
            // Setting it to 0 would cause SQLite to misinterpret overflow
            // pointers and report "database disk image is malformed".
            output.insert(output.end(), full.begin(), full.end());
        } else {
            output.insert(output.end(), dec.begin(), dec.end());
            if (dec.size() < PAGE_SIZE)
                output.insert(output.end(), PAGE_SIZE - dec.size(), 0);
        }
    }

    std::ofstream fout(output_path, std::ios::binary);
    fout.write(reinterpret_cast<const char*>(output.data()),
               static_cast<std::streamsize>(output.size()));
    fout.close();

    // Quick validation with sqlite3
    sqlite3* db = nullptr;
    if (sqlite3_open(output_path.string().c_str(), &db) != SQLITE_OK)
        return false;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(
        db, "SELECT name FROM sqlite_master WHERE type='table'",
        -1, &stmt, nullptr);
    int table_count = 0;
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) ++table_count;
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return table_count > 0;
}
// ── Process wait helper ──────────────────────────────────────────────────

static bool is_process_alive(DWORD pid)
{
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return false;
    DWORD ret = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return ret == WAIT_TIMEOUT;   // still running
}

static void wait_for_process_exit(DWORD pid, int timeout_sec = 300)
{
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return;
    WaitForSingleObject(h, timeout_sec * 1000);
    CloseHandle(h);
}
// ── Argument parsing ────────────────────────────────────────────────────────

struct Args {
    std::string qq;
    DWORD       pid    = 0;
    std::string output = "key_map.json";
    std::string db_dir;   // optional: override DB search directory
};

static Args parse_args(int argc, char** argv)
{
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if (a == "--qq"  && i + 1 < argc)                args.qq     = argv[++i];
        else if (a == "--pid" && i + 1 < argc)            args.pid    = std::stoul(argv[++i]);
        else if ((a == "-o" || a == "--output") && i + 1 < argc)
                                                          args.output = argv[++i];
        else if (a == "--db-dir" && i + 1 < argc)         args.db_dir = argv[++i];
    }
    if (args.qq.empty()) {
        std::cerr << "Usage: qq_dump_db --qq <QQ_NUMBER> [--pid PID] "
                     "[--db-dir DIR] [-o output.json]\n";
        std::exit(1);
    }
    return args;
}

// ── Main ────────────────────────────────────────────────────────────────────

int main(int argc, char** argv)
{
    auto args = parse_args(argc, argv);

    // 1. Find QQ main process
    DWORD main_pid;
    if (args.pid) {
        main_pid = args.pid;
        std::cout << "Using PID: " << main_pid << "\n";
    } else {
        main_pid = find_qq_main_pid();
        if (!main_pid) {
            std::cerr << "ERROR: No QQ.exe found. Start QQ or use --pid.\n";
            return 1;
        }
    }

    // 2. Discover DBs
    auto [global_dbs, pa_salt_map] = find_and_collect_dbs(args.qq, args.db_dir);

    size_t pa_files = 0;
    for (auto& [k, v] : pa_salt_map) pa_files += v.size();

    std::cout << "\nGlobal DBs: " << global_dbs.size()
              << "  (fixed key, no scan)\n"
              << "Per-account: " << pa_files << " files, "
              << pa_salt_map.size() << " unique salts\n";

    if (pa_salt_map.empty() && global_dbs.empty()) {
        std::cerr << "ERROR: No NTQQ databases found.\n";
        return 1;
    }

    // 3. Global DBs: fixed PRE_LOGIN_KEY
    std::map<std::string, std::string> global_results;   // salt_hex -> key_hex
    for (auto& info : global_dbs) {
        auto enc_key = derive_enc_key(PRE_LOGIN_KEY, PRE_LOGIN_KEY_LEN,
                                      info.page1.data());
        auto fn = info.filepath.filename().string();
        std::string sh = to_hex(info.page1.data(), SALT_SIZE);
        if (verify_key_hmac(info.page1.data(), enc_key.data())) {
            global_results[sh] = to_hex(enc_key.data(), KEY_SIZE);
            std::cout << "  [global] " << fn << ": OK\n";
        } else {
            std::cout << "  [global] " << fn << ": HMAC mismatch\n";
        }
    }

    // 4. Per-account DBs: memory scan
    std::map<std::string, std::string> results;          // salt_hex -> key_hex
    if (!pa_salt_map.empty()) {
        HANDLE handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, main_pid);
        if (!handle) {
            std::cerr << "Cannot open PID " << main_pid
                      << " (err " << GetLastError() << ")\n";
            return 1;
        }

        std::vector<std::string> salt_list;
        salt_list.reserve(pa_salt_map.size());
        for (auto& [k, v] : pa_salt_map) salt_list.push_back(k);

        std::cout << "\n-- Scanning PID " << main_pid << " for "
                  << salt_list.size() << " known salts --\n";
        auto scan_hits = scan_by_salt(handle, salt_list);

        for (auto& [salt_hex, hit] : scan_hits) {
            auto enc_key = from_hex(hit.key_hex);
            auto& page1  = pa_salt_map[salt_hex][0].page1;
            if (verify_key_hmac(page1.data(), enc_key.data())) {
                results[salt_hex] = hit.key_hex;
                auto fn = pa_salt_map[salt_hex][0].filepath.filename().string();
                std::cout << "  [hit] " << fn << ": key="
                          << hit.key_hex.substr(0, 16) << ".. @ 0x"
                          << std::hex << std::uppercase << hit.addr
                          << std::dec << "\n";
            }
        }
        CloseHandle(handle);
    }

    // 5. Output summary
    std::map<std::string, std::string> all_results;
    all_results.insert(global_results.begin(), global_results.end());
    all_results.insert(results.begin(), results.end());

    std::set<std::string> total_salt_set;
    for (auto& info : global_dbs)
        total_salt_set.insert(to_hex(info.page1.data(), SALT_SIZE));
    for (auto& [k, v] : pa_salt_map)
        total_salt_set.insert(k);

    std::cout << "\n" << std::string(72, '=') << "\n"
              << "RESULTS: " << all_results.size() << "/"
              << total_salt_set.size() << " database keys recovered\n"
              << std::string(72, '=') << "\n";

    for (auto& [sh, kh] : global_results) {
        std::string names;
        for (auto& info : global_dbs) {
            if (to_hex(info.page1.data(), SALT_SIZE) == sh) {
                if (!names.empty()) names += ", ";
                names += info.filepath.filename().string();
            }
        }
        std::cout << "  [global] " << sh << " -> "
                  << kh.substr(0, 32) << "..  (" << names << ")\n";
    }
    for (auto& [sh, kh] : results) {
        std::string names;
        for (auto& info : pa_salt_map[sh]) {
            if (!names.empty()) names += ", ";
            names += info.filepath.filename().string();
        }
        std::cout << "  [acct]   " << sh << " -> "
                  << kh.substr(0, 32) << "..  (" << names << ")\n";
    }

    // Unresolved salts
    std::vector<std::string> unresolved;
    for (auto& [sh, v] : pa_salt_map) {
        if (results.find(sh) == results.end())
            unresolved.push_back(sh);
    }
    if (!unresolved.empty()) {
        std::cout << "\nUnresolved (" << unresolved.size() << "):\n";
        for (auto& sh : unresolved) {
            std::string names;
            for (auto& info : pa_salt_map[sh]) {
                if (!names.empty()) names += ", ";
                names += info.filepath.filename().string();
            }
            std::cout << "  " << sh << "  (" << names << ")\n";
        }
    }

    // 6. Save key_map.json
    fs::path out_dir = fs::current_path() / "output" / args.qq;
    fs::create_directories(out_dir);

    if (!all_results.empty()) {
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        struct tm tm_buf{};
        localtime_s(&tm_buf, &t);
        char ts[32];
        std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

        fs::path json_path = out_dir / args.output;
        std::ofstream jf(json_path);
        jf << "{\n  \"key_map\": {\n";
        size_t idx = 0;
        for (auto& [k, v] : all_results) {
            jf << "    \"" << k << "\": \"" << v << "\"";
            if (++idx < all_results.size()) jf << ",";
            jf << "\n";
        }
        jf << "  },\n  \"_generated\": \"" << ts << "\"\n}\n";
        jf.close();
        std::cout << "\nKey map saved to " << json_path << "\n";
    }

    if (all_results.empty()) {
        std::cerr << "ERROR: No keys recovered, nothing to decrypt.\n";
        return 1;
    }

    // 7. Wait for QQ to close (WAL checkpoint)
    //    QQ must be closed so that WAL is merged back into the .db files,
    //    otherwise some tables may appear malformed after decryption.
    std::cout << "\n" << std::string(72, '=') << "\n"
              << "  Keys extracted successfully!\n"
              << "  Please CLOSE QQ now so WAL data is flushed to the database files.\n"
              << std::string(72, '=') << "\n";

    // Collect all QQ PIDs to monitor
    auto qq_pids = find_qq_pids();
    if (qq_pids.empty()) {
        std::cout << "  QQ is already closed. Proceeding...\n";
    } else {
        std::cout << "  Waiting for QQ to exit (PIDs:";
        for (auto p : qq_pids) std::cout << " " << p;
        std::cout << ") ...\n"
                  << "  (or press Enter to proceed without waiting)\n";

        // Poll: wait for all QQ processes to exit, or user presses Enter
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        while (true) {
            // Check if any QQ process is still alive
            bool any_alive = false;
            for (auto pid : qq_pids) {
                if (is_process_alive(pid)) {
                    any_alive = true;
                    break;
                }
            }
            if (!any_alive) {
                std::cout << "  QQ has exited.\n";
                break;
            }

            // Check if user pressed Enter (non-blocking)
            INPUT_RECORD ir;
            DWORD events = 0;
            if (PeekConsoleInput(hStdin, &ir, 1, &events) && events > 0) {
                ReadConsoleInput(hStdin, &ir, 1, &events);
                if (ir.EventType == KEY_EVENT &&
                    ir.Event.KeyEvent.bKeyDown &&
                    ir.Event.KeyEvent.wVirtualKeyCode == VK_RETURN) {
                    std::cout << "  User pressed Enter, proceeding (WAL may not be flushed)...\n";
                    break;
                }
            }

            Sleep(500);
        }
    }

    // 8. Brief delay for filesystem to settle
    Sleep(1000);

    // 9. Re-discover DB files (WAL has been checkpointed, page1 may differ)
    std::cout << "\n-- Re-reading database files --\n";
    auto [fresh_global, fresh_pa_map] = find_and_collect_dbs(args.qq, args.db_dir);

    // Build filepath -> key_hex mapping from all_results (salt_hex -> key_hex)
    // We need to re-match by filepath since salt in page1 is stable across checkpoint
    std::map<fs::path, std::string> file_key_map;  // filepath -> key_hex

    for (auto& info : fresh_global) {
        std::string sh = to_hex(info.page1.data(), SALT_SIZE);
        auto it = all_results.find(sh);
        if (it != all_results.end())
            file_key_map[info.filepath] = it->second;
    }
    for (auto& [sh, infos] : fresh_pa_map) {
        auto it = all_results.find(sh);
        if (it != all_results.end()) {
            for (auto& info : infos)
                file_key_map[info.filepath] = it->second;
        }
    }

    std::cout << "  Matched " << file_key_map.size() << " database files to keys\n";

    // 10. Decrypt all recovered DBs to output folder
    std::cout << "\n-- Decrypting to " << out_dir << " --\n";

    int ok_count = 0, fail_count = 0;

    for (auto& [src_path, key_hex] : file_key_map) {
        auto key = from_hex(key_hex);
        auto dst = out_dir / src_path.filename();
        if (decrypt_db(src_path, dst, key.data())) {
            auto sz = fs::file_size(dst) / 1024;
            std::cout << "  OK  " << src_path.filename()
                      << " (" << sz << " KB)\n";
            ++ok_count;
        } else {
            std::cout << "  FAIL " << src_path.filename() << "\n";
            ++fail_count;
        }
    }

    std::cout << "\nDecrypted: " << ok_count << " OK, " << fail_count
              << " failed -> " << out_dir << "\n";
    return 0;
}
