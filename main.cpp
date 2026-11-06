/*
 * Auto-dump NTQQ SQLCipher database keys from a running QQ process.
 *
 * Zero prior knowledge required - no hardcoded PIDs, keys, addresses, or salts.
 * Maps QQ instances from nt_msg.db handles, then validates distinct key candidates
 * against database page-1 HMACs.
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
#include <cstddef>
#include <cctype>
#include <limits>

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

static std::vector<DWORD> find_qq_wrapper_pids(const std::vector<DWORD>& pids)
{
    std::vector<DWORD> wrapper_pids;

    std::cout << "QQ PIDs:";
    for (DWORD pid : pids) std::cout << " " << pid;
    std::cout << "\n";

    for (DWORD pid : pids) {
        if (pid_has_module(pid, L"wrapper.node")) {
            wrapper_pids.push_back(pid);
            std::cout << "  PID " << pid << " has wrapper.node\n";
        }
    }
    return wrapper_pids;
}

// ── DB discovery ────────────────────────────────────────────────────────────

struct DbInfo {
    std::string          account;
    fs::path             filepath;
    std::vector<uint8_t> page1;   // PAGE_SIZE bytes
};

// SystemExtendedHandleInformation (SystemInformationClass = 64) is a
// Windows Native API information class. Keep the declarations local so the
// code builds with the regular Windows SDK without depending on private SDK
// headers.
using NtQuerySystemInformationFn = LONG (NTAPI*)(
    ULONG, PVOID, ULONG, PULONG);

struct SystemHandleEntryExLocal {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
};

struct SystemHandleInformationExLocal {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SystemHandleEntryExLocal Handles[1];
};

static bool get_final_path_from_handle(HANDLE file_handle, fs::path& result)
{
    constexpr DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    DWORD capacity = 512;

    while (capacity <= 32768) {
        std::vector<wchar_t> buffer(capacity, L'\0');
        DWORD length = GetFinalPathNameByHandleW(
            file_handle, buffer.data(), capacity, flags);
        if (length == 0)
            return false;
        if (length < capacity) {
            result = fs::path(std::wstring(buffer.data(), length));
            return true;
        }
        if (length >= 32768)
            break;
        capacity = length + 1;
    }
    return false;
}

static bool equals_ignore_case(const std::wstring& a, const wchar_t* b)
{
    return _wcsicmp(a.c_str(), b) == 0;
}

static bool parse_qq_account_from_db_path(const fs::path& db_path,
                                          std::string& account)
{
    // Expected NTQQ layout:
    // <data root>\\Tencent Files\\<QQ number>\\nt_qq\\nt_db\\nt_msg.db
    if (!equals_ignore_case(db_path.filename().wstring(), L"nt_msg.db"))
        return false;

    const fs::path db_dir = db_path.parent_path();
    const fs::path nt_qq_dir = db_dir.parent_path();
    const fs::path account_dir = nt_qq_dir.parent_path();
    const fs::path tencent_files_dir = account_dir.parent_path();

    if (!equals_ignore_case(db_dir.filename().wstring(), L"nt_db") ||
        !equals_ignore_case(nt_qq_dir.filename().wstring(), L"nt_qq") ||
        !equals_ignore_case(tencent_files_dir.filename().wstring(), L"Tencent Files"))
        return false;

    const std::wstring account_w = account_dir.filename().wstring();
    if (account_w.empty() || account_w == L"." || account_w == L"..")
        return false;

    // QQ account directory names are normally decimal. Reject unexpected
    // path components rather than accidentally treating a directory as an ID.
    if (!std::all_of(account_w.begin(), account_w.end(),
                     [](wchar_t c) { return c >= L'0' && c <= L'9'; }))
        return false;

    account.clear();
    account.reserve(account_w.size());
    for (wchar_t c : account_w)
        account.push_back(static_cast<char>(c));
    return true;
}

struct QqInstanceMapping {
    std::string account;
    DWORD       wrapper_pid = 0;  // PID whose address space contains wrapper.node
    DWORD       handle_pid = 0;   // PID that owns the nt_msg.db file handle
    fs::path    db_path;
};

static std::map<DWORD, DWORD> get_qq_parent_map()
{
    std::map<DWORD, DWORD> parents;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return parents;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring name(pe.szExeFile);
            std::transform(name.begin(), name.end(), name.begin(), ::towlower);
            if (name == L"qq.exe")
                parents[pe.th32ProcessID] = pe.th32ParentProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return parents;
}

static DWORD resolve_wrapper_pid_for_handle_owner(
    DWORD owner_pid,
    const std::set<DWORD>& wrapper_pids,
    const std::map<DWORD, DWORD>& parent_map)
{
    if (wrapper_pids.find(owner_pid) != wrapper_pids.end())
        return owner_pid;

    // First, walk upward: a QQ helper process may inherit its instance from
    // a wrapper.node-bearing QQ parent.
    std::set<DWORD> visited;
    DWORD current = owner_pid;
    while (visited.insert(current).second) {
        const auto it = parent_map.find(current);
        if (it == parent_map.end() || it->second == 0)
            break;
        current = it->second;
        if (wrapper_pids.find(current) != wrapper_pids.end())
            return current;
    }

    // Then walk upward from wrapper processes to see whether the handle owner
    // is their QQ.exe ancestor. Only accept exactly one descendant wrapper;
    // choosing the "nearest" of several clients could silently mis-map an ID.
    DWORD matched_pid = 0;
    for (DWORD candidate : wrapper_pids) {
        std::set<DWORD> candidate_visited;
        DWORD node = candidate;
        while (candidate_visited.insert(node).second) {
            const auto it = parent_map.find(node);
            if (it == parent_map.end() || it->second == 0)
                break;
            node = it->second;
            if (node == owner_pid) {
                if (matched_pid != 0 && matched_pid != candidate)
                    return 0;
                matched_pid = candidate;
                break;
            }
        }
    }
    return matched_pid;
}

// Build PID -> QQ account mappings from the process that owns an open nt_msg.db
// handle. The handle owner's PID is correlated to the wrapper.node process by
// the QQ.exe parent/child tree. No account is inferred from PID order.
static bool find_qq_instance_mappings(
    const std::vector<DWORD>& input_pids,
    const std::vector<DWORD>& input_wrapper_pids,
    std::vector<QqInstanceMapping>& mappings)
{
    mappings.clear();
    if (input_pids.empty()) {
        std::cerr << "ERROR: No QQ process IDs available for handle inspection.\n";
        return false;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto query_system_information = ntdll
        ? reinterpret_cast<NtQuerySystemInformationFn>(
              GetProcAddress(ntdll, "NtQuerySystemInformation"))
        : nullptr;
    if (!query_system_information) {
        std::cerr << "ERROR: NtQuerySystemInformation is unavailable.\n";
        return false;
    }

    constexpr ULONG SYSTEM_EXTENDED_HANDLE_INFORMATION = 64;
    constexpr LONG STATUS_INFO_LENGTH_MISMATCH_VALUE =
        static_cast<LONG>(0xC0000004L);
    constexpr LONG STATUS_BUFFER_TOO_SMALL_VALUE =
        static_cast<LONG>(0xC0000023L);

    std::vector<uint8_t> handle_buffer;
    ULONG buffer_size = 1u * 1024u * 1024u;
    bool queried = false;
    for (int attempt = 0; attempt < 12; ++attempt) {
        handle_buffer.resize(buffer_size);
        ULONG returned_length = 0;
        LONG status = query_system_information(
            SYSTEM_EXTENDED_HANDLE_INFORMATION,
            handle_buffer.data(), buffer_size, &returned_length);
        if (status >= 0) {
            queried = true;
            break;
        }
        if (status != STATUS_INFO_LENGTH_MISMATCH_VALUE &&
            status != STATUS_BUFFER_TOO_SMALL_VALUE) {
            std::cerr << "ERROR: NtQuerySystemInformation failed (NTSTATUS 0x"
                      << std::hex << static_cast<uint32_t>(status)
                      << std::dec << ").\n";
            return false;
        }
        if (returned_length > buffer_size) {
            buffer_size = returned_length;
        } else {
            if (buffer_size > std::numeric_limits<ULONG>::max() / 2) {
                std::cerr << "ERROR: System handle table is too large.\n";
                return false;
            }
            buffer_size *= 2;
        }
    }
    if (!queried) {
        std::cerr << "ERROR: Could not allocate a large enough system handle table.\n";
        return false;
    }

    const size_t handles_offset =
        offsetof(SystemHandleInformationExLocal, Handles);
    if (handle_buffer.size() < handles_offset) {
        std::cerr << "ERROR: Invalid system handle table response.\n";
        return false;
    }

    const auto* handle_info = reinterpret_cast<
        const SystemHandleInformationExLocal*>(handle_buffer.data());
    const size_t max_entries =
        (handle_buffer.size() - handles_offset) /
        sizeof(SystemHandleEntryExLocal);
    const size_t handle_count = static_cast<size_t>(
        std::min<ULONG_PTR>(handle_info->NumberOfHandles, max_entries));

    std::set<DWORD> qq_pid_set(input_pids.begin(), input_pids.end());
    std::map<DWORD, HANDLE> process_handles;
    for (DWORD pid : qq_pid_set) {
        HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (process)
            process_handles.emplace(pid, process);
    }
    if (process_handles.empty()) {
        std::cerr << "ERROR: Cannot open any QQ process for handle inspection. "
                  << "Run with sufficient permissions.\n";
        return false;
    }

    const std::set<DWORD> wrapper_set(
        input_wrapper_pids.begin(), input_wrapper_pids.end());
    const auto parent_map = get_qq_parent_map();
    const HANDLE current_process = GetCurrentProcess();

    // Keep PID + path together. A path-only set loses the crucial ownership
    // information needed to map a QQ instance to its account.
    std::set<std::pair<DWORD, fs::path>> found_handles;
    for (size_t i = 0; i < handle_count; ++i) {
        const auto& entry = handle_info->Handles[i];
        if (entry.UniqueProcessId > std::numeric_limits<DWORD>::max())
            continue;
        const DWORD owner_pid = static_cast<DWORD>(entry.UniqueProcessId);
        const auto process_it = process_handles.find(owner_pid);
        if (process_it == process_handles.end())
            continue;

        HANDLE duplicated = nullptr;
        const HANDLE source = reinterpret_cast<HANDLE>(entry.HandleValue);
        if (!DuplicateHandle(process_it->second, source, current_process,
                             &duplicated, 0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;

        if (GetFileType(duplicated) == FILE_TYPE_DISK) {
            fs::path file_path;
            std::string account;
            if (get_final_path_from_handle(duplicated, file_path) &&
                parse_qq_account_from_db_path(file_path, account)) {
                found_handles.emplace(owner_pid, std::move(file_path));
            }
        }
        CloseHandle(duplicated);
    }

    for (auto& [pid, process] : process_handles) {
        (void)pid;
        CloseHandle(process);
    }

    for (const auto& [owner_pid, path] : found_handles) {
        std::string account;
        if (!parse_qq_account_from_db_path(path, account))
            continue;
        const DWORD wrapper_pid = resolve_wrapper_pid_for_handle_owner(
            owner_pid, wrapper_set, parent_map);
        mappings.push_back({account, wrapper_pid, owner_pid, path});
    }

    if (mappings.empty()) {
        std::cerr << "ERROR: No QQ-owned nt_msg.db handle with the expected "
                     "Tencent Files/<QQ>/nt_qq/nt_db layout was found.\n"
                  << "Make sure QQ is logged in and the message database is open.\n";
        return false;
    }

    // De-duplicate repeated handle observations while retaining ownership.
    std::sort(mappings.begin(), mappings.end(),
              [](const QqInstanceMapping& a, const QqInstanceMapping& b) {
                  if (a.account != b.account) return a.account < b.account;
                  if (a.db_path != b.db_path) return a.db_path < b.db_path;
                  if (a.wrapper_pid != b.wrapper_pid) return a.wrapper_pid < b.wrapper_pid;
                  return a.handle_pid < b.handle_pid;
              });
    mappings.erase(std::unique(mappings.begin(), mappings.end(),
        [](const QqInstanceMapping& a, const QqInstanceMapping& b) {
            return a.account == b.account && a.db_path == b.db_path &&
                   a.wrapper_pid == b.wrapper_pid && a.handle_pid == b.handle_pid;
        }), mappings.end());

    std::cout << "\nDetected QQ process/account mappings:\n";
    for (const auto& mapping : mappings) {
        if (mapping.wrapper_pid) {
            std::cout << "  PID " << mapping.wrapper_pid << " -> QQ "
                      << mapping.account << " (nt_msg.db handle owner PID "
                      << mapping.handle_pid << ")\n";
        } else {
            std::cout << "  PID ? -> QQ " << mapping.account
                      << " (nt_msg.db handle owner PID " << mapping.handle_pid
                      << "; wrapper.node process could not be correlated)\n";
        }
    }
    return true;
}

static bool select_qq_instance(
    const std::string& qq_number,
    const std::vector<QqInstanceMapping>& mappings,
    fs::path& db_directory,
    std::vector<DWORD>& matched_wrapper_pids)
{
    std::vector<fs::path> account_paths;
    for (const auto& mapping : mappings) {
        if (mapping.account == qq_number)
            account_paths.push_back(mapping.db_path);
    }
    std::sort(account_paths.begin(), account_paths.end());
    account_paths.erase(std::unique(account_paths.begin(), account_paths.end()),
                        account_paths.end());

    if (account_paths.empty()) {
        std::cerr << "ERROR: No running QQ instance was mapped to account "
                  << qq_number << ".\n";
        return false;
    }
    if (account_paths.size() != 1) {
        std::cerr << "ERROR: Multiple nt_msg.db paths were mapped to QQ account "
                  << qq_number << ":\n";
        for (const auto& path : account_paths)
            std::cerr << "  " << path.string() << "\n";
        return false;
    }

    db_directory = account_paths.front().parent_path();
    std::set<DWORD> unique_pids;
    for (const auto& mapping : mappings) {
        if (mapping.account == qq_number && mapping.db_path == account_paths.front() &&
            mapping.wrapper_pid != 0)
            unique_pids.insert(mapping.wrapper_pid);
    }
    matched_wrapper_pids.assign(unique_pids.begin(), unique_pids.end());

    std::cout << "  Selected QQ " << qq_number << " database: "
              << (account_paths.front()).string() << "\n";
    if (matched_wrapper_pids.empty()) {
        std::cout << "  WARNING: No wrapper.node PID could be correlated to this "
                     "database handle owner.\n";
    } else {
        std::cout << "  Matching wrapper.node PID(s):";
        for (DWORD pid : matched_wrapper_pids)
            std::cout << " " << pid;
        std::cout << "\n";
    }
    return true;
}

static std::pair<std::vector<DbInfo>,
                 std::map<std::string, std::vector<DbInfo>>>
find_and_collect_dbs(const std::string& qq_number,
                     const std::string& custom_db_dir = "",
                     const fs::path& discovered_account_db_dir = {})
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
        if (discovered_account_db_dir.empty() ||
            !fs::is_directory(discovered_account_db_dir)) {
            std::cerr << "ERROR: Account DB directory was not discovered from "
                         "QQ process handles.\n";
            return {global_dbs, pa_map};
        }

        // Expected layout: <data_root>/<account>/nt_qq/nt_db.
        // Derive the shared root from the located nt_msg.db path, not from
        // USERPROFILE or a hard-coded Documents directory.
        const fs::path account_nt_qq_dir = discovered_account_db_dir.parent_path();
        const fs::path account_root = account_nt_qq_dir.parent_path();
        const fs::path data_root = account_root.parent_path();
        const fs::path gdir = data_root / "nt_qq" / "global" / "nt_db";

        if (fs::is_directory(gdir))
            dirs.push_back({"global", gdir});
        else
            std::cerr << "WARNING: Global DB directory not found: "
                      << gdir << "\n";

        dirs.push_back({qq_number, discovered_account_db_dir});
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
    DWORD       pid = 0;
    uintptr_t   addr = 0;
    std::string key_hex;
};

using ScanResults = std::map<std::string, std::vector<ScanHit>>;

static constexpr size_t SCAN_CHUNK_SIZE = 4ULL * 1024 * 1024;
static constexpr size_t KEY_BLOB_SIZE = 99; // x' + 64 key hex + 32 salt hex + '
static constexpr size_t SCAN_OVERLAP = KEY_BLOB_SIZE - 1;

static std::string lower_hex(const uint8_t* data, size_t len)
{
    std::string value(reinterpret_cast<const char*>(data), len);
    for (char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

static void scan_buffer_for_key_blobs(
    const std::vector<uint8_t>& data,
    uintptr_t data_address,
    DWORD pid,
    const std::set<std::string>& wanted_salts,
    ScanResults& results)
{
    if (data.size() < KEY_BLOB_SIZE) return;

    for (size_t i = 0; i + KEY_BLOB_SIZE <= data.size(); ++i) {
        const uint8_t prefix = data[i];
        if ((prefix != 'x' && prefix != 'X') ||
            (data[i + 1] != '\'' && data[i + 1] != '"'))
            continue;

        const uint8_t quote = data[i + 1];
        if (data[i + KEY_BLOB_SIZE - 1] != quote)
            continue;

        bool all_hex = true;
        for (size_t j = i + 2; j < i + KEY_BLOB_SIZE - 1; ++j) {
            if (!is_hex_char(data[j])) {
                all_hex = false;
                break;
            }
        }
        if (!all_hex) continue;

        const std::string key_hex = lower_hex(data.data() + i + 2, 64);
        const std::string salt_hex = lower_hex(data.data() + i + 66, 32);
        if (wanted_salts.find(salt_hex) == wanted_salts.end())
            continue;

        auto& candidates = results[salt_hex];
        const auto duplicate = std::find_if(
            candidates.begin(), candidates.end(),
            [&](const ScanHit& hit) { return hit.key_hex == key_hex; });
        if (duplicate == candidates.end())
            candidates.push_back({pid, data_address + i, key_hex});
    }
}

static ScanResults scan_by_salt(
    HANDLE handle,
    DWORD pid,
    const std::vector<std::string>& salt_hexes)
{
    ScanResults results;
    const std::set<std::string> wanted_salts(
        salt_hexes.begin(), salt_hexes.end());

    size_t total = 0;
    const auto t0 = std::chrono::steady_clock::now();
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;

    while (true) {
        if (VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(addr),
                           &mbi, sizeof(mbi)) == 0)
            break;

        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const size_t size = mbi.RegionSize;
        const DWORD protection = mbi.Protect;
        const DWORD base_protection = protection & 0xFF;
        const bool readable_candidate =
            mbi.State == MEM_COMMIT &&
            base_protection != PAGE_NOACCESS &&
            (protection & PAGE_GUARD) == 0;

        if (readable_candidate && size > 0) {
            std::vector<uint8_t> carry;
            size_t region_offset = 0;

            while (region_offset < size) {
                const size_t request = std::min(
                    SCAN_CHUNK_SIZE, size - region_offset);
                std::vector<uint8_t> chunk(request);
                SIZE_T bytes_read = 0;
                const BOOL read_ok = ReadProcessMemory(
                    handle,
                    reinterpret_cast<LPCVOID>(base + region_offset),
                    chunk.data(), request, &bytes_read);

                if (bytes_read > 0) {
                    chunk.resize(static_cast<size_t>(bytes_read));
                    total += static_cast<size_t>(bytes_read);

                    std::vector<uint8_t> window;
                    window.reserve(carry.size() + chunk.size());
                    window.insert(window.end(), carry.begin(), carry.end());
                    window.insert(window.end(), chunk.begin(), chunk.end());
                    const uintptr_t window_address =
                        base + region_offset - carry.size();

                    scan_buffer_for_key_blobs(
                        window, window_address, pid, wanted_salts, results);

                    const size_t keep = std::min(SCAN_OVERLAP, window.size());
                    carry.assign(window.end() - static_cast<ptrdiff_t>(keep),
                                 window.end());

                    region_offset += static_cast<size_t>(bytes_read);
                    if (!read_ok || bytes_read < request) {
                        // Do not let a blob span bytes that were not read.
                        region_offset += request - static_cast<size_t>(bytes_read);
                        carry.clear();
                    }
                } else {
                    region_offset += request;
                    carry.clear();
                }
            }
        }

        const uintptr_t next = base + size;
        if (next <= addr || next >= 0x7FFFFFFFFFFF)
            break;
        addr = next;
    }

    size_t candidate_count = 0;
    for (const auto& [salt, candidates] : results) {
        (void)salt;
        candidate_count += candidates.size();
    }
    const double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    std::cout << "  PID " << pid << ": scanned " << (total / 1048576)
              << " MB in " << std::fixed << std::setprecision(1)
              << elapsed << "s -> " << results.size() << "/"
              << salt_hexes.size() << " salts, " << candidate_count
              << " distinct candidates\n";
    return results;
}

static void merge_scan_results(ScanResults& destination,
                               const ScanResults& source)
{
    for (const auto& [salt, candidates] : source) {
        auto& merged = destination[salt];
        for (const auto& candidate : candidates) {
            const auto duplicate = std::find_if(
                merged.begin(), merged.end(),
                [&](const ScanHit& hit) {
                    return hit.key_hex == candidate.key_hex;
                });
            if (duplicate == merged.end())
                merged.push_back(candidate);
        }
    }
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

    // 1. Discover QQ processes and the account each wrapper.node instance
    // belongs to. Account identity is derived from the nt_msg.db handle path,
    // not from process order or the mere presence of wrapper.node.
    const auto qq_pids = find_qq_pids();
    const auto wrapper_pids = find_qq_wrapper_pids(qq_pids);
    if (wrapper_pids.empty() && !args.pid) {
        std::cerr << "ERROR: No QQ.exe process with wrapper.node was found. "
                     "Start QQ or specify --pid.\n";
        return 1;
    }

    std::vector<DWORD> handle_owner_pids = qq_pids;
    if (args.pid && std::find(handle_owner_pids.begin(), handle_owner_pids.end(),
                              args.pid) == handle_owner_pids.end())
        handle_owner_pids.push_back(args.pid);

    std::vector<QqInstanceMapping> instance_mappings;
    const bool mapping_available = !handle_owner_pids.empty() &&
        find_qq_instance_mappings(handle_owner_pids, wrapper_pids, instance_mappings);

    // 2. Select the database directory and the wrapper process(es) associated
    // with --qq. An explicit --pid remains a diagnostic override.
    std::vector<DWORD> scan_pids;
    fs::path discovered_account_db_dir;
    if (args.db_dir.empty()) {
        if (!mapping_available ||
            !select_qq_instance(args.qq, instance_mappings,
                                discovered_account_db_dir, scan_pids)) {
            return 1;
        }
        if (scan_pids.empty() && !args.pid) {
            std::cerr << "ERROR: The database path was identified, but no "
                         "wrapper.node PID could be mapped to QQ " << args.qq << ".\n";
            return 1;
        }
    } else {
        // A manually supplied DB directory is authoritative. If automatic
        // mapping succeeded, narrow the scan to matching instances; otherwise
        // keep the previous all-wrapper-process diagnostic behavior.
        if (mapping_available) {
            for (const auto& mapping : instance_mappings) {
                if (mapping.account == args.qq && mapping.wrapper_pid != 0)
                    scan_pids.push_back(mapping.wrapper_pid);
            }
            std::sort(scan_pids.begin(), scan_pids.end());
            scan_pids.erase(std::unique(scan_pids.begin(), scan_pids.end()),
                            scan_pids.end());
        }
        if (scan_pids.empty()) {
            scan_pids = wrapper_pids;
            std::cout << "WARNING: Could not map --db-dir to a live QQ instance; "
                         "scanning all wrapper.node processes.\n";
        }
    }

    if (args.pid) {
        scan_pids.assign(1, args.pid);
        std::cout << "Using explicit scan PID override: " << args.pid << "\n";
        bool pid_account_known = false;
        for (const auto& mapping : instance_mappings) {
            if (mapping.wrapper_pid == args.pid) {
                pid_account_known = true;
                if (mapping.account != args.qq) {
                    std::cerr << "WARNING: PID " << args.pid
                              << " maps to QQ " << mapping.account
                              << ", not requested QQ " << args.qq << ".\n";
                } else {
                    std::cout << "  PID/account mapping confirmed: "
                              << args.pid << " -> " << args.qq << "\n";
                }
            }
        }
        if (!pid_account_known)
            std::cout << "WARNING: No file-handle mapping was confirmed for PID "
                      << args.pid << "; proceeding because --pid was explicit.\n";
    } else {
        std::cout << "Will scan " << scan_pids.size()
                  << " wrapper.node process(es) mapped to QQ " << args.qq << ".\n";
    }

    // 3. Collect database files from the located directories.
    auto [global_dbs, pa_salt_map] = find_and_collect_dbs(
        args.qq, args.db_dir, discovered_account_db_dir);

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

    // 4. Per-account DBs: scan each selected process, retain all distinct
    // candidates for each salt, and let HMAC verification choose the key.
    std::map<std::string, std::string> results; // salt_hex -> verified key_hex
    if (!pa_salt_map.empty()) {
        std::vector<std::string> salt_list;
        salt_list.reserve(pa_salt_map.size());
        for (const auto& [salt, dbs] : pa_salt_map) {
            (void)dbs;
            salt_list.push_back(salt);
        }

        ScanResults all_scan_hits;
        for (DWORD pid : scan_pids) {
            HANDLE process = OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!process) {
                std::cerr << "  WARNING: Cannot open PID " << pid
                          << " for memory reading (err " << GetLastError()
                          << "). Skipping.\n";
                continue;
            }

            std::cout << "\n-- Scanning PID " << pid << " for "
                      << salt_list.size() << " known salts --\n";
            const auto process_hits = scan_by_salt(process, pid, salt_list);
            merge_scan_results(all_scan_hits, process_hits);
            CloseHandle(process);
        }

        size_t total_candidates = 0;
        for (const auto& [salt, candidates] : all_scan_hits) {
            (void)salt;
            total_candidates += candidates.size();
        }
        std::cout << "\nCombined scan results: " << all_scan_hits.size()
                  << "/" << salt_list.size() << " salts, "
                  << total_candidates << " distinct candidate keys across "
                  << scan_pids.size() << " process(es).\n";

        for (const auto& [salt_hex, candidates] : all_scan_hits) {
            const auto db_it = pa_salt_map.find(salt_hex);
            if (db_it == pa_salt_map.end() || db_it->second.empty())
                continue;

            bool verified = false;
            size_t rejected = 0;
            for (const auto& hit : candidates) {
                const auto enc_key = from_hex(hit.key_hex);
                if (enc_key.size() != KEY_SIZE) {
                    ++rejected;
                    continue;
                }

                // If several DB files share a salt, try each page-1 HMAC.
                // A damaged first DB must not reject an otherwise valid key.
                std::string verified_filename;
                for (const auto& db : db_it->second) {
                    if (verify_key_hmac(db.page1.data(), enc_key.data())) {
                        verified_filename = db.filepath.filename().string();
                        break;
                    }
                }

                if (!verified_filename.empty()) {
                    results[salt_hex] = hit.key_hex;
                    std::cout << "  [hit] " << verified_filename
                              << ": key=" << hit.key_hex.substr(0, 16)
                              << ".. @ PID " << hit.pid << " 0x"
                              << std::hex << std::uppercase << hit.addr
                              << std::dec << " (verified after "
                              << (rejected + 1) << " candidate(s))\n";
                    verified = true;
                    break;
                }
                ++rejected;
            }

            if (!verified) {
                std::string names;
                for (const auto& db : db_it->second) {
                    if (!names.empty()) names += ", ";
                    names += db.filepath.filename().string();
                }
                std::cout << "  [miss] " << names << ": "
                          << candidates.size()
                          << " candidate(s), none passed HMAC\n";
            }
        }

        for (const auto& [salt, dbs] : pa_salt_map) {
            if (all_scan_hits.find(salt) == all_scan_hits.end()) {
                std::string names;
                for (const auto& db : dbs) {
                    if (!names.empty()) names += ", ";
                    names += db.filepath.filename().string();
                }
                std::cout << "  [miss] " << names
                          << ": no matching key blob found in scanned process(es)\n";
            }
        }
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
    auto remaining_qq_pids = find_qq_pids();
    if (remaining_qq_pids.empty()) {
        std::cout << "  QQ is already closed. Proceeding...\n";
    } else {
        std::cout << "  Waiting for QQ to exit (PIDs:";
        for (auto p : remaining_qq_pids) std::cout << " " << p;
        std::cout << ") ...\n"
                  << "  (or press Enter to proceed without waiting)\n";

        // Poll: wait for all QQ processes to exit, or user presses Enter
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        while (true) {
            // Check if any QQ process is still alive
            bool any_alive = false;
            for (auto pid : remaining_qq_pids) {
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
    auto [fresh_global, fresh_pa_map] = find_and_collect_dbs(
        args.qq, args.db_dir, discovered_account_db_dir);

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
