#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <chrono>
#include <ctime>

namespace qq_dump_db {
namespace fs = std::filesystem;

inline constexpr size_t EXT_HEADER = 1024;
inline constexpr size_t PAGE_SIZE  = 4096;
inline constexpr size_t SALT_SIZE  = 16;
inline constexpr size_t KEY_SIZE   = 32;
inline constexpr size_t IV_SIZE    = 16;
inline constexpr size_t HMAC_SIZE  = 20;
inline constexpr size_t RESERVE    = 48;
inline constexpr uint8_t HMAC_MASK = 0x3a;
inline constexpr int KDF_ITER      = 4000;
inline constexpr int FAST_ITER     = 2;
inline constexpr size_t PRE_LOGIN_KEY_LEN = 20;
inline constexpr size_t SCAN_CHUNK_SIZE = 4ULL * 1024 * 1024;
inline constexpr size_t KEY_BLOB_SIZE = 99;
inline constexpr size_t SCAN_OVERLAP = KEY_BLOB_SIZE - 1;
inline constexpr const char* APP_VERSION = "2.0.0";
inline constexpr uint8_t PRE_LOGIN_KEY[] = "BD156D6710D54D8782F4";

struct Args {
    std::string qq;
    DWORD pid = 0;
    fs::path output = fs::u8path("key_map.json");
    fs::path output_dir;
    fs::path db_dir;
    std::string lang = "auto";
    bool no_wait = false;
};

struct DbInfo {
    std::string account;
    fs::path filepath;
    std::vector<uint8_t> page1;
};
using DbCollection = std::pair<
    std::vector<DbInfo>, std::map<std::string, std::vector<DbInfo>>>;

struct QqInstanceMapping {
    std::string account;
    DWORD wrapper_pid = 0;
    DWORD handle_pid = 0;
    fs::path db_path;
};

struct ScanHit {
    DWORD pid = 0;
    uintptr_t addr = 0;
    std::string key_hex;
};
using ScanResults = std::map<std::string, std::vector<ScanHit>>;

} // namespace qq_dump_db
