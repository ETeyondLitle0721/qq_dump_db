#include "qq_dump_db/platform/win32/memory.hpp"
#include "qq_dump_db/utils/hex.hpp"
#include "qq_dump_db/i18n/catalog.hpp"

namespace qq_dump_db {
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

 ScanResults scan_by_salt(
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
    std::cout << tr("memory.summary_prefix") << pid << tr("memory.summary_scanned")
              << (total / 1048576) << tr("memory.summary_mb")
              << std::fixed << std::setprecision(1) << elapsed
              << tr("memory.summary_hit") << results.size() << "/"
              << salt_hexes.size() << tr("memory.combined_salts") << candidate_count
              << tr("memory.summary_candidates");
    return results;
}

 void merge_scan_results(ScanResults& destination,
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

} // namespace qq_dump_db
