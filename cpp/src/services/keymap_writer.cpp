#include "qq_dump_db/services/keymap_writer.hpp"

namespace qq_dump_db {
bool write_key_map(const std::map<std::string, std::string>& key_map,
                   const fs::path& output_path, std::string& error_message) {
    try {
        const fs::path parent = output_path.parent_path();
        if (!parent.empty()) fs::create_directories(parent);

        fs::path temp_path = output_path;
        temp_path += L".tmp." + std::to_wstring(GetCurrentProcessId());

        const auto now = std::chrono::system_clock::now();
        const std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::tm utc{};
#if defined(_WIN32)
        gmtime_s(&utc, &now_time);
#else
        gmtime_r(&now_time, &utc);
#endif
        char timestamp[32]{};
        if (std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) {
            error_message = "timestamp_format_failed";
            return false;
        }

        {
            std::ofstream output(temp_path, std::ios::binary | std::ios::trunc);
            if (!output) {
                error_message = "temporary_file_open_failed";
                return false;
            }
            output << "{\n  \"schema_version\": 1,\n  \"key_map\": {\n";
            size_t index = 0;
            for (const auto& [salt, key] : key_map) {
                output << "    \"" << salt << "\": \"" << key << "\"";
                if (++index < key_map.size()) output << ',';
                output << '\n';
            }
            output << "  },\n  \"_generated\": \"" << timestamp << "\"\n}\n";
            output.flush();
            if (!output.good()) {
                error_message = "temporary_file_write_failed";
                output.close();
                fs::remove(temp_path);
                return false;
            }
        }

        const std::wstring temp_wide = temp_path.wstring();
        const std::wstring output_wide = output_path.wstring();
        if (!MoveFileExW(temp_wide.c_str(), output_wide.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            error_message = "atomic_replace_failed_win32_" + std::to_string(GetLastError());
            fs::remove(temp_path);
            return false;
        }
        return true;
    } catch (const std::exception& exc) {
        error_message = exc.what();
        return false;
    }
}
} // namespace qq_dump_db
