#include "qq_dump_db/discovery/databases.hpp"
#include "qq_dump_db/utils/hex.hpp"
#include "qq_dump_db/i18n/catalog.hpp"

namespace qq_dump_db {
DbCollection find_and_collect_dbs(const std::string& qq_number,
                     const fs::path& custom_db_dir,
                     const fs::path& discovered_account_db_dir)
{
    std::vector<DbInfo>                        global_dbs;
    std::map<std::string, std::vector<DbInfo>> pa_map;   // salt_hex -> DBs

    struct Dir { std::string account; fs::path path; };
    std::vector<Dir> dirs;

    if (!custom_db_dir.empty()) {
        // User-specified directory: inspect .db files directly in this directory
        fs::path custom(custom_db_dir);
        if (fs::is_directory(custom)) {
            dirs.push_back({qq_number, custom});
        } else {
            std::cerr << tr("db.custom_missing") << path_to_utf8(custom) << "\n";
        }
    } else {
        if (discovered_account_db_dir.empty() ||
            !fs::is_directory(discovered_account_db_dir)) {
            std::cerr << tr("db.account_missing") << "\n";
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
            std::cerr << tr("warning.prefix") << tr("db.global_missing")
                      << path_to_utf8(gdir) << "\n";

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

} // namespace qq_dump_db
