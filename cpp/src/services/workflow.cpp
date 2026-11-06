#include "qq_dump_db/services/workflow.hpp"

#include "qq_dump_db/crypto/sqlcipher.hpp"
#include "qq_dump_db/discovery/databases.hpp"
#include "qq_dump_db/discovery/qq_instances.hpp"
#include "qq_dump_db/i18n/catalog.hpp"
#include "qq_dump_db/platform/win32/handles.hpp"
#include "qq_dump_db/platform/win32/memory.hpp"
#include "qq_dump_db/platform/win32/processes.hpp"
#include "qq_dump_db/services/decryptor.hpp"
#include "qq_dump_db/services/keymap_writer.hpp"
#include "qq_dump_db/services/waiter.hpp"
#include "qq_dump_db/utils/hex.hpp"

#include <exception>
#include <cwctype>

namespace qq_dump_db {
namespace {
constexpr int EXIT_OK = 0;
constexpr int EXIT_QQ_PROCESS_NOT_FOUND = 11;
constexpr int EXIT_INSTANCE_MAPPING_FAILED = 12;
constexpr int EXIT_DATABASE_NOT_FOUND = 13;
constexpr int EXIT_KEY_NOT_RECOVERED = 20;
constexpr int EXIT_OUTPUT_IO_FAILED = 21;
constexpr int EXIT_DECRYPT_FAILED = 22;
constexpr int EXIT_INTERNAL_ERROR = 70;

int fail(int code, const char* error_id, const std::string& message) {
    std::cerr << tr("error.label") << "[" << error_id << "]: " << message << "\n";
    return code;
}

bool same_existing_path(const fs::path& left, const fs::path& right) {
    std::error_code ec1, ec2;
    const fs::path a = fs::weakly_canonical(left, ec1);
    const fs::path b = fs::weakly_canonical(right, ec2);
    if (!ec1 && !ec2) {
        std::wstring aw = a.wstring();
        std::wstring bw = b.wstring();
        std::transform(aw.begin(), aw.end(), aw.begin(), ::towlower);
        std::transform(bw.begin(), bw.end(), bw.begin(), ::towlower);
        return aw == bw;
    }
    return left.lexically_normal() == right.lexically_normal();
}

std::string db_names(const std::vector<DbInfo>& dbs) {
    std::string names;
    for (const auto& db : dbs) {
        if (!names.empty()) names += ", ";
        names += path_to_utf8(db.filepath.filename());
    }
    return names;
}
}

int run_workflow(const Args& args) {
    try {
        // Stage 1: discover QQ processes and map the account to its database handle.
        const auto qq_pids = find_qq_pids();
        const auto wrapper_pids = find_qq_wrapper_pids(qq_pids);
        if (wrapper_pids.empty() && args.pid == 0)
            return fail(EXIT_QQ_PROCESS_NOT_FOUND, "QQ_PROCESS_NOT_FOUND", tr("process.not_found"));

        std::vector<DWORD> handle_owner_pids = qq_pids;
        if (args.pid && std::find(handle_owner_pids.begin(), handle_owner_pids.end(), args.pid) == handle_owner_pids.end())
            handle_owner_pids.push_back(args.pid);

        std::vector<QqInstanceMapping> mappings;
        bool mapping_available = false;
        if (!handle_owner_pids.empty())
            mapping_available = find_qq_instance_mappings(handle_owner_pids, wrapper_pids, mappings);

        std::vector<DWORD> scan_pids;
        fs::path discovered_account_db_dir;
        if (args.db_dir.empty()) {
            if (!mapping_available)
                return fail(EXIT_INSTANCE_MAPPING_FAILED, "INSTANCE_MAPPING_FAILED", tr("error.mapping"));
            if (!select_qq_instance(args.qq, mappings, discovered_account_db_dir, scan_pids))
                return fail(EXIT_INSTANCE_MAPPING_FAILED, "INSTANCE_MAPPING_FAILED", tr("error.mapping"));
            if (scan_pids.empty() && args.pid == 0)
                return fail(EXIT_INSTANCE_MAPPING_FAILED, "INSTANCE_MAPPING_FAILED", tr("mapping.unmapped"));
        } else {
            if (mapping_available) {
                for (const auto& mapping : mappings) {
                    if (mapping.account == args.qq && mapping.wrapper_pid)
                        scan_pids.push_back(mapping.wrapper_pid);
                }
                std::sort(scan_pids.begin(), scan_pids.end());
                scan_pids.erase(std::unique(scan_pids.begin(), scan_pids.end()), scan_pids.end());
            }
            if (scan_pids.empty()) {
                scan_pids = wrapper_pids;
                if (scan_pids.empty() && args.pid) scan_pids.push_back(args.pid);
                if (!scan_pids.empty())
                    std::cout << tr("warning.prefix") << tr("mapping.no_wrapper_match") << "\n";
            }
        }

        if (args.pid) {
            scan_pids.assign(1, args.pid);
            std::cout << tr("mapping.manual") << args.pid << "\n";
            bool account_confirmed = false;
            for (const auto& mapping : mappings) {
                if (mapping.wrapper_pid == args.pid) {
                    account_confirmed = true;
                    if (mapping.account != args.qq)
                        std::cout << tr("warning.prefix") << tr("mapping.mismatch") << mapping.account
                                  << " (requested " << args.qq << ").\n";
                }
            }
            if (!account_confirmed)
                std::cout << tr("warning.prefix") << tr("mapping.unconfirmed") << "\n";
        } else {
            std::cout << tr("workflow.scan_prefix") << scan_pids.size()
                      << tr("workflow.scan_middle") << args.qq << tr("workflow.scan_suffix");
        }

        // Stage 2: find databases and collect page-1 salts.
        DbCollection collected;
        try {
            collected = find_and_collect_dbs(args.qq, args.db_dir, discovered_account_db_dir);
        } catch (const std::exception&) {
            return fail(EXIT_DATABASE_NOT_FOUND, "DATABASE_NOT_FOUND", tr("error.database"));
        }
        auto& global_dbs = collected.first;
        auto& account_salt_map = collected.second;
        if (global_dbs.empty() && account_salt_map.empty())
            return fail(EXIT_DATABASE_NOT_FOUND, "DATABASE_NOT_FOUND", tr("db.none"));

        size_t account_file_count = 0;
        for (const auto& [salt, entries] : account_salt_map) {
            (void)salt;
            account_file_count += entries.size();
        }
        std::cout << tr("db.summary_global") << global_dbs.size() << tr("db.summary_fixed")
                  << account_file_count << tr("db.summary_files") << account_salt_map.size()
                  << tr("db.summary_salts");

        // Stage 3: validate built-in global-key candidates against page-1 HMACs.
        std::map<std::string, std::string> global_results;
        for (const auto& db : global_dbs) {
            const std::string salt_hex = to_hex(db.page1.data(), SALT_SIZE);
            const auto key = derive_enc_key(PRE_LOGIN_KEY, PRE_LOGIN_KEY_LEN, db.page1.data());
            if (verify_key_hmac(db.page1.data(), key.data()))
                global_results[salt_hex] = to_hex(key.data(), key.size());
        }

        // Stage 4: scan only the selected processes; accept candidates only after HMAC validation.
        std::map<std::string, std::string> account_results;
        if (!account_salt_map.empty()) {
            ScanResults all_scan_hits;
            std::vector<std::string> salt_list;
            salt_list.reserve(account_salt_map.size());
            for (const auto& [salt, entries] : account_salt_map) {
                (void)entries;
                salt_list.push_back(salt);
            }

            for (DWORD pid : scan_pids) {
                HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
                if (!process) {
                    std::cout << tr("warning.prefix") << tr("memory.cannot_open") << pid
                              << " (" << GetLastError() << "), skipping.\n";
                    continue;
                }
                std::cout << tr("memory.scanning") << pid << ", " << salt_list.size()
                          << tr("memory.scanning_suffix");
                const ScanResults hits = scan_by_salt(process, pid, salt_list);
                merge_scan_results(all_scan_hits, hits);
                CloseHandle(process);
            }

            size_t total_candidates = 0;
            for (const auto& [salt, candidates] : all_scan_hits) {
                (void)salt;
                total_candidates += candidates.size();
            }
            std::cout << tr("memory.combined") << all_scan_hits.size() << "/" << salt_list.size()
                      << tr("memory.combined_salts") << total_candidates
                      << tr("memory.combined_candidates") << scan_pids.size() << tr("memory.processes");

            for (const auto& [salt_hex, candidates] : all_scan_hits) {
                const auto db_it = account_salt_map.find(salt_hex);
                if (db_it == account_salt_map.end() || db_it->second.empty()) continue;

                bool verified = false;
                size_t tested = 0;
                for (const auto& hit : candidates) {
                    const auto key = from_hex(hit.key_hex);
                    ++tested;
                    if (key.size() != KEY_SIZE) continue;
                    bool valid = false;
                    for (const auto& db : db_it->second) {
                        if (verify_key_hmac(db.page1.data(), key.data())) {
                            valid = true;
                            break;
                        }
                    }
                    if (valid) {
                        account_results[salt_hex] = hit.key_hex;
                        std::cout << tr("memory.hit") << db_names(db_it->second)
                                  << tr("memory.hit_verified") << hit.pid
                                  << tr("memory.address") << std::hex << std::uppercase << hit.addr
                                  << std::dec << tr("memory.tested") << tested << tr("memory.candidate");
                        verified = true;
                        break;
                    }
                }
                if (!verified)
                    std::cout << tr("memory.miss") << db_names(db_it->second)
                              << tr("memory.miss_candidates");
            }

            for (const auto& [salt, dbs] : account_salt_map) {
                if (all_scan_hits.find(salt) == all_scan_hits.end())
                    std::cout << tr("memory.miss") << db_names(dbs) << tr("memory.miss_none");
            }
        }

        std::map<std::string, std::string> all_results = global_results;
        all_results.insert(account_results.begin(), account_results.end());

        std::set<std::string> total_salts;
        for (const auto& db : global_dbs) total_salts.insert(to_hex(db.page1.data(), SALT_SIZE));
        for (const auto& [salt, entries] : account_salt_map) {
            (void)entries;
            total_salts.insert(salt);
        }
        std::cout << tr("result.header") << all_results.size() << tr("result.of")
                  << total_salts.size() << tr("result.keys");
        for (const auto& [salt, key] : global_results) {
            (void)key;
            std::vector<DbInfo> matching;
            for (const auto& db : global_dbs)
                if (to_hex(db.page1.data(), SALT_SIZE) == salt) matching.push_back(db);
            std::cout << tr("result.global") << salt << tr("result.arrow") << db_names(matching) << "\n";
        }
        for (const auto& [salt, key] : account_results) {
            (void)key;
            const auto it = account_salt_map.find(salt);
            if (it != account_salt_map.end())
                std::cout << tr("result.account") << salt << tr("result.arrow") << db_names(it->second) << "\n";
        }
        std::vector<std::string> unresolved;
        for (const auto& [salt, entries] : account_salt_map) {
            (void)entries;
            if (account_results.find(salt) == account_results.end()) unresolved.push_back(salt);
        }
        if (!unresolved.empty()) {
            std::cout << tr("result.unresolved") << unresolved.size() << tr("result.unresolved_end");
            for (const auto& salt : unresolved)
                std::cout << "  " << salt << " (" << db_names(account_salt_map[salt]) << ")\n";
        }

        if (all_results.empty())
            return fail(EXIT_KEY_NOT_RECOVERED, "KEY_NOT_RECOVERED", tr("result.none"));

        // Stage 5: persist the versioned key map under the unified output root.
        fs::path output_dir = args.output_dir;
        if (output_dir.empty()) output_dir = fs::current_path() / "output" / fs::u8path(args.qq);
        try {
            fs::create_directories(output_dir);
        } catch (const std::exception& exc) {
            return fail(EXIT_OUTPUT_IO_FAILED, "OUTPUT_IO_FAILED",
                        tr("output.mkdir") + path_to_utf8(output_dir) + " (" + exc.what() + ")");
        }
        fs::path key_map_path = args.output.is_absolute() ? args.output : output_dir / args.output;
        key_map_path = fs::absolute(key_map_path).lexically_normal();
        for (const auto& db : global_dbs)
            if (same_existing_path(key_map_path, db.filepath))
                return fail(EXIT_OUTPUT_IO_FAILED, "OUTPUT_IO_FAILED", tr("output.collision"));
        for (const auto& [salt, entries] : account_salt_map) {
            (void)salt;
            for (const auto& db : entries)
                if (same_existing_path(key_map_path, db.filepath))
                    return fail(EXIT_OUTPUT_IO_FAILED, "OUTPUT_IO_FAILED", tr("output.collision"));
        }
        std::string write_error;
        if (!write_key_map(all_results, key_map_path, write_error))
            return fail(EXIT_OUTPUT_IO_FAILED, "OUTPUT_IO_FAILED", tr("error.output") + " (" + write_error + ")");
        std::cout << tr("result.saved") << path_to_utf8(key_map_path) << "\n";

        // Stage 6: wait for selected QQ processes, unless explicitly skipped.
        wait_for_qq_exit(scan_pids, args.no_wait);
        Sleep(1000);

        // Stage 7: rediscover DBs after the wait, then match by stable salt.
        std::cout << tr("workflow.reread");
        DbCollection fresh;
        try {
            fresh = find_and_collect_dbs(args.qq, args.db_dir, discovered_account_db_dir);
        } catch (const std::exception&) {
            return fail(EXIT_DECRYPT_FAILED, "DECRYPT_FAILED", tr("error.decrypt"));
        }
        std::map<fs::path, std::string> file_key_map;
        for (const auto& db : fresh.first) {
            const std::string salt = to_hex(db.page1.data(), SALT_SIZE);
            const auto it = all_results.find(salt);
            if (it != all_results.end()) file_key_map[db.filepath] = it->second;
        }
        for (const auto& [salt, dbs] : fresh.second) {
            const auto it = all_results.find(salt);
            if (it != all_results.end())
                for (const auto& db : dbs) file_key_map[db.filepath] = it->second;
        }
        std::cout << tr("workflow.matched_prefix") << file_key_map.size() << tr("workflow.matched_suffix");
        if (file_key_map.empty())
            return fail(EXIT_DECRYPT_FAILED, "DECRYPT_FAILED", tr("error.decrypt"));

        // Stage 8: reject basename collisions and decrypt each file to the output directory.
        std::cout << tr("decrypt.header") << path_to_utf8(output_dir) << " --\n";
        std::map<std::string, size_t> basename_counts;
        for (const auto& [source, key_hex] : file_key_map) {
            (void)key_hex;
            ++basename_counts[path_to_utf8(source.filename())];
        }
        int ok_count = 0;
        int fail_count = 0;
        for (const auto& [source, key_hex] : file_key_map) {
            const std::string basename = path_to_utf8(source.filename());
            const fs::path target = output_dir / source.filename();
            if (basename_counts[basename] > 1 || same_existing_path(source, target)) {
                std::cout << tr("decrypt.fail") << basename << " - " << tr("decrypt.conflict") << basename << "\n";
                ++fail_count;
                continue;
            }
            const auto key = from_hex(key_hex);
            if (key.size() != KEY_SIZE || !decrypt_db(source, target, key.data())) {
                std::cout << tr("decrypt.fail") << basename << "\n";
                ++fail_count;
                continue;
            }
            std::error_code size_error;
            const auto size_kb = fs::file_size(target, size_error) / 1024;
            std::cout << tr("decrypt.ok") << basename;
            if (!size_error) std::cout << " (" << size_kb << " KB)";
            std::cout << "\n";
            ++ok_count;
        }
        std::cout << tr("decrypt.summary") << ok_count << tr("decrypt.ok_count")
                  << fail_count << tr("decrypt.fail_count") << path_to_utf8(output_dir) << "\n";
        if (fail_count != 0) return fail(EXIT_DECRYPT_FAILED, "DECRYPT_FAILED", tr("error.decrypt"));
        std::cout << tr("exit.complete");
        return EXIT_OK;
    } catch (const std::filesystem::filesystem_error& exc) {
        return fail(EXIT_INTERNAL_ERROR, "INTERNAL_ERROR", tr("error.internal") + " " + exc.what());
    } catch (const std::exception& exc) {
        return fail(EXIT_INTERNAL_ERROR, "INTERNAL_ERROR", tr("error.internal") + " " + exc.what());
    }
}
} // namespace qq_dump_db
