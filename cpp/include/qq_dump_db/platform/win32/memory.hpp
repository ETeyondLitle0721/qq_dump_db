#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
ScanResults scan_by_salt(HANDLE handle, DWORD pid,
                         const std::vector<std::string>& salt_hexes);
void merge_scan_results(ScanResults& destination, const ScanResults& source);
}
