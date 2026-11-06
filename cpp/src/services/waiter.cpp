#include "qq_dump_db/services/waiter.hpp"
#include "qq_dump_db/platform/win32/processes.hpp"
#include "qq_dump_db/i18n/catalog.hpp"

namespace qq_dump_db {
void wait_for_qq_exit(const std::vector<DWORD>& target_pids, bool no_wait) {
    if (no_wait) {
        std::cout << tr("wait.skipped");
        return;
    }
    std::vector<DWORD> active;
    for (DWORD pid : target_pids) {
        if (pid && std::find(active.begin(), active.end(), pid) == active.end() && is_process_alive(pid))
            active.push_back(pid);
    }
    if (active.empty()) {
        std::cout << tr("wait.done");
        return;
    }

    std::cout << tr("wait.prompt") << tr("wait.waiting");
    for (size_t i = 0; i < active.size(); ++i) {
        if (i) std::cout << ' ';
        std::cout << active[i];
    }
    std::cout << "\n";

    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD console_mode = 0;
    if (input == INVALID_HANDLE_VALUE || !GetConsoleMode(input, &console_mode)) {
        std::cout << tr("wait.noninteractive");
        return;
    }

    while (true) {
        bool any_alive = false;
        for (DWORD pid : active) {
            if (is_process_alive(pid)) {
                any_alive = true;
                break;
            }
        }
        if (!any_alive) {
            std::cout << tr("wait.done");
            return;
        }

        INPUT_RECORD record{};
        DWORD events = 0;
        if (PeekConsoleInputW(input, &record, 1, &events) && events > 0) {
            ReadConsoleInputW(input, &record, 1, &events);
            if (record.EventType == KEY_EVENT && record.Event.KeyEvent.bKeyDown &&
                record.Event.KeyEvent.wVirtualKeyCode == VK_RETURN) {
                std::cout << tr("wait.skipped");
                return;
            }
        }
        Sleep(500);
    }
}
} // namespace qq_dump_db
