"""QQ account and process-instance correlation helpers."""
import ntpath

def parse_qq_account_from_db_path(path):
    """Parse Tencent Files/<QQ>/nt_qq/nt_db/nt_msg.db strictly."""
    parts = [part for part in path.replace('/', '\\').split('\\') if part]
    if len(parts) < 5:
        return None
    if parts[-1].lower() != 'nt_msg.db':
        return None
    if parts[-2].lower() != 'nt_db' or parts[-3].lower() != 'nt_qq':
        return None
    if parts[-5].lower() != 'tencent files':
        return None
    account = parts[-4]
    if not account or not account.isascii() or not account.isdecimal():
        return None
    return account


def resolve_wrapper_pid_for_handle_owner(owner_pid, wrapper_pids, parent_map):
    """Correlate a file-handle owner to its wrapper.node QQ process via ancestry."""
    wrapper_set = set(wrapper_pids)
    if owner_pid in wrapper_set:
        return owner_pid

    # A helper process may be a child of the wrapper.node process.
    visited = set()
    current = owner_pid
    while current not in visited:
        visited.add(current)
        parent = parent_map.get(current, 0)
        if not parent:
            break
        current = parent
        if current in wrapper_set:
            return current

    # Or the file-handle owner may be a QQ.exe parent of wrapper processes.
    # Only accept one descendant wrapper; never choose arbitrarily among clients.
    matched_pid = 0
    for candidate in wrapper_set:
        visited = set()
        node = candidate
        while node not in visited:
            visited.add(node)
            parent = parent_map.get(node, 0)
            if not parent:
                break
            node = parent
            if node == owner_pid:
                if matched_pid and matched_pid != candidate:
                    return 0
                matched_pid = candidate
                break
    return matched_pid


def select_qq_instance(qq_number, mappings):
    account_paths = sorted({
        item['db_path'] for item in mappings
        if item['account'] == str(qq_number)
    })
    if not account_paths:
        raise RuntimeError(f"No running QQ instance was mapped to account {qq_number}.")
    if len(account_paths) != 1:
        raise RuntimeError(
            f"Multiple nt_msg.db paths were mapped to QQ account {qq_number}:\n  " +
            "\n  ".join(account_paths)
        )

    matched_pids = sorted({
        item['wrapper_pid'] for item in mappings
        if item['account'] == str(qq_number)
        and item['db_path'] == account_paths[0]
        and item['wrapper_pid']
    })
    if not matched_pids:
        raise RuntimeError(
            f"Located the database for QQ {qq_number}, but could not associate "
            "its file-handle owner with a wrapper.node process."
        )

    db_directory = ntpath.dirname(account_paths[0])
    return db_directory, matched_pids

