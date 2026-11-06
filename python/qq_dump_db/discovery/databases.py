"""NTQQ database directory and page-1 metadata discovery."""
import os
from ..crypto.sqlcipher import EXT_HEADER, PAGE_SIZE, SALT_SIZE
from ..i18n import tr

def find_db_dirs(qq_number, account_db_dir=None, custom_db_dir=None):
    if custom_db_dir:
        if not os.path.isdir(custom_db_dir):
            raise RuntimeError(tr("db.custom_missing", path=custom_db_dir))
        return [(qq_number, custom_db_dir)]

    if not account_db_dir or not os.path.isdir(account_db_dir):
        raise RuntimeError(tr("db.no_account_dir"))

    # Expected layout: <data_root>/<account>/nt_qq/nt_db.
    # Derive the shared root from the located nt_msg.db path.
    account_nt_qq_dir = os.path.dirname(account_db_dir)
    account_root = os.path.dirname(account_nt_qq_dir)
    data_root = os.path.dirname(account_root)
    global_dir = os.path.join(data_root, 'nt_qq', 'global', 'nt_db')

    candidates = []
    if os.path.isdir(global_dir):
        candidates.append(('global', global_dir))
    else:
        print(tr("db.global_missing", path=global_dir))
    candidates.append((qq_number, account_db_dir))
    return candidates


def collect_db_info(db_dirs):
    global_dbs = []
    pa_map = {}
    for account, d in db_dirs:
        for fn in os.listdir(d):
            if not fn.lower().endswith('.db'):
                continue
            fp = os.path.join(d, fn)
            try:
                with open(fp, 'rb') as f:
                    hdr = f.read(EXT_HEADER + PAGE_SIZE)
                if len(hdr) < EXT_HEADER + PAGE_SIZE:
                    continue
                if hdr[:16] != b'SQLite header 3\x00':
                    continue
                page1 = hdr[EXT_HEADER: EXT_HEADER + PAGE_SIZE]
                salt_hex = page1[:SALT_SIZE].hex()
                if account == 'global':
                    global_dbs.append((account, fp, page1))
                else:
                    pa_map.setdefault(salt_hex, []).append((account, fp, page1))
            except (OSError, PermissionError):
                continue
    return global_dbs, pa_map

