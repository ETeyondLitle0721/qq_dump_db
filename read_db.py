"""Inspect decrypted NTQQ SQLite databases from output/<QQ号>/.

Examples:
    python read_db.py --qq 1627126029
    python read_db.py --qq 1627126029 --db nt_msg.db
    python read_db.py --qq 1627126029 --db nt_msg.db --table c2c_msg_table --limit 20
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent / "python"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from qq_dump_db.i18n import get_language, set_language, tr  # noqa: E402


FTS_SHADOW_SUFFIXES = ("_fts", "_fts_config", "_fts_data", "_fts_docsize", "_fts_idx")


def list_tables(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    cur = conn.execute(
        "SELECT name, type FROM sqlite_master "
        "WHERE type IN ('table','view') ORDER BY name"
    )
    return cur.fetchall()


def is_fts_shadow(name: str, all_names: set[str]) -> bool:
    return any(name.endswith(suffix) for suffix in FTS_SHADOW_SUFFIXES)


def table_row_count(conn: sqlite3.Connection, table: str) -> int | str:
    try:
        cur = conn.execute(f'SELECT COUNT(*) FROM "{table}"')
        return cur.fetchone()[0]
    except sqlite3.DatabaseError:
        return "?"


def show_table(conn: sqlite3.Connection, table: str, limit: int = 10):
    try:
        cur = conn.execute(f'SELECT * FROM "{table}" LIMIT {limit}')
    except sqlite3.DatabaseError as exc:
        print(tr("viewer.table_skip", name=table, error=exc))
        print("  └─")
        return

    columns = [description[0] for description in cur.description]
    rows = cur.fetchall()
    count = table_row_count(conn, table)
    print(tr("viewer.table_header", name=table, count=count, shown=len(rows)))
    print(tr("viewer.columns", columns=", ".join(columns)))
    print("  │")

    for index, row in enumerate(rows):
        cells = []
        for value in row:
            if isinstance(value, bytes):
                cells.append(f"<BLOB {len(value)} bytes>" if len(value) > 64 else value.hex())
            elif isinstance(value, str) and len(value) > 120:
                cells.append(value[:120] + "...")
            else:
                cells.append(repr(value))
        print(f"  │  [{index}] {', '.join(cells)}")
    print("  └─")


def inspect_db(db_path: Path, table_filter: str | None = None, limit: int = 10):
    print("\n" + "=" * 72)
    print(tr("viewer.database", name=db_path.name, size=db_path.stat().st_size / 1024))
    print("=" * 72)
    try:
        with sqlite3.connect(str(db_path)) as conn:
            all_tables = list_tables(conn)
            if not all_tables:
                print(tr("viewer.no_tables"))
                return

            all_names = {name for name, _kind in all_tables}
            regular = [(name, kind) for name, kind in all_tables if not is_fts_shadow(name, all_names)]
            skipped = [(name, kind) for name, kind in all_tables if is_fts_shadow(name, all_names)]
            print(tr("viewer.table_count", total=len(all_tables), regular=len(regular), fts=len(skipped)))
            print(tr("viewer.regular", names=", ".join(name for name, _kind in regular)))
            if skipped:
                print(tr("viewer.fts", names=", ".join(name for name, _kind in skipped)))

            if table_filter:
                if table_filter in all_names:
                    show_table(conn, table_filter, limit)
                else:
                    print(tr("viewer.not_found", name=table_filter))
            else:
                for name, _kind in regular:
                    show_table(conn, name, limit)
    except sqlite3.DatabaseError as exc:
        print(tr("viewer.db_error", error=exc))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    requested = "auto"
    for index, item in enumerate(argv):
        if item == "--lang" and index + 1 < len(argv):
            requested = argv[index + 1]
        elif item.startswith("--lang="):
            requested = item.split("=", 1)[1]
    set_language(get_language(requested))

    parser = argparse.ArgumentParser(description=tr("viewer.description"))
    parser.add_argument("--qq", required=True, help=tr("viewer.qq_help"))
    parser.add_argument("--db", default=None, help=tr("viewer.db_help"))
    parser.add_argument("--table", default=None, help=tr("viewer.table_help"))
    parser.add_argument("--limit", type=int, default=10, help=tr("viewer.limit_help"))
    parser.add_argument("--lang", choices=("auto", "zh-CN", "en-US"), default="auto", help=tr("viewer.lang_help"))
    if get_language(requested) == "zh-CN":
        parser._optionals.title = "选项"
    args = parser.parse_args(argv)
    set_language(get_language(args.lang))
    if args.limit < 0:
        parser.error("--limit must be zero or a positive integer")

    output_dir = Path.cwd() / "output" / str(args.qq)
    if not output_dir.exists():
        print(tr("viewer.directory_missing", path=output_dir))
        return 1

    db_files = sorted(output_dir.glob("*.db"))
    if not db_files:
        print(tr("viewer.no_db_files", path=output_dir))
        return 1

    if args.db:
        target = output_dir / args.db
        if not target.exists():
            print(tr("viewer.db_missing", name=args.db, path=output_dir))
            print(tr("viewer.available", names=", ".join(path.name for path in db_files)))
            return 1
        db_files = [target]

    print(tr("viewer.qq", qq=args.qq))
    print(tr("viewer.directory", path=output_dir))
    print(tr("viewer.databases", count=len(db_files)))
    for db_path in db_files:
        inspect_db(db_path, args.table, args.limit)
    print(tr("viewer.done", count=len(db_files)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
