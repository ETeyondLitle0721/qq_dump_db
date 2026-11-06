"""Command-line parser and stable legacy entry point."""
from __future__ import annotations

import argparse
import os
import re
import sys

from . import __version__
from .i18n import get_language, set_language, tr


class LocalizedArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        print(self.format_usage().rstrip(), file=sys.stderr)
        print(tr("error.prefix", code="CLI_USAGE", message=tr("cli.usage_error", detail=message)), file=sys.stderr)
        raise SystemExit(2)


def build_parser(language="zh-CN"):
    set_language(language)
    parser = LocalizedArgumentParser(
        prog="qq_dump_db",
        description=tr("app.description"),
        add_help=False,
    )
    parser.add_argument("--qq", required=True, help=tr("cli.qq"))
    parser.add_argument("--pid", type=int, default=0, help=tr("cli.pid"))
    parser.add_argument("-o", "--output", default=None, help=tr("cli.output"))
    parser.add_argument("--db-dir", default="", help=tr("cli.db_dir"))
    parser.add_argument("--output-dir", default=None, help=tr("cli.output_dir"))
    parser.add_argument("--lang", choices=("auto", "zh-CN", "en-US"), default="auto", help=tr("cli.lang"))
    parser.add_argument("--no-wait", action="store_true", help=tr("cli.no_wait"))
    parser.add_argument("-h", "--help", action="help", help=tr("cli.help"))
    parser.add_argument("--version", action="version", version=tr("app.version", version=__version__), help=tr("cli.version"))
    if language == "zh-CN":
        parser._optionals.title = "选项"
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Use an explicit language early enough to localize parser/help messages.
    requested = "auto"
    for index, item in enumerate(argv):
        if item == "--lang" and index + 1 < len(argv):
            requested = argv[index + 1]
        elif item.startswith("--lang="):
            requested = item.split("=", 1)[1]
    language = get_language(requested)
    set_language(language)
    parser = build_parser(language)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    args.language = get_language(args.lang)
    set_language(args.language)
    if not re.fullmatch(r"[0-9]+", args.qq or ""):
        print(tr("error.prefix", code="CLI_USAGE", message=tr("cli.invalid_qq")), file=sys.stderr)
        return 2
    pid_was_supplied = any(item == "--pid" or item.startswith("--pid=") for item in argv)
    if args.pid < 0 or (args.pid == 0 and pid_was_supplied):
        print(tr("error.prefix", code="CLI_USAGE", message=tr("cli.invalid_pid")), file=sys.stderr)
        return 2
    if args.db_dir and not os.path.isdir(args.db_dir):
        print(tr("error.prefix", code="DATABASE_NOT_FOUND", message=tr("cli.db_dir_missing", path=args.db_dir)), file=sys.stderr)
        return 13
    from .app import run
    return run(args)
