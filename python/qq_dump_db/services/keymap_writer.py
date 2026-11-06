"""Versioned key-map serialization with atomic file replacement."""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def resolve_output_paths(args):
    cwd = Path.cwd()
    if args.output_dir:
        root = Path(args.output_dir).expanduser()
        if not root.is_absolute():
            root = cwd / root
    else:
        root = cwd / "output" / str(args.qq)
    root = root.resolve()

    if args.output:
        key_path = Path(args.output).expanduser()
        if not key_path.is_absolute():
            key_path = root / key_path
    else:
        key_path = root / "key_map.json"
    return root, key_path.resolve()


def write_key_map(path, key_map):
    """Write schema v1 JSON atomically; never leave a partial key-map file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not key_map:
        raise ValueError("key_map must contain at least one verified key")
    for salt_hex, key_hex in key_map.items():
        if not isinstance(salt_hex, str) or not re.fullmatch(r"[0-9a-f]{32}", salt_hex):
            raise ValueError("salt keys must be 32 lowercase hexadecimal characters")
        if not isinstance(key_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", key_hex):
            raise ValueError("encryption keys must be 64 lowercase hexadecimal characters")

    payload = {
        "schema_version": 1,
        "key_map": dict(sorted(key_map.items())),
        "_generated": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return payload
