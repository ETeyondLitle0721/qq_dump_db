"""Application boundary: run workflow and translate failures to exit codes."""
from __future__ import annotations

import sys

from .errors import QQDumpError, EXIT_INTERNAL_ERROR, EXIT_INTERRUPTED
from .i18n import tr
from .services.workflow import run_workflow


def run(args) -> int:
    try:
        return run_workflow(args)
    except QQDumpError as exc:
        print(tr("error.prefix", code=exc.error_id, message=exc.message), file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        print(tr("error.prefix", code="INTERRUPTED", message=tr("app.interrupted")), file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as exc:  # last-resort boundary; never print process memory or key material
        print(tr("error.prefix", code="INTERNAL_ERROR", message=tr("app.internal_error", detail=type(exc).__name__)), file=sys.stderr)
        return EXIT_INTERNAL_ERROR
