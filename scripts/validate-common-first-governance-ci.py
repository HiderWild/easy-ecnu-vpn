#!/usr/bin/env python3
"""验证 Git 范围可读取，并报告其中非权威的历史宿主尾注。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from requirement_host_acceptance import AcceptanceError, validate_range


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def emit(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    elif payload["ok"]:
        print(payload["status"])
    else:
        print(
            f"{payload['code']}: {payload.get('field', '')}: "
            f"{payload.get('message', '')}"
        )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = validate_range(
            repo=args.repo,
            base=args.base,
            head=args.head,
        )
    except (AcceptanceError, OSError, UnicodeError) as error:
        payload = {
            "ok": False,
            "status": "historical_range_error",
            "code": getattr(error, "code", "ACCEPTANCE_IO_ERROR"),
            "field": getattr(error, "field", ""),
            "message": str(error),
        }
        emit(payload, args.format)
        return 1
    emit(payload, args.format)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
