#!/usr/bin/env python3
"""Generate the resolved typed ActionId usage manifest.

This is a semantic companion to the CMake graph gate. Public action wire text
may enter generated parsers, but production policy branches must use ActionId.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


ACTION_MAPPING = re.compile(
    r"\{ActionId::(?P<id>[A-Za-z0-9_]+),\s*\"(?P<action>[^\"]+)\""
)
TYPED_REFERENCE = re.compile(r"\bActionId::(?P<id>[A-Za-z0-9_]+)\b")
RAW_COMPARISON = re.compile(
    r"(?:==|!=)\s*[\"'](?P<right>[a-z][A-Za-z0-9_.]+)[\"']"
    r"|[\"'](?P<left>[a-z][A-Za-z0-9_.]+)[\"']\s*(?:==|!=)"
)
DIGEST = re.compile(
    r'SYSTEM_CONTRACT_DIGEST\s*=\s*\"(?P<digest>sha256:[0-9a-f]{64})\"'
)

PRODUCTION_SCOPES = (
    "src/common",
    "src/core",
    "src/app/ui_shell",
    "src/cli",
)
SOURCE_SUFFIXES = {".cpp", ".hpp", ".cc", ".cxx", ".h"}


class UsageManifestError(RuntimeError):
    pass


def source_files(root: Path):
    for scope in PRODUCTION_SCOPES:
        directory = root / scope
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.suffix in SOURCE_SUFFIXES:
                yield path


def generate_manifest(root: Path) -> dict:
    generated_path = root / "src/contracts/generated/system_contract.hpp"
    generated = generated_path.read_text(encoding="utf-8")
    mapping = {
        match.group("id"): match.group("action")
        for match in ACTION_MAPPING.finditer(generated)
    }
    if not mapping:
        raise UsageManifestError("generated ActionId mapping is missing")
    digest_match = DIGEST.search(generated)
    if digest_match is None:
        raise UsageManifestError("generated system contract digest is missing")

    usages: dict[str, set[str]] = {action: set() for action in mapping.values()}
    raw_comparisons: list[dict[str, object]] = []
    for path in source_files(root):
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in TYPED_REFERENCE.finditer(line):
                action = mapping.get(match.group("id"))
                if action is not None:
                    usages[action].add(f"{relative}:{line_number}")
            for match in RAW_COMPARISON.finditer(line):
                action = match.group("right") or match.group("left")
                if action in usages:
                    raw_comparisons.append(
                        {
                            "action": action,
                            "source": relative,
                            "line": line_number,
                        }
                    )
    if raw_comparisons:
        preview = ", ".join(
            f"{item['source']}:{item['line']}:{item['action']}"
            for item in raw_comparisons[:12]
        )
        raise UsageManifestError(
            f"COMMON_RAW_ACTION_POLICY_COMPARISON:{preview}"
        )

    source_digest_input = {
        "system_contract_digest": digest_match.group("digest"),
        "typed_usages": {
            action: sorted(sites) for action, sites in sorted(usages.items())
        },
    }
    canonical = json.dumps(
        source_digest_input,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "schema_version": "1.0",
        "system_contract_digest": digest_match.group("digest"),
        "source_digest": "sha256:"
        + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "actions": [
            {
                "action": action,
                "action_id": action_id,
                "typed_reference_sites": sorted(usages[action]),
            }
            for action_id, action in sorted(
                mapping.items(), key=lambda item: item[1]
            )
        ],
        "raw_policy_comparison_count": 0,
    }


def render(root: Path) -> str:
    return json.dumps(
        generate_manifest(root),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("contracts/generated/action_policy_usage_manifest.json"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output
    if not output.is_absolute():
        output = root / output
    try:
        rendered = render(root)
    except (OSError, UsageManifestError) as error:
        print(f"action policy usage manifest error: {error}")
        return 1
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(f"action policy usage manifest is stale: {output}")
            return 1
        print("action policy usage manifest is current; raw comparisons: 0")
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
        output.write_text(rendered, encoding="utf-8")
    print(f"generated {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
