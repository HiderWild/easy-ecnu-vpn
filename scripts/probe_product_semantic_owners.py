#!/usr/bin/env python3
"""Probe product-semantic owners above and beside Common Runtime V3.

The checked-in inventory is the authority for the G0 baseline.  ``--gate``
returns non-zero while any known second semantic owner remains.  The
``--assert-baseline`` mode is intentionally green only when the exact
open/closed inventory state matches production source, which keeps the red
baseline executable without weakening the eventual release gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


INVENTORY_PATH = Path(
    "contracts/runtime_v3/product_semantic_surface_inventory.json"
)
ALLOWED_KINDS = {
    "all_patterns_present",
    "any_pattern_present",
    "required_patterns_missing",
    "file_exists",
}
ALLOWED_STATES = {"open", "closed"}


class SemanticOwnerProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class FindingResult:
    finding_id: str
    title: str
    source: str
    detected: bool
    expected_open: bool
    current_owner: str
    required_owner: str
    closure_phase: str


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SemanticOwnerProbeError(f"cannot read {path}: {error}") from error


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical_json(value).encode("utf-8")
    ).hexdigest()


def _require_keys(
    value: dict[str, Any],
    required: set[str],
    allowed: set[str],
    context: str,
) -> None:
    missing = sorted(required - value.keys())
    extra = sorted(value.keys() - allowed)
    if missing:
        raise SemanticOwnerProbeError(
            f"{context}: missing keys: {', '.join(missing)}"
        )
    if extra:
        raise SemanticOwnerProbeError(
            f"{context}: unknown keys: {', '.join(extra)}"
        )


def _validate_source_path(source: str, context: str) -> None:
    path = Path(source)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise SemanticOwnerProbeError(
            f"{context}: source must be a repository-relative path"
        )


def validate_inventory(inventory: Any) -> dict[str, Any]:
    if not isinstance(inventory, dict):
        raise SemanticOwnerProbeError("inventory must be an object")
    top_keys = {
        "schema_version",
        "requirement_id",
        "baseline",
        "findings",
        "settings_fields",
        "renderer_state_families",
    }
    _require_keys(inventory, top_keys, top_keys, "inventory")
    if inventory["schema_version"] != "1.0":
        raise SemanticOwnerProbeError("unsupported inventory schema_version")
    if (
        inventory["requirement_id"]
        != "vpn-common-v3-product-semantics-convergence"
    ):
        raise SemanticOwnerProbeError("unexpected inventory requirement_id")
    baseline = inventory["baseline"]
    if not isinstance(baseline, dict):
        raise SemanticOwnerProbeError("baseline must be an object")
    _require_keys(
        baseline,
        {"parent_common_tip", "audited_darwin_tip"},
        {"parent_common_tip", "audited_darwin_tip"},
        "baseline",
    )
    for name, value in baseline.items():
        if (
            not isinstance(value, str)
            or len(value) != 40
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise SemanticOwnerProbeError(
                f"baseline.{name} must be a full lowercase git object id"
            )

    findings = inventory["findings"]
    if not isinstance(findings, list) or not findings:
        raise SemanticOwnerProbeError("findings must be a non-empty array")
    finding_ids: set[str] = set()
    finding_keys = {
        "id",
        "title",
        "source",
        "current_owner",
        "required_owner",
        "closure_phase",
        "state",
        "detection",
    }
    detection_keys = {"kind", "patterns"}
    for index, finding in enumerate(findings):
        context = f"findings[{index}]"
        if not isinstance(finding, dict):
            raise SemanticOwnerProbeError(f"{context} must be an object")
        _require_keys(finding, finding_keys, finding_keys, context)
        finding_id = finding["id"]
        if (
            not isinstance(finding_id, str)
            or not finding_id.startswith("PSO-")
            or len(finding_id) != 7
            or not finding_id[4:].isdigit()
        ):
            raise SemanticOwnerProbeError(f"{context}.id is invalid")
        if finding_id in finding_ids:
            raise SemanticOwnerProbeError(
                f"duplicate finding id: {finding_id}"
            )
        finding_ids.add(finding_id)
        for key in (
            "title",
            "source",
            "current_owner",
            "required_owner",
            "closure_phase",
        ):
            if not isinstance(finding[key], str) or not finding[key]:
                raise SemanticOwnerProbeError(
                    f"{context}.{key} must be a non-empty string"
                )
        _validate_source_path(finding["source"], context)
        if finding["state"] not in ALLOWED_STATES:
            raise SemanticOwnerProbeError(f"{context}.state is invalid")
        detection = finding["detection"]
        if not isinstance(detection, dict):
            raise SemanticOwnerProbeError(
                f"{context}.detection must be an object"
            )
        _require_keys(
            detection, detection_keys, detection_keys, f"{context}.detection"
        )
        kind = detection["kind"]
        patterns = detection["patterns"]
        if kind not in ALLOWED_KINDS:
            raise SemanticOwnerProbeError(
                f"{context}.detection.kind is invalid"
            )
        if not isinstance(patterns, list) or any(
            not isinstance(pattern, str) or not pattern
            for pattern in patterns
        ):
            raise SemanticOwnerProbeError(
                f"{context}.detection.patterns must contain strings"
            )
        if kind == "file_exists" and patterns:
            raise SemanticOwnerProbeError(
                f"{context}: file_exists accepts no patterns"
            )
        if kind != "file_exists" and not patterns:
            raise SemanticOwnerProbeError(
                f"{context}: {kind} requires patterns"
            )

    for collection_name, identity_key in (
        ("settings_fields", "field"),
        ("renderer_state_families", "family"),
    ):
        collection = inventory[collection_name]
        if not isinstance(collection, list) or not collection:
            raise SemanticOwnerProbeError(
                f"{collection_name} must be a non-empty array"
            )
        identities: set[str] = set()
        for index, entry in enumerate(collection):
            if not isinstance(entry, dict):
                raise SemanticOwnerProbeError(
                    f"{collection_name}[{index}] must be an object"
                )
            identity = entry.get(identity_key)
            if not isinstance(identity, str) or not identity:
                raise SemanticOwnerProbeError(
                    f"{collection_name}[{index}].{identity_key} is invalid"
                )
            if identity in identities:
                raise SemanticOwnerProbeError(
                    f"duplicate {collection_name} identity: {identity}"
                )
            identities.add(identity)
            for key, value in entry.items():
                if not isinstance(value, str) or not value:
                    raise SemanticOwnerProbeError(
                        f"{collection_name}[{index}].{key} is invalid"
                    )
    return inventory


def load_inventory(root: Path) -> dict[str, Any]:
    return validate_inventory(_read_json(root / INVENTORY_PATH))


def _detect(root: Path, finding: dict[str, Any]) -> bool:
    path = root / finding["source"]
    detection = finding["detection"]
    kind = detection["kind"]
    if kind == "file_exists":
        return path.is_file()
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return False
    patterns = detection["patterns"]
    if kind == "all_patterns_present":
        return all(pattern in source for pattern in patterns)
    if kind == "any_pattern_present":
        return any(pattern in source for pattern in patterns)
    if kind == "required_patterns_missing":
        return not all(pattern in source for pattern in patterns)
    raise AssertionError(f"validated detection kind not handled: {kind}")


def probe(root: Path, inventory: dict[str, Any]) -> list[FindingResult]:
    results: list[FindingResult] = []
    for finding in inventory["findings"]:
        results.append(
            FindingResult(
                finding_id=finding["id"],
                title=finding["title"],
                source=finding["source"],
                detected=_detect(root, finding),
                expected_open=finding["state"] == "open",
                current_owner=finding["current_owner"],
                required_owner=finding["required_owner"],
                closure_phase=finding["closure_phase"],
            )
        )
    return results


def render_json(
    root: Path,
    inventory: dict[str, Any],
    results: list[FindingResult],
) -> str:
    detected = [result for result in results if result.detected]
    mismatches = [
        result
        for result in results
        if result.detected != result.expected_open
    ]
    document = {
        "schema_version": "1.0",
        "requirement_id": inventory["requirement_id"],
        "inventory_digest": _digest(inventory),
        "root": str(root),
        "summary": {
            "finding_count": len(results),
            "detected_count": len(detected),
            "expected_open_count": sum(
                result.expected_open for result in results
            ),
            "baseline_mismatch_count": len(mismatches),
        },
        "findings": [
            {
                "id": result.finding_id,
                "title": result.title,
                "source": result.source,
                "detected": result.detected,
                "expected_open": result.expected_open,
                "current_owner": result.current_owner,
                "required_owner": result.required_owner,
                "closure_phase": result.closure_phase,
            }
            for result in results
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True)


def render_text(
    inventory: dict[str, Any], results: list[FindingResult]
) -> str:
    detected = [result for result in results if result.detected]
    mismatches = [
        result
        for result in results
        if result.detected != result.expected_open
    ]
    lines = [
        "Product semantic owner probe",
        f"requirement: {inventory['requirement_id']}",
        f"inventory: {_digest(inventory)}",
        f"findings: {len(results)}",
        f"detected: {len(detected)}",
        f"baseline mismatches: {len(mismatches)}",
    ]
    for result in results:
        state = "RED" if result.detected else "CLEARED"
        expected = "open" if result.expected_open else "closed"
        lines.append(
            f"- {result.finding_id}: {state} "
            f"(inventory={expected}, phase={result.closure_phase}) "
            f"{result.source}"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--gate", action="store_true")
    mode.add_argument("--assert-baseline", action="store_true")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        inventory = load_inventory(root)
        results = probe(root, inventory)
    except SemanticOwnerProbeError as error:
        print(f"PRODUCT_SEMANTIC_PROBE_ERROR: {error}")
        return 2

    if args.format == "json":
        print(render_json(root, inventory, results))
    else:
        print(render_text(inventory, results))

    mismatches = [
        result
        for result in results
        if result.detected != result.expected_open
    ]
    if args.assert_baseline:
        return 2 if mismatches else 0
    return 1 if any(result.detected for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
