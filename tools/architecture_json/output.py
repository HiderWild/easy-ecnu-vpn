"""Deterministic bounded rendering for agent and human callers."""

from __future__ import annotations

import copy
import json
from typing import Any

from .errors import ArchitectureQueryError


CONTRACT_VERSION = "exv.architecture-query/v1"
MAX_OUTPUT_BYTES = 256 * 1024


def success_envelope(
    *,
    source: dict[str, Any],
    command: str,
    parameters: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_VERSION,
        "ok": True,
        "source": source,
        "query": {"command": command, "parameters": parameters},
        "result": result,
        "diagnostics": [],
    }


def failure_envelope(error: ArchitectureQueryError) -> dict[str, Any]:
    return {
        "contract": CONTRACT_VERSION,
        "ok": False,
        "error": error.to_dict(),
        "diagnostics": [],
    }


def _serialize(value: Any, *, pretty: bool) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=False,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
        )
        + "\n"
    )


def _serialized_size(value: Any, *, pretty: bool) -> int:
    return len(_serialize(value, pretty=pretty).encode("utf-8"))


def _prune_last_tree_child(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    children = node.get("children")
    if not isinstance(children, list) or not children:
        return False
    if _prune_last_tree_child(children[-1]):
        node["truncated"] = True
        return True
    children.pop()
    node["truncated"] = True
    return True


def _fit_envelope(envelope: dict[str, Any], *, pretty: bool) -> dict[str, Any]:
    if _serialized_size(envelope, pretty=pretty) <= MAX_OUTPUT_BYTES:
        return envelope
    if not envelope.get("ok"):
        raise ArchitectureQueryError(
            "ARCH_INTERNAL_ERROR",
            "failure envelope exceeds output safety ceiling",
            exit_code=70,
        )

    fitted = copy.deepcopy(envelope)
    result = fitted.get("result", {})
    kind = result.get("kind")
    if kind == "list" and isinstance(result.get("items"), list):
        items = result["items"]
        had_items = bool(items)
        while items and _serialized_size(fitted, pretty=pretty) > MAX_OUTPUT_BYTES:
            items.pop()
        if had_items and not items:
            raise ArchitectureQueryError(
                "ARCH_RESULT_TOO_LARGE",
                "one list item exceeds the safe output ceiling; project fewer fields",
                exit_code=6,
                details={"max_output_bytes": MAX_OUTPUT_BYTES, "result_kind": kind},
            )
        result["returned"] = len(items)
        result["truncated"] = result.get("total", len(items)) > result.get(
            "offset", 0
        ) + len(items)
        if _serialized_size(fitted, pretty=pretty) <= MAX_OUTPUT_BYTES:
            return fitted
    elif kind == "tree" and isinstance(result.get("data"), dict):
        while _serialized_size(fitted, pretty=pretty) > MAX_OUTPUT_BYTES:
            if not _prune_last_tree_child(result["data"]):
                break
        if _serialized_size(fitted, pretty=pretty) <= MAX_OUTPUT_BYTES:
            return fitted

    raise ArchitectureQueryError(
        "ARCH_RESULT_TOO_LARGE",
        "query result exceeds the safe output ceiling; request a smaller slice",
        exit_code=6,
        details={"max_output_bytes": MAX_OUTPUT_BYTES, "result_kind": kind},
    )


def render_json(envelope: dict[str, Any], *, pretty: bool) -> str:
    return _serialize(_fit_envelope(envelope, pretty=pretty), pretty=pretty)


def render_jsonl(envelope: dict[str, Any]) -> str:
    result = envelope.get("result", {})
    if not envelope.get("ok") or result.get("kind") != "list":
        raise ArchitectureQueryError(
            "ARCH_USAGE_INVALID",
            "JSONL output is supported only for successful list results",
            exit_code=2,
        )
    fitted = _fit_envelope(envelope, pretty=False)
    result = fitted["result"]
    items = result.get("items", [])
    metadata_result = {key: value for key, value in result.items() if key != "items"}
    metadata = {
        "contract": CONTRACT_VERSION,
        "record": "meta",
        "ok": True,
        "source": fitted["source"],
        "query": fitted["query"],
        "result": metadata_result,
    }
    lines = [_serialize(metadata, pretty=False).rstrip("\n")]
    digest = fitted["source"].get("canonical_sha256")
    offset = result.get("offset", 0)
    for index, item in enumerate(items, start=offset):
        record = {
            "contract": CONTRACT_VERSION,
            "record": "item",
            "source_sha256": digest,
            "index": index,
            "item": item,
        }
        if _serialized_size(record, pretty=False) > MAX_OUTPUT_BYTES:
            raise ArchitectureQueryError(
                "ARCH_RESULT_TOO_LARGE",
                "one JSONL item exceeds the safe output ceiling",
                exit_code=6,
                details={"index": index, "max_output_bytes": MAX_OUTPUT_BYTES},
            )
        lines.append(_serialize(record, pretty=False).rstrip("\n"))
    return "\n".join(lines) + "\n"


def render_text(envelope: dict[str, Any]) -> str:
    if not envelope.get("ok"):
        error = envelope["error"]
        return f"{error['code']}: {error['message']}\n"
    result = envelope["result"]
    if result.get("kind") == "list":
        return "\n".join(
            json.dumps(item, ensure_ascii=False, sort_keys=True, allow_nan=False)
            for item in result.get("items", [])
        ) + ("\n" if result.get("items") else "")
    return (
        json.dumps(
            result, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
        )
        + "\n"
    )
