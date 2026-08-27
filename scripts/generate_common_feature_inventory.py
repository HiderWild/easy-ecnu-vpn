#!/usr/bin/env python3
"""Generate the Common V3 executable-conformance inventory.

Feature identities come from checked-in Common authorities.  Executor
contracts assign every feature dimension to a real test binary, but assignment
is deliberately *not* coverage.  Coverage is granted only when
``run_common_executed_receipts.py`` executes those binaries and validates the
resulting immutable receipt set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


FEATURE_MARKER = re.compile(
    r"EXV_COMMON_FEATURE:\s*([a-z][a-z0-9_]*)"
    r":([a-z0-9][a-z0-9_.-]*)"
)
REQUIRED_DIMENSIONS: dict[str, tuple[str, ...]] = {
    "capability": (
        "valid_request",
        "malformed_request",
        "wrong_identity",
        "stale_identity",
        "duplicate_completion",
    ),
    "capability_outcome": ("classified_completion",),
    "completion_requirement": ("required_fields",),
    "outcome_class": ("common_disposition",),
    "resource": ("acquire_exact", "retire_exact", "uncertain_recovery"),
    "composite": ("child_matrix", "order_independence"),
    "transition": (
        "guard_false",
        "guard_true",
        "resource_delta",
        "illegal_or_stale_event",
    ),
    "invariant": ("accept_valid", "reject_violation"),
    "terminal_state": ("reachable", "production_projection"),
    "scenario_obligation": (
        "required_trace",
        "fault",
        "interruption",
        "terminal",
    ),
    "diagnostic": (
        "exact_code",
        "unknown_safe_code",
        "raw_text_forbidden",
        "presentation_preserved",
    ),
    "presentation_rule": ("matched", "action_preserved"),
    "public_action": (
        "canonical_name",
        "correct_target",
        "success",
        "typed_failure",
        "missing_endpoint",
        "response_shape",
    ),
    "action_alias": ("canonicalization", "correct_target", "response_shape"),
    "error": ("exact_code", "domain", "message_independent", "recovery"),
    "error_alias": ("canonicalization", "domain"),
    "artifact_rule": ("production_behavior",),
    "identity_rule": ("production_behavior",),
    "lifecycle_rule": ("production_behavior",),
    "authority_rule": ("production_behavior",),
    "extension_rule": ("production_behavior",),
    "registry_rule": ("production_behavior",),
}


class InventoryError(RuntimeError):
    pass


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"cannot read {path}: {error}") from error


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def feature(
    feature_class: str, value: str, authority: str
) -> dict[str, Any]:
    if feature_class not in REQUIRED_DIMENSIONS:
        raise InventoryError(f"unknown Common feature class: {feature_class}")
    return {
        "id": f"{feature_class}:{value}",
        "class": feature_class,
        "authority": authority,
        "required_dimensions": list(REQUIRED_DIMENSIONS[feature_class]),
    }


def derive_model_features(model: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    source = "contracts/runtime_v3/business_flow.model.json"

    for entry in model["capabilities"]:
        capability_id = entry["id"]
        result.append(feature("capability", capability_id, f"{source}#capabilities"))
        for outcome in entry["allowed_outcomes"]:
            result.append(
                feature(
                    "capability_outcome",
                    f"{capability_id}/{outcome}",
                    f"{source}#capabilities/{capability_id}/allowed_outcomes",
                )
            )

    for entry in model["completion_requirements"]:
        capability_id = entry["capability"]
        for outcome in entry["outcomes"]:
            result.append(
                feature(
                    "completion_requirement",
                    f"{capability_id}/{outcome}",
                    f"{source}#completion_requirements",
                )
            )

    list_sources = {
        "outcome_class": "outcome_classes",
        "resource": "resources",
        "composite": "composites",
        "transition": "transitions",
        "invariant": "invariants",
        "presentation_rule": "presentation_rules",
        "terminal_state": "terminal_state_classes",
        "scenario_obligation": "scenario_obligations",
    }
    for feature_class, key in list_sources.items():
        for entry in model[key]:
            result.append(feature(feature_class, entry["id"], f"{source}#{key}"))

    for entry in model["diagnostic_policy"]["catalog"]:
        result.append(
            feature(
                "diagnostic",
                entry["semantic_code"],
                f"{source}#diagnostic_policy/catalog",
            )
        )
    return result


def derive_system_features(contract: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    source = "contracts/system.contract.json"
    for entry in contract["action_contracts"]:
        result.append(
            feature("public_action", entry["name"], f"{source}#action_contracts")
        )
    for entry in contract.get("action_aliases", []):
        result.append(
            feature(
                "action_alias",
                entry["alias"],
                f"{source}#action_aliases",
            )
        )
    for entry in contract["error_contracts"]:
        result.append(feature("error", entry["code"], f"{source}#error_contracts"))
    for entry in contract["error_aliases"]:
        result.append(
            feature("error_alias", entry["alias"], f"{source}#error_aliases")
        )
    return result


def derive_marker_features(
    root: Path, marker_sources: list[str]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    result: list[dict[str, Any]] = []
    contents: dict[str, str] = {}
    for relative in marker_sources:
        path = root / relative
        if not path.is_file():
            raise InventoryError(f"marker source does not exist: {relative}")
        text = path.read_text(encoding="utf-8")
        contents[relative] = text
        matches = list(FEATURE_MARKER.finditer(text))
        if not matches:
            raise InventoryError(f"marker source has no Common features: {relative}")
        for match in matches:
            result.append(
                feature(
                    match.group(1),
                    match.group(2),
                    f"{relative}#EXV_COMMON_FEATURE",
                )
            )
    return result, contents


def validate_unique_features(features: list[dict[str, Any]]) -> None:
    counts = Counter(item["id"] for item in features)
    duplicates = sorted(name for name, count in counts.items() if count != 1)
    if duplicates:
        raise InventoryError("duplicate feature IDs: " + ", ".join(duplicates))


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def validate_executor(
    root: Path,
    executor: dict[str, Any],
    feature_by_id: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    executor_id = executor.get("id")
    target = executor.get("test_target")
    test_source = executor.get("test_source")
    entrypoint = executor.get("production_entrypoint_id")
    oracle_source = executor.get("oracle_source")
    success_marker = executor.get("success_marker")
    execution_budget_seconds = executor.get("execution_budget_seconds")
    timeout_margin_seconds = executor.get("timeout_margin_seconds")
    identity_fields = (
        executor_id,
        target,
        test_source,
        entrypoint,
        oracle_source,
        success_marker,
    )
    if not all(_nonempty_string(value) for value in identity_fields):
        raise InventoryError(
            "executor requires id, target, source, entrypoint, oracle and marker"
        )
    if (
        not isinstance(execution_budget_seconds, int)
        or isinstance(execution_budget_seconds, bool)
        or execution_budget_seconds <= 0
    ):
        raise InventoryError(
            f"{executor_id}: execution_budget_seconds must be a positive integer"
        )
    if (
        not isinstance(timeout_margin_seconds, int)
        or isinstance(timeout_margin_seconds, bool)
        or timeout_margin_seconds <= 0
    ):
        raise InventoryError(
            f"{executor_id}: timeout_margin_seconds must be a positive integer"
        )
    hard_timeout_seconds = execution_budget_seconds + timeout_margin_seconds
    maximum_hard_timeout_seconds = 600
    if hard_timeout_seconds > maximum_hard_timeout_seconds:
        raise InventoryError(
            f"{executor_id}: execution_budget_seconds + "
            "timeout_margin_seconds must be at most "
            f"{maximum_hard_timeout_seconds}"
        )
    minimum_margin_seconds = max(
        30, (execution_budget_seconds + 3) // 4
    )
    if timeout_margin_seconds < minimum_margin_seconds:
        raise InventoryError(
            f"{executor_id}: timeout_margin_seconds must be at least "
            f"{minimum_margin_seconds}"
        )
    if not (root / test_source).is_file():
        raise InventoryError(f"{executor_id}: missing test source {test_source}")
    oracle_path = oracle_source.split("#", 1)[0]
    if not (root / oracle_path).is_file():
        raise InventoryError(f"{executor_id}: missing oracle source {oracle_path}")

    selectors = executor.get("selectors")
    if not isinstance(selectors, list) or not selectors:
        raise InventoryError(f"{executor_id}: selectors must be nonempty")

    executions: list[dict[str, Any]] = []
    for selector in selectors:
        dimensions = selector.get("dimensions")
        if (
            not isinstance(dimensions, list)
            or not dimensions
            or any(not _nonempty_string(value) for value in dimensions)
        ):
            raise InventoryError(
                f"{executor_id}: selector dimensions must be explicit"
            )
        if "*" in dimensions:
            raise InventoryError(
                f"{executor_id}: wildcard dimensions are forbidden"
            )

        class_selector = selector.get("feature_classes")
        id_selector = selector.get("feature_ids")
        if bool(class_selector) == bool(id_selector):
            raise InventoryError(
                f"{executor_id}: selector needs exactly one of "
                "feature_classes or feature_ids"
            )

        selected: list[dict[str, Any]] = []
        if class_selector:
            if not isinstance(class_selector, list):
                raise InventoryError(
                    f"{executor_id}: feature_classes must be a list"
                )
            for feature_class in class_selector:
                if feature_class not in REQUIRED_DIMENSIONS:
                    raise InventoryError(
                        f"{executor_id}: unknown feature class {feature_class}"
                    )
                selected.extend(
                    item
                    for item in feature_by_id.values()
                    if item["class"] == feature_class
                )
        else:
            if not isinstance(id_selector, list):
                raise InventoryError(
                    f"{executor_id}: feature_ids must be a list"
                )
            for feature_id in id_selector:
                item = feature_by_id.get(feature_id)
                if item is None:
                    raise InventoryError(
                        f"{executor_id}: orphaned feature reference {feature_id}"
                    )
                selected.append(item)
        if not selected:
            raise InventoryError(
                f"{executor_id}: selector matched no Common features"
            )

        for item in selected:
            for dimension in dimensions:
                if dimension not in item["required_dimensions"]:
                    raise InventoryError(
                        f"{executor_id}: {item['id']} has no dimension "
                        f"{dimension}"
                    )
                scenario = {
                    "feature_id": item["id"],
                    "dimension_id": dimension,
                    "executor_id": executor_id,
                    "test_target": target,
                    "production_entrypoint_id": entrypoint,
                    "ordered_inputs": [
                        {
                            "sequence": 1,
                            "operation": "execute_test_binary",
                            "target": target,
                            "feature_id": item["id"],
                            "dimension_id": dimension,
                        }
                    ],
                    "injected_classified_outcomes": [
                        dimension
                    ] if dimension in {
                        "classified_completion",
                        "common_disposition",
                        "fault",
                        "typed_failure",
                        "unknown_safe_code",
                        "reject_violation",
                    } else [],
                    "expected_observations": [
                        {
                            "kind": "production_entrypoint",
                            "equals": entrypoint,
                        },
                        {
                            "kind": "success_marker",
                            "equals": success_marker,
                        },
                    ],
                    "expected_invariants": [
                        "test_binary_exit_code_zero",
                        "binary_identity_matches_executed_artifact",
                    ],
                    "expected_terminal": "passed",
                    "oracle_source": oracle_source,
                }
                scenario["scenario_digest"] = "sha256:" + hashlib.sha256(
                    canonical_json(scenario).encode("utf-8")
                ).hexdigest()
                executions.append(scenario)

    descriptor = {
        "id": executor_id,
        "test_target": target,
        "test_source": test_source,
        "production_entrypoint_id": entrypoint,
        "oracle_source": oracle_source,
        "success_marker": success_marker,
        "execution_budget_seconds": execution_budget_seconds,
        "timeout_margin_seconds": timeout_margin_seconds,
    }
    return descriptor, executions


def generate_inventory(root: Path) -> dict[str, Any]:
    model_path = root / "contracts/runtime_v3/business_flow.model.json"
    contract_path = root / "contracts/system.contract.json"
    scenario_path = root / "contracts/runtime_v3/common_mock_scenarios.json"
    model = read_json(model_path)
    contract = read_json(contract_path)
    scenarios = read_json(scenario_path)

    if scenarios.get("schema_version") != "2.1":
        raise InventoryError("common mock scenario schema_version must be 2.1")
    if scenarios.get("receipt_scope") != "common_mock_module_only":
        raise InventoryError(
            "common mock receipt_scope must be common_mock_module_only"
        )
    if scenarios.get("host_real_passed") is not False:
        raise InventoryError("common mock receipt cannot claim host real pass")
    marker_sources = scenarios.get("declared_feature_sources")
    if not isinstance(marker_sources, list) or not marker_sources:
        raise InventoryError("declared_feature_sources must be a nonempty list")

    marker_features, marker_contents = derive_marker_features(root, marker_sources)
    features = (
        derive_model_features(model)
        + derive_system_features(contract)
        + marker_features
    )
    validate_unique_features(features)
    features.sort(key=lambda item: item["id"])
    feature_by_id = {item["id"]: item for item in features}

    execution_plan: list[dict[str, Any]] = []
    executor_descriptors: list[dict[str, Any]] = []
    executors = scenarios.get("executors")
    if not isinstance(executors, list) or not executors:
        raise InventoryError("executors must be a nonempty list")
    executor_ids: set[str] = set()
    for executor in executors:
        executor_id = executor.get("id")
        if executor_id in executor_ids:
            raise InventoryError(f"duplicate executor: {executor_id}")
        executor_ids.add(executor_id)
        descriptor, assigned = validate_executor(root, executor, feature_by_id)
        executor_descriptors.append(descriptor)
        execution_plan.extend(assigned)

    execution_plan.sort(
        key=lambda item: (
            item["feature_id"],
            item["dimension_id"],
            item["executor_id"],
        )
    )
    assigned_counts = Counter(
        (item["feature_id"], item["dimension_id"]) for item in execution_plan
    )
    duplicates = sorted(
        pair for pair, count in assigned_counts.items() if count != 1
    )
    if duplicates:
        preview = ", ".join(f"{feature}#{dimension}" for feature, dimension in duplicates[:12])
        raise InventoryError(
            f"COMMON_EXECUTOR_ASSIGNMENT_DUPLICATE ({len(duplicates)}): {preview}"
        )
    assigned = set(assigned_counts)
    missing = [
        {"feature_id": item["id"], "dimension_id": dimension}
        for item in features
        for dimension in item["required_dimensions"]
        if (item["id"], dimension) not in assigned
    ]
    digest_input = {
        "model": model,
        "system_contract": contract,
        "scenarios": scenarios,
        "declared_feature_sources": marker_contents,
    }
    class_counts = Counter(item["class"] for item in features)
    return {
        "schema_version": "2.1",
        "requirement_id": "vpn-common-v3-runtime-boundary-decoupling",
        "receipt_scope": scenarios["receipt_scope"],
        "host_real_passed": scenarios["host_real_passed"],
        "source_digest": "sha256:"
        + hashlib.sha256(canonical_json(digest_input).encode("utf-8")).hexdigest(),
        "features": features,
        "executors": sorted(executor_descriptors, key=lambda item: item["id"]),
        "expected_executions": execution_plan,
        "summary": {
            "feature_count": len(features),
            "required_dimension_count": sum(
                len(item["required_dimensions"]) for item in features
            ),
            "executor_count": len(executor_descriptors),
            "expected_execution_count": len(execution_plan),
            "unassigned_dimension_count": len(missing),
            "feature_counts_by_class": dict(sorted(class_counts.items())),
        },
    }


def validate_receipts(
    inventory: dict[str, Any],
    receipt_document: dict[str, Any],
    trusted_binary_identities: dict[str, str],
) -> dict[str, int]:
    """Fail closed unless receipts exactly match the generated execution plan."""
    if receipt_document.get("schema_version") != "1.0":
        raise InventoryError("receipt schema_version must be 1.0")
    if receipt_document.get("receipt_scope") != "common_mock_module_only":
        raise InventoryError("receipt scope must remain common_mock_module_only")
    if receipt_document.get("host_real_passed") is not False:
        raise InventoryError("mock receipt cannot claim host real pass")
    if receipt_document.get("inventory_source_digest") != inventory.get(
        "source_digest"
    ):
        raise InventoryError("COMMON_RECEIPT_STALE_INVENTORY")

    expected = {
        (item["feature_id"], item["dimension_id"]): item
        for item in inventory["expected_executions"]
    }
    observed: dict[tuple[str, str], dict[str, Any]] = {}
    receipts = receipt_document.get("receipts")
    if not isinstance(receipts, list):
        raise InventoryError("receipts must be a list")
    for receipt in receipts:
        key = (receipt.get("feature_id"), receipt.get("dimension_id"))
        if key in observed:
            raise InventoryError(
                f"COMMON_RECEIPT_DUPLICATE:{key[0]}#{key[1]}"
            )
        scenario = expected.get(key)
        if scenario is None:
            raise InventoryError(
                f"COMMON_RECEIPT_UNKNOWN:{key[0]}#{key[1]}"
            )
        target = scenario["test_target"]
        if receipt.get("scenario_digest") != scenario["scenario_digest"]:
            raise InventoryError(
                f"COMMON_RECEIPT_SCENARIO_MISMATCH:{key[0]}#{key[1]}"
            )
        if (
            receipt.get("executor_id") != scenario["executor_id"]
            or receipt.get("test_target") != target
            or receipt.get("observed_entrypoint")
            != scenario["production_entrypoint_id"]
        ):
            raise InventoryError(
                f"COMMON_RECEIPT_ENTRYPOINT_MISMATCH:{key[0]}#{key[1]}"
            )
        if receipt.get("binary_identity") != trusted_binary_identities.get(
            target
        ):
            raise InventoryError(
                f"COMMON_RECEIPT_UNTRUSTED_BINARY:{key[0]}#{key[1]}"
            )
        if (
            receipt.get("exit_code") != 0
            or receipt.get("observed_terminal") != "passed"
            or not _nonempty_string(receipt.get("stdout_digest"))
        ):
            raise InventoryError(
                f"COMMON_RECEIPT_FAILED_EXECUTION:{key[0]}#{key[1]}"
            )
        observed[key] = receipt

    missing = sorted(set(expected) - set(observed))
    if missing:
        preview = ", ".join(
            f"{feature}#{dimension}" for feature, dimension in missing[:12]
        )
        raise InventoryError(
            f"COMMON_RECEIPT_MISSING ({len(missing)}): {preview}"
        )
    return {
        "expected_execution_count": len(expected),
        "executed_verified_count": len(observed),
        "missing_count": 0,
        "duplicate_count": 0,
        "untrusted_count": 0,
    }


def render_inventory(root: Path) -> str:
    return json.dumps(
        generate_inventory(root),
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
        default=Path("contracts/generated/common_feature_inventory.json"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    root = args.root.resolve()
    output = args.output
    if not output.is_absolute():
        output = root / output
    try:
        rendered = render_inventory(root)
    except InventoryError as error:
        print(f"common feature inventory error: {error}")
        return 1

    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(f"common feature inventory is stale: {output}")
            return 1
        print("common feature inventory is complete and up to date")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
        output.write_text(rendered, encoding="utf-8")
    print(f"generated {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
