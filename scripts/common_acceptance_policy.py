#!/usr/bin/env python3
"""Machine-checked configuration for local Common module checks.

The configuration describes only commands this runner actually executes.  It
does not classify commits, identify delivery candidates, or infer host pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "docs/superpowers/governance/common-native-acceptance-policy.json"
HOSTS = ("darwin", "win32")
COMMON_ONLY_MODULE_COMPONENTS = [
    "generate-contracts-check",
    "generate-product-semantic-contracts-check",
    "generate-action-policy-usage-manifest-check",
    "generate-common-feature-inventory-check",
    "generate-runtime-contract-identity-check",
    "common-decoupling",
]


class AcceptancePolicyError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    validate_policy(policy)
    return policy


def _require_exact_keys(
    value: Any, keys: Iterable[str], where: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcceptancePolicyError(f"{where}: must be an object")
    expected = set(keys)
    actual = set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unexpected:
            details.append("unexpected=" + ",".join(unexpected))
        raise AcceptancePolicyError(f"{where}: keys are not exact: {';'.join(details)}")
    return value


def validate_policy(policy: dict[str, Any]) -> None:
    root = _require_exact_keys(
        policy,
        (
            "schema_version",
            "policy_kind",
            "module_profiles",
            "test_discovery",
            "timing_policy",
        ),
        "policy",
    )
    if root["schema_version"] != "2.0":
        raise AcceptancePolicyError("module policy schema_version must be 2.0")
    if root["policy_kind"] != "common_native_module_checks":
        raise AcceptancePolicyError(
            "policy_kind must describe Common native module checks"
        )

    profiles = _require_exact_keys(
        root["module_profiles"], ("common-only",), "module_profiles"
    )
    profile = _require_exact_keys(
        profiles["common-only"],
        (
            "build_type",
            "host_cmake_definitions",
            "native_jobs",
            "ctest_parallelism",
            "module_components",
            "platform_exclusions",
        ),
        "module_profiles.common-only",
    )
    if profile["build_type"] != "Release":
        raise AcceptancePolicyError("common-only build type must be Release")
    if profile["host_cmake_definitions"] != {
        "darwin": [],
        "win32": ["EXV_BUILD_WINDOWS_SETUP=OFF"],
    }:
        raise AcceptancePolicyError(
            "common-only host CMake definitions are not exact"
        )
    limits = _require_exact_keys(
        profile["native_jobs"],
        ("minimum", "maximum"),
        "common-only.native_jobs",
    )
    if (
        type(limits["minimum"]) is not int
        or type(limits["maximum"]) is not int
        or limits != {"minimum": 1, "maximum": 8}
    ):
        raise AcceptancePolicyError(
            "common-only native_jobs must be bounded to 1..8"
        )
    if (
        type(profile["ctest_parallelism"]) is not int
        or profile["ctest_parallelism"] != 1
    ):
        raise AcceptancePolicyError("common-only CTest must remain serial")
    if profile["module_components"] != COMMON_ONLY_MODULE_COMPONENTS:
        raise AcceptancePolicyError("common-only module components are not exact")
    if profile["platform_exclusions"] != {
        "darwin": [],
        "win32": ["windows-setup"],
    }:
        raise AcceptancePolicyError("common-only platform exclusions are not exact")

    discovery = _require_exact_keys(
        root["test_discovery"],
        ("module_labels", "empty_result"),
        "test_discovery",
    )
    if discovery["module_labels"] != ["common-decoupling"]:
        raise AcceptancePolicyError("Common module CTest labels are not exact")
    if discovery["empty_result"] != "local_module_failure":
        raise AcceptancePolicyError(
            "an empty local module discovery must be reported as a local failure"
        )

    timing = _require_exact_keys(
        root["timing_policy"],
        (
            "expected_budget_effect",
            "hard_timeout_effect",
            "platform_specific_common_budget_override",
            "standardized_performance_lane_may_enforce_expected_budget",
        ),
        "timing_policy",
    )
    if timing["expected_budget_effect"] != "telemetry":
        raise AcceptancePolicyError("expected runtime budget must be telemetry")
    if timing["hard_timeout_effect"] != "local_module_failure":
        raise AcceptancePolicyError("hard timeout must be a local module failure")
    if timing["platform_specific_common_budget_override"] is not False:
        raise AcceptancePolicyError("Common budgets cannot vary by platform")
    if timing["standardized_performance_lane_may_enforce_expected_budget"] is not True:
        raise AcceptancePolicyError(
            "the optional performance lane setting must be explicit"
        )


def module_profile_descriptor(
    policy: dict[str, Any], profile_name: str, host: str
) -> dict[str, Any]:
    validate_policy(policy)
    if profile_name != "common-only":
        raise AcceptancePolicyError(
            f"unsupported Common module profile: {profile_name}"
        )
    if host not in HOSTS:
        raise AcceptancePolicyError(f"unsupported native host: {host}")
    profile = policy["module_profiles"][profile_name]
    profile_digest = sha256_text(
        canonical_json({"name": profile_name, "profile": profile})
    )
    return {
        "name": profile_name,
        "host": host,
        "build_type": profile["build_type"],
        "cmake_definitions": list(profile["host_cmake_definitions"][host]),
        "native_jobs": dict(profile["native_jobs"]),
        "ctest_parallelism": profile["ctest_parallelism"],
        "module_components": list(profile["module_components"]),
        "platform_exclusions": list(profile["platform_exclusions"][host]),
        "profile_digest": profile_digest,
    }


def observe_test_set(test_ids: Iterable[str]) -> dict[str, Any]:
    ordered = sorted(set(test_ids))
    if not ordered or any(not item for item in ordered):
        raise AcceptancePolicyError("test-id set must be nonempty")
    return {
        "count": len(ordered),
        "test_ids": ordered,
    }


def classify_changed_paths(
    policy: dict[str, Any], paths: Iterable[str]
) -> dict[str, Any]:
    validate_policy(policy)
    values = sorted(set(paths))
    return {
        "classification": "change_observed" if values else "no_change",
        "development_ok": True,
        "host_real_passed": False,
        "affected_hosts": [],
        "paths": values,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check")
    classify = subparsers.add_parser("classify-paths")
    classify.add_argument("paths", nargs="*")
    args = parser.parse_args()

    try:
        policy = load_policy(args.policy)
        if args.command == "check":
            result: Any = {
                "ok": True,
                "policy_digest": sha256_text(canonical_json(policy)),
            }
        else:
            result = classify_changed_paths(policy, args.paths)
    except (AcceptancePolicyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"COMMON_MODULE_POLICY_INVALID:{error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
