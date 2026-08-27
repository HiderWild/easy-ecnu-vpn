#!/usr/bin/env python3
"""Reproduce the reopened Runtime V3 boundary defects without changing state.

This is a WP-0 red-evidence probe, not the final decoupling acceptance gate.
It returns non-zero while any known root-gap signature remains. Later work
packages must replace each source signature with behavioral and graph-backed
acceptance coverage before removing the corresponding probe.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import importlib.util
import json
from pathlib import Path
import re
import tempfile
from types import ModuleType


@dataclass(frozen=True)
class Finding:
    id: str
    invariant: str
    summary: str
    evidence: tuple[str, ...]


HISTORICAL_FINDING_IDS = (
    "RED-R01-CANONICAL-INGRESS",
    "RED-R02-ALIAS-HANDLERS",
    "RED-R03-DESKTOP-SURFACE",
    "RED-R04-POLICY-AUTHORITY",
    "RED-R05-METADATA-FAIL-OPEN",
    "RED-R06-REGISTRY-CLOSURE-RETRY",
    "RED-R07-TEXT-DERIVED-AUTH",
    "RED-R08-UNOWNED-ASYNC",
    "RED-R09-PAPER-MOCK-CLOSURE",
    "RED-R10-CMAKE-GRAPH-BYPASS",
)
EXPECTED_FINDING_IDS: tuple[str, ...] = ()


def read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def production_sources(root: Path):
    for path in sorted((root / "src").rglob("*")):
        if path.suffix not in {".cpp", ".hpp", ".cc", ".cxx", ".h", ".mm"}:
            continue
        if path.as_posix().endswith("src/contracts/generated/system_contract.hpp"):
            continue
        yield path


def canonical_ingress_gap(root: Path) -> Finding | None:
    callers = []
    for path in production_sources(root):
        text = path.read_text(encoding="utf-8")
        if (
            "canonical_action_for(" in text
            or "ActionIngress::parse(" in text
        ):
            callers.append(path.relative_to(root).as_posix())
    if callers:
        return None
    return Finding(
        id="RED-R01-CANONICAL-INGRESS",
        invariant="INV-R01",
        summary="No production ingress invokes generated action canonicalization.",
        evidence=(
            "src/contracts/generated/system_contract.hpp defines canonical_action_for",
            "production caller count is zero",
        ),
    )


def alias_handler_gap(root: Path) -> Finding | None:
    contract = json.loads(read(root, "contracts/system.contract.json"))
    aliases = sorted(item["alias"] for item in contract["action_aliases"])
    registered: list[str] = []
    for path in production_sources(root):
        text = path.read_text(encoding="utf-8")
        for alias in aliases:
            pattern = rf"register_(?:legacy_)?handler\(\s*\"{re.escape(alias)}\""
            if re.search(pattern, text):
                registered.append(f"{alias}@{path.relative_to(root).as_posix()}")
    if not registered:
        return None
    return Finding(
        id="RED-R02-ALIAS-HANDLERS",
        invariant="INV-R03",
        summary="Compatibility aliases still own production handlers.",
        evidence=tuple(registered),
    )


def desktop_surface_gap(root: Path) -> Finding | None:
    text = read(root, "src/app/ui_shell/host_bridge.cpp")
    if "is_public_action(action)" not in text:
        return None
    return Finding(
        id="RED-R03-DESKTOP-SURFACE",
        invariant="INV-R02",
        summary="Renderer host admission uses the global public set, not desktop surface.",
        evidence=(
            "src/app/ui_shell/host_bridge.cpp:is_allowed_host_action -> is_public_action",
            "generated is_desktop_rpc_action has no production caller",
        ),
    )


def policy_authority_gap(root: Path) -> Finding | None:
    metadata = read(root, "src/core/rpc/rpc_action_metadata.cpp")
    bridge = read(root, "src/app/ui_shell/async_host_bridge.cpp")
    if (
        "default_metadata_for_action" not in metadata
        and "request_timeout_for_action" not in bridge
    ):
        return None
    evidence = []
    if "default_metadata_for_action" in metadata:
        evidence.append(
            "src/core/rpc/rpc_action_metadata.cpp owns handwritten lane/conflict/mutation policy"
        )
    if "request_timeout_for_action" in bridge:
        evidence.append(
            "src/app/ui_shell/async_host_bridge.cpp owns handwritten deadline policy"
        )
    if '"config.getKey"' in metadata and '"key.status"' in metadata:
        evidence.append("config.getKey and key.status are classified by different branches")
    return Finding(
        id="RED-R04-POLICY-AUTHORITY",
        invariant="INV-R04",
        summary="Execution policy remains outside the generated action descriptor.",
        evidence=tuple(evidence),
    )


def metadata_fail_open_gap(root: Path) -> Finding | None:
    metadata = read(root, "src/core/rpc/rpc_action_metadata.cpp")
    core_process = read(root, "src/core/core_process.cpp")
    default_lane = re.search(
        r"return\s+metadata\(RpcLane::ReadModel\);\s*\n\}", metadata
    )
    fallback = ".value_or(exv::core_api::default_metadata_for_action(" in core_process
    if not (default_lane and fallback):
        return None
    return Finding(
        id="RED-R05-METADATA-FAIL-OPEN",
        invariant="INV-R01",
        summary="Missing action metadata silently receives ReadModel policy before rejection.",
        evidence=(
            "rpc_action_metadata.cpp ends unknown lookup with RpcLane::ReadModel",
            "core_process.cpp value_or(default_metadata_for_action(...)) schedules the fallback",
        ),
    )


def registry_gap(root: Path) -> Finding | None:
    dispatcher = read(root, "src/core/rpc/app_rpc_dispatcher.cpp")
    registry = read(root, "src/core/app_api/desktop_action_registry.cpp")
    seal_without_closure = bool(
        re.search(r"void\s+AppRpcDispatcher::seal\(\)\s*\{\s*sealed_\s*=\s*true;\s*\}", dispatcher)
    )
    cached_result = bool(
        re.search(
            r"static\s+const\s+auto\s+registry\s*=\s*build_desktop_action_registry",
            registry,
        )
    )
    if not (seal_without_closure or cached_result):
        return None
    evidence = []
    if seal_without_closure:
        evidence.append("AppRpcDispatcher::seal only sets sealed_=true")
    if cached_result:
        evidence.append("desktop_registry caches a typed build result in function-local static")
    return Finding(
        id="RED-R06-REGISTRY-CLOSURE-RETRY",
        invariant="INV-R05/INV-R06",
        summary="Production registry lacks exact closure and retryable lifecycle.",
        evidence=tuple(evidence),
    )


def text_auth_gap(root: Path) -> Finding | None:
    text = read(root, "webui/src/stores/vpn.ts")
    signatures = (
        "function isAuthFailureMessage",
        "localizedRawError",
        "recommended_action: 'retry_password'",
    )
    if not all(signature in text for signature in signatures):
        return None
    return Finding(
        id="RED-R07-TEXT-DERIVED-AUTH",
        invariant="INV-R07/INV-R08",
        summary="WebUI raw-message fallback can select authentication recovery.",
        evidence=(
            "webui/src/stores/vpn.ts:isAuthFailureMessage matches human-readable text",
            "localizedRawError maps the match to auth_failed/retry_password",
            "normalizeError calls localizedRawError for missing or unknown typed codes",
        ),
    )


def unowned_async_gap(root: Path) -> Finding | None:
    text = read(root, "src/app/ui_shell/async_host_bridge.cpp")
    thread = re.search(
        r"std::thread\(\[future\s*=\s*std::move\(future\).*?\}\)\.detach\(\);",
        text,
        re.DOTALL,
    )
    if not thread:
        return None
    body = thread.group(0)
    if "future.get()" not in body or "catch" in body:
        return None
    return Finding(
        id="RED-R08-UNOWNED-ASYNC",
        invariant="INV-R09",
        summary="Detached request thread lets an exceptional future escape its entrypoint.",
        evidence=(
            "src/app/ui_shell/async_host_bridge.cpp detaches each request thread",
            "future.get() has no exception boundary",
            "request work is not joined or drained by AsyncHostBridge shutdown",
        ),
    )


def paper_mock_gap(root: Path) -> Finding | None:
    scenarios = json.loads(read(root, "contracts/runtime_v3/common_mock_scenarios.json"))
    wildcard_suites = []
    for suite in scenarios.get("coverage_suites", []):
        for declaration in suite.get("covers", []):
            if "*" in declaration.get("dimensions", []):
                wildcard_suites.append(suite.get("id", "<unknown>"))
                break
    generator = read(root, "scripts/generate_common_feature_inventory.py")
    explorer = read(root, "tests/common/runtime_v3_model_explorer_test.cpp")
    declarative_only = (
        "declared_data_driven = set(DATA_DRIVEN_MARKER.findall(test_text))" in generator
        and "if symbol not in test_text:" in generator
        and "exercise_every_scenario_obligation" in explorer
        and "references unknown fault class" in explorer
        and "references unknown terminal class" in explorer
    )
    if not wildcard_suites or not declarative_only:
        return None
    return Finding(
        id="RED-R09-PAPER-MOCK-CLOSURE",
        invariant="INV-R10",
        summary="Wildcard declarations and source markers can claim scenario coverage.",
        evidence=(
            "wildcard suites: " + ", ".join(sorted(wildcard_suites)),
            "inventory validates marker and production-symbol strings",
            "scenario explorer validates fault/terminal IDs without executing each scenario trace",
        ),
    )


def load_decoupling_validator(root: Path) -> ModuleType:
    path = root / "scripts/validate-common-runtime-decoupling.py"
    spec = importlib.util.spec_from_file_location("runtime_decoupling_guard", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load decoupling validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cmake_graph_bypass_gap(root: Path) -> Finding | None:
    validator = load_decoupling_validator(root)
    with tempfile.TemporaryDirectory(prefix="exv-runtime-boundary-probe-") as directory:
        fixture = Path(directory)
        for relative in (
            "src/common/runtime_v3/provider.cpp",
            "src/common/runtime_v3/model_bundle.cpp",
            "src/platform/darwin/native.cpp",
            "src/helper/helper.cpp",
        ):
            source = fixture / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("int fixture_symbol() { return 1; }\n", encoding="utf-8")
        (fixture / "CMakeLists.txt").write_text(
            "\n".join(
                (
                    "cmake_minimum_required(VERSION 3.28)",
                    "project(runtime_boundary_probe LANGUAGES CXX)",
                    "add_library(exv-runtime-v3-provider-contract STATIC",
                    "  src/common/runtime_v3/provider.cpp",
                    ")",
                    "add_library(exv-business-flow-v3 STATIC",
                    "  src/common/runtime_v3/model_bundle.cpp",
                    ")",
                    "target_link_libraries(exv-business-flow-v3 PUBLIC",
                    "  exv-runtime-v3-provider-contract",
                    ")",
                    "add_library(exv-helper-runtime STATIC",
                    "  src/helper/helper.cpp",
                    ")",
                    "target_link_libraries(exv-helper-runtime PUBLIC",
                    "  exv-runtime-v3-provider-contract",
                    ")",
                    "target_sources(exv-business-flow-v3 PRIVATE",
                    "  src/platform/darwin/native.cpp",
                    ")",
                    "",
                )
            ),
            encoding="utf-8",
        )
        violations = validator.validate_cmake_boundary(fixture)
    platform_violation = any(
        item.startswith("COMMON_PRODUCTION_TEST_OR_PLATFORM_LINK")
        for item in violations
    )
    if platform_violation:
        return None
    return Finding(
        id="RED-R10-CMAKE-GRAPH-BYPASS",
        invariant="INV-R11",
        summary="Direct-body CMake parsing misses a platform source added by target_sources.",
        evidence=(
            "temporary target_sources fixture adds src/platform/darwin/native.cpp",
            "validate_cmake_boundary emits no COMMON_PRODUCTION_TEST_OR_PLATFORM_LINK",
            "other missing-gate diagnostics, if any, do not detect the dependency edge",
        ),
    )


CHECKS = (
    canonical_ingress_gap,
    alias_handler_gap,
    desktop_surface_gap,
    policy_authority_gap,
    metadata_fail_open_gap,
    registry_gap,
    text_auth_gap,
    unowned_async_gap,
    paper_mock_gap,
    cmake_graph_bypass_gap,
)


def probe_repository(root: Path) -> list[Finding]:
    findings = [finding for check in CHECKS if (finding := check(root)) is not None]
    return sorted(findings, key=lambda item: item.id)


def render_text(root: Path, findings: list[Finding]) -> str:
    lines = [
        "Runtime boundary root-gap red probe",
        f"root: {root}",
        f"findings: {len(findings)}",
    ]
    for finding in findings:
        lines.append(f"- {finding.id} [{finding.invariant}]: {finding.summary}")
        lines.extend(f"  evidence: {item}" for item in finding.evidence)
    if findings:
        lines.append("result: RED (candidate is not eligible for acceptance)")
    else:
        lines.append(
            "result: signatures cleared; run behavioral/graph acceptance gates before GREEN"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    root = args.root.resolve()
    findings = probe_repository(root)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "probe": "vpn-common-v3-runtime-boundary-root-gaps",
                    "root": str(root),
                    "status": "red" if findings else "signatures_cleared",
                    "findings": [asdict(finding) for finding in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(render_text(root, findings))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
