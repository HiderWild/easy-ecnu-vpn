#!/usr/bin/env python3
"""Fail closed when Common Runtime V3 regains a platform or test dependency."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any


NATIVE_INCLUDE = re.compile(
    r"#\s*include\s*[<\"][^>\"]*"
    r"(?:windows(?:\.h)?|win32|darwin|mach/|CoreFoundation|Security/|linux/)"
)
OS_POLICY_BRANCH = re.compile(
    r"#\s*(?:if|ifdef|ifndef|elif)\b[^\n]*"
    r"(?:_WIN32|WIN32|__APPLE__|__linux__|EXV_PLATFORM_(?:WINDOWS|DARWIN|LINUX))"
)
MANUAL_ROUTE_TOKENS = (
    "is_product_authority_action",
    "is_v3_product_action",
    "product_route_policy",
)
PRIVATE_MODEL_INCLUDES = (
    '"generated/runtime_v3_embedded_model.hpp"',
    '"common/runtime_v3/model_bundle_internal.hpp"',
)
SEMANTIC_EXCLUSIONS = {
    "configured_platform_bootstrap.cpp",
    "configured_product_authority_transport.cpp",
}


def source_files(path: Path):
    if not path.is_dir():
        return
    for candidate in sorted(path.rglob("*")):
        if candidate.suffix in {".cpp", ".hpp", ".cc", ".cxx", ".h"}:
            yield candidate


def relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def validate_semantic_sources(root: Path) -> list[str]:
    violations: list[str] = []
    scopes = [root / "src/common/runtime_v3", root / "src/feedback"]
    for scope in scopes:
        for path in source_files(scope):
            if path.name in SEMANTIC_EXCLUSIONS:
                continue
            text = path.read_text(encoding="utf-8")
            if NATIVE_INCLUDE.search(text):
                violations.append(
                    f"COMMON_NATIVE_INCLUDE:{relative(root, path)}"
                )
            if OS_POLICY_BRANCH.search(text):
                violations.append(f"COMMON_OS_POLICY:{relative(root, path)}")
    return violations


def validate_private_model_storage(root: Path) -> list[str]:
    violations: list[str] = []
    source_root = root / "src"
    allowed = "src/common/runtime_v3/model_bundle.cpp"
    for path in source_files(source_root):
        path_relative = relative(root, path)
        if path_relative == allowed:
            continue
        text = path.read_text(encoding="utf-8")
        for include in PRIVATE_MODEL_INCLUDES:
            if include in text:
                violations.append(
                    f"COMMON_MODEL_STORAGE_LEAK:{path_relative}:{include}"
                )
    return violations


def validate_generated_routing(root: Path) -> list[str]:
    violations: list[str] = []
    scopes = [
        root / "src/common",
        root / "src/core",
        root / "src/app/ui_shell",
    ]
    for scope in scopes:
        for path in source_files(scope):
            text = path.read_text(encoding="utf-8")
            for token in MANUAL_ROUTE_TOKENS:
                if token in text:
                    violations.append(
                        f"COMMON_MANUAL_ACTION_ROUTE:{relative(root, path)}:{token}"
                    )
    return violations


COMMON_PRODUCTION_TARGETS = {
    "exv-business-flow-v3",
    "exv-runtime-v3-provider-contract",
}
PRIVILEGED_CONSUMER_TARGETS = {"exv-helper-runtime"}
NARROW_PROVIDER_FORBIDDEN_SOURCE_NAMES = {
    "business_flow_machine.cpp",
    "business_flow_service.cpp",
    "capability_manifest.cpp",
    "common_capability_ports.cpp",
    "composite_capability_port.cpp",
    "configured_platform_bootstrap.cpp",
    "configured_product_authority_transport.cpp",
    "platform_bootstrap.cpp",
    "product_authority_endpoint.cpp",
    "product_ingress.cpp",
    "product_runtime.cpp",
    "runtime_authority_host.cpp",
    "runtime_lifecycle_port.cpp",
}
FORBIDDEN_SOURCE_PARTS = (
    "/src/platform/",
    "/tests/",
    "/test_support/",
    "/mocks/",
    "/mock/",
    "/fakes/",
    "/fake/",
)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _configure_codemodel(root: Path, build_dir: Path) -> Path:
    query_dir = build_dir / ".cmake/api/v1/query/client-exv-common-boundary"
    query_dir.mkdir(parents=True, exist_ok=True)
    (query_dir / "query.json").write_text(
        json.dumps(
            {
                "requests": [
                    {"kind": "codemodel", "version": {"major": 2}}
                ]
            }
        ),
        encoding="utf-8",
    )
    configure_command = [
        "cmake",
        "-S",
        str(root),
        "-B",
        str(build_dir),
        "-G",
        "Ninja",
        "-DCMAKE_BUILD_TYPE=Debug",
    ]
    compiler = os.environ.get("EXV_COMMON_GUARD_CXX_COMPILER")
    if compiler:
        configure_command.append(f"-DCMAKE_CXX_COMPILER={compiler}")
    completed = subprocess.run(
        configure_command,
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if completed.returncode != 0:
        detail = (completed.stdout + completed.stderr)[-3000:].replace(
            "\n", " | "
        )
        raise RuntimeError(f"COMMON_CMAKE_CONFIGURE_FAILED:{detail}")
    reply_dir = build_dir / ".cmake/api/v1/reply"
    indexes = sorted(reply_dir.glob("index-*.json"))
    if not indexes:
        raise RuntimeError("COMMON_CMAKE_FILE_API_REPLY_MISSING")
    index = _read_json(indexes[-1])
    reply = index.get("reply", {}).get("client-exv-common-boundary", {})
    query_reply = reply.get("query.json", {})
    responses = query_reply.get("responses", [])
    for response in responses:
        if response.get("kind") == "codemodel":
            return reply_dir / response["jsonFile"]
    raise RuntimeError("COMMON_CMAKE_CODEMODEL_MISSING")


def _load_target_graph(
    root: Path, build_dir: Path
) -> tuple[dict[str, dict[str, Any]], Path, Path]:
    codemodel_path = _configure_codemodel(root, build_dir)
    reply_dir = codemodel_path.parent
    codemodel = _read_json(codemodel_path)
    configurations = codemodel.get("configurations", [])
    if not configurations:
        raise RuntimeError("COMMON_CMAKE_CONFIGURATION_MISSING")
    configuration = configurations[0]
    source_root = Path(codemodel["paths"]["source"]).resolve()
    build_root = Path(codemodel["paths"]["build"]).resolve()
    graph: dict[str, dict[str, Any]] = {}
    id_to_name: dict[str, str] = {}
    raw_targets: list[dict[str, Any]] = []
    for reference in configuration.get("targets", []):
        target = _read_json(reply_dir / reference["jsonFile"])
        name = target["name"]
        id_to_name[target["id"]] = name
        raw_targets.append(target)
        graph[name] = {
            "name": name,
            "type": target.get("type", ""),
            "sources": [],
            "generated_sources": [],
            "include_directories": [],
            "compile_definitions": [],
            "dependencies": [],
        }
        for source in target.get("sources", []):
            source_path = Path(source["path"])
            if not source_path.is_absolute():
                base = build_root if source.get("isGenerated") else source_root
                source_path = base / source_path
            normalized = source_path.resolve().as_posix()
            graph[name]["sources"].append(normalized)
            if source.get("isGenerated"):
                graph[name]["generated_sources"].append(normalized)
        for group in target.get("compileGroups", []):
            for include in group.get("includes", []):
                include_path = Path(include["path"])
                if not include_path.is_absolute():
                    include_path = source_root / include_path
                graph[name]["include_directories"].append(
                    include_path.resolve().as_posix()
                )
            graph[name]["compile_definitions"].extend(
                definition["define"]
                for definition in group.get("defines", [])
                if "define" in definition
            )
    for target in raw_targets:
        graph[target["name"]]["dependencies"] = sorted(
            {
                id_to_name[dependency["id"]]
                for dependency in target.get("dependencies", [])
                if dependency.get("id") in id_to_name
            }
        )
    return graph, source_root, build_root


def _dependency_closure(
    graph: dict[str, dict[str, Any]], root_target: str
) -> set[str]:
    pending = [root_target]
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        pending.extend(graph.get(name, {}).get("dependencies", []))
    return seen


def _is_forbidden_source(path: str) -> bool:
    normalized = "/" + path.lower().strip("/") + "/"
    return any(part in normalized for part in FORBIDDEN_SOURCE_PARTS)


def _graph_semantic_violations(
    graph: dict[str, dict[str, Any]], source_root: Path
) -> list[str]:
    violations: list[str] = []
    for common_target in sorted(COMMON_PRODUCTION_TARGETS):
        if common_target not in graph:
            violations.append(f"COMMON_TARGET_MISSING:{common_target}")
            continue
        for target_name in sorted(
            _dependency_closure(graph, common_target)
        ):
            target = graph.get(target_name, {})
            for source in target.get("sources", []):
                if _is_forbidden_source(source):
                    violations.append(
                        "COMMON_PRODUCTION_TEST_OR_PLATFORM_LINK:"
                        f"{common_target}->{target_name}:{source}"
                    )

    provider = "exv-runtime-v3-provider-contract"
    if provider in graph:
        provider_closure = _dependency_closure(graph, provider)
        if "exv-business-flow-v3" in provider_closure:
            violations.append(
                "COMMON_PROVIDER_REDUCER_DEPENDENCY:"
                "exv-runtime-v3-provider-contract->exv-business-flow-v3"
            )
        for source in graph[provider].get("sources", []):
            if Path(source).name in NARROW_PROVIDER_FORBIDDEN_SOURCE_NAMES:
                violations.append(
                    "COMMON_PROVIDER_SEMANTIC_SOURCE:"
                    f"{provider}:{source}"
                )

    for consumer in sorted(PRIVILEGED_CONSUMER_TARGETS):
        if consumer not in graph:
            continue
        closure = _dependency_closure(graph, consumer)
        if "exv-business-flow-v3" in closure:
            violations.append(
                f"COMMON_HELPER_PRODUCT_REDUCER_LINK:{consumer}"
            )

    for common_target in sorted(COMMON_PRODUCTION_TARGETS):
        for target_name in _dependency_closure(graph, common_target):
            for source in graph.get(target_name, {}).get("sources", []):
                path = Path(source)
                if (
                    path.is_file()
                    and source_root in path.parents
                    and path.suffix in {".cpp", ".hpp", ".cc", ".cxx", ".h"}
                ):
                    text = path.read_text(encoding="utf-8")
                    if NATIVE_INCLUDE.search(text):
                        violations.append(
                            f"COMMON_NATIVE_INCLUDE_GRAPH:{common_target}:"
                            f"{target_name}:{source}"
                        )
                    if OS_POLICY_BRANCH.search(text):
                        violations.append(
                            f"COMMON_OS_POLICY_GRAPH:{common_target}:"
                            f"{target_name}:{source}"
                        )
    return violations


def _validate_registered_executors(root: Path) -> list[str]:
    path = root / "CMakeLists.txt"
    scenarios_path = (
        root / "contracts/runtime_v3/common_mock_scenarios.json"
    )
    if not path.is_file() or not scenarios_path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    scenarios = _read_json(scenarios_path)
    targets = {
        executor["test_target"]
        for executor in scenarios.get("executors", [])
    }
    list_match = re.search(
        r"set\(_common_runtime_decoupling_tests(?P<body>.*?)\n\)",
        text,
        re.DOTALL,
    )
    if list_match is None:
        return [
            "COMMON_GATE_TARGET_LIST_MISSING:"
            "_common_runtime_decoupling_tests"
        ]
    tokens = set(re.findall(r"[A-Za-z0-9_.+-]+", list_match.group("body")))
    return [
        f"COMMON_MOCK_TEST_NOT_IN_GATE:{target}"
        for target in sorted(targets - tokens)
    ]


def validate_cmake_boundary(root: Path) -> list[str]:
    if not (root / "CMakeLists.txt").is_file():
        return ["COMMON_CMAKE_MISSING:CMakeLists.txt"]
    try:
        with tempfile.TemporaryDirectory(
            prefix="exv-common-cmake-graph-"
        ) as directory:
            graph, source_root, _ = _load_target_graph(
                root, Path(directory)
            )
            violations = _graph_semantic_violations(graph, source_root)
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        return [str(error)]
    return sorted(set(violations + _validate_registered_executors(root)))


def validate_inventory(root: Path) -> list[str]:
    generator = root / "scripts/generate_common_feature_inventory.py"
    if not generator.is_file():
        return ["COMMON_INVENTORY_GENERATOR_MISSING"]
    completed = subprocess.run(
        [sys.executable, str(generator), "--root", str(root), "--check"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode == 0:
        return []
    detail = (completed.stdout + completed.stderr).strip().replace("\n", " | ")
    return [f"COMMON_MOCK_COVERAGE_INVALID:{detail}"]


def validate_action_usage_manifest(root: Path) -> list[str]:
    generator = root / "scripts/generate_action_policy_usage_manifest.py"
    if not generator.is_file():
        return ["COMMON_ACTION_USAGE_GENERATOR_MISSING"]
    completed = subprocess.run(
        [sys.executable, str(generator), "--root", str(root), "--check"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode == 0:
        return []
    detail = (completed.stdout + completed.stderr).strip().replace("\n", " | ")
    return [f"COMMON_ACTION_USAGE_INVALID:{detail}"]


def validate_repository(root: Path, *, check_inventory: bool = True) -> list[str]:
    violations = (
        validate_semantic_sources(root)
        + validate_private_model_storage(root)
        + validate_generated_routing(root)
        + validate_cmake_boundary(root)
    )
    if check_inventory:
        violations += validate_inventory(root)
        violations += validate_action_usage_manifest(root)
    return sorted(set(violations))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    root = args.root.resolve()
    violations = validate_repository(root)
    if violations:
        print("Common runtime decoupling validation failed:")
        for violation in violations:
            print(f"- {violation}")
        return 1
    print("Common runtime decoupling validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
