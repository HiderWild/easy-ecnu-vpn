#!/usr/bin/env python3
"""在原生宿主上运行 Common 本机模块检查；结果不构成真实业务流验收。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_SCRIPT = ROOT / "scripts/common_acceptance_policy.py"
POLICY_SPEC = importlib.util.spec_from_file_location(
    "common_acceptance_policy", POLICY_SCRIPT
)
assert POLICY_SPEC is not None and POLICY_SPEC.loader is not None
POLICY_MODULE = importlib.util.module_from_spec(POLICY_SPEC)
POLICY_SPEC.loader.exec_module(POLICY_MODULE)


class NativeAcceptanceError(RuntimeError):
    """The legacy public error type for Common native module-check failures."""


MAX_NATIVE_JOBS = 8
COMMON_BUILD_TYPE = "Release"
COMMON_GENERATOR_CHECKS = [
    ("generate-contracts-check", ["scripts/generate_contracts.py", "--check"]),
    (
        "generate-product-semantic-contracts-check",
        ["scripts/generate_product_semantic_contracts.py", "--check"],
    ),
    (
        "generate-action-policy-usage-manifest-check",
        ["scripts/generate_action_policy_usage_manifest.py", "--check"],
    ),
    (
        "generate-common-feature-inventory-check",
        ["scripts/generate_common_feature_inventory.py", "--check"],
    ),
    (
        "generate-runtime-contract-identity-check",
        ["scripts/generate_runtime_contract_identity.py", "--check"],
    ),
]


def validate_jobs(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise NativeAcceptanceError("native job count must be an integer")
    if not 1 <= value <= MAX_NATIVE_JOBS:
        raise NativeAcceptanceError(
            f"native job count must be between 1 and {MAX_NATIVE_JOBS}"
        )
    return value


def default_jobs(cpu_count: int | None = None) -> int:
    available = os.cpu_count() if cpu_count is None else cpu_count
    return min(MAX_NATIVE_JOBS, max(1, available or 1))


def cmake_configure_command(
    root: Path,
    build_dir: Path,
    python: Path,
    *,
    host: str,
    profile: str,
    policy: dict[str, Any],
    cxx: str | None = None,
) -> list[str]:
    descriptor = POLICY_MODULE.module_profile_descriptor(
        policy, profile, host
    )
    if descriptor["build_type"] != COMMON_BUILD_TYPE:
        raise NativeAcceptanceError("GOV_COMMON_PROFILE_INVALID: build type")
    command = [
        "cmake",
        "--fresh",
        "-S",
        str(root),
        "-B",
        str(build_dir),
        "-G",
        "Ninja",
        f"-DCMAKE_BUILD_TYPE={COMMON_BUILD_TYPE}",
        f"-DPython3_EXECUTABLE={python}",
    ]
    command.extend(
        f"-D{definition}" for definition in descriptor["cmake_definitions"]
    )
    if cxx:
        command.append(f"-DCMAKE_CXX_COMPILER={cxx}")
    return command


def common_module_commands(
    build_dir: Path, jobs: int
) -> tuple[list[str], list[str]]:
    """Build Common test binaries, then run only the local Common test label."""

    bounded_jobs = validate_jobs(jobs)
    return (
        [
            "cmake",
            "--build",
            str(build_dir),
            "--target",
            "exv_common_module_test_targets",
            "-j",
            str(bounded_jobs),
        ],
        [
            "ctest",
            "--test-dir",
            str(build_dir),
            "--output-on-failure",
            "-L",
            "common-decoupling",
            "--parallel",
            "1",
        ],
    )


def decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def write_console_text(
    value: str,
    *,
    stream: Any | None = None,
    end: str = "\n",
    flush: bool = False,
) -> None:
    destination = sys.stdout if stream is None else stream
    rendered = value + end
    encoding = getattr(destination, "encoding", None)
    if encoding:
        rendered = rendered.encode(
            encoding, errors="backslashreplace"
        ).decode(encoding)
    destination.write(rendered)
    if flush:
        destination.flush()


def output_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_doctor_document(output: str) -> tuple[dict[str, Any], set[str]]:
    try:
        document = json.loads(output)
        result = document["result"]
        dependencies = result["dependencies"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise NativeAcceptanceError(
            "architecture doctor output is malformed"
        ) from error
    if (
        document.get("ok") is not True
        or result.get("capabilities", {}).get("mutate") is not True
    ):
        raise NativeAcceptanceError("architecture doctor did not qualify mutate")
    available = {
        item["name"]
        for item in dependencies
        if isinstance(item, dict) and item.get("available") is True
    }
    return document, available


def cached_python_values(cache_path: Path) -> list[str]:
    if not cache_path.is_file():
        return []
    values = []
    for line in cache_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if re.match(r"^_?Python3_EXECUTABLE(?::[^=]+)?=", line):
            values.append(line.partition("=")[2])
    return sorted(set(values))


def extract_ctest_ids(document: dict[str, Any]) -> list[str]:
    tests = document.get("tests")
    if not isinstance(tests, list):
        raise NativeAcceptanceError("CTest discovery document has no test list")
    names = []
    for test in tests:
        name = test.get("name") if isinstance(test, dict) else None
        if not isinstance(name, str) or not name:
            raise NativeAcceptanceError("CTest discovery contains an invalid test id")
        names.append(name)
    return names


def command_result(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    name: str,
    timeout_seconds: int = 7200,
    allowed_return_codes: tuple[int, ...] = (0,),
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    rendered = " ".join(command)
    write_console_text(
        f"[common-native-module-check] START {name}: {rendered}", flush=True
    )
    started = time.monotonic()
    try:
        raw_completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=False,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise NativeAcceptanceError(
            f"{name} exceeded hard command timeout {timeout_seconds}s"
        ) from error
    except OSError as error:
        executable = command[0] if command else "<empty>"
        raise NativeAcceptanceError(
            f"{name} could not start {executable}: {error}"
        ) from error
    completed = subprocess.CompletedProcess(
        args=raw_completed.args,
        returncode=raw_completed.returncode,
        stdout=decode_output(raw_completed.stdout),
        stderr=decode_output(raw_completed.stderr),
    )
    elapsed = round(time.monotonic() - started, 3)
    if completed.stdout:
        write_console_text(
            completed.stdout,
            end="" if completed.stdout.endswith("\n") else "\n",
        )
    if completed.stderr:
        write_console_text(
            completed.stderr,
            stream=sys.stderr,
            end="" if completed.stderr.endswith("\n") else "\n",
        )
    result = {
        "name": name,
        "command": command,
        "return_code": completed.returncode,
        "elapsed_seconds": elapsed,
        "stdout_digest": output_digest(completed.stdout),
        "stderr_digest": output_digest(completed.stderr),
    }
    if completed.returncode not in allowed_return_codes:
        raise NativeAcceptanceError(f"{name} failed with {completed.returncode}")
    write_console_text(
        f"[common-native-module-check] PASS {name} ({elapsed:.3f}s)", flush=True
    )
    return completed, result


def module_check_summary(
    *,
    host: str,
    descriptor: dict[str, Any],
    test_sets: dict[str, dict[str, Any]],
    command_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create a non-host receipt only after every declared module check ran."""

    required = descriptor.get("module_components")
    if (
        not isinstance(required, list)
        or not required
        or len(required) != len(set(required))
        or any(not isinstance(component, str) or not component for component in required)
    ):
        raise NativeAcceptanceError("Common module components are malformed")
    observed = {
        result["component"]
        for result in command_results
        if isinstance(result, dict)
        and isinstance(result.get("component"), str)
        and result["component"]
    }
    missing = sorted(set(required) - observed)
    unexpected = sorted(observed - set(required))
    if missing or unexpected:
        raise NativeAcceptanceError(
            "Common module command coverage differs from policy: "
            f"missing={missing} unexpected={unexpected}"
        )
    if set(test_sets) != {"common-decoupling"}:
        raise NativeAcceptanceError("Common module CTest discovery is not exact")
    test_ids = test_sets["common-decoupling"].get("test_ids")
    if not isinstance(test_ids, list) or not test_ids:
        raise NativeAcceptanceError("Common module CTest discovery is empty")
    return {
        "schema_version": "3.0",
        "evidence_kind": "common_native_module_checks",
        "host": host,
        "status": "module_checks_passed",
        "receipt_scope": "common_mock_module_only",
        "host_real_passed": False,
        "module_components": list(required),
        "test_sets": test_sets,
        "command_results": command_results,
    }


def write_atomic(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=path.name + ".",
        suffix=".tmp",
        delete=False,
    ) as destination:
        destination.write(rendered)
        temporary = Path(destination.name)
    temporary.replace(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=POLICY_MODULE.HOSTS, required=True)
    parser.add_argument("--profile", choices=("common-only",), required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=default_jobs())
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()

    root = args.root.resolve()
    build_dir = args.build_dir.resolve()
    output = (
        args.output
        if args.output is None or args.output.is_absolute()
        else root / args.output
    )
    environment = dict(os.environ)
    environment["EXV_PYTHON"] = str(Path(sys.executable).resolve())
    results: list[dict[str, Any]] = []

    try:
        jobs = validate_jobs(args.jobs)
        policy = POLICY_MODULE.load_policy(
            root / "docs/superpowers/governance/common-native-acceptance-policy.json"
        )
        descriptor = POLICY_MODULE.module_profile_descriptor(
            policy, args.profile, args.host
        )

        doctor, doctor_result = command_result(
            [
                sys.executable,
                "-m",
                "tools.architecture_json",
                "doctor",
                "--require",
                "mutate",
            ],
            cwd=root,
            environment=environment,
            name="architecture-json-doctor",
        )
        results.append(doctor_result)
        doctor_document, _ = parse_doctor_document(doctor.stdout)
        if (
            Path(doctor_document["result"]["python"]["executable"]).resolve()
            != Path(sys.executable).resolve()
        ):
            raise NativeAcceptanceError(
                "architecture doctor and module runner use different Python"
            )

        cache_path = build_dir / "CMakeCache.txt"
        configure = cmake_configure_command(
            root,
            build_dir,
            Path(sys.executable).resolve(),
            host=args.host,
            profile=args.profile,
            policy=policy,
            cxx=environment.get("CXX"),
        )
        _, result = command_result(
            configure,
            cwd=root,
            environment=environment,
            name="cmake-configure",
        )
        results.append(result)
        if cached_python_values(cache_path) != [str(Path(sys.executable).resolve())]:
            raise NativeAcceptanceError(
                "CMake did not bind every Python discovery variable to the doctor interpreter"
            )

        for component, suffix in COMMON_GENERATOR_CHECKS:
            _, result = command_result(
                [sys.executable, *suffix],
                cwd=root,
                environment=environment,
                name=component,
            )
            result["component"] = component
            results.append(result)

        test_sets: dict[str, dict[str, Any]] = {}
        for label in policy["test_discovery"]["module_labels"]:
            completed, result = command_result(
                [
                    "ctest",
                    "--test-dir",
                    str(build_dir),
                    "--show-only=json-v1",
                    "-L",
                    label,
                ],
                cwd=root,
                environment=environment,
                name=f"ctest-discover-{label}",
            )
            results.append(result)
            test_sets[label] = POLICY_MODULE.observe_test_set(
                extract_ctest_ids(json.loads(completed.stdout))
            )

        build_command, test_command = common_module_commands(build_dir, jobs)
        for name, command in (
            ("common-decoupling-build", build_command),
            ("common-decoupling-execution", test_command),
        ):
            _, result = command_result(
                command,
                cwd=root,
                environment=environment,
                name=name,
            )
            result["component"] = "common-decoupling"
            results.append(result)

        summary = module_check_summary(
            host=args.host,
            descriptor=descriptor,
            test_sets=test_sets,
            command_results=results,
        )
        if output is not None:
            write_atomic(output, summary)
    except (
        NativeAcceptanceError,
        POLICY_MODULE.AcceptancePolicyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        write_console_text(
            f"COMMON_NATIVE_MODULE_CHECKS_FAILED:{error}", stream=sys.stderr
        )
        return 1

    write_console_text(
        f"COMMON_NATIVE_MODULE_CHECKS_PASSED:{args.host}:host_real_passed=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
