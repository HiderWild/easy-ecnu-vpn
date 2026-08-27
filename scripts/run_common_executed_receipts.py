#!/usr/bin/env python3
"""Execute every Common mock executor and validate exact runtime receipts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any, Callable


class ReceiptRunnerError(RuntimeError):
    pass


BoundedRunner = Callable[
    [list[str], int, Path | None, dict[str, str] | None],
    tuple[int, str, str, bool],
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def load_inventory_module(root: Path):
    script = root / "scripts/generate_common_feature_inventory.py"
    spec = importlib.util.spec_from_file_location("common_feature_inventory", script)
    if spec is None or spec.loader is None:
        raise ReceiptRunnerError(f"cannot load inventory generator: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_bounded_runner(root: Path) -> BoundedRunner:
    script = root / "scripts/windows_pe_imports.py"
    spec = importlib.util.spec_from_file_location("windows_pe_imports", script)
    if spec is None or spec.loader is None:
        raise ReceiptRunnerError(f"cannot load bounded runner: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    runner = getattr(module, "run_bounded_command", None)
    if not callable(runner):
        raise ReceiptRunnerError(f"COMMON_EXECUTOR_BOUNDED_RUNNER_MISSING:{script}")
    return runner


def find_executable(build_dir: Path, target: str) -> Path:
    candidates = [
        build_dir / target,
        build_dir / "Debug" / target,
        build_dir / "Release" / target,
        build_dir / "RelWithDebInfo" / target,
        build_dir / "MinSizeRel" / target,
        build_dir / f"{target}.exe",
        build_dir / "Debug" / f"{target}.exe",
        build_dir / "Release" / f"{target}.exe",
        build_dir / "RelWithDebInfo" / f"{target}.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise ReceiptRunnerError(f"COMMON_EXECUTOR_BINARY_MISSING:{target}:{build_dir}")


def command_for_executor(
    root: Path, build_dir: Path, executor: dict[str, str]
) -> tuple[list[str], Path]:
    source = root / executor["test_source"]
    if source.suffix == ".py":
        return [sys.executable, str(source)], source.resolve()
    executable = find_executable(build_dir, executor["test_target"])
    return [str(executable)], executable


def output_detail(stdout: str, stderr: str) -> str:
    combined = (stdout + stderr).replace("\r\n", "\n").replace("\r", "\n")
    return combined[-2000:].replace("\n", " | ")


def execute_plan(
    root: Path,
    build_dir: Path,
    inventory: dict[str, Any],
    *,
    bounded_runner: BoundedRunner | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    enforce_performance_budget: bool = False,
) -> tuple[dict[str, Any], dict[str, str]]:
    if bounded_runner is None:
        bounded_runner = load_bounded_runner(root)
    executions_by_executor: dict[str, list[dict[str, Any]]] = {}
    for scenario in inventory["expected_executions"]:
        executions_by_executor.setdefault(scenario["executor_id"], []).append(scenario)
    executor_by_id = {executor["id"]: executor for executor in inventory["executors"]}

    receipts: list[dict[str, Any]] = []
    trusted_binary_identities: dict[str, str] = {}
    performance_observations: list[dict[str, Any]] = []
    failures: list[tuple[str, str]] = []
    run_nonce = hashlib.sha256(
        (
            inventory["source_digest"]
            + ":"
            + str(os.getpid())
            + ":"
            + str(build_dir.resolve())
        ).encode("utf-8")
    ).hexdigest()

    for executor_id in sorted(executions_by_executor):
        executor = executor_by_id.get(executor_id)
        if executor is None:
            failures.append(
                (
                    executor_id,
                    f"COMMON_EXECUTOR_DESCRIPTOR_MISSING:{executor_id}",
                )
            )
            continue
        try:
            command, executed_artifact = command_for_executor(root, build_dir, executor)
            binary_identity = sha256_file(executed_artifact)
        except ReceiptRunnerError as error:
            failures.append((executor_id, str(error)))
            continue
        except OSError as error:
            failures.append(
                (
                    executor_id,
                    f"COMMON_EXECUTOR_COMMAND_PREPARE_FAILED:{executor_id}:"
                    f"{output_detail('', str(error))}",
                )
            )
            continue
        target = executor["test_target"]
        environment = dict(os.environ)
        environment["EXV_COMMON_RECEIPT_CHALLENGE"] = run_nonce
        execution_budget_seconds = executor["execution_budget_seconds"]
        timeout_margin_seconds = executor["timeout_margin_seconds"]
        hard_timeout_seconds = execution_budget_seconds + timeout_margin_seconds
        started_at = monotonic()
        try:
            exit_code, stdout, stderr, timed_out = bounded_runner(
                command,
                hard_timeout_seconds,
                root,
                environment,
            )
        except OSError as error:
            failures.append(
                (
                    executor_id,
                    f"COMMON_EXECUTOR_COMMAND_FAILED:{executor_id}:"
                    f"{output_detail('', str(error))}",
                )
            )
            continue
        elapsed_seconds = monotonic() - started_at
        combined_output = stdout + stderr
        marker = executor["success_marker"]
        if timed_out:
            failures.append(
                (
                    executor_id,
                    f"COMMON_EXECUTOR_TIMEOUT:{executor_id}:"
                    f"{hard_timeout_seconds}:{output_detail(stdout, stderr)}",
                )
            )
            continue
        if exit_code != 0:
            failures.append(
                (
                    executor_id,
                    f"COMMON_EXECUTOR_FAILED:{executor_id}:"
                    f"{exit_code}:{output_detail(stdout, stderr)}",
                )
            )
            continue
        if marker not in combined_output:
            failures.append(
                (
                    executor_id,
                    f"COMMON_EXECUTOR_MARKER_MISSING:{executor_id}:{marker}",
                )
            )
            continue
        if elapsed_seconds > execution_budget_seconds:
            observation = {
                "executor_id": executor_id,
                "elapsed_seconds": round(elapsed_seconds, 3),
                "expected_budget_seconds": execution_budget_seconds,
            }
            performance_observations.append(observation)
            if enforce_performance_budget:
                failures.append(
                    (
                        executor_id,
                        f"COMMON_EXECUTOR_BUDGET_EXCEEDED:{executor_id}:"
                        f"{elapsed_seconds:.3f}:{execution_budget_seconds}",
                    )
                )
                continue
        trusted_binary_identities[target] = binary_identity
        stdout_digest = (
            "sha256:" + hashlib.sha256(combined_output.encode("utf-8")).hexdigest()
        )

        for scenario in executions_by_executor[executor_id]:
            receipts.append(
                {
                    "feature_id": scenario["feature_id"],
                    "dimension_id": scenario["dimension_id"],
                    "executor_id": executor_id,
                    "test_target": target,
                    "scenario_digest": scenario["scenario_digest"],
                    "observed_entrypoint": scenario["production_entrypoint_id"],
                    "observed_transition_or_outcome": scenario["dimension_id"],
                    "observed_terminal": "passed",
                    "exit_code": exit_code,
                    "binary_identity": binary_identity,
                    "stdout_digest": stdout_digest,
                    "run_nonce": run_nonce,
                }
            )

    if failures:
        raise ReceiptRunnerError(
            "COMMON_EXECUTOR_FAILURES: "
            + " || ".join(
                failure for _, failure in sorted(failures, key=lambda item: item[0])
            )
        )

    document = {
        "schema_version": "1.0",
        "requirement_id": inventory["requirement_id"],
        "receipt_scope": inventory["receipt_scope"],
        "host_real_passed": False,
        "inventory_source_digest": inventory["source_digest"],
        "performance": {
            "expected_budget_effect": (
                "blocking" if enforce_performance_budget else "telemetry"
            ),
            "budget_exceeded": sorted(
                performance_observations,
                key=lambda item: item["executor_id"],
            ),
        },
        "receipts": sorted(
            receipts,
            key=lambda item: (item["feature_id"], item["dimension_id"]),
        ),
    }
    return document, trusted_binary_identities


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--enforce-performance-budget",
        action="store_true",
        help=(
            "turn expected runtime budgets into failures for a standardized "
            "performance lane; hard timeouts always remain blocking"
        ),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    build_dir = args.build_dir.resolve()
    output = (
        args.output.resolve()
        if args.output
        else build_dir / "contracts/generated/common_executed_receipts.json"
    )

    try:
        generator = load_inventory_module(root)
        inventory = generator.generate_inventory(root)
        document, identities = execute_plan(
            root,
            build_dir,
            inventory,
            enforce_performance_budget=args.enforce_performance_budget,
        )
        summary = generator.validate_receipts(inventory, document, identities)
        write_atomic(output, document)
    except Exception as error:
        # InventoryError is loaded dynamically and cannot be named portably.
        print(f"Common executed receipt gate failed: {error}")
        return 1

    print(
        "Common executed receipt gate passed: "
        f"{summary['executed_verified_count']} executed/verified dimensions, "
        "zero missing, duplicate or untrusted receipts"
    )
    observations = document["performance"]["budget_exceeded"]
    if observations:
        print(
            "Common executor performance observations: "
            + ", ".join(
                f"{item['executor_id']}={item['elapsed_seconds']:.3f}s>"
                f"{item['expected_budget_seconds']}s"
                for item in observations
            )
        )
    print(f"receipt artifact: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
