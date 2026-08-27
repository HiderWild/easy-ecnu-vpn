#!/usr/bin/env python3
"""Run the quarantined WP-0 behavior reproductions as one red suite.

This suite is intentionally not an acceptance gate. It exits 1 while any
reopened defect is reproduced, 0 only after every old behavior has cleared,
and 2 when the evidence infrastructure cannot be built or executed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys


EXPECTED_IDS = (
    "RED-B01-ALIAS-BEHAVIOR",
    "RED-B02-SURFACE-ESCAPE",
    "RED-B03-ALIAS-POLICY",
    "RED-B04-UNKNOWN-POLICY",
    "RED-B05-INCOMPLETE-REGISTRY",
    "RED-B06-REGISTRY-NO-RETRY",
    "RED-B07-TEXT-DERIVED-AUTH",
    "RED-B08-UNOWNED-EXCEPTION",
    "RED-B09-PAPER-SCENARIO-CREDIT",
    "RED-B10-CMAKE-GRAPH-BYPASS",
)
RED_ID = re.compile(r"\bRED-B\d{2}-[A-Z-]+\b")


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    output: str


def run(command: list[str], cwd: Path) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        return CommandResult(
            command=tuple(command),
            returncode=127,
            output=str(error),
        )
    return CommandResult(
        command=tuple(command),
        returncode=completed.returncode,
        output=(completed.stdout + completed.stderr).strip(),
    )


def executable(build_dir: Path, name: str) -> Path:
    direct = build_dir / name
    if direct.is_file():
        return direct
    windows = build_dir / f"{name}.exe"
    if windows.is_file():
        return windows
    raise FileNotFoundError(f"missing WP-0 probe executable: {direct}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("build/macos/cpp"),
        help="configured CMake build tree used for the two C++ probes",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    build_dir = args.build_dir
    if not build_dir.is_absolute():
        build_dir = root / build_dir

    build = run(
        [
            "cmake",
            "--build",
            str(build_dir),
            "--target",
            "ui_shell_async_host_bridge_test",
        ],
        root,
    )
    if build.returncode != 0:
        print("WP-0 red suite infrastructure failed while building probes")
        print(build.output)
        return 2

    try:
        behavior_binary = executable(build_dir, "ui_shell_async_host_bridge_test")
    except FileNotFoundError as error:
        print(error)
        return 2

    results = [
        run([str(behavior_binary), "--wp0-behavior-red-probe"], root),
        run(
            [
                "node",
                "scripts/run-runtime-boundary-behavior-red-probe.mjs",
            ],
            root / "webui",
        ),
    ]
    infrastructure_failures = [
        result for result in results if result.returncode not in (0, 1)
    ]
    if infrastructure_failures:
        print("WP-0 red suite infrastructure failed while running probes")
        for result in infrastructure_failures:
            print(f"- {' '.join(result.command)}: {result.returncode}")
            print(result.output)
        return 2
    findings: set[str] = set()
    for result in results:
        findings.update(RED_ID.findall(result.output))

    source_signatures = run(
        [
            sys.executable,
            "scripts/probe_runtime_boundary_root_gaps.py",
            "--root",
            str(root),
            "--format",
            "json",
        ],
        root,
    )
    if source_signatures.returncode not in (0, 1):
        print("WP-0 root-signature probe could not run")
        print(source_signatures.output)
        return 2
    if "RED-R06-REGISTRY-CLOSURE-RETRY" in source_signatures.output:
        findings.add("RED-B06-REGISTRY-NO-RETRY")

    async_child = run(
        [str(behavior_binary), "--wp0-exceptional-future-child"], root
    )
    if (
        async_child.returncode != 0
        and "wp0 injected future" in async_child.output
    ):
        findings.add("RED-B08-UNOWNED-EXCEPTION")
    elif async_child.returncode != 0:
        print("WP-0 async child failed without the injected-future signature")
        print(async_child.output)
        return 2

    paper_credit = run(
        [
            sys.executable,
            "-m",
            "unittest",
            "tests.tooling.test_probe_runtime_boundary_root_gaps."
            "RuntimeBoundaryRedProbeTest."
            "test_wildcard_receives_credit_without_executing_a_scenario",
        ],
        root,
    )
    if paper_credit.returncode == 0:
        findings.add("RED-B09-PAPER-SCENARIO-CREDIT")

    graph_bypass = run(
        [
            sys.executable,
            "-m",
            "unittest",
            "tests.tooling.test_probe_runtime_boundary_root_gaps."
            "RuntimeBoundaryRedProbeTest."
            "test_target_sources_platform_edge_reproduces_validator_false_negative",
        ],
        root,
    )
    if graph_bypass.returncode == 0:
        findings.add("RED-B10-CMAKE-GRAPH-BYPASS")

    print("Runtime boundary WP-0 behavior red suite")
    print(f"root: {root}")
    print(f"findings: {len(findings)}")
    for finding_id in EXPECTED_IDS:
        state = "RED" if finding_id in findings else "CLEARED"
        print(f"- {finding_id}: {state}")

    unexpected = sorted(findings - set(EXPECTED_IDS))
    if unexpected:
        print("WP-0 red suite infrastructure emitted unknown finding IDs:")
        for finding_id in unexpected:
            print(f"- {finding_id}")
        return 2
    if findings:
        print("result: RED (reopened candidate is quarantined)")
        return 1
    print("result: old behaviors cleared; run G-R01..G-R10 before acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
