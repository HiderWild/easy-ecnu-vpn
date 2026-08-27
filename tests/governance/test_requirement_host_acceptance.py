"""回归保护：提交历史只能作为非权威的宿主验收观察。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "requirement_host_acceptance.py"
CLI_PATH = ROOT / "scripts" / "validate-requirement-host-acceptance.py"
RANGE_CLI_PATH = ROOT / "scripts" / "validate-common-first-governance-ci.py"
CMAKE_PATH = ROOT / "CMakeLists.txt"
REQUIREMENT_ID = "vpn-business-first-host-repair-governance"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "requirement_host_acceptance_under_test", MODULE_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load requirement host acceptance module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        capture_output=True,
        check=False,
        encoding="utf-8",
    )


def initialize_repository(repo: Path) -> str:
    initialized = git(repo, "init", "-q")
    if initialized.returncode:
        raise RuntimeError(initialized.stderr)
    (repo / "seed.txt").write_text("seed\n", encoding="utf-8")
    added = git(repo, "add", "seed.txt")
    if added.returncode:
        raise RuntimeError(added.stderr)
    committed = git(
        repo,
        "-c",
        "user.name=Governance Test",
        "-c",
        "user.email=governance-test@example.invalid",
        "commit",
        "-q",
        "-m",
        "seed",
    )
    if committed.returncode:
        raise RuntimeError(committed.stderr)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def commit(repo: Path, filename: str, message: str) -> str:
    (repo / filename).write_text(filename + "\n", encoding="utf-8")
    added = git(repo, "add", filename)
    if added.returncode:
        raise RuntimeError(added.stderr)
    committed = git(
        repo,
        "-c",
        "user.name=Governance Test",
        "-c",
        "user.email=governance-test@example.invalid",
        "commit",
        "-q",
        "-m",
        message,
    )
    if committed.returncode:
        raise RuntimeError(committed.stderr)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def run_cli(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(path), *arguments],
        capture_output=True,
        check=False,
        encoding="utf-8",
    )


def warning_codes(payload: dict[str, object]) -> set[str]:
    warnings = payload["warnings"]
    if not isinstance(warnings, list):
        raise AssertionError("warnings must be a list")
    return {
        warning["code"]
        for warning in warnings
        if isinstance(warning, dict) and isinstance(warning.get("code"), str)
    }


class RequirementHostAcceptanceTests(unittest.TestCase):
    def test_host_acceptance_trailer_is_historical_not_real_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            initialize_repository(repo)
            commit(
                repo,
                "trailer.txt",
                "历史声明\n\n"
                f"Requirement-ID: {REQUIREMENT_ID}\n"
                "Host-Acceptance: win32=passed\n",
            )

            completed = run_cli(
                CLI_PATH,
                "--repo",
                str(repo),
                "--requirement",
                REQUIREMENT_ID,
                "--host",
                "win32",
                "--format",
                "json",
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["development_ok"])
        self.assertFalse(payload["host_real_passed"])
        self.assertEqual([], payload["host_real_evidence"])
        self.assertIn("HOST_REAL_EVIDENCE_MISSING", warning_codes(payload))
        self.assertIn(
            "HOST_ACCEPTANCE_HISTORICAL_DECLARATION", warning_codes(payload)
        )
        self.assertEqual("historical_non_authoritative", payload["status"])

    def test_body_trailer_like_lines_are_ignored_when_final_block_is_text(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            initialize_repository(repo)
            commit(
                repo,
                "body-only.txt",
                "正文中的同名行\n"
                f"Requirement-ID: {REQUIREMENT_ID}\n"
                "Host-Acceptance: win32=passed\n\n"
                "最终段不是 trailer block\n",
            )

            completed = run_cli(
                CLI_PATH,
                "--repo",
                str(repo),
                "--requirement",
                REQUIREMENT_ID,
                "--host",
                "win32",
                "--format",
                "json",
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual([], payload["historical_observations"])
        self.assertNotIn(
            "HOST_ACCEPTANCE_HISTORICAL_DECLARATION", warning_codes(payload)
        )

    def test_only_final_trailer_block_owns_conflicting_requirement_id(self) -> None:
        body_requirement = "body-only-requirement"
        final_requirement = "final-trailer-requirement"
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            initialize_repository(repo)
            commit(
                repo,
                "conflict.txt",
                "正文观察\n"
                f"Requirement-ID: {body_requirement}\n"
                "Host-Acceptance: darwin=passed\n\n"
                f"Requirement-ID: {final_requirement}\n"
                "Host-Acceptance: win32=inherited\n",
            )

            final_completed = run_cli(
                CLI_PATH,
                "--repo",
                str(repo),
                "--requirement",
                final_requirement,
                "--host",
                "win32",
                "--format",
                "json",
            )
            body_completed = run_cli(
                CLI_PATH,
                "--repo",
                str(repo),
                "--requirement",
                body_requirement,
                "--host",
                "darwin",
                "--format",
                "json",
            )

        self.assertEqual(0, final_completed.returncode, final_completed.stderr)
        self.assertEqual(0, body_completed.returncode, body_completed.stderr)
        final_payload = json.loads(final_completed.stdout)
        body_payload = json.loads(body_completed.stdout)
        self.assertEqual(1, len(final_payload["historical_observations"]))
        observation = final_payload["historical_observations"][0]
        self.assertEqual(final_requirement, observation["requirement_id"])
        self.assertIn(
            "HOST_ACCEPTANCE_HISTORICAL_DECLARATION",
            warning_codes(final_payload),
        )
        self.assertEqual([], body_payload["historical_observations"])
        self.assertNotIn(
            "HOST_ACCEPTANCE_HISTORICAL_DECLARATION",
            warning_codes(body_payload),
        )

    def test_missing_real_evidence_does_not_block_requested_or_other_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            initialize_repository(repo)
            commit(
                repo,
                "repair.txt",
                "旧修补记录\n\n"
                f"Requirement-ID: {REQUIREMENT_ID}\n"
                "Common-Change-Kind: host-repair\n"
                "Affected-Hosts: win32\n"
                "Host-Acceptance: win32=passed\n",
            )

            completed = run_cli(
                CLI_PATH,
                "--repo",
                str(repo),
                "--requirement",
                REQUIREMENT_ID,
                "--host",
                "darwin",
                "--format",
                "json",
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["development_ok"])
        self.assertFalse(payload["host_real_passed"])
        self.assertEqual([], payload["host_real_evidence"])
        self.assertNotIn("integration_pending", payload)
        self.assertNotIn("pending_repair_hosts", payload)
        self.assertNotIn("blockers", payload)
        self.assertIn("HOST_REAL_EVIDENCE_MISSING", warning_codes(payload))
        self.assertIn("LEGACY_HOST_REPAIR_HISTORICAL", warning_codes(payload))

    def test_unknown_observations_are_preserved_without_semantic_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repository(repo)
            commit(
                repo,
                "unknown.txt",
                "历史观察\n\n"
                f"Requirement-ID: {REQUIREMENT_ID}\n"
                "Common-Change-Kind: agile-host-repair\n"
                "Common-Defect: unknown\n"
                "Cross-Host-Invariant: 未知\n",
            )

            completed = run_cli(
                RANGE_CLI_PATH,
                "--repo",
                str(repo),
                "--base",
                base,
                "--head",
                "HEAD",
                "--format",
                "json",
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["development_ok"])
        self.assertIn("LEGACY_AGILE_HOST_REPAIR_HISTORICAL", warning_codes(payload))
        observations = json.dumps(payload["historical_observations"], ensure_ascii=False)
        self.assertIn("unknown", observations)
        self.assertIn("未知", observations)

    def test_invalid_git_range_still_reports_the_actual_git_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            initialize_repository(repo)

            completed = run_cli(
                RANGE_CLI_PATH,
                "--repo",
                str(repo),
                "--base",
                "missing-revision",
                "--head",
                "HEAD",
                "--format",
                "json",
            )

        self.assertNotEqual(0, completed.returncode)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual("ACCEPTANCE_GIT_ERROR", payload["code"])
        self.assertIn("missing-revision", payload["message"])

    def test_text_errors_include_revision_and_git_root_cause(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            initialize_repository(repo)
            commands = (
                (
                    RANGE_CLI_PATH,
                    "--repo",
                    str(repo),
                    "--base",
                    "missing-range-revision",
                    "--head",
                    "HEAD",
                ),
                (
                    CLI_PATH,
                    "--repo",
                    str(repo),
                    "--requirement",
                    REQUIREMENT_ID,
                    "--host",
                    "win32",
                    "--head",
                    "missing-report-revision",
                ),
            )
            completed = [run_cli(*command) for command in commands]

        expected_revisions = (
            "missing-range-revision",
            "missing-report-revision",
        )
        for result, revision in zip(completed, expected_revisions, strict=True):
            with self.subTest(revision=revision):
                self.assertNotEqual(0, result.returncode)
                self.assertIn(revision, result.stdout)
                self.assertIn("fatal:", result.stdout)

    def test_cli_and_validate_range_remain_callable(self) -> None:
        module = load_module()
        parser = module.build_parser()
        parsed = parser.parse_args(
            [
                "--repo",
                ".",
                "--requirement",
                REQUIREMENT_ID,
                "--host",
                "all",
                "--format",
                "json",
            ]
        )
        self.assertEqual(REQUIREMENT_ID, parsed.requirement)
        self.assertTrue(callable(module.validate_range))

    def test_cmake_governance_checks_are_not_release_blocking(self) -> None:
        cmake = CMAKE_PATH.read_text(encoding="utf-8")
        for test_name in (
            "requirement_host_acceptance_test",
            "agile_common_host_repair_integration_test",
            "business_first_host_repair_policy_test",
        ):
            with self.subTest(test_name=test_name):
                match = re.search(
                    rf"set_tests_properties\({test_name} PROPERTIES\s+"
                    r'LABELS "([^"]+)"',
                    cmake,
                )
                self.assertIsNotNone(match)
                labels = set(match.group(1).split(";")) if match else set()
                self.assertIn("governance", labels)
                self.assertNotIn("release-blocking", labels)


if __name__ == "__main__":
    unittest.main()
