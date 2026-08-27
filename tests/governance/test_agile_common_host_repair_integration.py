"""回归保护：旧宿主修补尾注只能产生稳定的历史提醒。"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RANGE_CLI_PATH = ROOT / "scripts" / "validate-common-first-governance-ci.py"
REQUIREMENT_ID = "vpn-business-first-host-repair-governance"


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
    git(repo, "add", "seed.txt")
    seeded = git(
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
    if seeded.returncode:
        raise RuntimeError(seeded.stderr)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def commit(repo: Path, kind: str) -> None:
    filename = f"{kind}.txt"
    (repo / filename).write_text(kind + "\n", encoding="utf-8")
    git(repo, "add", filename)
    committed = git(
        repo,
        "-c",
        "user.name=Governance Test",
        "-c",
        "user.email=governance-test@example.invalid",
        "commit",
        "-q",
        "-m",
        "历史修补\n\n"
        f"Requirement-ID: {REQUIREMENT_ID}\n"
        f"Common-Change-Kind: {kind}\n",
    )
    if committed.returncode:
        raise RuntimeError(committed.stderr)


def run_range(repo: Path, base: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(RANGE_CLI_PATH),
            "--repo",
            str(repo),
            "--base",
            base,
            "--head",
            "HEAD",
            "--format",
            "json",
        ],
        capture_output=True,
        check=False,
        encoding="utf-8",
    )


class LegacyHostRepairHistoryTests(unittest.TestCase):
    def test_incomplete_non_merge_legacy_history_is_non_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repository(repo)
            for kind in (
                "host-repair",
                "agile-host-repair",
                "host-repair-integration",
            ):
                commit(repo, kind)

            completed = run_range(repo, base)

        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["development_ok"])
        self.assertEqual("historical_non_authoritative_range", payload["status"])
        self.assertNotIn("integration_pending", payload)
        self.assertNotIn("pending_repair_hosts", payload)
        self.assertNotIn("accepted", json.dumps(payload))
        self.assertNotIn("evidence_commit", json.dumps(payload))
        warning_codes = {
            warning["code"]
            for warning in payload["warnings"]
            if isinstance(warning, dict)
        }
        self.assertEqual(
            {
                "LEGACY_HOST_REPAIR_HISTORICAL",
                "LEGACY_AGILE_HOST_REPAIR_HISTORICAL",
                "LEGACY_HOST_REPAIR_INTEGRATION_HISTORICAL",
            },
            warning_codes,
        )


if __name__ == "__main__":
    unittest.main()
