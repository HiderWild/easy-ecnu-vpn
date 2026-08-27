#!/usr/bin/env python3
"""Verify source and packaged consumers use one immutable contract identity."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROLES = ("app", "core", "helper", "renderer")
NATIVE_ROLES = ("app", "core", "helper")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PROBE_ARGUMENT = "--print-runtime-contract-identity"
PROBE_TIMEOUT_SECONDS = 15
IDENTITY_FIELDS = (
    "model_schema_version",
    "model_digest",
    "system_contract_digest",
    "provider_contract_digest",
)
PROBE_DOCUMENT_FIELDS = ("role",) + IDENTITY_FIELDS
ProbeRunner = Callable[[str, list[str]], subprocess.CompletedProcess[str]]
_BOUNDED_PROCESS_RUNNER = None


class CoherenceError(RuntimeError):
    pass


def load_identity_generator(root: Path):
    script = root / "scripts" / "generate_runtime_contract_identity.py"
    spec = importlib.util.spec_from_file_location(
        "exv_runtime_contract_identity_generator", script
    )
    if spec is None or spec.loader is None:
        raise CoherenceError(
            f"PACKAGE_IDENTITY_GENERATOR_UNAVAILABLE:{script}"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_consumer(value: str) -> tuple[str, Path]:
    role, separator, raw_path = value.partition("=")
    if not separator or role not in ROLES or not raw_path:
        raise argparse.ArgumentTypeError(
            "consumer must be app=PATH, core=PATH, helper=PATH or renderer=PATH"
        )
    return role, Path(raw_path)


def expected_identity(root: Path) -> dict[str, str]:
    generator = load_identity_generator(root)
    generated = generator.generate_identity(root)
    identity = generated.get("identity")
    if not isinstance(identity, dict):
        raise CoherenceError("PACKAGE_IDENTITY_DESCRIPTOR_MALFORMED:generated")
    required = {
        "model_schema_version",
        "model_digest",
        "system_contract_digest",
        "provider_contract_digest",
    }
    if set(identity) != required:
        raise CoherenceError("PACKAGE_IDENTITY_DESCRIPTOR_MALFORMED:generated")
    for field in required - {"model_schema_version"}:
        if not isinstance(identity[field], str) or not DIGEST_RE.fullmatch(
            identity[field]
        ):
            raise CoherenceError(
                f"PACKAGE_IDENTITY_DESCRIPTOR_MALFORMED:generated:{field}"
            )
    return identity


def verify_source(root: Path, expected: dict[str, str]) -> None:
    required_occurrences = {
        root / "src/contracts/generated/system_contract.hpp": (
            expected["system_contract_digest"],
        ),
        root / "webui/desktop/shared/generated/system-contract.ts": (
            expected["system_contract_digest"],
        ),
        root / "webui/host/shared/generated/system-contract.ts": (
            expected["system_contract_digest"],
        ),
        root / "src/contracts/generated/runtime_contract_identity.hpp": (
            expected["model_digest"],
            expected["system_contract_digest"],
            expected["provider_contract_digest"],
        ),
        root / "contracts/generated/runtime_contract_identity.json": (
            expected["model_digest"],
            expected["system_contract_digest"],
            expected["provider_contract_digest"],
        ),
    }
    for path, needles in required_occurrences.items():
        if not path.is_file():
            raise CoherenceError(f"PACKAGE_IDENTITY_SOURCE_MISSING:{path}")
        content = path.read_text(encoding="utf-8")
        for needle in needles:
            if content.count(needle) < 1:
                raise CoherenceError(
                    f"PACKAGE_IDENTITY_SOURCE_STALE:{path}:{needle}"
                )

    semantic_markers = {
        root / "webui/src/runtime/contractIdentity.ts": (
            "SYSTEM_CONTRACT_DIGEST",
            "__EXV_RENDERER_CONTRACT_DIGEST__",
        ),
        root / "src/app/ui_shell/host_bridge.cpp": (
            "contract_digest_mismatch",
            "SYSTEM_CONTRACT_DIGEST",
        ),
        root / "src/app/ui_shell/async_host_bridge.cpp": (
            "contract_digest_mismatch",
            "renderer_contract_digest_matches",
        ),
        root / "src/platform/darwin/ui_shell/wk_webview_host_darwin.mm": (
            "contract_digest: window.__EXV_RENDERER_CONTRACT_DIGEST__",
            "renderer_contract_digest_matches(parsed)",
        ),
        root / "src/platform/win32/ui_shell/webview2_host_win32.cpp": (
            "contract_digest: window.__EXV_RENDERER_CONTRACT_DIGEST__",
            "renderer_contract_digest_matches(parsed)",
        ),
        root / "src/platform/linux/ui_shell/webkitgtk_host_linux.cpp": (
            "contract_digest: window.__EXV_RENDERER_CONTRACT_DIGEST__",
        ),
        root / "scripts/package_ui_shell.py": (
            "verify_package_contract_identity(package_dir, platform)",
            "verify_packaged_contract_coherence.py",
        ),
    }
    for path, markers in semantic_markers.items():
        if not path.is_file():
            raise CoherenceError(f"PACKAGE_IDENTITY_SOURCE_MISSING:{path}")
        content = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in content:
                raise CoherenceError(
                    f"PACKAGE_IDENTITY_SOURCE_STALE:{path}:{marker}"
                )


def artifact_contains(path: Path, needle: bytes) -> bool:
    if path.is_file():
        return needle in path.read_bytes()
    if path.is_dir():
        for candidate in sorted(path.rglob("*")):
            if candidate.is_file() and needle in candidate.read_bytes():
                return True
    return False


def load_bounded_process_runner():
    global _BOUNDED_PROCESS_RUNNER
    if _BOUNDED_PROCESS_RUNNER is not None:
        return _BOUNDED_PROCESS_RUNNER
    script = Path(__file__).with_name("windows_pe_imports.py")
    spec = importlib.util.spec_from_file_location(
        "exv_bounded_process_runner", script
    )
    if spec is None or spec.loader is None:
        raise CoherenceError(
            f"PACKAGE_IDENTITY_PROBE_MISSING:runner:{script}"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _BOUNDED_PROCESS_RUNNER = module
    return module


def run_native_probe(
    role: str,
    command: list[str],
) -> subprocess.CompletedProcess[str]:
    environment = None
    if sys.platform.startswith("win") and role == "app":
        environment = os.environ.copy()
        # exv-ui intentionally retains its requireAdministrator application
        # manifest.  The identity probe is the sole no-bootstrap path that may
        # run as the caller: this process-local compatibility layer lets the
        # verifier execute the actual App bytes without UAC or elevation.
        environment["__COMPAT_LAYER"] = "RunAsInvoker"
    runner = load_bounded_process_runner()
    return_code, stdout, stderr, timed_out = runner.run_bounded_command(
        command,
        PROBE_TIMEOUT_SECONDS,
        env=environment,
    )
    if timed_out:
        raise subprocess.TimeoutExpired(
            command,
            PROBE_TIMEOUT_SECONDS,
            output=stdout,
            stderr=stderr,
        )
    return subprocess.CompletedProcess(
        args=command,
        returncode=return_code,
        stdout=stdout,
        stderr=stderr,
    )


def inspect_native_consumer(
    role: str,
    path: Path,
    probe_runner: ProbeRunner,
) -> dict[str, str]:
    if (
        not path.is_file()
        or path.suffix.lower() == ".json"
    ):
        raise CoherenceError(f"PACKAGE_IDENTITY_PROBE_MISSING:{role}:{path}")

    command = [str(path), PROBE_ARGUMENT]
    try:
        completed = probe_runner(role, command)
    except subprocess.TimeoutExpired as error:
        raise CoherenceError(
            f"PACKAGE_IDENTITY_PROBE_NONZERO:{role}:timeout"
        ) from error
    except OSError as error:
        raise CoherenceError(
            f"PACKAGE_IDENTITY_PROBE_MISSING:{role}:{path}:{error}"
        ) from error

    if completed.returncode != 0:
        raise CoherenceError(
            f"PACKAGE_IDENTITY_PROBE_NONZERO:{role}:{completed.returncode}"
        )
    if not isinstance(completed.stdout, str) or completed.stdout == "":
        raise CoherenceError(f"PACKAGE_IDENTITY_PROBE_MISSING:{role}:{path}")
    if not isinstance(completed.stderr, str) or completed.stderr != "":
        raise CoherenceError(
            f"PACKAGE_IDENTITY_PROBE_MALFORMED:{role}:stderr"
        )

    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise CoherenceError(
            f"PACKAGE_IDENTITY_PROBE_MALFORMED:{role}:json"
        ) from error
    canonical_document = json.dumps(document, separators=(",", ":"))
    if (
        not isinstance(document, dict)
        or tuple(document) != PROBE_DOCUMENT_FIELDS
        or set(document) != set(PROBE_DOCUMENT_FIELDS)
        or completed.stdout
        not in {
            canonical_document + "\n",
            canonical_document + "\r\n",
        }
    ):
        raise CoherenceError(
            f"PACKAGE_IDENTITY_PROBE_MALFORMED:{role}:document"
        )
    if not isinstance(document["role"], str):
        raise CoherenceError(
            f"PACKAGE_IDENTITY_PROBE_MALFORMED:{role}:role"
        )
    if document["role"] != role:
        raise CoherenceError(
            f"PACKAGE_IDENTITY_ROLE_MISMATCH:{role}:{document['role']}"
        )
    if (
        not isinstance(document["model_schema_version"], str)
        or not document["model_schema_version"]
    ):
        raise CoherenceError(
            f"PACKAGE_IDENTITY_PROBE_MALFORMED:{role}:"
            "model_schema_version"
        )
    for field in IDENTITY_FIELDS[1:]:
        value = document[field]
        if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
            raise CoherenceError(
                f"PACKAGE_IDENTITY_PROBE_MALFORMED:{role}:{field}"
            )
    return {field: document[field] for field in IDENTITY_FIELDS}


def verify_native_consumers(
    consumers: list[tuple[str, Path]],
    expected: dict[str, str],
    probe_runner: ProbeRunner | None = None,
) -> dict[str, dict[str, str]]:
    by_role: dict[str, Path] = {}
    for role, path in consumers:
        if role not in NATIVE_ROLES:
            raise CoherenceError(f"PACKAGE_IDENTITY_ROLE_INVALID:{role}")
        if role in by_role:
            raise CoherenceError(f"PACKAGE_IDENTITY_ROLE_DUPLICATE:{role}")
        by_role[role] = path.resolve()
    missing = [role for role in NATIVE_ROLES if role not in by_role]
    if missing:
        raise CoherenceError(
            "PACKAGE_IDENTITY_ROLE_MISSING:" + ",".join(missing)
        )

    runner = probe_runner or run_native_probe
    observed = {
        role: inspect_native_consumer(role, by_role[role], runner)
        for role in NATIVE_ROLES
    }
    if len(
        {
            tuple(sorted(identity.items()))
            for identity in observed.values()
        }
    ) != 1:
        raise CoherenceError("PACKAGE_IDENTITY_MIXED_CONSUMERS")

    identity = observed[NATIVE_ROLES[0]]
    if identity != expected:
        mismatches = sorted(
            field
            for field in IDENTITY_FIELDS
            if identity.get(field) != expected[field]
        )
        raise CoherenceError(
            "PACKAGE_IDENTITY_MISMATCH:native:" + ",".join(mismatches)
        )
    return observed


def verify_renderer(
    path: Path,
    expected: dict[str, str],
) -> None:
    if not path.exists():
        raise CoherenceError(
            f"PACKAGE_IDENTITY_CONSUMER_MISSING:renderer:{path}"
        )
    digest = expected["system_contract_digest"]
    if not artifact_contains(path, digest.encode("ascii")):
        raise CoherenceError(
            "PACKAGE_IDENTITY_MISMATCH:renderer:system_contract_digest"
        )


def verify_consumers(
    consumers: list[tuple[str, Path]],
    expected: dict[str, str],
    probe_runner: ProbeRunner | None = None,
) -> None:
    by_role: dict[str, Path] = {}
    for role, path in consumers:
        if role in by_role:
            raise CoherenceError(f"PACKAGE_IDENTITY_ROLE_DUPLICATE:{role}")
        by_role[role] = path.resolve()
    missing = [role for role in ROLES if role not in by_role]
    if missing:
        raise CoherenceError(
            "PACKAGE_IDENTITY_ROLE_MISSING:" + ",".join(missing)
        )

    verify_native_consumers(
        [(role, by_role[role]) for role in NATIVE_ROLES],
        expected,
        probe_runner=probe_runner,
    )
    verify_renderer(by_role["renderer"], expected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--consumer", action="append", default=[], type=parse_consumer
    )
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        expected = expected_identity(root)
        verify_source(root, expected)
        if args.consumer:
            verify_consumers(args.consumer, expected)
    except (CoherenceError, OSError, ValueError) as error:
        print(f"package contract coherence failed: {error}")
        return 1
    if args.consumer:
        print(
            "package contract coherence passed: "
            "App/Core/Helper/Renderer use one identity"
        )
    else:
        print("source contract coherence passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
