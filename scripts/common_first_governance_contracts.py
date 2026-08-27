"""Pure data and path contracts for common-first delivery governance.

This module deliberately has no Git or Markdown dependency.  The phase-B CLI
validator composes these deterministic checks with revision and ancestry checks.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


LEGACY_NON_BLOCKING = True


REQUIREMENT_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?$")
PLATFORM_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
PV_ID_PATTERN = re.compile(r"^PV-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
WORK_ITEM_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
LANE_BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
CANONICAL_MANIFEST_PATTERN = re.compile(
    r"^docs/superpowers/requirements/([a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)/common-first-manifest\.json$"
)
CANONICAL_LANE_RECORD_PATTERN = re.compile(
    r"^docs/superpowers/platforms/([a-z][a-z0-9-]*)/([a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)/lane-record\.json$"
)
CANONICAL_PROVISIONAL_LANE_RECORD_PATTERN = re.compile(
    r"^docs/superpowers/platforms/([a-z][a-z0-9-]*)/([a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)/provisional-lane-record\.json$"
)
CANONICAL_COMMON_NATIVE_BUNDLE_PATTERN = re.compile(
    r"^docs/superpowers/evidence/common-native-acceptance/([a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)/bundle\.json$"
)
CANONICAL_COMMON_NATIVE_ATTESTATION_PATTERN = re.compile(
    r"^docs/superpowers/evidence/common-native-acceptance/([a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)/(darwin|win32)\.json$"
)
CANONICAL_PLATFORM_PLAN_PATTERN = re.compile(
    r"^docs/superpowers/platforms/([a-z][a-z0-9-]*)/[A-Za-z0-9][A-Za-z0-9._/-]*\.md$"
)

MANIFEST_REQUIRED_FIELDS = {
    "schema_version",
    "requirement_id",
    "top_level_spec_path",
    "common_architecture_spec_path",
    "common_plan_path",
    "common_branch",
    "accepted_common_implementation_commit",
    "baseline_record_mode",
    "platform_lanes",
}
PLATFORM_LANE_FIELDS = {
    "platform",
    "disposition",
    "rationale",
    "planned_branch",
    "planned_plan_path",
    "planned_lane_record_path",
    "required_production_verifications",
    "allowed_path_prefixes",
}
REQUIRED_PROTECTED_PATH_CLASSES = {
    "governance_and_evidence_authority": {
        "exact_paths": frozenset(
            {
                "AGENTS.md",
                "docs/architecture/guardrail_allowlist.yml",
                "scripts/architecture-guardrails.ps1",
                "scripts/architecture-guardrails.sh",
                "scripts/common_acceptance_policy.py",
                "scripts/common_first_governance_contracts.py",
                "scripts/requirement_host_acceptance.py",
                "scripts/run_common_executed_receipts.py",
                "scripts/run_common_native_acceptance.py",
                "scripts/validate-common-first-governance.py",
                "scripts/validate-common-first-governance-ci.py",
                "scripts/validate-common-runtime-decoupling.py",
                "scripts/validate-requirement-host-acceptance.py",
            }
        ),
        "prefixes": frozenset(
            {
                ".github/workflows/",
                "docs/superpowers/evidence/",
                "docs/superpowers/requirements/",
                "docs/superpowers/governance/",
                "docs/superpowers/templates/",
                "tests/governance/",
            }
        ),
        "path_patterns": frozenset(),
    },
}

LANE_STATUSES = {
    "not_started",
    "in_progress",
    "blocked_external",
    "ready_for_review",
    "delivered",
}
LEGACY_DISPLAY_ONLY_LANE_STATUSES = frozenset({"blocked_by_common"})
DELIVERY_VERDICTS = {"not_deliverable", "pending_evidence", "deliverable"}
UNFINISHED_STATES = {"open", "blocked", "resolved"}
BLOCKER_KINDS = {"external", "environment", "decision"}
LEGACY_DISPLAY_ONLY_BLOCKER_KINDS = frozenset({"common"})
LEGACY_DISPLAY_ONLY_COMMON_BLOCKER_FIELDS = frozenset(
    {"common_change_requirement_id"}
)
PV_STATUSES = {"not_run", "passed", "failed", "blocked", "skipped_mock"}
EVIDENCE_KINDS = {
    "real_machine",
    "native_system",
    "platform_test",
    "integration_test",
    "mock",
}
PROVISIONAL_LANE_FIELDS_V1_0 = {
    "schema_version",
    "requirement_id",
    "platform",
    "candidate_common_commit",
    "candidate_non_evidence_tree_digest",
    "planned_manifest_path",
    "provisional_branch",
    "status",
    "delivery_verdict",
    "allowed_path_prefixes",
    "unfinished_subrequirements",
    "blockers",
    "expires_on_manifest_creation",
}
PROVISIONAL_LANE_FIELDS_V1_1 = PROVISIONAL_LANE_FIELDS_V1_0 | {"allowed_paths"}
COMMON_NATIVE_BUNDLE_FIELDS = {
    "schema_version",
    "requirement_id",
    "candidate_common_commit",
    "candidate_non_evidence_tree_digest",
    "common_only_profile_digest",
    "gate_set_digest",
    "environment_policy_digest",
    "runtime_identity",
    "host_attestations",
}
COMMON_NATIVE_RUNTIME_IDENTITY_FIELDS = {
    "model_digest",
    "model_schema_version",
    "provider_contract_digest",
    "system_contract_digest",
}

BOOTSTRAP_EXEMPTION_SCHEMA_VERSION = "1.0"
BOOTSTRAP_REQUIREMENT_ID = "vpn-common-first-provisional-lane-attestation-binding"
BOOTSTRAP_BRANCH = (
    "codex/req-vpn-common-first-provisional-lane-attestation-binding-common-repair"
)
BOOTSTRAP_BASE_COMMIT = "e27d6e20b086c724c1d76e7784b8498f9c0ef795"
BOOTSTRAP_EXEMPTION_PATH = (
    "docs/superpowers/governance/bootstrap-exemptions/"
    "vpn-common-first-provisional-lane-attestation-binding.json"
)
BOOTSTRAP_LEGACY_FAILURES = ("GOV_CI_UNMANAGED_PROTECTED_CHANGE",)
BOOTSTRAP_ALLOWED_PATHS = (
    "docs/superpowers/governance/README.md",
    "docs/superpowers/governance/bootstrap-exemptions/"
    "vpn-common-first-provisional-lane-attestation-binding.json",
    "docs/superpowers/governance/common-first-bootstrap-exemption.schema.json",
    "docs/superpowers/governance/common-first-protected-paths.json",
    "docs/superpowers/governance/common-first-provisional-lane-record.schema.json",
    "docs/superpowers/governance/common-first-requirement-manifest.schema.json",
    "docs/superpowers/governance/common-native-acceptance-bundle.schema.json",
    "docs/superpowers/governance/common-native-acceptance-policy.json",
    "docs/superpowers/governance/platform-acceptance-campaign.md",
    "docs/superpowers/plans/"
    "2026-08-02-common-first-provisional-lane-attestation-binding.md",
    "docs/superpowers/specs/"
    "2026-08-02-common-first-provisional-lane-attestation-binding-design.md",
    "docs/superpowers/specs/"
    "vpn-common-first-provisional-lane-attestation-binding-common-architecture.md",
    "docs/superpowers/specs/"
    "vpn-common-first-provisional-lane-attestation-binding.md",
    "scripts/common_acceptance_policy.py",
    "scripts/common_first_governance_contracts.py",
    "scripts/run_common_native_acceptance.py",
    "scripts/validate-common-first-governance-ci.py",
    "scripts/validate-common-first-governance.py",
    "tests/governance/fixtures/common-first-provisional-lane-seed.json",
    "tests/governance/fixtures/common-native-acceptance-bundle-seed.json",
    "tests/governance/test_common_acceptance_policy.py",
    "tests/governance/test_run_common_native_acceptance.py",
    "tests/governance/test_validate_common_first_governance.py",
)
BOOTSTRAP_TARGET_GATE_COMMANDS = (
    (
        "python",
        "-m",
        "unittest",
        "tests.governance.test_validate_common_first_governance",
        "-v",
    ),
    (
        "python",
        "scripts/validate-common-first-governance-ci.py",
        "--base",
        BOOTSTRAP_BASE_COMMIT,
        "--head",
        "HEAD",
        "--format",
        "json",
    ),
)
BOOTSTRAP_ACTIVE_FIELDS = {
    "schema_version",
    "requirement_id",
    "authorized_branch",
    "authorized_base_commit",
    "reason_code",
    "legacy_gate_expected_failures",
    "allowed_paths",
    "allowed_path_prefixes",
    "target_gate_commands",
    "state",
    "prohibits_delivery",
}
BOOTSTRAP_CONSUMED_FIELDS = BOOTSTRAP_ACTIVE_FIELDS | {
    "consumed_implementation_commit"
}


class ContractViolation(ValueError):
    """A stable, machine-readable contract error with its JSON field path."""

    def __init__(self, code: str, field: str, message: str) -> None:
        self.code = code
        self.field = field
        super().__init__(f"{code} at {field}: {message}")


def _fail(code: str, field: str, message: str) -> None:
    raise ContractViolation(code, field, message)


def _mapping(value: Any, field: str, code: str = "GOV_DOCUMENT_INVALID") -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(code, field, "must be an object")
    return value


def _list(value: Any, field: str, code: str = "GOV_DOCUMENT_INVALID") -> list[Any]:
    if not isinstance(value, list):
        _fail(code, field, "must be an array")
    return value


def _string(value: Any, field: str, code: str = "GOV_DOCUMENT_INVALID") -> str:
    if not isinstance(value, str) or not value:
        _fail(code, field, "must be a non-empty string")
    return value


def _matches(pattern: re.Pattern[str], value: Any, field: str, code: str, message: str) -> str:
    text = _string(value, field, code)
    if pattern.fullmatch(text) is None:
        _fail(code, field, message)
    return text


def _require_enum(value: Any, allowed: set[str], field: str, code: str) -> str:
    text = _string(value, field, code)
    if text not in allowed:
        _fail(code, field, "is not recognized")
    return text


def validate_repository_path(value: Any, *, require_directory_prefix: bool = False) -> str:
    """Validate a repository-relative path without normalizing aliases.

    A directory prefix is represented by exactly one trailing slash.  Every
    other path is a file-like repository path and therefore cannot end in `/`.
    """

    field = "path"
    path = _string(value, field, "GOV_PATH_INVALID")
    if (
        path.startswith("/")
        or re.match(r"^[A-Za-z]:", path)
        or "\\" in path
        or "//" in path
    ):
        _fail("GOV_PATH_INVALID", field, "must be a canonical repository-relative path")

    has_trailing_slash = path.endswith("/")
    if require_directory_prefix != has_trailing_slash:
        expected = "end in one slash" if require_directory_prefix else "not end in a slash"
        _fail("GOV_PATH_INVALID", field, f"must {expected}")

    segments = path[:-1].split("/") if has_trailing_slash else path.split("/")
    if not segments or any(not segment for segment in segments):
        _fail("GOV_PATH_INVALID", field, "contains an empty path segment")
    for segment in segments:
        if segment in {".", ".."}:
            _fail("GOV_PATH_INVALID", field, "contains a traversal or current-directory segment")
        if re.fullmatch(r"[A-Za-z0-9._][A-Za-z0-9._-]*", segment) is None:
            _fail("GOV_PATH_INVALID", field, "contains an invalid path segment")
    return path


def _validate_path(value: Any, field: str, *, directory: bool = False) -> str:
    try:
        return validate_repository_path(value, require_directory_prefix=directory)
    except ContractViolation as error:
        _fail(error.code, field, str(error))


def _require_exact_keys(document: Mapping[str, Any], keys: set[str], field: str, code: str) -> None:
    if set(document) != keys:
        _fail(code, field, "has missing or unknown fields")


def _require_schema_keys(
    document: Mapping[str, Any],
    required: set[str],
    optional: set[str],
    field: str,
    code: str,
) -> None:
    keys = set(document)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        _fail(code, field, "has missing or unknown fields")


def _require_const(value: Any, expected: Any, field: str, code: str) -> None:
    if value != expected or type(value) is not type(expected):
        _fail(code, field, f"must equal {expected!r}")


def _require_unique_items(items: list[Any], field: str, code: str) -> None:
    for index, item in enumerate(items):
        if any(item == previous for previous in items[:index]):
            _fail(code, f"{field}[{index}]", "duplicates an earlier array item")


def _validate_file_extension(value: Any, field: str, extension: str, code: str) -> str:
    path = _validate_path(value, field)
    if not path.endswith(extension):
        _fail(code, field, f"must end in {extension}")
    return path


def _validate_protected_path_policy(policy: Mapping[str, Any]) -> None:
    classes = _list(
        policy.get("protected_path_classes"),
        "protected_path_classes",
        "GOV_POLICY_INVALID",
    )
    validated: dict[str, dict[str, frozenset[str]]] = {}
    for index, item in enumerate(classes):
        field = f"protected_path_classes[{index}]"
        path_class = _mapping(item, field, "GOV_POLICY_INVALID")
        _require_schema_keys(
            path_class,
            {"id", "description", "exact_paths", "prefixes"},
            {"path_patterns"},
            field,
            "GOV_POLICY_INVALID",
        )
        class_id = _string(path_class["id"], f"{field}.id", "GOV_POLICY_INVALID")
        _string(path_class["description"], f"{field}.description", "GOV_POLICY_INVALID")
        if class_id in validated:
            _fail("GOV_POLICY_INVALID", f"{field}.id", "duplicates a protected class")

        exact_paths = _list(path_class["exact_paths"], f"{field}.exact_paths", "GOV_POLICY_INVALID")
        prefixes = _list(path_class["prefixes"], f"{field}.prefixes", "GOV_POLICY_INVALID")
        patterns = _list(
            path_class.get("path_patterns", []),
            f"{field}.path_patterns",
            "GOV_POLICY_INVALID",
        )
        _require_unique_items(exact_paths, f"{field}.exact_paths", "GOV_POLICY_INVALID")
        _require_unique_items(prefixes, f"{field}.prefixes", "GOV_POLICY_INVALID")
        _require_unique_items(patterns, f"{field}.path_patterns", "GOV_POLICY_INVALID")

        validated_exact = frozenset(
            _validate_path(path, f"{field}.exact_paths[{path_index}]")
            for path_index, path in enumerate(exact_paths)
        )
        validated_prefixes = frozenset(
            _validate_path(path, f"{field}.prefixes[{path_index}]", directory=True)
            for path_index, path in enumerate(prefixes)
        )
        validated_patterns: set[str] = set()
        for pattern_index, pattern in enumerate(patterns):
            pattern_field = f"{field}.path_patterns[{pattern_index}]"
            pattern_text = _string(pattern, pattern_field, "GOV_POLICY_INVALID")
            try:
                re.compile(pattern_text)
            except re.error as error:
                _fail("GOV_POLICY_INVALID", pattern_field, str(error))
            validated_patterns.add(pattern_text)
        validated[class_id] = {
            "exact_paths": validated_exact,
            "prefixes": validated_prefixes,
            "path_patterns": frozenset(validated_patterns),
        }

    for class_id, required in REQUIRED_PROTECTED_PATH_CLASSES.items():
        actual = validated.get(class_id)
        if actual is None:
            _fail("GOV_POLICY_INVALID", "protected_path_classes", f"missing {class_id}")
        for path_kind, required_paths in required.items():
            if not required_paths.issubset(actual[path_kind]):
                _fail(
                    "GOV_POLICY_INVALID",
                    f"protected_path_classes.{class_id}.{path_kind}",
                    "removes a required protected path",
                )


def is_protected_repository_path(path: Any, policy: Mapping[str, Any]) -> bool:
    """Classify one canonical repository path using the validated policy."""

    repository_path = validate_repository_path(path)
    protected_policy = _mapping(policy, "protected_policy", "GOV_POLICY_INVALID")
    _validate_protected_path_policy(protected_policy)
    for path_class in _list(
        protected_policy.get("protected_path_classes"),
        "protected_path_classes",
        "GOV_POLICY_INVALID",
    ):
        protected = _mapping(path_class, "protected_path_classes[]", "GOV_POLICY_INVALID")
        exact_paths = _list(
            protected.get("exact_paths"),
            "protected_path_classes[].exact_paths",
            "GOV_POLICY_INVALID",
        )
        prefixes = _list(
            protected.get("prefixes"),
            "protected_path_classes[].prefixes",
            "GOV_POLICY_INVALID",
        )
        patterns = _list(
            protected.get("path_patterns", []),
            "protected_path_classes[].path_patterns",
            "GOV_POLICY_INVALID",
        )
        if repository_path in exact_paths or any(
            repository_path.startswith(prefix) for prefix in prefixes
        ):
            return True
        if any(re.search(pattern, repository_path) is not None for pattern in patterns):
            return True
    return False


def _validate_required_production_verifications(
    lane: Mapping[str, Any], field: str
) -> None:
    verifications = _list(
        lane.get("required_production_verifications"),
        f"{field}.required_production_verifications",
    )
    _require_unique_items(
        verifications,
        f"{field}.required_production_verifications",
        "GOV_PV_ENTRY_DUPLICATE",
    )

    for index, item in enumerate(verifications):
        item_field = f"{field}.required_production_verifications[{index}]"
        verification = _mapping(item, item_field, "GOV_PV_ENTRY_INVALID")
        _require_exact_keys(verification, {"id", "requires_real_machine"}, item_field, "GOV_PV_ENTRY_INVALID")
        _matches(
            PV_ID_PATTERN,
            verification.get("id"),
            f"{item_field}.id",
            "GOV_PV_ID_INVALID",
            "must use the canonical PV-... format",
        )
        if not isinstance(verification.get("requires_real_machine"), bool):
            _fail("GOV_PV_ENTRY_INVALID", f"{item_field}.requires_real_machine", "must be boolean")


def _validate_allowlist(
    lane: Mapping[str, Any], field: str, _policy: Mapping[str, Any]
) -> None:
    """Check historical allowlist shape; `_policy` grants no path authority."""

    _matches(
        PLATFORM_PATTERN,
        lane.get("platform"),
        f"{field}.platform",
        "GOV_PLATFORM_INVALID",
        "must be a lowercase platform name",
    )
    entries = _list(lane.get("allowed_path_prefixes"), f"{field}.allowed_path_prefixes")
    _require_unique_items(entries, f"{field}.allowed_path_prefixes", "GOV_ALLOWLIST_ITEM_DUPLICATE")
    for index, item in enumerate(entries):
        item_field = f"{field}.allowed_path_prefixes[{index}]"
        if not isinstance(item, Mapping):
            _fail("GOV_ALLOWLIST_ITEM_INVALID", item_field, "must be a named-template object")
        _require_exact_keys(item, {"template_id", "prefix"}, item_field, "GOV_ALLOWLIST_ITEM_INVALID")
        _string(item.get("template_id"), f"{item_field}.template_id", "GOV_ALLOWLIST_ITEM_INVALID")
        _validate_path(item.get("prefix"), f"{item_field}.prefix", directory=True)


def _validate_exact_allowlist(
    lane: Mapping[str, Any], field: str, _policy: Mapping[str, Any]
) -> None:
    """Check historical exact-path shape; `_policy` grants no path authority."""

    _matches(
        PLATFORM_PATTERN,
        lane.get("platform"),
        f"{field}.platform",
        "GOV_PLATFORM_INVALID",
        "must be a lowercase platform name",
    )
    entries = _list(lane.get("allowed_paths"), f"{field}.allowed_paths")
    _require_unique_items(
        entries, f"{field}.allowed_paths", "GOV_ALLOWLIST_ITEM_DUPLICATE"
    )
    for index, item in enumerate(entries):
        item_field = f"{field}.allowed_paths[{index}]"
        if not isinstance(item, Mapping):
            _fail(
                "GOV_ALLOWLIST_ITEM_INVALID",
                item_field,
                "must be a named-template object",
            )
        _require_exact_keys(
            item,
            {"template_id", "path"},
            item_field,
            "GOV_ALLOWLIST_ITEM_INVALID",
        )
        _string(item.get("template_id"), f"{item_field}.template_id", "GOV_ALLOWLIST_ITEM_INVALID")
        _validate_path(item.get("path"), f"{item_field}.path")


def validate_bootstrap_exemption(document: Any, exemption_path: Any) -> None:
    """Validate the pure-data portion of a one-time governance bootstrap record."""

    code = "GOV_BOOTSTRAP_EXEMPTION_INVALID"
    record = _mapping(document, "bootstrap_exemption", code)
    state = _require_enum(record.get("state"), {"active", "consumed"}, "state", code)
    fields = BOOTSTRAP_ACTIVE_FIELDS if state == "active" else BOOTSTRAP_CONSUMED_FIELDS
    _require_exact_keys(record, fields, "bootstrap_exemption", code)

    try:
        canonical_path = validate_repository_path(exemption_path)
    except ContractViolation as error:
        _fail(code, "exemption_path", str(error))
    if canonical_path != BOOTSTRAP_EXEMPTION_PATH:
        _fail(code, "exemption_path", "must name the authorized one-time record")

    constants = {
        "schema_version": BOOTSTRAP_EXEMPTION_SCHEMA_VERSION,
        "requirement_id": BOOTSTRAP_REQUIREMENT_ID,
        "authorized_branch": BOOTSTRAP_BRANCH,
        "authorized_base_commit": BOOTSTRAP_BASE_COMMIT,
        "reason_code": "target_gate_bootstrap",
        "prohibits_delivery": True,
    }
    for field, expected in constants.items():
        _require_const(record.get(field), expected, field, code)

    failures = _list(record.get("legacy_gate_expected_failures"), "legacy_gate_expected_failures", code)
    if failures != list(BOOTSTRAP_LEGACY_FAILURES):
        _fail(code, "legacy_gate_expected_failures", "must equal the authorized legacy failure set")

    allowed_paths = _list(record.get("allowed_paths"), "allowed_paths", code)
    validated_paths: list[str] = []
    for index, path in enumerate(allowed_paths):
        try:
            validated_paths.append(validate_repository_path(path))
        except ContractViolation as error:
            _fail(code, f"allowed_paths[{index}]", str(error))
    if validated_paths != list(BOOTSTRAP_ALLOWED_PATHS):
        _fail(code, "allowed_paths", "must equal the authorized exact-path scope")

    allowed_prefixes = _list(record.get("allowed_path_prefixes"), "allowed_path_prefixes", code)
    for index, prefix in enumerate(allowed_prefixes):
        try:
            validate_repository_path(prefix, require_directory_prefix=True)
        except ContractViolation as error:
            _fail(code, f"allowed_path_prefixes[{index}]", str(error))
    if allowed_prefixes:
        _fail(code, "allowed_path_prefixes", "this one-time authorization has no directory-wide scope")

    commands = _list(record.get("target_gate_commands"), "target_gate_commands", code)
    validated_commands: list[list[str]] = []
    for command_index, command in enumerate(commands):
        arguments = _list(command, f"target_gate_commands[{command_index}]", code)
        if not arguments:
            _fail(code, f"target_gate_commands[{command_index}]", "must not be empty")
        validated_commands.append(
            [
                _string(argument, f"target_gate_commands[{command_index}][{argument_index}]", code)
                for argument_index, argument in enumerate(arguments)
            ]
        )
    if validated_commands != [list(command) for command in BOOTSTRAP_TARGET_GATE_COMMANDS]:
        _fail(code, "target_gate_commands", "must equal the authorized target gate commands")

    if state == "consumed":
        _matches(
            SHA_PATTERN,
            record.get("consumed_implementation_commit"),
            "consumed_implementation_commit",
            code,
            "must be a full lowercase Git commit SHA",
        )


def validate_common_native_acceptance_bundle(
    document: Any, bundle_path: Any
) -> None:
    """Validate the strict dual-host bundle structure without reading files."""

    code = "GOV_COMMON_BUNDLE_INVALID"
    host_set_code = "GOV_COMMON_ATTESTATION_SET_INVALID"
    bundle = _mapping(document, "common_native_acceptance_bundle", code)
    _require_exact_keys(
        bundle,
        COMMON_NATIVE_BUNDLE_FIELDS,
        "common_native_acceptance_bundle",
        code,
    )
    _require_const(bundle["schema_version"], "1.0", "schema_version", code)
    requirement_id = _matches(
        REQUIREMENT_ID_PATTERN,
        bundle.get("requirement_id"),
        "requirement_id",
        code,
        "must be a canonical requirement ID",
    )
    _matches(
        SHA_PATTERN,
        bundle.get("candidate_common_commit"),
        "candidate_common_commit",
        code,
        "must be a full lowercase Git commit SHA",
    )
    for field in (
        "candidate_non_evidence_tree_digest",
        "common_only_profile_digest",
        "gate_set_digest",
        "environment_policy_digest",
    ):
        _matches(
            SHA256_PATTERN,
            bundle.get(field),
            field,
            code,
            "must be a sha256 digest",
        )

    try:
        canonical_bundle_path = validate_repository_path(bundle_path)
    except ContractViolation as error:
        _fail(code, "bundle_path", str(error))
    bundle_match = CANONICAL_COMMON_NATIVE_BUNDLE_PATTERN.fullmatch(
        canonical_bundle_path
    )
    if bundle_match is None or bundle_match.group(1) != requirement_id:
        _fail(
            code,
            "bundle_path",
            "must be the canonical bundle path for this requirement",
        )

    runtime_identity = _mapping(
        bundle.get("runtime_identity"), "runtime_identity", code
    )
    _require_exact_keys(
        runtime_identity,
        COMMON_NATIVE_RUNTIME_IDENTITY_FIELDS,
        "runtime_identity",
        code,
    )
    for field in (
        "model_digest",
        "provider_contract_digest",
        "system_contract_digest",
    ):
        _matches(
            SHA256_PATTERN,
            runtime_identity.get(field),
            f"runtime_identity.{field}",
            code,
            "must be a sha256 digest",
        )
    _string(
        runtime_identity.get("model_schema_version"),
        "runtime_identity.model_schema_version",
        code,
    )

    attestations = _list(
        bundle.get("host_attestations"), "host_attestations", code
    )
    if len(attestations) != 2:
        _fail(host_set_code, "host_attestations", "must contain two hosts")
    observed_hosts: list[str] = []
    for index, item in enumerate(attestations):
        field = f"host_attestations[{index}]"
        attestation = _mapping(item, field, code)
        _require_exact_keys(
            attestation,
            {"host", "evidence_kind", "path", "sha256"},
            field,
            code,
        )
        host = attestation.get("host")
        if not isinstance(host, str) or host not in {"darwin", "win32"}:
            _fail(host_set_code, f"{field}.host", "must be darwin or win32")
        observed_hosts.append(host)
        _require_const(
            attestation.get("evidence_kind"),
            "real_machine",
            f"{field}.evidence_kind",
            code,
        )
        try:
            attestation_path = validate_repository_path(attestation.get("path"))
        except ContractViolation as error:
            _fail(code, f"{field}.path", str(error))
        attestation_match = CANONICAL_COMMON_NATIVE_ATTESTATION_PATTERN.fullmatch(
            attestation_path
        )
        if (
            attestation_match is None
            or attestation_match.groups() != (requirement_id, host)
        ):
            _fail(
                code,
                f"{field}.path",
                "must be the canonical attestation path for this host",
            )
        _matches(
            SHA256_PATTERN,
            attestation.get("sha256"),
            f"{field}.sha256",
            code,
            "must be a sha256 digest",
        )
    if set(observed_hosts) != {"darwin", "win32"} or len(set(observed_hosts)) != 2:
        _fail(
            host_set_code,
            "host_attestations",
            "must contain exactly darwin and win32",
        )


def validate_provisional_lane_record(
    document: Any, record_path: Any, protected_policy: Any
) -> None:
    """Read a historical provisional lane as shape-only, non-authoritative data."""

    invalid_code = "GOV_PROVISIONAL_RECORD_INVALID"
    path_code = "GOV_PROVISIONAL_PATH_NOT_ALLOWED"
    record = _mapping(document, "provisional_lane_record", invalid_code)
    schema_version = _require_enum(
        record.get("schema_version"),
        {"1.0", "1.1"},
        "schema_version",
        invalid_code,
    )
    expected_fields = (
        PROVISIONAL_LANE_FIELDS_V1_0
        if schema_version == "1.0"
        else PROVISIONAL_LANE_FIELDS_V1_1
    )
    _require_exact_keys(
        record,
        expected_fields,
        "provisional_lane_record",
        invalid_code,
    )
    _matches(
        REQUIREMENT_ID_PATTERN,
        record.get("requirement_id"),
        "requirement_id",
        invalid_code,
        "must be a canonical requirement ID",
    )
    _matches(
        PLATFORM_PATTERN,
        record.get("platform"),
        "platform",
        invalid_code,
        "must be a canonical platform name",
    )
    _matches(
        SHA_PATTERN,
        record.get("candidate_common_commit"),
        "candidate_common_commit",
        invalid_code,
        "must be a full lowercase Git commit SHA",
    )
    _matches(
        SHA256_PATTERN,
        record.get("candidate_non_evidence_tree_digest"),
        "candidate_non_evidence_tree_digest",
        invalid_code,
        "must be a sha256 digest",
    )
    _matches(
        LANE_BRANCH_PATTERN,
        record.get("provisional_branch"),
        "provisional_branch",
        invalid_code,
        "must be a valid branch name",
    )
    _require_enum(
        record.get("status"),
        {"in_progress", "blocked_by_prerequisite", "ready_for_rebase"},
        "status",
        invalid_code,
    )
    _require_enum(
        record.get("delivery_verdict"),
        DELIVERY_VERDICTS,
        "delivery_verdict",
        invalid_code,
    )
    if not isinstance(record.get("expires_on_manifest_creation"), bool):
        _fail(
            invalid_code,
            "expires_on_manifest_creation",
            "must be boolean",
        )

    try:
        canonical_record_path = validate_repository_path(record_path)
    except ContractViolation as error:
        _fail(invalid_code, "record_path", str(error))
    if (
        CANONICAL_PROVISIONAL_LANE_RECORD_PATTERN.fullmatch(canonical_record_path)
        is None
    ):
        _fail(
            invalid_code,
            "record_path",
            "must use the canonical provisional lane record shape",
        )

    try:
        planned_manifest_path = validate_repository_path(
            record.get("planned_manifest_path")
        )
    except ContractViolation as error:
        _fail(invalid_code, "planned_manifest_path", str(error))
    if CANONICAL_MANIFEST_PATTERN.fullmatch(planned_manifest_path) is None:
        _fail(
            invalid_code,
            "planned_manifest_path",
            "must use the canonical manifest path shape",
        )

    policy = _mapping(protected_policy, "protected_policy", "GOV_POLICY_INVALID")
    _validate_protected_path_policy(policy)
    try:
        _validate_allowlist(record, "provisional_lane_record", policy)
        if schema_version == "1.1":
            _validate_exact_allowlist(record, "provisional_lane_record", policy)
    except ContractViolation as error:
        if error.code == "GOV_POLICY_INVALID":
            raise
        _fail(path_code, error.field, str(error))

    for field_name in ("unfinished_subrequirements", "blockers"):
        items = _list(record.get(field_name), field_name, invalid_code)
        _require_unique_items(items, field_name, invalid_code)
        for index, item in enumerate(items):
            try:
                _validate_work_item_id(item, f"{field_name}[{index}]")
            except ContractViolation as error:
                _fail(invalid_code, error.field, str(error))


def validate_requirement_manifest(
    document: Any, manifest_path: Any, protected_policy: Any
) -> None:
    """Read a historical manifest as shape-only, non-authoritative data."""

    manifest = _mapping(document, "manifest")
    policy = _mapping(protected_policy, "protected_policy", "GOV_POLICY_INVALID")
    _validate_protected_path_policy(policy)
    schema_version = _require_enum(
        manifest.get("schema_version"),
        {"1.0", "1.1"},
        "schema_version",
        "GOV_MANIFEST_INVALID",
    )
    optional_fields = {"supersedes"}
    if schema_version == "1.1":
        optional_fields.add("common_native_acceptance")
    _require_schema_keys(
        manifest,
        MANIFEST_REQUIRED_FIELDS,
        optional_fields,
        "manifest",
        "GOV_MANIFEST_INVALID",
    )
    if schema_version == "1.1" and "common_native_acceptance" not in manifest:
        _fail(
            "GOV_MANIFEST_INVALID",
            "common_native_acceptance",
            "is required by schema version 1.1",
        )
    _require_const(
        manifest["baseline_record_mode"],
        "metadata_only_following_implementation",
        "baseline_record_mode",
        "GOV_MANIFEST_INVALID",
    )
    path = _validate_path(manifest_path, "manifest_path")
    path_match = CANONICAL_MANIFEST_PATTERN.fullmatch(path)
    if path_match is None:
        _fail("GOV_MANIFEST_PATH_INVALID", "manifest_path", "must use the canonical manifest path")

    _matches(
        REQUIREMENT_ID_PATTERN,
        manifest.get("requirement_id"),
        "requirement_id",
        "GOV_REQUIREMENT_ID_INVALID",
        "must be a canonical requirement ID",
    )
    if schema_version == "1.1":
        binding = _mapping(
            manifest["common_native_acceptance"],
            "common_native_acceptance",
            "GOV_MANIFEST_INVALID",
        )
        _require_exact_keys(
            binding,
            {"mode", "bundle_path", "bundle_sha256"},
            "common_native_acceptance",
            "GOV_MANIFEST_INVALID",
        )
        _require_const(
            binding.get("mode"),
            "dual_host_attestation_bundle",
            "common_native_acceptance.mode",
            "GOV_MANIFEST_INVALID",
        )
        try:
            bundle_path = validate_repository_path(binding.get("bundle_path"))
        except ContractViolation as error:
            _fail(
                "GOV_MANIFEST_INVALID",
                "common_native_acceptance.bundle_path",
                str(error),
            )
        if CANONICAL_COMMON_NATIVE_BUNDLE_PATTERN.fullmatch(bundle_path) is None:
            _fail(
                "GOV_MANIFEST_INVALID",
                "common_native_acceptance.bundle_path",
                "must use the canonical Common native bundle path shape",
            )
        _matches(
            SHA256_PATTERN,
            binding.get("bundle_sha256"),
            "common_native_acceptance.bundle_sha256",
            "GOV_MANIFEST_INVALID",
            "must be a sha256 digest",
        )
    _matches(
        SHA_PATTERN,
        manifest.get("accepted_common_implementation_commit"),
        "accepted_common_implementation_commit",
        "GOV_SHA_INVALID",
        "must be an exact 40-character lowercase hexadecimal SHA",
    )

    for path_field in ("top_level_spec_path", "common_architecture_spec_path", "common_plan_path"):
        _validate_file_extension(
            manifest[path_field], path_field, ".md", "GOV_MARKDOWN_PATH_INVALID"
        )
    _matches(
        LANE_BRANCH_PATTERN,
        manifest["common_branch"],
        "common_branch",
        "GOV_COMMON_BRANCH_INVALID",
        "must be a valid non-empty branch name",
    )
    if "supersedes" in manifest:
        supersedes = manifest["supersedes"]
        supersedes_object = _mapping(supersedes, "supersedes", "GOV_SUPERSEDES_INVALID")
        _require_exact_keys(
            supersedes_object,
            {"requirement_id", "manifest_path"},
            "supersedes",
            "GOV_SUPERSEDES_INVALID",
        )
        _matches(
            REQUIREMENT_ID_PATTERN,
            supersedes_object["requirement_id"],
            "supersedes.requirement_id",
            "GOV_REQUIREMENT_ID_INVALID",
            "must be a canonical requirement ID",
        )
        superseded_path = _validate_file_extension(
            supersedes_object["manifest_path"],
            "supersedes.manifest_path",
            ".json",
            "GOV_SUPERSEDES_PATH_INVALID",
        )
        superseded_match = CANONICAL_MANIFEST_PATTERN.fullmatch(superseded_path)
        if superseded_match is None:
            _fail(
                "GOV_SUPERSEDES_PATH_INVALID",
                "supersedes.manifest_path",
                "must use the canonical manifest path",
            )
    lanes = _list(manifest["platform_lanes"], "platform_lanes")
    if not lanes:
        _fail("GOV_PLATFORM_LANES_INVALID", "platform_lanes", "must not be empty")
    _require_unique_items(
        lanes,
        "platform_lanes",
        "GOV_PLATFORM_LANE_DUPLICATE",
    )
    for index, item in enumerate(lanes):
        field = f"platform_lanes[{index}]"
        lane = _mapping(item, field, "GOV_PLATFORM_LANE_INVALID")
        _require_exact_keys(lane, PLATFORM_LANE_FIELDS, field, "GOV_PLATFORM_LANE_INVALID")
        _matches(
            PLATFORM_PATTERN,
            lane.get("platform"),
            f"{field}.platform",
            "GOV_PLATFORM_INVALID",
            "must be a lowercase platform name",
        )
        _string(lane["rationale"], f"{field}.rationale", "GOV_LANE_RATIONALE_INVALID")

        _require_enum(
            lane.get("disposition"),
            {"implement", "verify_only", "not_applicable"},
            f"{field}.disposition",
            "GOV_LANE_DISPOSITION_INVALID",
        )
        planned_branch = lane["planned_branch"]
        if planned_branch is not None:
            _matches(
                LANE_BRANCH_PATTERN,
                planned_branch,
                f"{field}.planned_branch",
                "GOV_LANE_BRANCH_INVALID",
                "is not a valid branch name",
            )

        plan_path = lane["planned_plan_path"]
        if plan_path is not None:
            validated_plan = _validate_file_extension(
                plan_path,
                f"{field}.planned_plan_path",
                ".md",
                "GOV_LANE_PLAN_PATH_INVALID",
            )
            plan_match = CANONICAL_PLATFORM_PLAN_PATTERN.fullmatch(validated_plan)
            if plan_match is None:
                _fail(
                    "GOV_LANE_PLAN_PATH_INVALID",
                    f"{field}.planned_plan_path",
                    "must be below the canonical platform plan root",
                )

        lane_record_path = lane["planned_lane_record_path"]
        if lane_record_path is not None:
            record_path = _validate_path(lane_record_path, f"{field}.planned_lane_record_path")
            record_match = CANONICAL_LANE_RECORD_PATTERN.fullmatch(record_path)
            if record_match is None:
                _fail("GOV_LANE_RECORD_PATH_INVALID", f"{field}.planned_lane_record_path", "must be canonical")

        _validate_required_production_verifications(lane, field)
        _validate_allowlist(lane, field, policy)


def _validate_work_item_id(value: Any, field: str) -> str:
    return _matches(WORK_ITEM_ID_PATTERN, value, field, "GOV_WORK_ITEM_ID_INVALID", "is not a valid work-item ID")


def _validate_evidence(evidence: Any, field: str) -> list[Mapping[str, Any]]:
    entries = _list(evidence, field, "GOV_EVIDENCE_INVALID")
    validated: list[Mapping[str, Any]] = []
    for index, item in enumerate(entries):
        item_field = f"{field}[{index}]"
        evidence_item = _mapping(item, item_field, "GOV_EVIDENCE_INVALID")
        _require_exact_keys(evidence_item, {"kind", "path"}, item_field, "GOV_EVIDENCE_INVALID")
        _require_enum(
            evidence_item.get("kind"),
            EVIDENCE_KINDS,
            f"{item_field}.kind",
            "GOV_EVIDENCE_KIND_INVALID",
        )
        _validate_path(evidence_item.get("path"), f"{item_field}.path")
        validated.append(evidence_item)
    return validated


def validate_platform_lane_record(document: Any) -> None:
    """Validate historical lane-record shape without deriving delivery authority."""

    record = _mapping(document, "lane_record")
    required_fields = {
        "schema_version",
        "requirement_id",
        "platform",
        "lane_branch",
        "accepted_common_implementation_commit",
        "common_baseline_record_commit",
        "lane_status",
        "delivery_verdict",
        "unfinished_subrequirements",
        "blockers",
        "production_verifications",
        "skip_mock_items",
    }
    _require_schema_keys(
        record,
        required_fields,
        {"$comment"},
        "lane_record",
        "GOV_LANE_RECORD_INVALID",
    )
    if "$comment" in record and not isinstance(record["$comment"], str):
        _fail("GOV_LANE_RECORD_INVALID", "$comment", "must be a string")
    if record.get("schema_version") != "1.0":
        _fail("GOV_LANE_RECORD_INVALID", "schema_version", "must be 1.0")
    _matches(REQUIREMENT_ID_PATTERN, record.get("requirement_id"), "requirement_id", "GOV_REQUIREMENT_ID_INVALID", "must be canonical")
    _matches(PLATFORM_PATTERN, record.get("platform"), "platform", "GOV_PLATFORM_INVALID", "must be canonical")
    _matches(LANE_BRANCH_PATTERN, record.get("lane_branch"), "lane_branch", "GOV_LANE_BRANCH_INVALID", "must be valid")
    for sha_field in ("accepted_common_implementation_commit", "common_baseline_record_commit"):
        _matches(SHA_PATTERN, record.get(sha_field), sha_field, "GOV_SHA_INVALID", "must be an exact 40-character lowercase hexadecimal SHA")
    lane_status = record.get("lane_status")
    legacy_display_only = (
        isinstance(lane_status, str)
        and lane_status in LEGACY_DISPLAY_ONLY_LANE_STATUSES
    )
    _require_enum(
        lane_status,
        LEGACY_DISPLAY_ONLY_LANE_STATUSES if legacy_display_only else LANE_STATUSES,
        "lane_status",
        "GOV_LANE_STATUS_INVALID",
    )
    _require_enum(
        record.get("delivery_verdict"),
        DELIVERY_VERDICTS,
        "delivery_verdict",
        "GOV_DELIVERY_VERDICT_INVALID",
    )

    unfinished = _list(record.get("unfinished_subrequirements"), "unfinished_subrequirements")
    for index, item in enumerate(unfinished):
        field = f"unfinished_subrequirements[{index}]"
        subrequirement = _mapping(item, field, "GOV_UNFINISHED_INVALID")
        _require_exact_keys(subrequirement, {"id", "state"}, field, "GOV_UNFINISHED_INVALID")
        _validate_work_item_id(subrequirement.get("id"), f"{field}.id")
        _require_enum(
            subrequirement.get("state"),
            UNFINISHED_STATES,
            f"{field}.state",
            "GOV_UNFINISHED_STATE_INVALID",
        )

    blockers = _list(record.get("blockers"), "blockers")
    for index, item in enumerate(blockers):
        field = f"blockers[{index}]"
        blocker = _mapping(item, field, "GOV_BLOCKER_INVALID")
        blocker_kind = blocker.get("kind")
        legacy_common_blocker = (
            legacy_display_only
            and isinstance(blocker_kind, str)
            and blocker_kind in LEGACY_DISPLAY_ONLY_BLOCKER_KINDS
        )
        blocker_fields = {
            "id",
            "kind",
            "affected_subrequirement_ids",
            "evidence_paths",
        }
        if legacy_common_blocker:
            blocker_fields.update(LEGACY_DISPLAY_ONLY_COMMON_BLOCKER_FIELDS)
        _require_exact_keys(
            blocker,
            blocker_fields,
            field,
            "GOV_BLOCKER_INVALID",
        )
        _validate_work_item_id(blocker.get("id"), f"{field}.id")
        _require_enum(
            blocker_kind,
            (
                LEGACY_DISPLAY_ONLY_BLOCKER_KINDS
                if legacy_common_blocker
                else BLOCKER_KINDS
            ),
            f"{field}.kind",
            "GOV_BLOCKER_KIND_INVALID",
        )
        if legacy_common_blocker:
            _matches(
                REQUIREMENT_ID_PATTERN,
                blocker.get("common_change_requirement_id"),
                f"{field}.common_change_requirement_id",
                "GOV_BLOCKER_INVALID",
                "must be a canonical historical requirement ID",
            )
        affected = _list(blocker.get("affected_subrequirement_ids"), f"{field}.affected_subrequirement_ids")
        if not affected:
            _fail("GOV_BLOCKER_INVALID", f"{field}.affected_subrequirement_ids", "must not be empty")
        _require_unique_items(
            affected,
            f"{field}.affected_subrequirement_ids",
            "GOV_ARRAY_ITEM_DUPLICATE",
        )
        for affected_index, identifier in enumerate(affected):
            _validate_work_item_id(identifier, f"{field}.affected_subrequirement_ids[{affected_index}]")
        evidence_paths = _list(blocker.get("evidence_paths"), f"{field}.evidence_paths")
        if not evidence_paths:
            _fail("GOV_BLOCKER_INVALID", f"{field}.evidence_paths", "must not be empty")
        _require_unique_items(
            evidence_paths, f"{field}.evidence_paths", "GOV_ARRAY_ITEM_DUPLICATE"
        )
        for evidence_index, path in enumerate(evidence_paths):
            _validate_path(path, f"{field}.evidence_paths[{evidence_index}]")
    production_verifications = _list(record.get("production_verifications"), "production_verifications")
    for index, item in enumerate(production_verifications):
        field = f"production_verifications[{index}]"
        verification = _mapping(item, field, "GOV_PV_ENTRY_INVALID")
        _require_exact_keys(verification, {"id", "status", "evidence"}, field, "GOV_PV_ENTRY_INVALID")
        _matches(PV_ID_PATTERN, verification.get("id"), f"{field}.id", "GOV_PV_ID_INVALID", "must use the canonical PV-... format")
        _require_enum(
            verification.get("status"),
            PV_STATUSES,
            f"{field}.status",
            "GOV_PV_STATUS_INVALID",
        )
        _validate_evidence(verification.get("evidence"), f"{field}.evidence")

    skip_mock_items = _list(record.get("skip_mock_items"), "skip_mock_items")
    for index, item in enumerate(skip_mock_items):
        field = f"skip_mock_items[{index}]"
        skip_item = _mapping(item, field, "GOV_SKIP_MOCK_INVALID")
        _require_exact_keys(skip_item, {"id", "affected_production_verification_ids", "evidence_paths"}, field, "GOV_SKIP_MOCK_INVALID")
        _validate_work_item_id(skip_item.get("id"), f"{field}.id")
        affected_ids = _list(skip_item.get("affected_production_verification_ids"), f"{field}.affected_production_verification_ids")
        if not affected_ids:
            _fail("GOV_SKIP_MOCK_INVALID", f"{field}.affected_production_verification_ids", "must not be empty")
        _require_unique_items(
            affected_ids,
            f"{field}.affected_production_verification_ids",
            "GOV_ARRAY_ITEM_DUPLICATE",
        )
        for affected_index, identifier in enumerate(affected_ids):
            _matches(PV_ID_PATTERN, identifier, f"{field}.affected_production_verification_ids[{affected_index}]", "GOV_PV_ID_INVALID", "must use the canonical PV-... format")
        evidence_paths = _list(skip_item.get("evidence_paths"), f"{field}.evidence_paths")
        if not evidence_paths:
            _fail("GOV_SKIP_MOCK_INVALID", f"{field}.evidence_paths", "must not be empty")
        _require_unique_items(
            evidence_paths, f"{field}.evidence_paths", "GOV_ARRAY_ITEM_DUPLICATE"
        )
        for evidence_index, path in enumerate(evidence_paths):
            _validate_path(path, f"{field}.evidence_paths[{evidence_index}]")
