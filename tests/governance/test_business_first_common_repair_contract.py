"""回归保护：宿主业务流可直接修补 Common，历史记录仅作只读展示。"""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[2]
CMAKE_PATH = ROOT / "CMakeLists.txt"
CONTRACTS_PATH = ROOT / "scripts/common_first_governance_contracts.py"
POLICY_PATH = ROOT / "docs/superpowers/governance/common-first-protected-paths.json"
PLATFORM_LANE_SCHEMA_PATH = (
    ROOT / "docs/superpowers/governance/platform-lane-record.schema.json"
)
MANIFEST_SCHEMA_PATH = (
    ROOT / "docs/superpowers/governance/common-first-requirement-manifest.schema.json"
)
PROVISIONAL_SCHEMA_PATH = (
    ROOT
    / "docs/superpowers/governance/common-first-provisional-lane-record.schema.json"
)
HISTORICAL_SCHEMA_PATHS = (MANIFEST_SCHEMA_PATH, PROVISIONAL_SCHEMA_PATH)
LEGACY_DARWIN_LANE_PATH = (
    ROOT
    / "docs/superpowers/platforms/darwin/vpn-business-flow-state-machine-v3/lane-record.json"
)
HISTORICAL_LANE_TEMPLATE_PATH = (
    ROOT / "docs/superpowers/templates/platform-lane-record.template.json"
)
MANIFEST_FIXTURE_ROOT = ROOT / "docs/superpowers/requirements"
TEMPLATE_PATHS = (
    ROOT / "docs/superpowers/templates/platform-implementation-plan-template.md",
    ROOT / "docs/superpowers/templates/platform-lane-status-template.md",
)
ACTIVE_POLICY_AND_TEMPLATE_PATHS = (POLICY_PATH, *TEMPLATE_PATHS)
FORBIDDEN_ACTIVE_GATE_TERMS = (
    "blocked_by_common",
    "common_change_requirement_id",
)
FORBIDDEN_OWNERSHIP_ENUMS = (
    "retain_common",
    "extract",
)


def load_contracts_module():
    spec = importlib.util.spec_from_file_location(
        "business_first_common_repair_contracts", CONTRACTS_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load common-first governance contracts")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def valid_delivered_record() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "requirement_id": "host-common-repair",
        "platform": "win32",
        "lane_branch": "codex/host-common-repair",
        "accepted_common_implementation_commit": "a" * 40,
        "common_baseline_record_commit": "b" * 40,
        "lane_status": "delivered",
        "delivery_verdict": "deliverable",
        "unfinished_subrequirements": [],
        "blockers": [],
        "production_verifications": [
            {
                "id": "PV-HOST-REPAIR",
                "status": "passed",
                "evidence": [
                    {
                        "kind": "platform_test",
                        "path": "evidence/host-repair.txt",
                    }
                ],
            }
        ],
        "skip_mock_items": [],
    }


def valid_provisional_record() -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "requirement_id": "host-common-repair",
        "platform": "win32",
        "candidate_common_commit": "a" * 40,
        "candidate_non_evidence_tree_digest": "sha256:" + "b" * 64,
        "planned_manifest_path": (
            "docs/superpowers/requirements/host-common-repair/"
            "common-first-manifest.json"
        ),
        "provisional_branch": "codex/host-common-repair",
        "status": "in_progress",
        "delivery_verdict": "not_deliverable",
        "allowed_path_prefixes": [
            {"template_id": "legacy-note", "prefix": "src/common/"}
        ],
        "allowed_paths": [
            {"template_id": "legacy-note", "path": "CMakeLists.txt"}
        ],
        "unfinished_subrequirements": [],
        "blockers": [],
        "expires_on_manifest_creation": True,
    }


def valid_manifest() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "requirement_id": "host-common-repair",
        "top_level_spec_path": "docs/superpowers/specs/host-common-repair.md",
        "common_architecture_spec_path": (
            "docs/superpowers/specs/host-common-repair-common-architecture.md"
        ),
        "common_plan_path": "docs/superpowers/plans/host-common-repair.md",
        "common_branch": "codex/host-common-repair-common",
        "accepted_common_implementation_commit": "a" * 40,
        "baseline_record_mode": "metadata_only_following_implementation",
        "platform_lanes": [
            {
                "platform": "win32",
                "disposition": "implement",
                "rationale": "历史展示记录",
                "planned_branch": "codex/host-common-repair-win32",
                "planned_plan_path": (
                    "docs/superpowers/platforms/win32/host-common-repair.md"
                ),
                "planned_lane_record_path": (
                    "docs/superpowers/platforms/win32/host-common-repair/"
                    "lane-record.json"
                ),
                "required_production_verifications": [
                    {"id": "PV-HOST-REPAIR", "requires_real_machine": False}
                ],
                "allowed_path_prefixes": [],
            }
        ],
    }


def shape_only_manifest(schema_version: str = "1.0") -> dict[str, object]:
    manifest = valid_manifest()
    manifest["schema_version"] = schema_version
    manifest["supersedes"] = {
        "requirement_id": "older-requirement",
        "manifest_path": (
            "docs/superpowers/requirements/different-history/"
            "common-first-manifest.json"
        ),
    }
    lane = manifest["platform_lanes"][0]
    lane["disposition"] = "not_applicable"
    lane["planned_branch"] = "codex/historical-unbound-branch"
    lane["planned_plan_path"] = (
        "docs/superpowers/platforms/darwin/different-plan.md"
    )
    lane["planned_lane_record_path"] = (
        "docs/superpowers/platforms/darwin/different-requirement/"
        "lane-record.json"
    )
    if schema_version == "1.1":
        manifest["common_native_acceptance"] = {
            "mode": "dual_host_attestation_bundle",
            "bundle_path": (
                "docs/superpowers/evidence/common-native-acceptance/"
                "different-bundle/bundle.json"
            ),
            "bundle_sha256": "sha256:" + "c" * 64,
        }
    return manifest


def iter_mappings(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_mappings(child)


class BusinessFirstCommonRepairContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contracts = load_contracts_module()
        cls.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        cls.platform_lane_schema = json.loads(
            PLATFORM_LANE_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        cls.manifest_schema = json.loads(
            MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        cls.provisional_schema = json.loads(
            PROVISIONAL_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        cls.platform_lane_validator = Draft202012Validator(cls.platform_lane_schema)
        cls.manifest_validator = Draft202012Validator(cls.manifest_schema)
        cls.provisional_validator = Draft202012Validator(cls.provisional_schema)

    def test_active_policy_templates_and_constants_have_no_legacy_common_gate(self) -> None:
        for path in ACTIVE_POLICY_AND_TEMPLATE_PATHS:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                for term in FORBIDDEN_ACTIVE_GATE_TERMS:
                    self.assertNotIn(term, text)
                for enum_name in FORBIDDEN_OWNERSHIP_ENUMS:
                    self.assertNotIn(enum_name, text)

        self.assertNotIn("blocked_by_common", self.contracts.LANE_STATUSES)
        self.assertNotIn("common", self.contracts.BLOCKER_KINDS)
        self.assertNotIn(
            "blocked_by_common",
            self.platform_lane_schema["$defs"]["active_lane_status"]["enum"],
        )
        self.assertNotIn(
            "common",
            self.platform_lane_schema["$defs"]["blocker"]["properties"]["kind"][
                "enum"
            ],
        )
        self.assertEqual(
            frozenset({"blocked_by_common"}),
            self.contracts.LEGACY_DISPLAY_ONLY_LANE_STATUSES,
        )
        self.assertEqual(
            frozenset({"common"}),
            self.contracts.LEGACY_DISPLAY_ONLY_BLOCKER_KINDS,
        )
        source = CONTRACTS_PATH.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\bGOV_BLOCKED_COMMON[A-Z0-9_]*\b", source))
        self.assertNotIn("GOV_PROVISIONAL_DELIVERY_FORBIDDEN", source)
        self.assertIsNone(
            re.search(
                r"\b(?:GOV_DELIVERABLE|GOV_SKIP_MOCK_(?:VERDICT|STATUS|UNKNOWN)|"
                r"GOV_PV_PASSED_)[A-Z0-9_]*\b",
                source,
            )
        )

    def test_historical_allowlist_descriptions_neither_authorize_nor_forbid_host_repairs(self) -> None:
        for path in HISTORICAL_SCHEMA_PATHS:
            schema = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(path=path):
                text = json.dumps(schema, ensure_ascii=False)
                self.assertIn("历史展示", text)
                self.assertIn("不授权", text)
                self.assertIn("不禁止", text)

    def test_policy_keeps_only_governance_evidence_protection_and_disables_predeclaration(self) -> None:
        self.assertNotEqual(
            "default_deny",
            self.policy["platform_allowed_prefix_policy"]["mode"],
        )
        repair_policy = self.policy["host_repair_policy"]
        self.assertFalse(repair_policy["predeclared_allowlist_required"])
        self.assertFalse(repair_policy["integration_recommendation_binding"])
        self.assertIn("真实业务流", repair_policy["description"])

        class_ids = {
            item["id"] for item in self.policy["protected_path_classes"]
        }
        self.assertEqual({"governance_and_evidence_authority"}, class_ids)
        all_protected_paths = json.dumps(
            self.policy["protected_path_classes"], ensure_ascii=False
        )
        for business_path in (
            "src/common/",
            "CMakeLists.txt",
            "contracts/",
            "tests/common/",
        ):
            self.assertNotIn(business_path, all_protected_paths)
        self.assertIn(".github/workflows/", all_protected_paths)

    def test_business_common_paths_are_repairable_but_governance_paths_remain_protected(self) -> None:
        for path in (
            "src/common/repair.cpp",
            "CMakeLists.txt",
            "contracts/host-repair.json",
            "tests/common/host_repair_test.cpp",
        ):
            with self.subTest(path=path):
                self.assertFalse(
                    self.contracts.is_protected_repository_path(path, self.policy)
                )

        for path in (
            "AGENTS.md",
            "docs/architecture/guardrail_allowlist.yml",
            "docs/superpowers/governance/rules.json",
            "scripts/architecture-guardrails.ps1",
            "scripts/architecture-guardrails.sh",
            "scripts/common_first_governance_contracts.py",
            "scripts/validate-common-first-governance.py",
            "scripts/validate-common-runtime-decoupling.py",
            "tests/governance/test_policy.py",
            ".github/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    self.contracts.is_protected_repository_path(path, self.policy)
                )

        required_exact_paths = self.contracts.REQUIRED_PROTECTED_PATH_CLASSES[
            "governance_and_evidence_authority"
        ]["exact_paths"]
        for path in (
            "docs/architecture/guardrail_allowlist.yml",
            "scripts/architecture-guardrails.ps1",
            "scripts/architecture-guardrails.sh",
        ):
            self.assertIn(path, required_exact_paths)

    def test_legacy_darwin_lane_is_readable_but_not_an_active_verdict_rule(self) -> None:
        record = json.loads(LEGACY_DARWIN_LANE_PATH.read_text(encoding="utf-8"))

        self.contracts.validate_platform_lane_record(record)
        self.platform_lane_validator.validate(record)

        display_only_record = deepcopy(record)
        display_only_record["delivery_verdict"] = "deliverable"
        self.contracts.validate_platform_lane_record(display_only_record)
        self.platform_lane_validator.validate(display_only_record)

        legacy_shapes = self.platform_lane_schema.get("oneOf", [])
        self.assertTrue(
            any(
                "deprecated" in json.dumps(shape).lower()
                and "non-authoritative" in json.dumps(shape).lower()
                for shape in legacy_shapes
            ),
            "schema must label its legacy oneOf shape deprecated/non-authoritative",
        )
        self.assertFalse(
            any("if" in node for node in iter_mappings(self.platform_lane_schema)),
            "historical lane schema must not derive verdicts across fields",
        )

    def test_platform_lane_comment_is_optional_display_only_compatibility_metadata(
        self,
    ) -> None:
        template = json.loads(
            HISTORICAL_LANE_TEMPLATE_PATH.read_text(encoding="utf-8")
        )
        validators = (
            (
                "contract",
                self.contracts.validate_platform_lane_record,
                self.contracts.ContractViolation,
            ),
            ("schema", self.platform_lane_validator.validate, ValidationError),
        )

        for validator_name, validate, _ in validators:
            with self.subTest(validator=validator_name, record="actual_template"):
                self.assertIsNone(validate(template))

        legacy_record = deepcopy(template)
        legacy_record.pop("$comment")
        for validator_name, validate, _ in validators:
            with self.subTest(validator=validator_name, record="legacy_fields"):
                self.assertIsNone(validate(legacy_record))

        for comment in ("", "任意历史显示文字不产生任何交付或授权结论。"):
            comment_record = deepcopy(legacy_record)
            comment_record["$comment"] = comment
            for validator_name, validate, _ in validators:
                with self.subTest(
                    validator=validator_name,
                    record="changed_display_comment",
                    comment=comment,
                ):
                    self.assertIsNone(validate(comment_record))

        for required_field in legacy_record:
            missing_field = deepcopy(legacy_record)
            missing_field.pop(required_field)
            for validator_name, validate, expected_error in validators:
                with self.subTest(
                    validator=validator_name,
                    record="missing_legacy_field",
                    field=required_field,
                ):
                    with self.assertRaises(expected_error):
                        validate(missing_field)

        for comment in (None, [], {}):
            malformed_comment = deepcopy(legacy_record)
            malformed_comment["$comment"] = comment
            for validator_name, validate, expected_error in validators:
                with self.subTest(
                    validator=validator_name,
                    record="non_string_comment",
                    comment=comment,
                ):
                    with self.assertRaises(expected_error):
                        validate(malformed_comment)

        unknown_field = deepcopy(legacy_record)
        unknown_field["unrecognized_lane_metadata"] = "must remain rejected"
        for validator_name, validate, expected_error in validators:
            with self.subTest(validator=validator_name, record="unknown_field"):
                with self.assertRaises(expected_error):
                    validate(unknown_field)

    def test_provisional_allowlist_custom_template_and_common_paths_match_python_and_schema(self) -> None:
        record = valid_provisional_record()
        record_path = (
            "docs/superpowers/platforms/win32/host-common-repair/"
            "provisional-lane-record.json"
        )

        self.contracts.validate_provisional_lane_record(
            record, record_path, self.policy
        )
        self.provisional_validator.validate(record)

        for schema_version in ("1.0", "1.1"):
            empty_record = deepcopy(record)
            empty_record["schema_version"] = schema_version
            empty_record["allowed_path_prefixes"] = []
            empty_record["allowed_paths"] = []
            if schema_version == "1.0":
                del empty_record["allowed_paths"]
            with self.subTest(schema_version=schema_version, allowlist="empty"):
                self.contracts.validate_provisional_lane_record(
                    empty_record, record_path, self.policy
                )
                self.provisional_validator.validate(empty_record)

        segment_record = deepcopy(record)
        segment_record["allowed_path_prefixes"][0]["prefix"] = "_private/"
        segment_record["allowed_paths"][0]["path"] = "_private/repair.cpp"
        self.contracts.validate_provisional_lane_record(
            segment_record, record_path, self.policy
        )
        self.provisional_validator.validate(segment_record)

    def test_provisional_records_are_shape_only_without_lifecycle_or_identity_gates(self) -> None:
        record = valid_provisional_record()
        record["delivery_verdict"] = "deliverable"
        record["status"] = "in_progress"
        record["blockers"] = ["historical_blocker"]
        record["expires_on_manifest_creation"] = False
        record["planned_manifest_path"] = (
            "docs/superpowers/requirements/different-requirement/"
            "common-first-manifest.json"
        )
        mismatched_record_path = (
            "docs/superpowers/platforms/darwin/different-requirement/"
            "provisional-lane-record.json"
        )

        self.contracts.validate_provisional_lane_record(
            record, mismatched_record_path, self.policy
        )
        self.provisional_validator.validate(record)

        self.assertFalse(hasattr(self.contracts, "PROVISIONAL_DELIVERY_FIELDS"))
        conditions = [
            json.dumps(node["if"])
            for node in iter_mappings(self.provisional_schema)
            if "if" in node
        ]
        self.assertTrue(conditions)
        self.assertTrue(all("schema_version" in condition for condition in conditions))

    def test_manifest_implement_lane_accepts_empty_predeclared_allowlist_in_python_and_schema(self) -> None:
        manifest = valid_manifest()
        manifest_path = (
            "docs/superpowers/requirements/host-common-repair/"
            "common-first-manifest.json"
        )

        self.contracts.validate_requirement_manifest(
            manifest, manifest_path, self.policy
        )
        self.manifest_validator.validate(manifest)

        segment_manifest = deepcopy(manifest)
        segment_manifest["platform_lanes"][0]["allowed_path_prefixes"] = [
            {"template_id": "legacy-note", "prefix": "_private/"}
        ]
        self.contracts.validate_requirement_manifest(
            segment_manifest, manifest_path, self.policy
        )
        self.manifest_validator.validate(segment_manifest)

        for unsafe_prefix in ("src/-bad/", "src/common/\n"):
            unsafe_manifest = deepcopy(manifest)
            unsafe_manifest["platform_lanes"][0]["allowed_path_prefixes"] = [
                {"template_id": "legacy-note", "prefix": unsafe_prefix}
            ]
            with self.subTest(manifest_prefix=unsafe_prefix):
                with self.assertRaises(self.contracts.ContractViolation):
                    self.contracts.validate_requirement_manifest(
                        unsafe_manifest, manifest_path, self.policy
                    )
                self.assertTrue(
                    list(self.manifest_validator.iter_errors(unsafe_manifest))
                )

    def test_manifest_records_are_shape_only_without_identity_or_lifecycle_gates(self) -> None:
        manifest_path = (
            "docs/superpowers/requirements/different-container/"
            "common-first-manifest.json"
        )
        for schema_version in ("1.0", "1.1"):
            manifest = shape_only_manifest(schema_version)
            with self.subTest(schema_version=schema_version):
                self.contracts.validate_requirement_manifest(
                    manifest, manifest_path, self.policy
                )
                self.manifest_validator.validate(manifest)

            implement_without_branch = deepcopy(manifest)
            implement_lane = implement_without_branch["platform_lanes"][0]
            implement_lane["disposition"] = "implement"
            implement_lane["planned_branch"] = None
            with self.subTest(
                schema_version=schema_version,
                lifecycle_shape="implement_without_branch",
            ):
                self.contracts.validate_requirement_manifest(
                    implement_without_branch, manifest_path, self.policy
                )
                self.manifest_validator.validate(implement_without_branch)

        source = CONTRACTS_PATH.read_text(encoding="utf-8")
        for code in (
            "GOV_MANIFEST_REQUIREMENT_MISMATCH",
            "GOV_SUPERSEDES_REQUIREMENT_MISMATCH",
            "GOV_LANE_BRANCH_REQUIRED",
            "GOV_LANE_BRANCH_NOT_APPLICABLE",
            "GOV_LANE_PLAN_REQUIRED",
            "GOV_LANE_PLAN_NOT_APPLICABLE",
            "GOV_LANE_PLAN_PLATFORM_MISMATCH",
            "GOV_LANE_RECORD_PLATFORM_MISMATCH",
            "GOV_LANE_RECORD_REQUIREMENT_MISMATCH",
            "GOV_LANE_RECORD_NOT_APPLICABLE",
            "GOV_PV_REQUIRED",
            "GOV_PV_NOT_APPLICABLE",
        ):
            self.assertNotIn(code, source)
        self.assertNotIn("allOf", self.manifest_schema["$defs"]["platform_lane"])
        conditions = [
            json.dumps(node["if"])
            for node in iter_mappings(self.manifest_schema)
            if "if" in node
        ]
        self.assertTrue(conditions)
        self.assertTrue(all("schema_version" in condition for condition in conditions))

    def test_shape_only_paths_still_require_safe_canonical_syntax_in_python_and_schema(self) -> None:
        provisional_path = (
            "docs/superpowers/platforms/win32/host-common-repair/"
            "provisional-lane-record.json"
        )
        for planned_manifest_path in (
            "docs/superpowers/requirements/history/common-first-manifest.json\n",
            "docs/history.json",
        ):
            record = valid_provisional_record()
            record["planned_manifest_path"] = planned_manifest_path
            with self.subTest(provisional_path=planned_manifest_path):
                with self.assertRaises(self.contracts.ContractViolation):
                    self.contracts.validate_provisional_lane_record(
                        record, provisional_path, self.policy
                    )
                self.assertTrue(list(self.provisional_validator.iter_errors(record)))

        manifest_path = (
            "docs/superpowers/requirements/history/common-first-manifest.json"
        )
        manifest_cases = (
            (
                "common_native_acceptance.bundle_path",
                lambda manifest: manifest["common_native_acceptance"].__setitem__(
                    "bundle_path",
                    "docs/superpowers/evidence/common-native-acceptance/history/"
                    "bundle.json\n",
                ),
            ),
            (
                "supersedes.manifest_path",
                lambda manifest: manifest["supersedes"].__setitem__(
                    "manifest_path",
                    "docs/superpowers/requirements/history/"
                    "common-first-manifest.json\n",
                ),
            ),
            (
                "planned_plan_path",
                lambda manifest: manifest["platform_lanes"][0].__setitem__(
                    "planned_plan_path",
                    "docs/superpowers/platforms/darwin/history.md\n",
                ),
            ),
            (
                "planned_lane_record_path",
                lambda manifest: manifest["platform_lanes"][0].__setitem__(
                    "planned_lane_record_path",
                    "docs/superpowers/platforms/darwin/history/lane-record.json\n",
                ),
            ),
        )
        for field, mutate in manifest_cases:
            manifest = shape_only_manifest("1.1")
            mutate(manifest)
            with self.subTest(manifest_path=field):
                with self.assertRaises(self.contracts.ContractViolation):
                    self.contracts.validate_requirement_manifest(
                        manifest, manifest_path, self.policy
                    )
                self.assertTrue(list(self.manifest_validator.iter_errors(manifest)))

    def test_manifest_list_uniqueness_is_structural_not_identity_binding(self) -> None:
        manifest_path = (
            "docs/superpowers/requirements/history/common-first-manifest.json"
        )

        repeated_platform = shape_only_manifest()
        second_lane = deepcopy(repeated_platform["platform_lanes"][0])
        second_lane["rationale"] = "同一历史 platform 的另一条展示记录"
        repeated_platform["platform_lanes"].append(second_lane)

        repeated_pv_id = shape_only_manifest()
        repeated_pv_id["platform_lanes"][0][
            "required_production_verifications"
        ].append({"id": "PV-HOST-REPAIR", "requires_real_machine": True})

        for name, manifest in (
            ("platform", repeated_platform),
            ("production_verification_id", repeated_pv_id),
        ):
            with self.subTest(repeated_identity=name):
                self.contracts.validate_requirement_manifest(
                    manifest, manifest_path, self.policy
                )
                self.manifest_validator.validate(manifest)

        duplicate_lane = shape_only_manifest()
        duplicate_lane["platform_lanes"].append(
            deepcopy(duplicate_lane["platform_lanes"][0])
        )
        duplicate_pv = shape_only_manifest()
        duplicate_pv["platform_lanes"][0][
            "required_production_verifications"
        ].append(
            deepcopy(
                duplicate_pv["platform_lanes"][0][
                    "required_production_verifications"
                ][0]
            )
        )
        for name, manifest in (
            ("lane", duplicate_lane),
            ("production_verification", duplicate_pv),
        ):
            with self.subTest(exact_duplicate=name):
                with self.assertRaises(self.contracts.ContractViolation):
                    self.contracts.validate_requirement_manifest(
                        manifest, manifest_path, self.policy
                    )
                self.assertTrue(list(self.manifest_validator.iter_errors(manifest)))

    def test_all_repository_manifest_fixtures_match_python_and_schema(self) -> None:
        fixture_paths = sorted(MANIFEST_FIXTURE_ROOT.rglob("common-first-manifest.json"))
        self.assertEqual(26, len(fixture_paths))

        for path in fixture_paths:
            document = json.loads(path.read_text(encoding="utf-8"))
            repository_path = path.relative_to(ROOT).as_posix()
            with self.subTest(path=repository_path):
                self.contracts.validate_requirement_manifest(
                    document, repository_path, self.policy
                )
                self.manifest_validator.validate(document)

    def test_allowlist_rejects_empty_template_ids_and_unsafe_paths_in_python_and_schema(self) -> None:
        record_path = (
            "docs/superpowers/platforms/win32/host-common-repair/"
            "provisional-lane-record.json"
        )
        for collection in ("allowed_path_prefixes", "allowed_paths"):
            record = valid_provisional_record()
            record[collection][0]["template_id"] = ""
            with self.subTest(collection=collection, template_id=""):
                with self.assertRaises(self.contracts.ContractViolation) as caught:
                    self.contracts.validate_provisional_lane_record(
                        record, record_path, self.policy
                    )
                self.assertIn(".template_id", caught.exception.field)

                schema_errors = list(self.provisional_validator.iter_errors(record))
                self.assertTrue(schema_errors, "schema accepted an empty template ID")
                self.assertTrue(
                    any(
                        list(error.absolute_path)[-1:] == ["template_id"]
                        for error in schema_errors
                    ),
                    "schema rejection must identify the empty template_id field",
                )

        cases = (
            ("allowed_path_prefixes", "prefix", "/src/common/"),
            ("allowed_path_prefixes", "prefix", "C:/src/common/"),
            ("allowed_path_prefixes", "prefix", "src\\common\\"),
            ("allowed_path_prefixes", "prefix", "src/../common/"),
            ("allowed_path_prefixes", "prefix", "src/-bad/"),
            ("allowed_path_prefixes", "prefix", "src/common/\n"),
            ("allowed_paths", "path", "/CMakeLists.txt"),
            ("allowed_paths", "path", "C:/CMakeLists.txt"),
            ("allowed_paths", "path", "src\\repair.cpp"),
            ("allowed_paths", "path", "src/../repair.cpp"),
            ("allowed_paths", "path", "src/-bad.cpp"),
            ("allowed_paths", "path", "src/repair.cpp\n"),
        )

        for collection, field, invalid_path in cases:
            record = valid_provisional_record()
            record[collection][0]["template_id"] = "platform_source"
            record[collection][0][field] = invalid_path
            with self.subTest(collection=collection, invalid_path=invalid_path):
                with self.assertRaises(self.contracts.ContractViolation) as caught:
                    self.contracts.validate_provisional_lane_record(
                        record, record_path, self.policy
                    )
                self.assertIn(f".{field}", caught.exception.field)

                schema_errors = list(self.provisional_validator.iter_errors(record))
                self.assertTrue(schema_errors, "schema accepted an unsafe path")
                self.assertTrue(
                    any(
                        list(error.absolute_path)[-1:] == [field]
                        for error in schema_errors
                    ),
                    "schema rejection must identify the unsafe path field",
                )

    def test_current_lane_records_are_readable_without_delivery_authority(self) -> None:
        record = valid_delivered_record()

        self.contracts.validate_platform_lane_record(record)
        self.platform_lane_validator.validate(record)

        display_only_record = deepcopy(record)
        display_only_record["lane_status"] = "in_progress"
        display_only_record["unfinished_subrequirements"] = [
            {"id": "host_repair", "state": "open"}
        ]
        display_only_record["blockers"] = [
            {
                "id": "historical_observation",
                "kind": "environment",
                "affected_subrequirement_ids": ["host_repair"],
                "evidence_paths": ["evidence/historical-observation.txt"],
            }
        ]
        display_only_record["production_verifications"][0]["status"] = "blocked"
        display_only_record["production_verifications"][0]["evidence"] = []
        self.contracts.validate_platform_lane_record(display_only_record)
        self.platform_lane_validator.validate(display_only_record)

        self.assertNotIn(
            "host_real_passed",
            json.dumps(self.platform_lane_schema) + json.dumps(self.policy),
        )

    def test_lane_production_verifications_have_no_id_identity_gate(self) -> None:
        record = valid_delivered_record()
        record["production_verifications"] = [
            {
                "id": "PV-DUPLICATE",
                "status": "passed",
                "evidence": [
                    {
                        "kind": "platform_test",
                        "path": "evidence/duplicate-passed.txt",
                    }
                ],
            },
            {
                "id": "PV-DUPLICATE",
                "status": "failed",
                "evidence": [
                    {
                        "kind": "integration_test",
                        "path": "evidence/duplicate-failed.txt",
                    }
                ],
            },
        ]
        self.contracts.validate_platform_lane_record(record)
        self.platform_lane_validator.validate(record)

        exact_duplicate = valid_delivered_record()
        verification = deepcopy(exact_duplicate["production_verifications"][0])
        verification["id"] = "PV-DUPLICATE"
        exact_duplicate["production_verifications"] = [
            verification,
            deepcopy(verification),
        ]
        self.contracts.validate_platform_lane_record(exact_duplicate)
        self.platform_lane_validator.validate(exact_duplicate)

        source = CONTRACTS_PATH.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\bverification_ids\b", source))
        self.assertNotIn("GOV_PV_ID_DUPLICATE", source)

    def test_malformed_legacy_discriminators_raise_contract_violations(self) -> None:
        malformed_records = []

        lane_status_record = valid_delivered_record()
        lane_status_record["lane_status"] = []
        malformed_records.append(("lane_status", lane_status_record))

        blocker_kind_record = json.loads(
            LEGACY_DARWIN_LANE_PATH.read_text(encoding="utf-8")
        )
        blocker_kind_record["blockers"][0]["kind"] = []
        malformed_records.append(("blocker.kind", blocker_kind_record))

        for field, record in malformed_records:
            with self.subTest(field=field):
                with self.assertRaises(self.contracts.ContractViolation):
                    self.contracts.validate_platform_lane_record(record)

    def test_templates_record_facts_and_real_user_business_flow_without_legacy_blocking(self) -> None:
        for path in TEMPLATE_PATHS:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                for phrase in (
                    "观察事实",
                    "当前修补",
                    "当前活动接线",
                    "非约束建议",
                    "模块测试",
                    "真实用户业务流",
                ):
                    self.assertIn(phrase, text)
                self.assertNotIn("唯一机器权威", text)

    def test_cmake_registers_contract_test_as_governance_only(self) -> None:
        cmake = CMAKE_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"set_tests_properties\(business_first_common_repair_contract_test "
            r'PROPERTIES\s+LABELS "([^"]+)"',
            cmake,
        )
        self.assertIsNotNone(match)
        labels = set(match.group(1).split(";")) if match else set()
        self.assertEqual({"governance"}, labels)


if __name__ == "__main__":
    unittest.main()
