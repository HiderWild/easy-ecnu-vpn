"""反门禁回归：历史模型探索器不得参与生产或验收。"""

from __future__ import annotations

import importlib.util
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CMAKE_PATH = ROOT / "CMakeLists.txt"
EXPLORER_SOURCE = ROOT / "tests/common/runtime_v3_model_explorer_test.cpp"
MOCK_RECEIPT_PATH = ROOT / "contracts/runtime_v3/common_mock_scenarios.json"
COMMON_ACCEPTANCE_POLICY_PATH = (
    ROOT / "docs/superpowers/governance/common-native-acceptance-policy.json"
)
COMMON_ACCEPTANCE_POLICY_SCRIPT = ROOT / "scripts/common_acceptance_policy.py"
COMMON_FEATURE_INVENTORY_SCRIPT = (
    ROOT / "scripts/generate_common_feature_inventory.py"
)
COMMON_FEATURE_COVERAGE_SCHEMA = (
    ROOT / "contracts/runtime_v3/common_feature_coverage.schema.json"
)
POLICY_RELATIVE_PATH = (
    "docs/superpowers/governance/business-first-host-repair-policy.md"
)
MOCK_RECEIPT_TESTS = (
    "runtime_v3_common_mock_coverage_test",
    "runtime_v3_common_mock_conformance_test",
    "common_executed_receipt_gate_test",
)
GLOBAL_MODEL_PROOF_TERMS = (
    "common-model-gate",
    "model_gate",
    "model_explorer_workers",
    "semantic_equivalence",
    "canonical_model_digest",
    "serial_parallel_semantic_digest",
    "scenario_dimension_id_set",
    "embedded_in_memory_model",
)


def cmake_block(cmake: str, expression: str) -> str:
    match = re.search(expression, cmake, flags=re.DOTALL)
    if match is None:
        raise AssertionError(f"CMake block not found: {expression}")
    return match.group(0)


def leading_comment_block(source: str) -> str:
    lines = source.splitlines()
    comments: list[str] = []
    for line in lines:
        if line.startswith("//"):
            comments.append(line)
            continue
        if not line and comments:
            break
        raise AssertionError("explorer source must start with a pure comment block")
    return "\n".join(comments)


def trailing_comment_block(source: str) -> str:
    lines = source.rstrip().splitlines()
    comments: list[str] = []
    for line in reversed(lines):
        if line.startswith("//"):
            comments.append(line)
            continue
        if not line and comments:
            break
        raise AssertionError("explorer source must end with a pure comment block")
    return "\n".join(reversed(comments))


class RuntimeV3ModelExplorerRetirementPolicyTest(unittest.TestCase):
    def test_explorer_is_not_a_build_ctest_or_aggregate_member(self) -> None:
        cmake = CMAKE_PATH.read_text(encoding="utf-8")

        self.assertNotRegex(cmake, r"\bruntime_v3_model_explorer_test\b")
        self.assertNotIn("EXV_MODEL_EXPLORER_WORKERS", cmake)

    def test_explorer_edges_are_pure_factual_comments(self) -> None:
        source = EXPLORER_SOURCE.read_text(encoding="utf-8")
        required_facts = (
            "当前未接线",
            "非生产",
            "非验收",
            "BusinessFlowMachine 仍接线",
            POLICY_RELATIVE_PATH,
            "无固定删除期限",
            "重新接线后须重跑真实用户业务流",
            "不得解释为生产状态机已退役",
        )

        for edge in (leading_comment_block(source), trailing_comment_block(source)):
            with self.subTest(edge=edge.splitlines()[0]):
                for fact in required_facts:
                    self.assertIn(fact, edge)
                self.assertNotIn("#error", edge)
                self.assertNotIn("#warning", edge)

    def test_cleanup_is_only_a_maintenance_audit(self) -> None:
        cmake = CMAKE_PATH.read_text(encoding="utf-8")
        cleanup_properties = cmake_block(
            cmake,
            r"set_tests_properties\(runtime_v3_single_line_cleanup_contract_test"
            r"\s+PROPERTIES.*?\n\)",
        )
        self.assertRegex(
            cleanup_properties,
            r'LABELS\s+"maintenance-audit"',
        )
        self.assertNotIn("release-blocking", cleanup_properties)

        aggregate_blocks = re.findall(
            r"set\(_[A-Za-z0-9_]*(?:tests|test_targets)\b.*?\n\)",
            cmake,
            flags=re.DOTALL,
        )
        for block in aggregate_blocks:
            self.assertNotRegex(
                block,
                r"\bruntime_v3_single_line_cleanup_contract_test\b",
            )

    def test_retirement_policy_ctest_is_governance_only(self) -> None:
        cmake = CMAKE_PATH.read_text(encoding="utf-8")
        properties = cmake_block(
            cmake,
            r"set_tests_properties\(runtime_v3_model_explorer_source_policy_test"
            r"\s+PROPERTIES.*?\n\)",
        )
        self.assertRegex(properties, r'LABELS\s+"governance"')
        self.assertNotIn("release-blocking", properties)

        aggregate_blocks = re.findall(
            r"set\(_[A-Za-z0-9_]*(?:tests|test_targets)\b.*?\n\)",
            cmake,
            flags=re.DOTALL,
        )
        for block in aggregate_blocks:
            self.assertNotRegex(
                block,
                r"\bruntime_v3_model_explorer_source_policy_test\b",
            )

    def test_mock_receipt_is_module_only_non_host_and_non_release(self) -> None:
        receipt = json.loads(MOCK_RECEIPT_PATH.read_text(encoding="utf-8"))
        self.assertEqual("common_mock_module_only", receipt["receipt_scope"])
        self.assertIs(receipt["host_real_passed"], False)
        self.assertNotIn(
            "runtime_v3_model_explorer_test",
            {executor["test_target"] for executor in receipt["executors"]},
        )

        cmake = CMAKE_PATH.read_text(encoding="utf-8")
        release_aggregates = (
            cmake_block(
                cmake,
                r"set\(_common_runtime_decoupling_tests\b.*?\n\)",
            ),
            cmake_block(
                cmake,
                r"set\(_release_blocking_tests\b.*?\n\)",
            ),
        )
        for test_id in MOCK_RECEIPT_TESTS:
            with self.subTest(test_id=test_id):
                properties = cmake_block(
                    cmake,
                    rf"set_tests_properties\({test_id}\s+PROPERTIES.*?\n\)",
                )
                self.assertNotIn("release-blocking", properties)
                for block in release_aggregates:
                    self.assertNotRegex(block, rf"\b{re.escape(test_id)}\b")

        audit_target = cmake_block(
            cmake,
            r"add_custom_target\(exv_common_mock_module_audits\b.*?\n\)",
        )
        self.assertIn("-L module-audit", audit_target)
        self.assertNotIn("release-blocking", audit_target)
        self.assertNotIn("common-decoupling", audit_target)

    def test_module_receipt_reports_partial_local_coverage_without_global_proof(
        self,
    ) -> None:
        spec = importlib.util.spec_from_file_location(
            "common_feature_inventory_under_test",
            COMMON_FEATURE_INVENTORY_SCRIPT,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        inventory = module.generate_inventory(ROOT)

        self.assertGreater(inventory["summary"]["unassigned_dimension_count"], 0)
        self.assertNotIn("model-reducer-explorer", {
            executor["id"] for executor in inventory["executors"]
        })
        generator_source = COMMON_FEATURE_INVENTORY_SCRIPT.read_text(
            encoding="utf-8"
        )
        self.assertNotIn("COMMON_EXECUTOR_MISSING", generator_source)
        self.assertNotIn("model-reducer-explorer", generator_source)

        schema = json.loads(
            COMMON_FEATURE_COVERAGE_SCHEMA.read_text(encoding="utf-8")
        )
        unassigned_schema = schema["$defs"]["summary"]["properties"][
            "unassigned_dimension_count"
        ]
        self.assertEqual({"type": "integer", "minimum": 0}, unassigned_schema)

    def test_common_acceptance_policy_has_no_global_model_gate(self) -> None:
        policy = json.loads(
            COMMON_ACCEPTANCE_POLICY_PATH.read_text(encoding="utf-8")
        )
        policy_source = COMMON_ACCEPTANCE_POLICY_SCRIPT.read_text(encoding="utf-8")
        cmake = CMAKE_PATH.read_text(encoding="utf-8")
        serialized_policy = json.dumps(policy, sort_keys=True)

        for forbidden in GLOBAL_MODEL_PROOF_TERMS:
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized_policy)
                self.assertNotIn(forbidden, policy_source)
                self.assertNotIn(forbidden, cmake)

        profile = policy["module_profiles"]["common-only"]
        self.assertEqual(
            ["common-decoupling"],
            policy["test_discovery"]["module_labels"],
        )
        self.assertNotIn("model_explorer_workers", profile)

        spec = importlib.util.spec_from_file_location(
            "common_acceptance_policy_under_test",
            COMMON_ACCEPTANCE_POLICY_SCRIPT,
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.validate_policy(policy)
        descriptor = module.module_profile_descriptor(
            policy, "common-only", "win32"
        )
        self.assertNotIn("model_explorer_workers", descriptor)


if __name__ == "__main__":
    unittest.main()
