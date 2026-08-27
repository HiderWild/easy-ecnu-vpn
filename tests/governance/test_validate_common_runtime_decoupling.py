from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-common-runtime-decoupling.py"
SPEC = importlib.util.spec_from_file_location("common_decoupling_guard", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class CommonRuntimeDecouplingGuardTest(unittest.TestCase):
    def test_repository_passes_all_source_and_dependency_guards(self) -> None:
        self.assertEqual([], GUARD.validate_repository(ROOT))

    def test_native_include_and_os_policy_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "src/common/runtime_v3/policy.cpp"
            path.parent.mkdir(parents=True)
            path.write_text(
                '#include <windows.h>\n#if defined(_WIN32)\n#endif\n',
                encoding="utf-8",
            )
            violations = GUARD.validate_semantic_sources(root)
            self.assertTrue(
                any(item.startswith("COMMON_NATIVE_INCLUDE:") for item in violations)
            )
            self.assertTrue(
                any(item.startswith("COMMON_OS_POLICY:") for item in violations)
            )

    def test_private_model_storage_leak_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "src/core/leak.cpp"
            path.parent.mkdir(parents=True)
            path.write_text(
                '#include "generated/runtime_v3_embedded_model.hpp"\n',
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    item.startswith("COMMON_MODEL_STORAGE_LEAK:")
                    for item in GUARD.validate_private_model_storage(root)
                )
            )

    def test_manual_action_route_predicate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "src/app/ui_shell/router.cpp"
            path.parent.mkdir(parents=True)
            path.write_text(
                "bool is_v3_product_action(std::string_view);\n",
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    item.startswith("COMMON_MANUAL_ACTION_ROUTE:")
                    for item in GUARD.validate_generated_routing(root)
                )
            )

    def make_graph_fixture(self, directory: str, mutation: str = "") -> Path:
        root = Path(directory)
        sources = {
            "src/common/provider.cpp": "int provider() { return 1; }\n",
            "src/common/business.cpp": "int business() { return 1; }\n",
            "src/common/business_flow_machine.cpp": (
                "int reducer_state_machine() { return 1; }\n"
            ),
            "src/helper/helper.cpp": "int helper() { return 1; }\n",
            "src/platform/darwin/native.cpp": "int native() { return 1; }\n",
            "tests/support/mock_runtime.cpp": "int mock_runtime() { return 1; }\n",
            "lib/hidden_policy.cpp": "int hidden_policy() { return 1; }\n",
        }
        for relative, content in sources.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        (root / "CMakeLists.txt").write_text(
            f"""
cmake_minimum_required(VERSION 3.28)
project(common_graph_fixture LANGUAGES CXX)
add_library(exv-runtime-v3-provider-contract STATIC src/common/provider.cpp)
add_library(exv-business-flow-v3 STATIC src/common/business.cpp)
target_link_libraries(exv-business-flow-v3 PUBLIC
    exv-runtime-v3-provider-contract)
add_library(exv-helper-runtime STATIC src/helper/helper.cpp)
target_link_libraries(exv-helper-runtime PUBLIC
    exv-runtime-v3-provider-contract)
{mutation}
""",
            encoding="utf-8",
        )
        return root

    def assert_graph_rejects(self, mutation: str, reason: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_graph_fixture(directory, mutation)
            violations = GUARD.validate_cmake_boundary(root)
            self.assertTrue(
                any(item.startswith(reason) for item in violations),
                violations,
            )

    def test_legal_resolved_graph_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_graph_fixture(directory)
            self.assertEqual([], GUARD.validate_cmake_boundary(root))

    def test_direct_and_target_sources_platform_injection_are_rejected(
        self,
    ) -> None:
        self.assert_graph_rejects(
            """
target_sources(exv-business-flow-v3 PRIVATE
    src/platform/darwin/native.cpp)
""",
            "COMMON_PRODUCTION_TEST_OR_PLATFORM_LINK:",
        )

    def test_object_library_injection_is_rejected(self) -> None:
        self.assert_graph_rejects(
            """
add_library(platform_object OBJECT src/platform/darwin/native.cpp)
target_link_libraries(exv-business-flow-v3 PRIVATE platform_object)
""",
            "COMMON_PRODUCTION_TEST_OR_PLATFORM_LINK:",
        )

    def test_interface_transitive_platform_link_is_rejected(self) -> None:
        self.assert_graph_rejects(
            """
add_library(platform_native STATIC src/platform/darwin/native.cpp)
add_library(platform_interface INTERFACE)
target_link_libraries(platform_interface INTERFACE platform_native)
target_link_libraries(exv-business-flow-v3 PRIVATE platform_interface)
""",
            "COMMON_PRODUCTION_TEST_OR_PLATFORM_LINK:",
        )

    def test_generator_expression_selected_source_is_rejected(self) -> None:
        self.assert_graph_rejects(
            """
target_sources(exv-business-flow-v3 PRIVATE
    "$<1:${CMAKE_CURRENT_SOURCE_DIR}/src/platform/darwin/native.cpp>")
""",
            "COMMON_PRODUCTION_TEST_OR_PLATFORM_LINK:",
        )

    def test_mock_hidden_behind_alias_is_rejected(self) -> None:
        self.assert_graph_rejects(
            """
add_library(hidden_mock STATIC tests/support/mock_runtime.cpp)
add_library(mock_alias ALIAS hidden_mock)
target_link_libraries(exv-business-flow-v3 PRIVATE mock_alias)
""",
            "COMMON_PRODUCTION_TEST_OR_PLATFORM_LINK:",
        )

    def test_os_policy_outside_old_scan_scope_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_graph_fixture(
                directory,
                """
target_sources(exv-business-flow-v3 PRIVATE lib/hidden_policy.cpp)
""",
            )
            (root / "lib/hidden_policy.cpp").write_text(
                "#if defined(__APPLE__)\nint policy() { return 1; }\n#endif\n",
                encoding="utf-8",
            )
            violations = GUARD.validate_cmake_boundary(root)
            self.assertTrue(
                any(
                    item.startswith("COMMON_OS_POLICY_GRAPH:")
                    for item in violations
                ),
                violations,
            )

    def test_privileged_helper_cannot_link_product_reducer(self) -> None:
        self.assert_graph_rejects(
            """
target_link_libraries(exv-helper-runtime PRIVATE exv-business-flow-v3)
""",
            "COMMON_HELPER_PRODUCT_REDUCER_LINK:",
        )

    def test_narrow_provider_cannot_absorb_reducer_source(self) -> None:
        self.assert_graph_rejects(
            """
target_sources(exv-runtime-v3-provider-contract PRIVATE
    src/common/business_flow_machine.cpp)
""",
            "COMMON_PROVIDER_SEMANTIC_SOURCE:",
        )


if __name__ == "__main__":
    unittest.main()
