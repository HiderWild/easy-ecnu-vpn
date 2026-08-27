from __future__ import annotations

import importlib.util
import inspect
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/run_common_native_acceptance.py"
POLICY_SCRIPT = ROOT / "scripts/common_acceptance_policy.py"
POLICY_JSON = ROOT / "docs/superpowers/governance/common-native-acceptance-policy.json"
CMAKE = ROOT / "CMakeLists.txt"
SPEC = importlib.util.spec_from_file_location("run_common_native_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def cmake_invocation(source: str, opening: str) -> str:
    start = source.index(opening)
    end = source.index("\n)", start) + 2
    return source[start:end]


class CommonNativeModuleRunnerTest(unittest.TestCase):
    def test_native_jobs_are_bounded_to_one_through_eight(self) -> None:
        self.assertEqual(1, RUNNER.validate_jobs(1))
        self.assertEqual(8, RUNNER.validate_jobs(8))
        for invalid in (0, -1, 9, 64):
            with self.subTest(invalid=invalid):
                with self.assertRaises(RUNNER.NativeAcceptanceError):
                    RUNNER.validate_jobs(invalid)

    def test_default_jobs_use_host_count_with_eight_core_cap(self) -> None:
        self.assertEqual(1, RUNNER.default_jobs(0))
        self.assertEqual(4, RUNNER.default_jobs(4))
        self.assertEqual(8, RUNNER.default_jobs(20))

    def test_runner_has_no_frozen_candidate_or_attestation_requirement(self) -> None:
        args = RUNNER.build_parser().parse_args(
            [
                "--host",
                "win32",
                "--profile",
                "common-only",
                "--build-dir",
                "build-test",
            ]
        )
        self.assertIsNone(args.output)
        self.assertFalse(hasattr(args, "with_webui"))
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("require_frozen_worktree", source)
        self.assertNotIn("awaiting_other_platform_acceptance", source)

    def test_common_only_profile_drives_host_specific_cmake_definitions(self) -> None:
        parameters = inspect.signature(RUNNER.cmake_configure_command).parameters
        self.assertIn("host", parameters)
        self.assertIn("profile", parameters)
        self.assertIn("policy", parameters)
        policy = RUNNER.POLICY_MODULE.load_policy()
        root = Path("C:/source")
        build = Path("C:/build")
        python = Path("C:/python/python.exe")
        win32 = RUNNER.cmake_configure_command(
            root,
            build,
            python,
            host="win32",
            profile="common-only",
            policy=policy,
        )
        darwin = RUNNER.cmake_configure_command(
            root,
            build,
            python,
            host="darwin",
            profile="common-only",
            policy=policy,
        )
        self.assertIn("-DEXV_BUILD_WINDOWS_SETUP=OFF", win32)
        self.assertNotIn("-DEXV_BUILD_WINDOWS_SETUP=OFF", darwin)
        self.assertIn("-DCMAKE_BUILD_TYPE=Release", win32)
        self.assertIn("-DCMAKE_BUILD_TYPE=Release", darwin)

    def test_common_commands_build_and_run_local_module_tests(self) -> None:
        build = Path("C:/build")
        build_command, test_command = RUNNER.common_module_commands(build, 8)
        self.assertEqual(
            [
                "cmake",
                "--build",
                str(build),
                "--target",
                "exv_common_module_test_targets",
                "-j",
                "8",
            ],
            build_command,
        )
        self.assertEqual(
            [
                "ctest",
                "--test-dir",
                str(build),
                "--output-on-failure",
                "-L",
                "common-decoupling",
                "--parallel",
                "1",
            ],
            test_command,
        )

    def test_retired_model_and_host_acceptance_paths_are_absent(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for retired in (
            "EXV_MODEL_EXPLORER_WORKERS",
            "runtime_v3_model_explorer",
            "common-model-gate",
            "model_gate",
            "validate_model_gate_discovery",
            "model_gate_execution_verdict",
            "exv_release_blocking_tests",
            "release-blocking",
            "native-consumer-build",
            "--with-webui",
            "verify_packaged_contract_coherence.py",
            "COMMON_NATIVE_ACCEPTANCE_PASSED",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, source)
        self.assertFalse(hasattr(RUNNER, "native_execution_environment"))
        self.assertFalse(hasattr(RUNNER, "native_gate_commands"))

    def test_every_policy_component_is_an_actual_module_check(self) -> None:
        policy = RUNNER.POLICY_MODULE.load_policy()
        descriptor = RUNNER.POLICY_MODULE.module_profile_descriptor(
            policy, "common-only", "win32"
        )
        generator_components = [
            name for name, _ in RUNNER.COMMON_GENERATOR_CHECKS
        ]
        self.assertEqual(
            [*generator_components, "common-decoupling"],
            descriptor["module_components"],
        )

    def test_module_summary_is_explicitly_non_host_and_complete(self) -> None:
        policy = RUNNER.POLICY_MODULE.load_policy()
        descriptor = RUNNER.POLICY_MODULE.module_profile_descriptor(
            policy, "common-only", "win32"
        )
        results = [
            {"name": component, "component": component, "return_code": 0}
            for component in descriptor["module_components"]
        ]
        test_sets = {
            "common-decoupling": RUNNER.POLICY_MODULE.observe_test_set(
                ["local-common-contract-test"]
            )
        }
        summary = RUNNER.module_check_summary(
            host="win32",
            descriptor=descriptor,
            test_sets=test_sets,
            command_results=results,
        )
        self.assertEqual("common_native_module_checks", summary["evidence_kind"])
        self.assertEqual("module_checks_passed", summary["status"])
        self.assertEqual("common_mock_module_only", summary["receipt_scope"])
        self.assertIs(summary["host_real_passed"], False)
        self.assertEqual(
            descriptor["module_components"], summary["module_components"]
        )
        with self.assertRaises(RUNNER.NativeAcceptanceError):
            RUNNER.module_check_summary(
                host="win32",
                descriptor=descriptor,
                test_sets=test_sets,
                command_results=results[:-1],
            )

    def test_module_policy_has_no_candidate_or_identity_prerequisites(self) -> None:
        policy = json.loads(POLICY_JSON.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                "schema_version",
                "policy_kind",
                "module_profiles",
                "test_discovery",
                "timing_policy",
            },
            set(policy),
        )
        source = POLICY_SCRIPT.read_text(encoding="utf-8")
        for retired in (
            "candidate_identity",
            "strict_identities",
            "change_invalidation",
            "evidence_reuse",
            "toolchains",
            "commit_trailer_required",
            "read_common_change_kind_and_affected_hosts",
            "check-version",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, source)
                self.assertNotIn(retired, POLICY_JSON.read_text(encoding="utf-8"))

    def test_changed_paths_are_observations_without_required_actions(self) -> None:
        policy = RUNNER.POLICY_MODULE.load_policy()
        observed = RUNNER.POLICY_MODULE.classify_changed_paths(
            policy, ["CMakeLists.txt"]
        )
        self.assertEqual("change_observed", observed["classification"])
        self.assertIs(observed["development_ok"], True)
        self.assertIs(observed["host_real_passed"], False)
        self.assertEqual([], observed["affected_hosts"])
        self.assertNotIn("required_action", observed)
        self.assertFalse(any("required" in key for key in observed))

        completed = subprocess.run(
            [
                str(Path(RUNNER.sys.executable)),
                str(POLICY_SCRIPT),
                "classify-paths",
                "CMakeLists.txt",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(observed, json.loads(completed.stdout))

    def test_empty_path_cli_reports_no_change_without_blocking(self) -> None:
        completed = subprocess.run(
            [
                str(Path(RUNNER.sys.executable)),
                str(POLICY_SCRIPT),
                "classify-paths",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(
            {
                "affected_hosts": [],
                "classification": "no_change",
                "development_ok": True,
                "host_real_passed": False,
                "paths": [],
            },
            json.loads(completed.stdout),
        )

    def test_cmake_exposes_build_only_module_target_and_governance_only_test(self) -> None:
        source = CMAKE.read_text(encoding="utf-8")
        build_only = cmake_invocation(
            source, "add_custom_target(exv_common_module_test_targets"
        )
        self.assertIn("DEPENDS ${_common_runtime_decoupling_test_targets}", build_only)
        self.assertNotIn("COMMAND", build_only)
        aggregate = cmake_invocation(
            source, "add_custom_target(exv_common_runtime_decoupling_tests"
        )
        self.assertIn("DEPENDS exv_common_module_test_targets", aggregate)
        properties = cmake_invocation(
            source,
            "set_tests_properties(common_native_acceptance_runner_test PROPERTIES",
        )
        self.assertIn('LABELS "governance"', properties)
        self.assertNotIn("release-blocking", properties)
        self.assertNotIn("architecture", properties)

    def test_cli_requires_the_common_only_profile(self) -> None:
        parser = RUNNER.build_parser()
        required = [
            "--host",
            "win32",
            "--build-dir",
            "C:/build",
            "--output",
            "C:/evidence.json",
        ]
        with self.assertRaises(SystemExit):
            parser.parse_args(required)
        args = parser.parse_args(["--profile", "common-only", *required])
        self.assertEqual("common-only", args.profile)
        with self.assertRaises(SystemExit):
            parser.parse_args(["--profile", "platform-campaign", *required])

    def test_doctor_parser_requires_mutation_and_dependency_availability(self) -> None:
        document = {
            "ok": True,
            "result": {
                "capabilities": {"read": True, "mutate": True},
                "dependencies": [
                    {"name": "jsonschema", "available": True},
                    {"name": "jsonpatch", "available": False},
                ],
            },
        }
        parsed, available = RUNNER.parse_doctor_document(json.dumps(document))
        self.assertEqual(document, parsed)
        self.assertEqual({"jsonschema"}, available)
        document["result"]["capabilities"]["mutate"] = False
        with self.assertRaises(RUNNER.NativeAcceptanceError):
            RUNNER.parse_doctor_document(json.dumps(document))

    def test_cached_python_finds_public_and_internal_cmake_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "CMakeCache.txt"
            cache.write_text(
                "Python3_EXECUTABLE:UNINITIALIZED=/qualified/python\n"
                "_Python3_EXECUTABLE:INTERNAL=/qualified/python\n"
                "SOMETHING_ELSE:FILEPATH=/old/python\n",
                encoding="utf-8",
            )
            self.assertEqual(["/qualified/python"], RUNNER.cached_python_values(cache))

    def test_ctest_identity_uses_test_names_and_rejects_malformed_entries(self) -> None:
        self.assertEqual(
            ["second", "first"],
            RUNNER.extract_ctest_ids(
                {"tests": [{"name": "second"}, {"name": "first"}]}
            ),
        )
        with self.assertRaises(RUNNER.NativeAcceptanceError):
            RUNNER.extract_ctest_ids({"tests": [{"command": ["missing-name"]}]})

    def test_command_output_decoding_is_total_for_mixed_windows_bytes(self) -> None:
        self.assertEqual("ok\ufffd", RUNNER.decode_output(b"ok\xff"))

    def test_command_result_renders_unicode_on_a_strict_gbk_console(self) -> None:
        output_bytes = io.BytesIO()
        output = io.TextIOWrapper(
            output_bytes, encoding="gbk", errors="strict", newline=""
        )
        completed = subprocess.CompletedProcess(
            args=["unicode-tool"],
            returncode=0,
            stdout="left\u2009right".encode("utf-8"),
            stderr=b"",
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            RUNNER.subprocess, "run", return_value=completed
        ), mock.patch.object(RUNNER.sys, "stdout", output):
            observed, result = RUNNER.command_result(
                ["unicode-tool"],
                cwd=Path(directory),
                environment={},
                name="unicode-output",
            )

        output.flush()
        self.assertEqual("left\u2009right", observed.stdout)
        self.assertEqual(0, result["return_code"])
        self.assertIn(r"left\u2009right", output_bytes.getvalue().decode("gbk"))

    def test_command_result_names_process_start_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            RUNNER.subprocess,
            "run",
            side_effect=FileNotFoundError(2, "missing executable"),
        ):
            with self.assertRaisesRegex(
                RUNNER.NativeAcceptanceError,
                r"common-decoupling-build.*missing-tool",
            ):
                RUNNER.command_result(
                    ["missing-tool", "argument"],
                    cwd=Path(directory),
                    environment={},
                    name="common-decoupling-build",
                )


if __name__ == "__main__":
    unittest.main()
