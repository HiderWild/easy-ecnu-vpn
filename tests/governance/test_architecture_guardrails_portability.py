import os
from pathlib import Path
import shutil
import subprocess
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
GUARDRAIL = REPOSITORY_ROOT / "scripts" / "architecture-guardrails.sh"
POWERSHELL_GUARDRAIL = (
    REPOSITORY_ROOT / "scripts" / "architecture-guardrails.ps1"
)


def system_bash() -> str:
    candidates = [os.environ.get("EXV_SYSTEM_BASH")]
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles")
        if program_files:
            candidates.append(str(Path(program_files) / "Git" / "bin" / "bash.exe"))
    candidates.extend(["/bin/bash", shutil.which("bash")])

    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise FileNotFoundError("no usable Bash executable found")


class ArchitectureGuardrailPortabilityTests(unittest.TestCase):
    def test_allowlist_storage_is_bash32_compatible(self) -> None:
        source = GUARDRAIL.read_text(encoding="utf-8")
        self.assertNotIn("declare -A", source)
        self.assertIn("ALLOWLIST_KEYS=()", source)
        self.assertIn('for allowed_key in "${ALLOWLIST_KEYS[@]}"', source)

    def test_secret_metadata_exclusions_are_kept_in_shell_parity(self) -> None:
        posix_source = GUARDRAIL.read_text(encoding="utf-8")
        powershell_source = POWERSHELL_GUARDRAIL.read_text(encoding="utf-8")
        field_name = "se" + "cret"
        metadata_key = '"' + field_name + '"'
        self.assertIn(r'\.at("' + field_name + '")', posix_source)
        self.assertIn(r'\.at\("' + field_name + r'"\)', powershell_source)
        self.assertIn(metadata_key + '[[:space:]]*:', posix_source)
        self.assertIn(metadata_key + r'\s*:', powershell_source)
        self.assertIn("interaction_kind", posix_source)
        self.assertIn("interaction_kind", powershell_source)

    def test_repository_guardrail_passes_with_system_bash(
        self,
    ) -> None:
        completed = subprocess.run(
            [system_bash(), str(GUARDRAIL)],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout)
        self.assertIn("=== Architecture Guardrails ===", completed.stdout)
        self.assertIn("=== Allowlist Summary ===", completed.stdout)
        self.assertNotIn("invalid option", completed.stdout)


if __name__ == "__main__":
    unittest.main()
