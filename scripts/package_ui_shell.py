#!/usr/bin/env python3
"""Build a native WebView shell package layout without Electron payloads."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MINGW_RUNTIME_DLLS = [
    "libgcc_s_seh-1.dll",
    "libstdc++-6.dll",
    "libwinpthread-1.dll",
]
PACKAGE_BINARIES = ("exv", "exv-helper")
WINDOWS_REQUIRED_RUNTIME_DLLS = ["wintun.dll"]
WINDOWS_PACKAGE_DEPENDENCIES = REPO_ROOT / "distribution" / "windows" / "package-dependencies.json"
WINDOWS_PE_IMPORT_INSPECTOR = REPO_ROOT / "scripts" / "windows_pe_imports.py"
WINDOWS_PE_INSPECTOR_TIMEOUT_SECONDS = 45
APP_ICON_ASSETS = ["icon.ico", "icon.icns", "icon.png", "icon.svg"]
_WINDOWS_DEPENDENCY_METADATA: dict | None = None


def normalized_platform(value: str | None = None) -> str:
    raw = (value or sys.platform).lower()
    if raw.startswith("win") or raw == "windows":
        return "windows"
    if raw == "darwin" or raw == "mac" or raw == "macos":
        return "macos"
    if raw.startswith("linux"):
        return "linux"
    return raw


MACOS_BUNDLE_NAME = "EXV"
MACOS_BUNDLE_IDENTIFIER = "com.exv.app"
MACOS_BUNDLE_EXECUTABLE = "EXV"
MACOS_BUNDLE_INFO_PLIST_KEYS = (
    "CFBundleName",
    "CFBundleIdentifier",
    "CFBundleVersion",
    "CFBundleShortVersionString",
)


def executable_name(stem: str, platform: str) -> str:
    return f"{stem}.exe" if platform == "windows" else stem


def first_existing(paths: list[Path], name: str) -> Path:
    for path in paths:
        if path.exists():
            return path
    checked = "\n  - ".join(str(path) for path in paths)
    raise SystemExit(f"{name} not found. Checked:\n  - {checked}")


def windows_dependency_metadata() -> dict:
    global _WINDOWS_DEPENDENCY_METADATA
    if _WINDOWS_DEPENDENCY_METADATA is None:
        try:
            _WINDOWS_DEPENDENCY_METADATA = json.loads(
                WINDOWS_PACKAGE_DEPENDENCIES.read_text(encoding="utf-8")
            )
        except OSError as exc:
            raise SystemExit(
                f"Windows package dependency metadata not found: {WINDOWS_PACKAGE_DEPENDENCIES}"
            ) from exc
        if _WINDOWS_DEPENDENCY_METADATA.get("schema") != 1:
            raise SystemExit(
                "Unsupported Windows package dependency metadata schema: "
                f"{_WINDOWS_DEPENDENCY_METADATA.get('schema')!r}"
            )
    return _WINDOWS_DEPENDENCY_METADATA


def windows_dependency(name: str) -> dict:
    dependencies = windows_dependency_metadata().get("dependencies", {})
    dependency = dependencies.get(name)
    if not isinstance(dependency, dict):
        raise SystemExit(f"Windows package dependency metadata missing: {name}")
    return dependency


def repo_relative_metadata_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_declared_file(path: Path, expected_sha256: str, label: str) -> Path:
    if not path.is_file():
        raise SystemExit(f"{label} not found: {path}")
    actual = sha256_file(path)
    expected = expected_sha256.lower()
    if actual.lower() != expected:
        raise SystemExit(
            f"{label} SHA-256 mismatch: expected {expected}, got {actual} at {path}"
        )
    return path


def validate_webview2_loader_dll(path: Path) -> Path:
    dependency = windows_dependency("webview2")
    payload = dependency["payloads"]["loaderDll"]
    return validate_declared_file(path, payload["sha256"], "WebView2Loader.dll")


def validate_wintun_dll(path: Path, label: str = "wintun.dll") -> Path:
    dependency = windows_dependency("wintun")
    payload = dependency["payloads"]["dll"]
    return validate_declared_file(path, payload["sha256"], label)


def default_cpp_build_dirs(platform: str) -> list[Path]:
    candidates: list[Path] = []
    if os.environ.get("EXV_CPP_BUILD_DIR"):
        candidates.append(Path(os.environ["EXV_CPP_BUILD_DIR"]))
    candidates.extend(
        [
            REPO_ROOT / "build" / platform / "cpp",
            REPO_ROOT / "build-windows" / "cpp",
            REPO_ROOT / "build",
        ]
    )
    return candidates


def default_renderer_candidates(platform: str) -> list[Path]:
    if os.environ.get("EXV_RENDERER_DIST_DIR"):
        return [Path(os.environ["EXV_RENDERER_DIST_DIR"])]
    return [
        REPO_ROOT / "build" / platform / "webview" / "dist",
        REPO_ROOT / "webui" / "dist",
    ]


def runtime_search_dirs(platform: str) -> list[Path]:
    candidates: list[Path] = []
    if os.environ.get("EXV_RUNTIME_DIR"):
        candidates.append(Path(os.environ["EXV_RUNTIME_DIR"]))
    candidates.extend(default_cpp_build_dirs(platform))
    if platform == "windows":
        candidates.extend(
            [
                REPO_ROOT / "runtime" / "win32-x64",
                REPO_ROOT / "runtime" / "win32",
                REPO_ROOT / "runtime" / "windows",
            ]
        )
        candidates.extend(Path(entry) for entry in os.environ.get("PATH", "").split(os.pathsep) if entry)
    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            normalized = candidate.resolve() if candidate.exists() else candidate
        except OSError:
            continue
        if normalized not in seen:
            unique.append(candidate)
            seen.add(normalized)
    return unique


def copy_tree_contents(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for entry in source.iterdir():
        destination = target / entry.name
        if entry.is_dir():
            shutil.copytree(entry, destination, dirs_exist_ok=True)
        else:
            shutil.copy2(entry, destination)


def find_binary(stem: str, platform: str) -> Path:
    name = executable_name(stem, platform)
    return first_existing(
        [candidate / name for candidate in default_cpp_build_dirs(platform)],
        f"{stem} executable",
    )


def find_webview2_loader(platform: str) -> Path | None:
    if platform != "windows":
        return None
    if os.environ.get("EXV_WEBVIEW2_LOADER_DLL"):
        return validate_webview2_loader_dll(Path(os.environ["EXV_WEBVIEW2_LOADER_DLL"]))
    return validate_webview2_loader_dll(first_existing(
        [candidate / "WebView2Loader.dll" for candidate in default_cpp_build_dirs(platform)],
        "WebView2Loader.dll",
    ))


def find_runtime_asset(name: str, platform: str) -> Path | None:
    for directory in runtime_search_dirs(platform):
        candidate = directory / name
        try:
            if candidate.exists():
                return candidate
        except OSError:
            continue
    return None


def find_declared_wintun_dll() -> Path:
    dependency = windows_dependency("wintun")
    if os.environ.get("EXV_WINTUN_DLL"):
        return validate_wintun_dll(Path(os.environ["EXV_WINTUN_DLL"]), "EXV_WINTUN_DLL")
    if os.environ.get("EXV_RUNTIME_DIR"):
        return validate_wintun_dll(
            Path(os.environ["EXV_RUNTIME_DIR"]) / "wintun.dll",
            "EXV_RUNTIME_DIR wintun.dll",
        )
    return validate_wintun_dll(
        repo_relative_metadata_path(dependency["installPath"]),
        "Declared Wintun DLL",
    )


def detect_project_version(platform: str) -> str:
    """Resolve the product version (e.g. 3.3.3) for the built binaries.

    Priority:
      1. EXV_PRODUCT_VERSION environment override.
      2. CMAKE_PROJECT_VERSION:STATIC in the CMake build cache.
      3. `exv --version` output from the built core binary.
    """
    override = os.environ.get("EXV_PRODUCT_VERSION", "").strip()
    if override:
        return override

    for build_dir in default_cpp_build_dirs(platform):
        cache = build_dir / "CMakeCache.txt"
        if not cache.is_file():
            continue
        for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("CMAKE_PROJECT_VERSION:STATIC="):
                value = line.split("=", 1)[1].strip()
                if value:
                    return value

    exv_path = find_binary("exv", platform)
    try:
        output = subprocess.check_output(
            [str(exv_path), "--version"], stderr=subprocess.STDOUT, text=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(
            f"Unable to detect product version from CMakeCache or `exv --version`: {exc}"
        )
    match = re.search(r"\d+\.\d+\.\d+", output)
    if not match:
        raise SystemExit(f"Unable to parse version from `exv --version`: {output!r}")
    return match.group(0)


def info_plist_contents(version: str) -> str:
    """Render a minimal macOS app bundle Info.plist."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>{MACOS_BUNDLE_NAME}</string>
  <key>CFBundleDisplayName</key>
  <string>{MACOS_BUNDLE_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>{MACOS_BUNDLE_IDENTIFIER}</string>
  <key>CFBundleExecutable</key>
  <string>{MACOS_BUNDLE_EXECUTABLE}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>{version}</string>
  <key>CFBundleVersion</key>
  <string>{version}</string>
  <key>CFBundleIconFile</key>
  <string>icon.icns</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
</dict>
</plist>
"""


def verify_app_icon_assets() -> None:
    icon_dir = REPO_ROOT / "assets" / "icons"
    missing = [name for name in APP_ICON_ASSETS if not (icon_dir / name).is_file()]
    if missing:
        raise SystemExit(
            "App icon asset(s) missing from assets/icons: " + ", ".join(missing)
        )


def run_windows_job_command(
    command: list[str],
    timeout_seconds: int,
    cwd: Path,
) -> tuple[int, str, bool]:
    support_path = Path(__file__).with_name("windows_pe_imports.py")
    spec = importlib.util.spec_from_file_location(
        "_exv_windows_job_support",
        support_path,
    )
    if spec is None or spec.loader is None:
        raise OSError(f"unable to load Windows Job support: {support_path}")
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    return support.run_windows_job_command(command, timeout_seconds, cwd)


def inspect_windows_pe_imports(
    binary: Path,
    timeout_seconds: int = WINDOWS_PE_INSPECTOR_TIMEOUT_SECONDS,
) -> set[str]:
    command = [sys.executable, str(WINDOWS_PE_IMPORT_INSPECTOR), str(binary)]
    if os.name == "nt":
        try:
            return_code, output, timed_out = run_windows_job_command(
                command,
                timeout_seconds,
                REPO_ROOT,
            )
        except OSError as exc:
            raise SystemExit(
                f"PE_IMPORT_INSPECTION_FAILED: unable to inspect {binary}: {exc}"
            ) from exc
        completed = subprocess.CompletedProcess(
            command,
            return_code,
            stdout=output,
            stderr="",
        )
    else:
        try:
            completed = subprocess.run(
                command,
                cwd=REPO_ROOT,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout_seconds,
                start_new_session=True,
            )
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            raise SystemExit(
                "PE_IMPORT_INSPECTION_FAILED: PE_IMPORT_INSPECTION_TIMEOUT: "
                f"inspector exceeded {timeout_seconds} seconds for {binary}"
            ) from exc
    if timed_out:
        raise SystemExit(
            "PE_IMPORT_INSPECTION_FAILED: PE_IMPORT_INSPECTION_TIMEOUT: "
            f"inspector exceeded {timeout_seconds} seconds for {binary}"
        )
    if completed.returncode != 0:
        detail = (completed.stdout + completed.stderr).strip()
        raise SystemExit(
            f"PE_IMPORT_INSPECTION_FAILED: unable to inspect {binary}: {detail}"
        )
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"PE_IMPORT_INSPECTION_FAILED: invalid inspector JSON for {binary}"
        ) from exc
    if (
        not isinstance(parsed, list)
        or not parsed
        or any(not isinstance(name, str) or not name.lower().endswith(".dll") for name in parsed)
    ):
        raise SystemExit(
            f"PE_IMPORT_INSPECTION_FAILED: invalid import inventory for {binary}"
        )
    return {name.casefold() for name in parsed}


def windows_package_binary_paths(package_dir: Path) -> tuple[Path, ...]:
    return (
        package_dir / "exv-ui.exe",
        package_dir / "bin" / "exv.exe",
        package_dir / "bin" / "exv-helper.exe",
    )


def windows_mingw_runtime_requirements(package_dir: Path) -> dict[Path, set[str]]:
    mingw_names = {name.casefold() for name in MINGW_RUNTIME_DLLS}
    requirements: dict[Path, set[str]] = {}
    for binary in windows_package_binary_paths(package_dir):
        imported = inspect_windows_pe_imports(binary)
        requirements.setdefault(binary.parent, set()).update(imported & mingw_names)
    return requirements


def copy_windows_runtime_assets(package_dir: Path) -> None:
    if not package_dir.exists():
        return
    bin_dir = package_dir / "bin"
    runtime_requirements = windows_mingw_runtime_requirements(package_dir)
    for destination_dir, imported_runtimes in runtime_requirements.items():
        for dll in MINGW_RUNTIME_DLLS:
            destination = destination_dir / dll
            if dll.casefold() not in imported_runtimes:
                if destination.exists():
                    raise SystemExit(
                        "Unimported MinGW runtime DLL present beside packaged "
                        f"binary: {destination}"
                    )
                continue
            source = find_runtime_asset(dll, "windows")
            if source is None:
                checked = "\n  - ".join(
                    str(path / dll) for path in runtime_search_dirs("windows")
                )
                raise SystemExit(
                    f"Imported MinGW runtime {dll} not found. Checked:\n  - {checked}"
                )
            shutil.copy2(source, destination)

    for dll in WINDOWS_REQUIRED_RUNTIME_DLLS:
        source = find_declared_wintun_dll() if dll == "wintun.dll" else find_runtime_asset(dll, "windows")
        if source is None:
            raise SystemExit(f"{dll} not found in declared Windows package dependencies")
        shutil.copy2(source, package_dir / dll)
        shutil.copy2(source, bin_dir / dll)


def validate_windows_package_vendor_payloads(package_dir: Path) -> None:
    if not package_dir.exists():
        return
    validate_webview2_loader_dll(package_dir / "WebView2Loader.dll")
    validate_wintun_dll(package_dir / "wintun.dll", "Packaged wintun.dll")
    validate_wintun_dll(package_dir / "bin" / "wintun.dll", "Packaged bin/wintun.dll")
    runtime_requirements = windows_mingw_runtime_requirements(package_dir)
    missing_runtime: list[str] = []
    surplus_runtime: list[str] = []
    for directory, imported_runtimes in runtime_requirements.items():
        for dll in MINGW_RUNTIME_DLLS:
            relative = (directory / dll).relative_to(package_dir).as_posix()
            present = (directory / dll).is_file()
            required = dll.casefold() in imported_runtimes
            if required and not present:
                missing_runtime.append(relative)
            elif present and not required:
                surplus_runtime.append(relative)
    if missing_runtime:
        raise SystemExit(
            "Imported MinGW runtime DLL(s) missing from package: "
            + ", ".join(missing_runtime)
        )
    if surplus_runtime:
        raise SystemExit(
            "Unimported MinGW runtime DLL(s) present in package: "
            + ", ".join(surplus_runtime)
        )


def assert_no_electron_payload(package_dir: Path) -> None:
    forbidden = ["electron.exe", "Electron Framework.framework", "chromium.pak"]
    found = [name for name in forbidden if list(package_dir.rglob(name))]
    if found:
        raise SystemExit(f"Electron/Chromium payload found: {', '.join(found)}")


def strip_crossorigin_for_file_protocol(webui_dir: Path) -> None:
    """Strip `crossorigin` attributes from the packaged webui's
    index.html so the Vite ES-module bundle executes under a file://
    origin.

    Vite emits `<script type="module" crossorigin src="./assets/...">`
    and `<link rel="modulepreload" crossorigin href="...">` by default.
    Under HTTP these are harmless, but under a file:// origin (the
    only load path our offline WKWebView/WebView2 bundles use) the
    `crossorigin` attribute flips each subresource into CORS mode,
    and WebKit/WPE treat every file:// URL as a distinct origin — so
    the module fetch is rejected by the same-origin policy and the
    bundle never executes. The failure is silent: the page reports
    `readyState: complete`, `#app` stays empty, and no console error
    is emitted.

    We only rewrite the bundled copy under `webui_dir/`; the webui
    dist that the renderer build produces is left untouched so dev
    servers and HTTP-served deployments keep their original CORS
    behavior.
    """
    import re
    index_path = webui_dir / "index.html"
    if not index_path.exists():
        return
    html = index_path.read_text(encoding="utf-8")
    # Match `crossorigin`, `crossorigin=""`, or `crossorigin="anonymous"`
    # as a standalone attribute (with its leading whitespace).
    html = re.sub(r'\s+crossorigin(="[^"]*")?', "", html)
    index_path.write_text(html, encoding="utf-8")


def write_launch_args(package_dir: Path, platform: str) -> None:
    exv_path = Path("bin") / executable_name("exv", platform)
    renderer_index = Path("webui") / "index.html"
    args = [
        "--exv",
        exv_path.as_posix(),
        "--renderer-index",
        renderer_index.as_posix(),
    ]
    (package_dir / "exv-ui.args").write_text("\n".join(args) + "\n", encoding="utf-8")


def validate_launch_args_targets(package_dir: Path) -> None:
    args_path = package_dir / "exv-ui.args"
    args = [line.strip() for line in args_path.read_text(encoding="utf-8").splitlines()]
    for token in args:
        if not token or token.startswith("--"):
            continue
        target = (package_dir / token).resolve()
        package_root = package_dir.resolve()
        if package_root not in (target, *target.parents) or not target.exists():
            raise SystemExit(f"Launch args target not found: {token}")


def validate_required_package_binaries(package_dir: Path, platform: str) -> None:
    required = [package_dir / executable_name("exv-ui", platform)]
    required.extend(
        package_dir / "bin" / executable_name(stem, platform)
        for stem in PACKAGE_BINARIES
    )
    missing = [
        path.relative_to(package_dir).as_posix()
        for path in required
        if not path.is_file()
    ]
    if missing:
        raise SystemExit(
            "Required package executable(s) missing: " + ", ".join(missing)
        )


def validate_macos_app_bundle(package_dir: Path) -> None:
    """Validate the EXV.app bundle that sits next to the flat package dir.

    Checks the Info.plist keys the smoke test requires, the MacOS executable,
    and that the bundle's relative launch-arg targets resolve inside Resources.
    """
    app_dir = package_dir / f"{MACOS_BUNDLE_NAME}.app"
    if not app_dir.is_dir():
        raise SystemExit(f"macOS .app bundle not found: {app_dir}")

    contents_dir = app_dir / "Contents"
    info_plist = contents_dir / "Info.plist"
    if not info_plist.is_file():
        raise SystemExit(f"Info.plist missing from bundle: {info_plist}")

    try:
        plist = plistlib.loads(info_plist.read_bytes())
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"Info.plist is not a valid plist: {exc}") from exc

    missing_keys = [key for key in MACOS_BUNDLE_INFO_PLIST_KEYS if not plist.get(key)]
    if missing_keys:
        raise SystemExit(f"Info.plist missing keys: {', '.join(missing_keys)}")

    macos_exec = contents_dir / "MacOS" / MACOS_BUNDLE_EXECUTABLE
    if not macos_exec.is_file():
        raise SystemExit(f"Bundle executable missing: {macos_exec}")

    resources_dir = contents_dir / "Resources"
    args_path = resources_dir / "exv-ui.args"
    if not args_path.is_file():
        raise SystemExit(f"Bundle exv-ui.args missing: {args_path}")
    for token in [line.strip() for line in args_path.read_text(encoding="utf-8").splitlines()]:
        if not token or token.startswith("--"):
            continue
        target = (resources_dir / token).resolve()
        resources_root = resources_dir.resolve()
        if resources_root not in (target, *target.parents) or not target.exists():
            raise SystemExit(f"Bundle launch args target not found: {token}")


def build_macos_app_bundle(flat_package_dir: Path) -> Path:
    """Assemble a macOS .app bundle from the flat native WebView package.

    Layout (matches tests/ui_shell_contract_test.cpp and
    scripts/macos-packaging-smoke.sh), with paths shown relative to the
    bundle root:

        EXV.app/Contents/Info.plist
        EXV.app/Contents/MacOS/EXV                 # exv-ui binary, renamed
        EXV.app/Contents/Resources/exv-ui.args     # relative; resolved at runtime
        EXV.app/Contents/Resources/bin/exv
        EXV.app/Contents/Resources/bin/exv-helper
        EXV.app/Contents/Resources/webui/...
        EXV.app/Contents/Resources/icon.icns

    The flat ``EXV/`` directory is preserved alongside the bundle so the
    existing flat-layout validators and non-macOS tooling keep working.
    """
    version = detect_project_version("macos")
    app_dir = flat_package_dir / f"{MACOS_BUNDLE_NAME}.app"
    if app_dir.exists():
        shutil.rmtree(app_dir)

    contents_dir = app_dir / "Contents"
    macos_dir = contents_dir / "MacOS"
    resources_dir = contents_dir / "Resources"
    macos_dir.mkdir(parents=True, exist_ok=True)
    resources_dir.mkdir(parents=True, exist_ok=True)

    ui_binary = flat_package_dir / "exv-ui"
    shutil.copy2(ui_binary, macos_dir / MACOS_BUNDLE_EXECUTABLE)
    os.chmod(macos_dir / MACOS_BUNDLE_EXECUTABLE, 0o755)

    copy_tree_contents(flat_package_dir / "bin", resources_dir / "bin")
    copy_tree_contents(flat_package_dir / "webui", resources_dir / "webui")

    # exv-ui.args must carry *relative* paths so the bundle stays portable
    # when dragged into /Applications; the binary resolves them against its
    # own Resources directory at runtime (see ui_shell_options.cpp).
    args = [
        "--exv",
        Path("bin/exv").as_posix(),
        "--renderer-index",
        Path("webui/index.html").as_posix(),
    ]
    (resources_dir / "exv-ui.args").write_text(
        "\n".join(args) + "\n", encoding="utf-8"
    )

    icns_source = REPO_ROOT / "assets" / "icons" / "icon.icns"
    if icns_source.is_file():
        shutil.copy2(icns_source, resources_dir / "icon.icns")

    (contents_dir / "Info.plist").write_text(
        info_plist_contents(version), encoding="utf-8"
    )
    return app_dir


def verify_contract_identity_consumer_set(
    label: str,
    app: Path,
    core: Path,
    helper: Path,
    renderer: Path,
) -> None:
    command = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "verify_packaged_contract_coherence.py"),
        "--root",
        str(REPO_ROOT),
        "--consumer",
        f"app={app}",
        "--consumer",
        f"core={core}",
        "--consumer",
        f"helper={helper}",
        "--consumer",
        f"renderer={renderer}",
    ]
    completed = subprocess.run(
        command, cwd=REPO_ROOT, text=True, capture_output=True, check=False
    )
    if completed.returncode != 0:
        detail = (completed.stdout + completed.stderr).strip()
        raise SystemExit(
            "Packaged App/Core/Helper/Renderer contract identity mismatch "
            f"for {label}:\n"
            + detail
        )


def verify_package_contract_identity(package_dir: Path, platform: str) -> None:
    suffix = ".exe" if platform == "windows" else ""
    verify_contract_identity_consumer_set(
        "flat-package",
        package_dir / ("exv-ui" + suffix),
        package_dir / "bin" / ("exv" + suffix),
        package_dir / "bin" / ("exv-helper" + suffix),
        package_dir / "webui",
    )
    if platform != "macos":
        return

    contents = package_dir / f"{MACOS_BUNDLE_NAME}.app" / "Contents"
    resources = contents / "Resources"
    verify_contract_identity_consumer_set(
        "macos-bundle",
        contents / "MacOS" / MACOS_BUNDLE_EXECUTABLE,
        resources / "bin" / "exv",
        resources / "bin" / "exv-helper",
        resources / "webui",
    )


def build_package(platform: str, output_root: Path) -> Path:
    verify_app_icon_assets()
    renderer_dir = first_existing(default_renderer_candidates(platform), "Renderer build directory")

    package_dir = output_root / "EXV"
    if package_dir.exists():
        shutil.rmtree(package_dir)

    bin_dir = package_dir / "bin"
    webui_dir = package_dir / "webui"
    bin_dir.mkdir(parents=True, exist_ok=True)

    ui_binary = find_binary("exv-ui", platform)
    shutil.copy2(ui_binary, package_dir / ui_binary.name)

    webview2_loader = find_webview2_loader(platform)
    if webview2_loader:
        shutil.copy2(webview2_loader, package_dir / "WebView2Loader.dll")

    for stem in PACKAGE_BINARIES:
        binary = find_binary(stem, platform)
        shutil.copy2(binary, bin_dir / binary.name)

    if platform == "windows":
        copy_windows_runtime_assets(package_dir)
        validate_windows_package_vendor_payloads(package_dir)

    copy_tree_contents(renderer_dir, webui_dir)
    strip_crossorigin_for_file_protocol(webui_dir)
    write_launch_args(package_dir, platform)
    validate_required_package_binaries(package_dir, platform)
    validate_launch_args_targets(package_dir)
    assert_no_electron_payload(package_dir)

    if platform == "macos":
        build_macos_app_bundle(package_dir)
        validate_macos_app_bundle(package_dir)
    verify_package_contract_identity(package_dir, platform)
    return package_dir


def parse_args() -> argparse.Namespace:
    platform = normalized_platform(os.environ.get("EXV_BUILD_PLATFORM"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", default=platform)
    parser.add_argument("--verify-launch-targets-only", action="store_true")
    parser.add_argument("--package-dir", type=Path)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPO_ROOT / "build" / platform / "webview" / "package",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    platform = normalized_platform(args.platform)
    if args.verify_launch_targets_only:
        if not args.package_dir:
            raise SystemExit("--package-dir is required with --verify-launch-targets-only")
        verify_app_icon_assets()
        validate_required_package_binaries(args.package_dir, platform)
        validate_launch_args_targets(args.package_dir)
        assert_no_electron_payload(args.package_dir)
        if platform == "windows":
            validate_windows_package_vendor_payloads(args.package_dir)
        if platform == "macos":
            validate_macos_app_bundle(args.package_dir)
        verify_package_contract_identity(args.package_dir, platform)
        print(f"verified native WebView shell package: {args.package_dir}")
        return 0

    package_dir = build_package(platform, args.output_root)
    print(f"packaged native WebView shell: {package_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
