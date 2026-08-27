#!/usr/bin/env python3
"""Write Finder .DS_Store metadata for a drag-to-Applications DMG.

Uses the pure-Python ds_store package with the key/value shapes Finder still
understands on modern macOS (Iloc positions + icvp background image).
"""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
import venv
from pathlib import Path


def venv_python(venv_dir: Path) -> Path:
    return venv_dir / "bin" / "python"


def ensure_deps(venv_dir: Path) -> Path:
    py = venv_python(venv_dir)
    if not py.exists():
        venv_dir.mkdir(parents=True, exist_ok=True)
        venv.create(venv_dir, with_pip=True)
    marker = venv_dir / ".exv-dsstore-ready"
    if not marker.exists():
        subprocess.check_call(
            [str(py), "-m", "pip", "install", "--quiet", "ds_store", "mac_alias"]
        )
        marker.write_text("ok\n", encoding="utf-8")
    return py


def reexec_in_venv(venv_dir: Path, argv: list[str]) -> None:
    py = ensure_deps(venv_dir)
    os.execv(str(py), [str(py), *argv])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("volume_root", type=Path)
    parser.add_argument("--width", type=int, default=660)
    parser.add_argument("--height", type=int, default=420)
    parser.add_argument("--icon-size", type=int, default=128)
    parser.add_argument("--app-x", type=int, default=160)
    parser.add_argument("--app-y", type=int, default=190)
    parser.add_argument("--applications-x", type=int, default=500)
    parser.add_argument("--applications-y", type=int, default=190)
    parser.add_argument(
        "--venv-dir",
        type=Path,
        default=Path(os.environ.get("TMPDIR", "/tmp")) / "exv-dsstore-venv",
    )
    args = parser.parse_args()

    # Ensure we are running with the dependency venv.
    try:
        from ds_store import DSStore  # type: ignore
        from mac_alias import Alias  # type: ignore
    except Exception:
        reexec_in_venv(
            args.venv_dir,
            [
                str(Path(__file__).resolve()),
                str(args.volume_root),
                "--width",
                str(args.width),
                "--height",
                str(args.height),
                "--icon-size",
                str(args.icon_size),
                "--app-x",
                str(args.app_x),
                "--app-y",
                str(args.app_y),
                "--applications-x",
                str(args.applications_x),
                "--applications-y",
                str(args.applications_y),
                "--venv-dir",
                str(args.venv_dir),
            ],
        )

    from ds_store import DSStore  # type: ignore
    from mac_alias import Alias  # type: ignore

    volume = args.volume_root.resolve()
    if not volume.is_dir():
        print(f"volume root not found: {volume}", file=sys.stderr)
        return 2

    bg = volume / ".background" / "background.png"
    if not bg.is_file():
        print(f"background image missing: {bg}", file=sys.stderr)
        return 2
    if not (volume / "EXV.app").exists():
        print(f"EXV.app missing under {volume}", file=sys.stderr)
        return 2
    if not (volume / "Applications").exists():
        print(f"Applications link missing under {volume}", file=sys.stderr)
        return 2

    ds_path = volume / ".DS_Store"
    if ds_path.exists():
        ds_path.unlink()

    # Finder window bounds payload: top, left, bottom, right + view mode.
    # Matching public DMG tooling (struct-packed fwi0 blob).
    fwi0 = (
        struct.pack(">H", 100)
        + struct.pack(">H", 100)
        + struct.pack(">H", 100 + args.height)
        + struct.pack(">H", 100 + args.width)
        + b"icnv"
        + b"\x00\x00\x00\x00"
    )

    background_alias = Alias.for_file(str(bg)).to_bytes()
    icvp = {
        "viewOptionsVersion": 1,
        "backgroundType": 2,  # picture
        "backgroundImageAlias": background_alias,
        "backgroundColorRed": 1.0,
        "backgroundColorGreen": 1.0,
        "backgroundColorBlue": 1.0,
        "gridOffsetX": 0.0,
        "gridOffsetY": 0.0,
        "gridSpacing": 100.0,
        "iconSize": float(args.icon_size),
        "textSize": 12.0,
        "scrollPositionX": 0.0,
        "scrollPositionY": 0.0,
        "labelOnBottom": True,
        "showItemInfo": False,
        "showIconPreview": True,
        "arrangeBy": "none",
    }

    with DSStore.open(str(ds_path), "w+") as ds:
        ds["."]["vSrn"] = ("long", 1)
        ds["."]["vstl"] = ("ustr", "icnv")
        ds["."]["ICVO"] = ("bool", True)
        ds["."]["icvt"] = ("shor", 12)
        ds["."]["fwvh"] = ("shor", args.height)
        ds["."]["fwsw"] = ("long", 0)
        ds["."]["fwi0"] = ("blob", fwi0)
        ds["."]["icvp"] = icvp
        # Icon positions (Finder coordinates, origin top-left).
        ds["EXV.app"]["Iloc"] = (args.app_x, args.app_y)
        ds["Applications"]["Iloc"] = (args.applications_x, args.applications_y)
        # Park helper items outside the visible window.
        ds[".background"]["Iloc"] = (args.width + 200, args.height + 200)
        ds[".DS_Store"]["Iloc"] = (args.width + 240, args.height + 200)

    print(ds_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
