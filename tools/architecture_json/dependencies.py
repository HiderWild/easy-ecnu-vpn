"""External dependency discovery without installation or repository policy."""

from __future__ import annotations

import importlib
import importlib.util
from importlib import metadata
from types import ModuleType
from typing import Any

from .errors import ArchitectureQueryError


READ_DEPENDENCIES = ("jmespath", "jsonpointer", "jsonschema")
MUTATION_DEPENDENCIES = ("jsonpatch", "json_source_map")
REQUIRED_DEPENDENCIES = READ_DEPENDENCIES + MUTATION_DEPENDENCIES


def dependency_report(
    names: tuple[str, ...] = REQUIRED_DEPENDENCIES,
) -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    for name in names:
        available = importlib.util.find_spec(name) is not None
        version: str | None = None
        if available:
            try:
                version = metadata.version(name)
            except metadata.PackageNotFoundError:
                version = None
        report.append({"name": name, "available": available, "version": version})
    return report


def require_dependency(name: str) -> ModuleType:
    if name not in REQUIRED_DEPENDENCIES:
        raise ArchitectureQueryError(
            "ARCH_DEPENDENCY_INCOMPATIBLE",
            "query implementation requested an undeclared external dependency",
            exit_code=7,
            details={"dependency": name},
        )
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as error:
        raise ArchitectureQueryError(
            "ARCH_DEPENDENCY_MISSING",
            f"required external Python package is unavailable: {name}",
            exit_code=7,
            details={"dependency": name},
        ) from error
    except Exception as error:
        raise ArchitectureQueryError(
            "ARCH_DEPENDENCY_INCOMPATIBLE",
            f"required external Python package could not be imported: {name}",
            exit_code=7,
            details={"dependency": name, "exception_type": type(error).__name__},
        ) from error
