"""Safe repository-local JSON loading, identity, and schema validation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

from .dependencies import require_dependency
from .errors import ArchitectureQueryError


JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True)
class RegisteredModel:
    model_id: str
    path: Path
    schema_path: Path


REGISTERED_MODELS = {
    "runtime-v3": RegisteredModel(
        model_id="runtime-v3",
        path=Path("contracts/runtime_v3/business_flow.model.json"),
        schema_path=Path("contracts/runtime_v3/business_flow.schema.json"),
    )
}


@dataclass(frozen=True)
class LoadedDocument:
    data: JsonValue
    repo_root: Path
    model_id: str | None
    path: Path
    schema_path: Path | None
    schema_version: str | None
    requirement_id: str | None
    canonical_sha256: str
    validation: Literal["schema", "parse"]
    source_size_bytes: int

    def source_metadata(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "path": self.path.as_posix(),
            "schema_path": self.schema_path.as_posix() if self.schema_path else None,
            "schema_version": self.schema_version,
            "requirement_id": self.requirement_id,
            "canonical_sha256": self.canonical_sha256,
            "validation": self.validation,
            "source_size_bytes": self.source_size_bytes,
        }


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate object key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def discover_repo_root(explicit: Path | None = None) -> Path:
    if explicit is not None:
        root = explicit.expanduser().resolve()
        if not root.is_dir():
            raise ArchitectureQueryError(
                "ARCH_SOURCE_NOT_FOUND",
                "repository root does not exist",
                exit_code=3,
                details={"repo": str(explicit)},
            )
        return root

    candidate = Path.cwd().resolve()
    for current in (candidate, *candidate.parents):
        if (current / ".git").exists():
            return current
    raise ArchitectureQueryError(
        "ARCH_SOURCE_NOT_FOUND",
        "unable to discover repository root; pass --repo",
        exit_code=3,
    )


def _repository_path(
    repo_root: Path, relative: Path, *, kind: str
) -> tuple[Path, Path]:
    if relative.is_absolute():
        raise ArchitectureQueryError(
            "ARCH_SOURCE_FORBIDDEN",
            f"{kind} path must be repository-relative",
            exit_code=3,
            details={"path": str(relative)},
        )
    root = repo_root.resolve()
    candidate = (root / relative).resolve(strict=False)
    if not candidate.is_relative_to(root):
        raise ArchitectureQueryError(
            "ARCH_SOURCE_FORBIDDEN",
            f"{kind} path escapes the repository",
            exit_code=3,
            details={"path": str(relative)},
        )
    try:
        canonical_relative = candidate.relative_to(root)
    except ValueError as error:
        raise ArchitectureQueryError(
            "ARCH_SOURCE_FORBIDDEN",
            f"{kind} path escapes the repository",
            exit_code=3,
            details={"path": str(relative)},
        ) from error
    return candidate, canonical_relative


def _read_json(path: Path, relative: Path, *, kind: str) -> JsonValue:
    if not path.is_file():
        raise ArchitectureQueryError(
            "ARCH_SOURCE_NOT_FOUND",
            f"{kind} file does not exist",
            exit_code=3,
            details={"path": relative.as_posix()},
        )
    try:
        text = path.read_text(encoding="utf-8")
        return parse_json_text(text, location=relative.as_posix(), kind=kind)
    except ArchitectureQueryError:
        raise
    except (UnicodeDecodeError,) as error:
        raise ArchitectureQueryError(
            "ARCH_JSON_INVALID",
            f"{kind} is not strict UTF-8 JSON",
            exit_code=3,
            location=relative.as_posix(),
            details={"reason": str(error)},
        ) from error


def parse_json_text(text: str, *, location: str, kind: str = "source") -> JsonValue:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except (json.JSONDecodeError, _DuplicateKeyError, ValueError) as error:
        raise ArchitectureQueryError(
            "ARCH_JSON_INVALID",
            f"{kind} is not strict UTF-8 JSON",
            exit_code=3,
            location=location,
            details={"reason": str(error)},
        ) from error


def _pointer_from_path(parts: Any) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "" if not escaped else "/" + "/".join(escaped)


def _validate_schema(data: JsonValue, schema: JsonValue, schema_relative: Path) -> None:
    jsonschema = require_dependency("jsonschema")
    try:
        validator_type = jsonschema.validators.validator_for(schema)
        validator_type.check_schema(schema)
        validator = validator_type(schema)
        errors = sorted(
            validator.iter_errors(data),
            key=lambda item: _pointer_from_path(item.absolute_path),
        )
    except ArchitectureQueryError:
        raise
    except Exception as error:
        raise ArchitectureQueryError(
            "ARCH_SCHEMA_INVALID",
            "JSON Schema document is invalid or incompatible",
            exit_code=4,
            location=schema_relative.as_posix(),
            details={"exception_type": type(error).__name__, "reason": str(error)},
        ) from error
    if errors:
        first = errors[0]
        raise ArchitectureQueryError(
            "ARCH_SCHEMA_INVALID",
            "JSON document does not satisfy its declared schema",
            exit_code=4,
            location=_pointer_from_path(first.absolute_path),
            details={
                "validator": first.validator,
                "reason": first.message,
                "error_count": len(errors),
            },
        )


def canonical_digest(data: JsonValue) -> str:
    canonical = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_document(
    *,
    repo_root: Path,
    model: str | None,
    file: Path | None,
    schema: Path | None,
    validation: Literal["schema", "parse"],
) -> LoadedDocument:
    if model is not None and file is not None:
        raise ArchitectureQueryError(
            "ARCH_USAGE_INVALID",
            "--model and --file are mutually exclusive",
            exit_code=2,
        )

    registered: RegisteredModel | None = None
    if model is not None:
        registered = REGISTERED_MODELS.get(model)
        if registered is None:
            raise ArchitectureQueryError(
                "ARCH_USAGE_INVALID",
                "registered model is unknown",
                exit_code=2,
                details={"model": model, "known_models": sorted(REGISTERED_MODELS)},
            )
        file = registered.path
        if schema is None:
            schema = registered.schema_path
    elif file is None:
        registered = REGISTERED_MODELS["runtime-v3"]
        model = registered.model_id
        file = registered.path
        if schema is None:
            schema = registered.schema_path

    assert file is not None
    source_path, source_relative = _repository_path(repo_root, file, kind="source")
    data = _read_json(source_path, source_relative, kind="source")

    schema_relative: Path | None = None
    if validation == "schema":
        if schema is None:
            raise ArchitectureQueryError(
                "ARCH_USAGE_INVALID",
                "schema validation requires --schema or a registered model",
                exit_code=2,
            )
        schema_path, schema_relative = _repository_path(
            repo_root, schema, kind="schema"
        )
        schema_data = _read_json(schema_path, schema_relative, kind="schema")
        _validate_schema(data, schema_data, schema_relative)

    root_object = data if isinstance(data, dict) else {}
    return LoadedDocument(
        data=data,
        repo_root=repo_root.resolve(),
        model_id=registered.model_id if registered else None,
        path=source_relative,
        schema_path=schema_relative,
        schema_version=(
            root_object.get("schema_version")
            if isinstance(root_object.get("schema_version"), str)
            else None
        ),
        requirement_id=(
            root_object.get("requirement_id")
            if isinstance(root_object.get("requirement_id"), str)
            else None
        ),
        canonical_sha256=canonical_digest(data),
        validation=validation,
        source_size_bytes=source_path.stat().st_size,
    )


def document_absolute_path(document: LoadedDocument) -> Path:
    return document.repo_root / document.path


def validate_candidate_data(
    document: LoadedDocument,
    data: JsonValue,
    *,
    source_size_bytes: int,
) -> LoadedDocument:
    if document.validation != "schema" or document.schema_path is None:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "mutations require a source loaded with schema validation",
            exit_code=2,
        )
    schema_path = document.repo_root / document.schema_path
    schema_data = _read_json(schema_path, document.schema_path, kind="schema")
    _validate_schema(data, schema_data, document.schema_path)
    root_object = data if isinstance(data, dict) else {}
    return replace(
        document,
        data=data,
        schema_version=(
            root_object.get("schema_version")
            if isinstance(root_object.get("schema_version"), str)
            else None
        ),
        requirement_id=(
            root_object.get("requirement_id")
            if isinstance(root_object.get("requirement_id"), str)
            else None
        ),
        canonical_sha256=canonical_digest(data),
        source_size_bytes=source_size_bytes,
    )
