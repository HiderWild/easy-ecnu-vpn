"""Guarded RFC 6902 Create/Update/Delete operations with format-preserving writes."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .dependencies import require_dependency
from .errors import ArchitectureQueryError
from .loader import (
    JsonValue,
    LoadedDocument,
    canonical_digest,
    document_absolute_path,
    parse_json_text,
    validate_candidate_data,
)
from .output import MAX_OUTPUT_BYTES
from .profiles.runtime_v3 import RuntimeV3Profile
from .references import ReferenceIndex, build_reference_index, escape_pointer_token


SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class TextEdit:
    start: int
    end: int
    replacement: str


@dataclass(frozen=True)
class PointerReplacement:
    pointer: str
    value: JsonValue


@dataclass(frozen=True)
class PointerAddition:
    pointer: str
    value: JsonValue


@dataclass(frozen=True)
class MutationPlan:
    operation: str
    target: dict[str, Any]
    patch: list[dict[str, Any]]
    text_edits: tuple[TextEdit, ...]
    source_bytes_sha256: str
    metadata: dict[str, Any] = field(default_factory=dict)


def _source_bytes_sha256(source_text: str) -> str:
    return hashlib.sha256(source_text.encode("utf-8")).hexdigest()


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _section_pointer(section: str) -> str:
    return "/" + _escape_pointer(section)


def _require_array_section(document: LoadedDocument, section: str) -> list[JsonValue]:
    if not isinstance(document.data, dict) or section not in document.data:
        raise ArchitectureQueryError(
            "ARCH_SECTION_UNKNOWN",
            "JSON section is unknown",
            exit_code=5,
            location=_section_pointer(section),
            details={"section": section},
        )
    items = document.data[section]
    if not isinstance(items, list):
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "Create/Update/Delete requires a top-level array section",
            exit_code=2,
            location=_section_pointer(section),
            details={"section": section},
        )
    return items


def _entity_index(
    document: LoadedDocument, section: str, entity_id: str
) -> tuple[int, dict[str, JsonValue]]:
    matches: list[tuple[int, dict[str, JsonValue]]] = []
    for index, item in enumerate(_require_array_section(document, section)):
        if isinstance(item, dict) and item.get("id") == entity_id:
            matches.append((index, item))
    if not matches:
        raise ArchitectureQueryError(
            "ARCH_ENTITY_NOT_FOUND",
            "entity id was not found",
            exit_code=5,
            location=_section_pointer(section),
            details={"section": section, "id": entity_id},
        )
    if len(matches) > 1:
        raise ArchitectureQueryError(
            "ARCH_DUPLICATE_ID",
            "entity id is duplicated",
            exit_code=4,
            location=_section_pointer(section),
            details={"section": section, "id": entity_id},
        )
    return matches[0]


def _source_map(source_text: str) -> dict[str, Any]:
    json_source_map = require_dependency("json_source_map")
    try:
        return json_source_map.calculate(source_text)
    except Exception as error:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "unable to calculate source locations for JSON mutation",
            exit_code=2,
            details={"exception_type": type(error).__name__, "reason": str(error)},
        ) from error


def _entry(source_map: dict[str, Any], pointer: str) -> Any:
    entry = source_map.get(pointer)
    if entry is None:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "source map does not contain the required JSON Pointer",
            exit_code=2,
            location=pointer,
        )
    return entry


def _format_value(value: JsonValue, *, column: int) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
        )
    except (TypeError, ValueError) as error:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "mutation value is not strict JSON data",
            exit_code=2,
            details={"reason": str(error)},
        ) from error
    return encoded.replace("\n", "\n" + " " * column)


def _assert_unique_new_id(
    document: LoadedDocument, section: str, entity_id: str
) -> None:
    for item in _require_array_section(document, section):
        if isinstance(item, dict) and item.get("id") == entity_id:
            raise ArchitectureQueryError(
                "ARCH_DUPLICATE_ID",
                "create target id already exists",
                exit_code=4,
                location=_section_pointer(section),
                details={"section": section, "id": entity_id},
            )


def plan_create(
    document: LoadedDocument,
    *,
    section: str,
    value: JsonValue,
    source_text: str,
) -> MutationPlan:
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("id"), str)
        or not value["id"]
    ):
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "create value must be an object with a non-empty string id",
            exit_code=2,
            details={"section": section},
        )
    entity_id = value["id"]
    _assert_unique_new_id(document, section, entity_id)
    items = _require_array_section(document, section)
    section_pointer = _section_pointer(section)
    source_map = _source_map(source_text)
    section_entry = _entry(source_map, section_pointer)

    if items:
        last_pointer = f"{section_pointer}/{len(items) - 1}"
        last_entry = _entry(source_map, last_pointer)
        item_column = last_entry.value_start.column
        text_edit = TextEdit(
            start=last_entry.value_end.position,
            end=last_entry.value_end.position,
            replacement=",\n"
            + " " * item_column
            + _format_value(value, column=item_column),
        )
        if isinstance(items[-1], dict) and "id" in items[-1]:
            test_path = f"{last_pointer}/id"
            test_value = items[-1]["id"]
        else:
            test_path = last_pointer
            test_value = items[-1]
    else:
        container_column = (
            section_entry.key_start.column
            if section_entry.key_start is not None
            else max(section_entry.value_start.column - 2, 0)
        )
        item_column = container_column + 2
        replacement = (
            "[\n"
            + " " * item_column
            + _format_value(value, column=item_column)
            + "\n"
            + " " * container_column
            + "]"
        )
        text_edit = TextEdit(
            start=section_entry.value_start.position,
            end=section_entry.value_end.position,
            replacement=replacement,
        )
        test_path = section_pointer
        test_value = []

    return MutationPlan(
        operation="create",
        target={"section": section, "id": entity_id},
        patch=[
            {"op": "test", "path": test_path, "value": test_value},
            {"op": "add", "path": f"{section_pointer}/-", "value": value},
        ],
        text_edits=(text_edit,),
        source_bytes_sha256=_source_bytes_sha256(source_text),
    )


def _validate_update_pointers(
    replacements: tuple[PointerReplacement, ...],
    additions: tuple[PointerAddition, ...],
) -> None:
    if not replacements and not additions:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "update requires at least one --set or --add operation",
            exit_code=2,
        )
    pointers = [item.pointer for item in (*replacements, *additions)]
    for pointer in pointers:
        if not pointer.startswith("/") or pointer == "/":
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "update pointers must be non-root RFC 6901 pointers",
                exit_code=2,
                details={"pointer": pointer},
            )
        if pointer == "/id" or pointer.startswith("/id/"):
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "stable entity id cannot be changed by update",
                exit_code=2,
                details={"pointer": pointer},
            )
    for index, pointer in enumerate(pointers):
        for other in pointers[index + 1 :]:
            if (
                pointer == other
                or pointer.startswith(other + "/")
                or other.startswith(pointer + "/")
            ):
                raise ArchitectureQueryError(
                    "ARCH_MUTATION_INVALID",
                    "update pointers must be unique and non-overlapping",
                    exit_code=2,
                    details={"pointer": pointer, "other": other},
                )


def plan_update(
    document: LoadedDocument,
    *,
    section: str,
    entity_id: str,
    replacements: tuple[PointerReplacement, ...],
    additions: tuple[PointerAddition, ...] = (),
    source_text: str,
) -> MutationPlan:
    _validate_update_pointers(replacements, additions)
    index, entity = _entity_index(document, section, entity_id)
    jsonpointer = require_dependency("jsonpointer")
    source_map = _source_map(source_text)
    entity_pointer = f"{_section_pointer(section)}/{index}"
    patch: list[dict[str, Any]] = [
        {"op": "test", "path": f"{entity_pointer}/id", "value": entity_id}
    ]
    edits: list[TextEdit] = []
    sentinel = object()
    for replacement in replacements:
        try:
            existing = jsonpointer.resolve_pointer(
                entity, replacement.pointer, default=sentinel
            )
        except Exception as error:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "update pointer is invalid",
                exit_code=2,
                details={"pointer": replacement.pointer, "reason": str(error)},
            ) from error
        if existing is sentinel:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "update currently replaces existing fields only",
                exit_code=2,
                details={"pointer": replacement.pointer},
            )
        target_pointer = entity_pointer + replacement.pointer
        target_entry = _entry(source_map, target_pointer)
        patch.append(
            {"op": "replace", "path": target_pointer, "value": replacement.value}
        )
        edits.append(
            TextEdit(
                start=target_entry.value_start.position,
                end=target_entry.value_end.position,
                replacement=_format_value(
                    replacement.value, column=target_entry.value_start.column
                ),
            )
        )
    addition_parents: set[str] = set()
    for addition in additions:
        try:
            pointer_parts = jsonpointer.JsonPointer(addition.pointer).parts
        except Exception as error:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "add pointer is invalid",
                exit_code=2,
                details={"pointer": addition.pointer, "reason": str(error)},
            ) from error
        if not pointer_parts:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "add pointer cannot target the entity root",
                exit_code=2,
                details={"pointer": addition.pointer},
            )
        parent_parts = pointer_parts[:-1]
        field_name = pointer_parts[-1]
        if not isinstance(field_name, str) or field_name == "":
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "add currently creates a non-empty object field only",
                exit_code=2,
                details={"pointer": addition.pointer},
            )
        parent_pointer = (
            ""
            if not parent_parts
            else "/"
            + "/".join(escape_pointer_token(str(part)) for part in parent_parts)
        )
        if parent_pointer in addition_parents:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "one update may add only one field per parent object",
                exit_code=2,
                details={"parent_pointer": parent_pointer},
            )
        addition_parents.add(parent_pointer)
        try:
            parent = jsonpointer.resolve_pointer(entity, parent_pointer)
        except Exception as error:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "add parent pointer does not exist",
                exit_code=2,
                details={"pointer": addition.pointer, "reason": str(error)},
            ) from error
        if not isinstance(parent, dict):
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "add parent must be an existing object",
                exit_code=2,
                details={"pointer": addition.pointer},
            )
        if field_name in parent:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "add refuses to overwrite an existing field; use --set",
                exit_code=2,
                details={"pointer": addition.pointer},
            )
        absolute_parent = entity_pointer + parent_pointer
        parent_entry = _entry(source_map, absolute_parent)
        encoded_key = json.dumps(field_name, ensure_ascii=False, allow_nan=False)
        if parent:
            last_key = next(reversed(parent))
            last_pointer = absolute_parent + "/" + escape_pointer_token(last_key)
            last_entry = _entry(source_map, last_pointer)
            if last_entry.key_start is None:
                raise ArchitectureQueryError(
                    "ARCH_MUTATION_INVALID",
                    "source map lacks an object-key position for add",
                    exit_code=2,
                    location=last_pointer,
                )
            key_column = last_entry.key_start.column
            value_column = key_column + len(encoded_key) + 2
            edit = TextEdit(
                start=parent_entry.value_end.position - 1,
                end=parent_entry.value_end.position - 1,
                replacement=",\n"
                + " " * key_column
                + encoded_key
                + ": "
                + _format_value(addition.value, column=value_column),
            )
        else:
            object_column = parent_entry.value_start.column
            key_column = object_column + 2
            value_column = key_column + len(encoded_key) + 2
            edit = TextEdit(
                start=parent_entry.value_start.position,
                end=parent_entry.value_end.position,
                replacement="{\n"
                + " " * key_column
                + encoded_key
                + ": "
                + _format_value(addition.value, column=value_column)
                + "\n"
                + " " * object_column
                + "}",
            )
        target_pointer = entity_pointer + addition.pointer
        patch.append({"op": "add", "path": target_pointer, "value": addition.value})
        edits.append(edit)
    return MutationPlan(
        operation="update",
        target={
            "section": section,
            "id": entity_id,
            "pointers": [item.pointer for item in (*replacements, *additions)],
            "added_pointers": [item.pointer for item in additions],
        },
        patch=patch,
        text_edits=tuple(edits),
        source_bytes_sha256=_source_bytes_sha256(source_text),
    )


def plan_rename(
    document: LoadedDocument,
    *,
    section: str,
    entity_id: str,
    new_id: str,
    source_text: str,
    reference_index: ReferenceIndex | None = None,
) -> MutationPlan:
    if not new_id:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "rename target id must be a non-empty string",
            exit_code=2,
        )
    if new_id == entity_id:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "rename target id must differ from the current id",
            exit_code=2,
        )
    index, _entity = _entity_index(document, section, entity_id)
    _assert_unique_new_id(document, section, new_id)
    if document.model_id is None and isinstance(document.data, dict):
        conflicting_sections = []
        for candidate_section, values in document.data.items():
            if candidate_section == section or not isinstance(values, list):
                continue
            if any(
                isinstance(item, dict) and item.get("id") == new_id for item in values
            ):
                conflicting_sections.append(candidate_section)
        if conflicting_sections:
            raise ArchitectureQueryError(
                "ARCH_REFERENCE_AMBIGUOUS",
                "generic rename target id already exists in another section",
                exit_code=4,
                details={"id": new_id, "sections": conflicting_sections},
            )
    references = (reference_index or build_reference_index(document)).incoming(
        section, entity_id
    )
    source_map = _source_map(source_text)
    jsonpointer = require_dependency("jsonpointer")
    entity_pointer = f"{_section_pointer(section)}/{index}"
    id_pointer = f"{entity_pointer}/id"
    id_entry = _entry(source_map, id_pointer)
    patch: list[dict[str, Any]] = [
        {"op": "test", "path": id_pointer, "value": entity_id},
        {"op": "replace", "path": id_pointer, "value": new_id},
    ]
    edits: list[TextEdit] = [
        TextEdit(
            start=id_entry.value_start.position,
            end=id_entry.value_end.position,
            replacement=_format_value(new_id, column=id_entry.value_start.column),
        )
    ]
    ordered_references = sorted(
        references,
        key=lambda item: (item.source_pointer, 0 if item.location == "key" else 1),
    )
    key_destinations = {
        item.source_pointer: item.source_pointer.rpartition("/")[0]
        + "/"
        + escape_pointer_token(new_id)
        for item in ordered_references
        if item.location == "key"
    }
    for reference in ordered_references:
        entry = _entry(source_map, reference.source_pointer)
        if reference.location == "value":
            patch_pointer = key_destinations.get(
                reference.source_pointer, reference.source_pointer
            )
            patch.extend(
                (
                    {
                        "op": "test",
                        "path": patch_pointer,
                        "value": entity_id,
                    },
                    {
                        "op": "replace",
                        "path": patch_pointer,
                        "value": new_id,
                    },
                )
            )
            edits.append(
                TextEdit(
                    start=entry.value_start.position,
                    end=entry.value_end.position,
                    replacement=_format_value(new_id, column=entry.value_start.column),
                )
            )
            continue

        if entry.key_start is None or entry.key_end is None:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "rename key reference lacks source-map key positions",
                exit_code=2,
                location=reference.source_pointer,
            )
        destination = key_destinations[reference.source_pointer]
        sentinel = object()
        existing = jsonpointer.resolve_pointer(
            document.data, destination, default=sentinel
        )
        if existing is not sentinel:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "rename would overwrite an existing object key",
                exit_code=2,
                location=destination,
                details={"source_pointer": reference.source_pointer},
            )
        current_value = jsonpointer.resolve_pointer(
            document.data, reference.source_pointer
        )
        patch.extend(
            (
                {
                    "op": "test",
                    "path": reference.source_pointer,
                    "value": current_value,
                },
                {
                    "op": "move",
                    "from": reference.source_pointer,
                    "path": destination,
                },
            )
        )
        edits.append(
            TextEdit(
                start=entry.key_start.position,
                end=entry.key_end.position,
                replacement=json.dumps(new_id, ensure_ascii=False, allow_nan=False),
            )
        )

    return MutationPlan(
        operation="rename",
        target={
            "section": section,
            "id": entity_id,
            "new_id": new_id,
        },
        patch=patch,
        text_edits=tuple(edits),
        source_bytes_sha256=_source_bytes_sha256(source_text),
        metadata={
            "reference_updates": len(references),
            "reference_policy": (
                "runtime_v3_declared_graph"
                if document.model_id == "runtime-v3"
                else "conservative_exact_string"
            ),
        },
    )


def _cascade_entity_closure(
    reference_index: ReferenceIndex,
    *,
    section: str,
    entity_id: str,
) -> set[tuple[str, str]]:
    deleted: set[tuple[str, str]] = {(section, entity_id)}
    pending = [(section, entity_id)]
    blockers = []
    while pending:
        target_section, target_id = pending.pop()
        for reference in reference_index.incoming(target_section, target_id):
            source = (
                reference.source_entity_section,
                reference.source_entity_id,
            )
            if source[0] is None or source[1] is None:
                blockers.append(reference)
                continue
            typed_source = (source[0], source[1])
            if typed_source in deleted:
                continue
            deleted.add(typed_source)
            pending.append(typed_source)
    if blockers:
        raise ArchitectureQueryError(
            "ARCH_CASCADE_BLOCKED",
            "cascade reaches references owned outside a stable-ID entity",
            exit_code=11,
            details={
                "blocker_count": len(blockers),
                "blockers": [item.to_result() for item in blockers[:50]],
                "candidate_deleted_entities": [
                    {"section": item[0], "id": item[1]} for item in sorted(deleted)
                ],
            },
        )
    return deleted


def _array_deletion_text_edits(
    source_map: dict[str, Any],
    *,
    section_pointer: str,
    item_count: int,
    deleted_indexes: set[int],
) -> list[TextEdit]:
    if not deleted_indexes:
        return []
    if min(deleted_indexes) < 0 or max(deleted_indexes) >= item_count:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "array deletion index is outside the source section",
            exit_code=2,
            location=section_pointer,
        )
    if len(deleted_indexes) == item_count:
        section_entry = _entry(source_map, section_pointer)
        return [
            TextEdit(
                start=section_entry.value_start.position,
                end=section_entry.value_end.position,
                replacement="[]",
            )
        ]

    ordered = sorted(deleted_indexes)
    runs: list[tuple[int, int]] = []
    run_start = ordered[0]
    run_end = ordered[0]
    for index in ordered[1:]:
        if index == run_end + 1:
            run_end = index
            continue
        runs.append((run_start, run_end))
        run_start = index
        run_end = index
    runs.append((run_start, run_end))

    edits: list[TextEdit] = []
    for run_start, run_end in runs:
        first_entry = _entry(source_map, f"{section_pointer}/{run_start}")
        last_entry = _entry(source_map, f"{section_pointer}/{run_end}")
        if run_end < item_count - 1:
            next_entry = _entry(source_map, f"{section_pointer}/{run_end + 1}")
            edits.append(
                TextEdit(
                    start=first_entry.value_start.position,
                    end=next_entry.value_start.position,
                    replacement="",
                )
            )
            continue

        previous_entry = _entry(source_map, f"{section_pointer}/{run_start - 1}")
        edits.append(
            TextEdit(
                start=previous_entry.value_end.position,
                end=last_entry.value_end.position,
                replacement="",
            )
        )
    return edits


def plan_delete(
    document: LoadedDocument,
    *,
    section: str,
    entity_id: str,
    source_text: str,
    cascade: bool = False,
    reference_index: ReferenceIndex | None = None,
) -> MutationPlan:
    index, _entity = _entity_index(document, section, entity_id)
    items = _require_array_section(document, section)
    section_pointer = _section_pointer(section)
    entity_pointer = f"{section_pointer}/{index}"
    references = (reference_index or build_reference_index(document)).incoming(
        section, entity_id
    )
    if references and not cascade:
        raise ArchitectureQueryError(
            "ARCH_REFERENCES_EXIST",
            "delete target still has references outside its own entity",
            exit_code=9,
            location=entity_pointer,
            details={
                "section": section,
                "id": entity_id,
                "reference_count": len(references),
                "references": [item.to_result() for item in references[:50]],
                "guard": (
                    "runtime_v3_declared_graph"
                    if document.model_id == "runtime-v3"
                    else "conservative_exact_string"
                ),
            },
        )

    source_map = _source_map(source_text)
    if cascade:
        reference_graph = reference_index or build_reference_index(document)
        deleted = _cascade_entity_closure(
            reference_graph,
            section=section,
            entity_id=entity_id,
        )
        grouped: dict[str, list[tuple[int, str]]] = {}
        for deleted_section, deleted_id in deleted:
            deleted_index, _ = _entity_index(document, deleted_section, deleted_id)
            grouped.setdefault(deleted_section, []).append((deleted_index, deleted_id))
        patch: list[dict[str, Any]] = []
        edits: list[TextEdit] = []
        for deleted_section in sorted(grouped):
            deleted_items = grouped[deleted_section]
            indexes = {item[0] for item in deleted_items}
            deleted_section_pointer = _section_pointer(deleted_section)
            for deleted_index, deleted_id in sorted(deleted_items, reverse=True):
                deleted_pointer = f"{deleted_section_pointer}/{deleted_index}"
                patch.extend(
                    (
                        {
                            "op": "test",
                            "path": f"{deleted_pointer}/id",
                            "value": deleted_id,
                        },
                        {"op": "remove", "path": deleted_pointer},
                    )
                )
            edits.extend(
                _array_deletion_text_edits(
                    source_map,
                    section_pointer=deleted_section_pointer,
                    item_count=len(
                        _require_array_section(document, deleted_section)
                    ),
                    deleted_indexes=indexes,
                )
            )
        deleted_entities = [
            {"section": item[0], "id": item[1]} for item in sorted(deleted)
        ]
        return MutationPlan(
            operation="delete",
            target={
                "section": section,
                "id": entity_id,
                "affected_sections": sorted(grouped),
            },
            patch=patch,
            text_edits=tuple(edits),
            source_bytes_sha256=_source_bytes_sha256(source_text),
            metadata={
                "cascade": {
                    "enabled": True,
                    "policy": "delete_dependent_entity_closure",
                    "deleted_entity_count": len(deleted_entities),
                    "deleted_entities": deleted_entities,
                }
            },
        )

    edit = _array_deletion_text_edits(
        source_map,
        section_pointer=section_pointer,
        item_count=len(items),
        deleted_indexes={index},
    )[0]
    return MutationPlan(
        operation="delete",
        target={"section": section, "id": entity_id},
        patch=[
            {"op": "test", "path": f"{entity_pointer}/id", "value": entity_id},
            {"op": "remove", "path": entity_pointer},
        ],
        text_edits=(edit,),
        source_bytes_sha256=_source_bytes_sha256(source_text),
        metadata={"cascade": {"enabled": False}},
    )


def _apply_text_edits(source_text: str, edits: tuple[TextEdit, ...]) -> str:
    ordered = sorted(edits, key=lambda item: (item.start, item.end))
    for previous, current in zip(ordered, ordered[1:], strict=False):
        if previous.end > current.start:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "format-preserving text edits overlap",
                exit_code=2,
            )
    result = source_text
    crlf_count = source_text.count("\r\n")
    lone_lf_count = source_text.count("\n") - crlf_count
    source_newline = "\r\n" if crlf_count > 0 and lone_lf_count == 0 else "\n"
    for edit in reversed(ordered):
        if edit.start < 0 or edit.end < edit.start or edit.end > len(result):
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "format-preserving text edit range is invalid",
                exit_code=2,
            )
        replacement = edit.replacement.replace("\r\n", "\n")
        if source_newline != "\n":
            replacement = replacement.replace("\n", source_newline)
        result = result[: edit.start] + replacement + result[edit.end :]
    return result


def _apply_json_patch(document: LoadedDocument, plan: MutationPlan) -> JsonValue:
    jsonpatch = require_dependency("jsonpatch")
    try:
        return jsonpatch.JsonPatch(plan.patch).apply(document.data, in_place=False)
    except Exception as error:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "RFC 6902 mutation failed in memory",
            exit_code=2,
            details={"exception_type": type(error).__name__, "reason": str(error)},
        ) from error


def _validate_section_ids(document: LoadedDocument, section: str) -> None:
    items = _require_array_section(document, section)
    ids: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ArchitectureQueryError(
                "ARCH_MODEL_INVALID",
                "mutated entity section contains an item without a stable id",
                exit_code=4,
                location=f"{_section_pointer(section)}/{index}",
            )
        entity_id = item["id"]
        if entity_id in ids:
            raise ArchitectureQueryError(
                "ARCH_DUPLICATE_ID",
                "mutated entity section contains a duplicate id",
                exit_code=4,
                location=f"{_section_pointer(section)}/{index}/id",
                details={"section": section, "id": entity_id},
            )
        ids.add(entity_id)


def _unified_diff(path: Path, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path.as_posix()}",
            tofile=f"b/{path.as_posix()}",
        )
    )


def atomic_replace(
    path: Path,
    *,
    expected_bytes: bytes,
    candidate_text: str,
) -> None:
    try:
        current_bytes = path.read_bytes()
    except OSError as error:
        raise ArchitectureQueryError(
            "ARCH_WRITE_FAILED",
            "unable to re-read mutation target before atomic replace",
            exit_code=10,
            details={"reason": str(error)},
        ) from error
    if current_bytes != expected_bytes:
        raise ArchitectureQueryError(
            "ARCH_STALE_SOURCE",
            "source bytes changed after mutation planning",
            exit_code=8,
            details={"path": str(path)},
        )

    temporary_path: Path | None = None
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(candidate_text.encode("utf-8"))
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
        temporary_path = None
        if hasattr(os, "O_DIRECTORY"):
            try:
                directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
    except ArchitectureQueryError:
        raise
    except OSError as error:
        raise ArchitectureQueryError(
            "ARCH_WRITE_FAILED",
            "atomic JSON replacement failed",
            exit_code=10,
            details={"reason": str(error)},
        ) from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def execute_mutation(
    document: LoadedDocument,
    *,
    plan: MutationPlan,
    expected_sha256: str,
    apply: bool,
) -> dict[str, Any]:
    if SHA256_PATTERN.fullmatch(expected_sha256) is None:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "--expected-sha256 must use sha256:<64 lowercase hex characters>",
            exit_code=2,
        )
    if document.canonical_sha256 != expected_sha256:
        raise ArchitectureQueryError(
            "ARCH_STALE_SOURCE",
            "source canonical digest does not match --expected-sha256",
            exit_code=8,
            details={
                "expected_sha256": expected_sha256,
                "actual_sha256": document.canonical_sha256,
            },
        )
    if document.validation != "schema":
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "mutations require --validation schema",
            exit_code=2,
        )

    path = document_absolute_path(document)
    try:
        original_bytes = path.read_bytes()
        source_text = original_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ArchitectureQueryError(
            "ARCH_WRITE_FAILED",
            "unable to read mutation source bytes",
            exit_code=10,
            details={"reason": str(error)},
        ) from error
    current_data = parse_json_text(
        source_text, location=document.path.as_posix(), kind="source"
    )
    if hashlib.sha256(original_bytes).hexdigest() != plan.source_bytes_sha256:
        raise ArchitectureQueryError(
            "ARCH_STALE_SOURCE",
            "source bytes changed after mutation planning",
            exit_code=8,
            details={"path": document.path.as_posix()},
        )
    if canonical_digest(current_data) != document.canonical_sha256:
        raise ArchitectureQueryError(
            "ARCH_STALE_SOURCE",
            "source changed after query loading",
            exit_code=8,
            details={"path": document.path.as_posix()},
        )

    after_data = _apply_json_patch(document, plan)
    candidate_text = _apply_text_edits(source_text, plan.text_edits)
    parsed_candidate = parse_json_text(
        candidate_text, location=document.path.as_posix(), kind="candidate"
    )
    if canonical_digest(parsed_candidate) != canonical_digest(after_data):
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "format-preserving text edit does not equal RFC 6902 result",
            exit_code=2,
            details={"operation": plan.operation},
        )
    if canonical_digest(after_data) == document.canonical_sha256:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            "mutation would not change the document",
            exit_code=2,
        )

    candidate_document = validate_candidate_data(
        document,
        after_data,
        source_size_bytes=len(candidate_text.encode("utf-8")),
    )
    affected_sections = plan.target.get("affected_sections", [plan.target["section"]])
    for section in affected_sections:
        _validate_section_ids(candidate_document, section)
    profile_validation = "stable_id_section"
    if candidate_document.model_id == "runtime-v3":
        RuntimeV3Profile(candidate_document)
        build_reference_index(candidate_document)
        profile_validation = "runtime_v3_identity_and_declared_references"

    diff = _unified_diff(document.path, source_text, candidate_text)
    result = {
        "kind": "mutation",
        "operation": plan.operation,
        "mode": "applied" if apply else "dry_run",
        "applied": apply,
        "changed": True,
        "target": plan.target,
        "before_sha256": document.canonical_sha256,
        "after_sha256": candidate_document.canonical_sha256,
        "patch": plan.patch,
        "validation": {
            "schema": True,
            "profile": profile_validation,
            "text_matches_patch": True,
        },
        "diff": diff,
        **plan.metadata,
    }
    compact_result = json.dumps(
        result,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    pretty_result = json.dumps(
        result,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
    )
    # In the JSON envelope, every pretty-printed result line is nested one
    # additional level. Reserve that indentation plus ample source/query metadata.
    serialized_result_size = max(
        len(compact_result.encode("utf-8")),
        len(pretty_result.encode("utf-8")) + 2 * (pretty_result.count("\n") + 1),
    )
    if serialized_result_size > MAX_OUTPUT_BYTES - 16 * 1024:
        raise ArchitectureQueryError(
            "ARCH_RESULT_TOO_LARGE",
            "mutation preview exceeds the safe output ceiling; split the mutation",
            exit_code=6,
            details={
                "max_output_bytes": MAX_OUTPUT_BYTES,
                "result_size_bytes": serialized_result_size,
            },
        )
    if apply:
        atomic_replace(
            path,
            expected_bytes=original_bytes,
            candidate_text=candidate_text,
        )
    return result
