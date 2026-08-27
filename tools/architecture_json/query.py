"""Generic bounded query operations over a loaded JSON document."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

from .dependencies import require_dependency
from .errors import ArchitectureQueryError
from .loader import JsonValue, LoadedDocument


MAX_TREE_NODES = 1000


@dataclass(frozen=True)
class ExactFieldPredicate:
    field: str
    expected: JsonValue


@dataclass(frozen=True)
class QueryPage:
    items: list[JsonValue]
    total: int
    offset: int
    limit: int
    returned: int
    truncated: bool

    def to_result(self) -> dict[str, Any]:
        return {
            "kind": "list",
            "total": self.total,
            "offset": self.offset,
            "limit": self.limit,
            "returned": self.returned,
            "truncated": self.truncated,
            "items": self.items,
        }


def json_type(value: JsonValue) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def resolve_pointer(document: LoadedDocument, pointer: str) -> JsonValue:
    jsonpointer = require_dependency("jsonpointer")
    sentinel = object()
    try:
        value = jsonpointer.resolve_pointer(document.data, pointer, default=sentinel)
    except Exception as error:
        if error.__class__.__module__.startswith("jsonpointer"):
            raise ArchitectureQueryError(
                "ARCH_QUERY_INVALID",
                "JSON Pointer syntax is invalid",
                exit_code=2,
                location=pointer,
                details={"reason": str(error)},
            ) from error
        raise
    if value is sentinel:
        raise ArchitectureQueryError(
            "ARCH_POINTER_NOT_FOUND",
            "JSON Pointer target was not found",
            exit_code=5,
            location=pointer,
        )
    return value


def select_jmespath(document: LoadedDocument, expression: str) -> JsonValue:
    jmespath = require_dependency("jmespath")
    try:
        compiled = jmespath.compile(expression)
        result = compiled.search(document.data)
        if result is document.data:
            raise ArchitectureQueryError(
                "ARCH_RESULT_TOO_LARGE",
                "whole-document projection is forbidden; request a semantic slice",
                exit_code=6,
                details={"expression": expression, "reason": "whole_document"},
            )
        return result
    except ArchitectureQueryError:
        raise
    except Exception as error:
        if error.__class__.__module__.startswith("jmespath"):
            raise ArchitectureQueryError(
                "ARCH_QUERY_INVALID",
                "JMESPath expression is invalid",
                exit_code=2,
                details={"expression": expression, "reason": str(error)},
            ) from error
        raise


def _require_array_section(document: LoadedDocument, section: str) -> list[JsonValue]:
    if not isinstance(document.data, dict) or section not in document.data:
        raise ArchitectureQueryError(
            "ARCH_SECTION_UNKNOWN",
            "JSON section is unknown",
            exit_code=5,
            location=f"/{section}",
            details={"section": section},
        )
    value = document.data[section]
    if not isinstance(value, list):
        raise ArchitectureQueryError(
            "ARCH_QUERY_INVALID",
            "list command requires an array section",
            exit_code=2,
            location=f"/{section}",
            details={"section": section, "actual_type": json_type(value)},
        )
    return value


def _sort_key(item: JsonValue, fields: tuple[str, ...]) -> tuple[Any, ...]:
    if not isinstance(item, dict):
        return tuple((1, "") for _ in fields)
    keys: list[tuple[int, str]] = []
    for field in fields:
        value = item.get(field)
        if value is None:
            keys.append((1, ""))
        elif isinstance(value, str):
            keys.append((0, value))
        else:
            keys.append(
                (
                    0,
                    json.dumps(
                        value,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ),
                )
            )
    return tuple(keys)


def paginate_values(
    values: Iterable[JsonValue],
    *,
    offset: int,
    limit: int,
) -> QueryPage:
    if offset < 0 or limit < 1 or limit > 500:
        raise ArchitectureQueryError(
            "ARCH_USAGE_INVALID",
            "pagination requires offset >= 0 and 1 <= limit <= 500",
            exit_code=2,
            details={"offset": offset, "limit": limit},
        )
    materialized = list(values)
    selected = materialized[offset : offset + limit]
    return QueryPage(
        items=selected,
        total=len(materialized),
        offset=offset,
        limit=limit,
        returned=len(selected),
        truncated=offset + len(selected) < len(materialized),
    )


def project_fields(item: JsonValue, fields: tuple[str, ...] | None) -> JsonValue:
    if fields is None:
        return item
    if not isinstance(item, dict):
        return item
    return {field: item[field] for field in fields if field in item}


def list_section(
    document: LoadedDocument,
    *,
    section: str,
    where: tuple[ExactFieldPredicate, ...] = (),
    fields: tuple[str, ...] | None = None,
    sort: tuple[str, ...] | None = None,
    offset: int = 0,
    limit: int = 50,
) -> QueryPage:
    items = _require_array_section(document, section)
    filtered: list[JsonValue] = []
    for item in items:
        if where and not isinstance(item, dict):
            continue
        if all(
            isinstance(item, dict) and item.get(predicate.field) == predicate.expected
            for predicate in where
        ):
            filtered.append(item)
    if sort:
        filtered.sort(key=lambda item: _sort_key(item, sort))
    page = paginate_values(filtered, offset=offset, limit=limit)
    projected = [project_fields(item, fields) for item in page.items]
    return QueryPage(
        items=projected,
        total=page.total,
        offset=page.offset,
        limit=page.limit,
        returned=page.returned,
        truncated=page.truncated,
    )


def section_inventory(document: LoadedDocument) -> QueryPage:
    if not isinstance(document.data, dict):
        values: list[JsonValue] = [
            {"name": "", "type": json_type(document.data), "count": None}
        ]
    else:
        values = []
        for name, value in document.data.items():
            entry: dict[str, JsonValue] = {"name": name, "type": json_type(value)}
            entry["count"] = len(value) if isinstance(value, (list, dict)) else None
            values.append(entry)
    return paginate_values(values, offset=0, limit=min(500, max(1, len(values))))


def document_summary(document: LoadedDocument) -> dict[str, Any]:
    sections = section_inventory(document).items
    counts = {
        item["name"]: item["count"]
        for item in sections
        if isinstance(item, dict) and item.get("count") is not None
    }
    return {
        "kind": "summary",
        "root_type": json_type(document.data),
        "top_level_field_count": len(document.data)
        if isinstance(document.data, dict)
        else 0,
        "section_counts": counts,
    }


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _tree_node(
    value: JsonValue,
    *,
    pointer: str,
    name: str | None,
    depth: int,
    include_values: bool,
    remaining_nodes: list[int],
) -> dict[str, Any]:
    remaining_nodes[0] -= 1
    node: dict[str, Any] = {
        "pointer": pointer,
        "type": json_type(value),
        "child_count": len(value) if isinstance(value, (list, dict)) else 0,
    }
    if name is not None:
        node["name"] = name
    if not isinstance(value, (list, dict)):
        if include_values:
            node["leaf"] = value
        return node
    if depth <= 0:
        node["truncated"] = bool(value)
        return node
    children: list[dict[str, Any]] = []
    iterable = value.items() if isinstance(value, dict) else enumerate(value)
    for child_name, child_value in iterable:
        if remaining_nodes[0] <= 0:
            break
        child_text = str(child_name)
        child_pointer = pointer + "/" + _escape_pointer(child_text)
        children.append(
            _tree_node(
                child_value,
                pointer=child_pointer,
                name=child_text,
                depth=depth - 1,
                include_values=include_values,
                remaining_nodes=remaining_nodes,
            )
        )
    node["children"] = children
    node["truncated"] = len(children) < len(value) or any(
        child.get("truncated", False) for child in children
    )
    return node


def describe_tree(
    document: LoadedDocument,
    *,
    pointer: str = "",
    depth: int = 2,
    include_values: bool = False,
) -> dict[str, Any]:
    if depth < 0 or depth > 20:
        raise ArchitectureQueryError(
            "ARCH_USAGE_INVALID",
            "tree depth must be between 0 and 20",
            exit_code=2,
            details={"depth": depth},
        )
    value = resolve_pointer(document, pointer)
    name = None if pointer == "" else pointer.rsplit("/", 1)[-1]
    tree = _tree_node(
        value,
        pointer=pointer,
        name=name,
        depth=depth,
        include_values=include_values,
        remaining_nodes=[MAX_TREE_NODES],
    )
    tree["depth"] = depth
    return tree
