"""Query metadata for the Runtime V3 business-flow model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..errors import ArchitectureQueryError
from ..loader import JsonValue, LoadedDocument


@dataclass(frozen=True)
class EntitySection:
    id_field: str = "id"
    module_relation: str | None = None


ENTITY_SECTIONS: dict[str, EntitySection] = {
    "modules": EntitySection(),
    "transport_media": EntitySection(),
    "state_regions": EntitySection(module_relation="owner_module"),
    "outcome_classes": EntitySection(),
    "type_definitions": EntitySection(module_relation="owner_module"),
    "message_schemas": EntitySection(),
    "events": EntitySection(module_relation="source_module"),
    "capabilities": EntitySection(module_relation="owner_module"),
    "resources": EntitySection(module_relation="owner_module"),
    "composites": EntitySection(),
    "partial_orders": EntitySection(),
    "transitions": EntitySection(),
    "invariants": EntitySection(),
    "presentation_rules": EntitySection(),
    "terminal_state_classes": EntitySection(),
    "scenario_obligations": EntitySection(),
}


class RuntimeV3Profile:
    """Stable-ID indexes and declared module relations for Runtime V3."""

    def __init__(self, document: LoadedDocument) -> None:
        if document.model_id != "runtime-v3":
            raise ArchitectureQueryError(
                "ARCH_QUERY_INVALID",
                "Runtime V3 semantic commands require --model runtime-v3",
                exit_code=2,
            )
        if not isinstance(document.data, dict):
            raise ArchitectureQueryError(
                "ARCH_MODEL_INVALID",
                "Runtime V3 model root must be an object",
                exit_code=4,
            )
        self.document = document
        self.entity_sections = tuple(ENTITY_SECTIONS)
        self._indexes: dict[str, dict[str, dict[str, JsonValue]]] = {}
        for section, specification in ENTITY_SECTIONS.items():
            items = document.data.get(section)
            if not isinstance(items, list):
                raise ArchitectureQueryError(
                    "ARCH_MODEL_INVALID",
                    "Runtime V3 entity section must be an array",
                    exit_code=4,
                    location=f"/{section}",
                    details={"section": section},
                )
            index: dict[str, dict[str, JsonValue]] = {}
            for offset, item in enumerate(items):
                if not isinstance(item, dict) or not isinstance(
                    item.get(specification.id_field), str
                ):
                    raise ArchitectureQueryError(
                        "ARCH_MODEL_INVALID",
                        "Runtime V3 entity lacks a stable string id",
                        exit_code=4,
                        location=f"/{section}/{offset}",
                    )
                entity_id = item[specification.id_field]
                if entity_id in index:
                    raise ArchitectureQueryError(
                        "ARCH_DUPLICATE_ID",
                        "Runtime V3 entity id is duplicated",
                        exit_code=4,
                        location=f"/{section}/{offset}/{specification.id_field}",
                        details={"section": section, "id": entity_id},
                    )
                index[entity_id] = item
            self._indexes[section] = index
        modules = self._indexes["modules"]
        for section, specification in ENTITY_SECTIONS.items():
            relation = specification.module_relation
            if relation is None:
                continue
            for entity_id, item in self._indexes[section].items():
                module_id = item.get(relation)
                if not isinstance(module_id, str) or module_id not in modules:
                    raise ArchitectureQueryError(
                        "ARCH_MODEL_INVALID",
                        "Runtime V3 entity references an unknown module",
                        exit_code=4,
                        location=f"/{section}/{entity_id}/{relation}",
                        details={
                            "section": section,
                            "id": entity_id,
                            "relation": relation,
                            "module_id": module_id,
                        },
                    )

    def ids(self, section: str) -> tuple[str, ...]:
        return tuple(self._section_index(section))

    def _section_index(self, section: str) -> dict[str, dict[str, JsonValue]]:
        index = self._indexes.get(section)
        if index is None:
            raise ArchitectureQueryError(
                "ARCH_SECTION_UNKNOWN",
                "Runtime V3 entity section is unknown",
                exit_code=5,
                location=f"/{section}",
                details={"section": section},
            )
        return index

    def get_entity(self, section: str, entity_id: str) -> dict[str, JsonValue]:
        entity = self._section_index(section).get(entity_id)
        if entity is None:
            raise ArchitectureQueryError(
                "ARCH_ENTITY_NOT_FOUND",
                "entity id was not found",
                exit_code=5,
                location=f"/{section}",
                details={"section": section, "id": entity_id},
            )
        return entity

    def _require_module(self, module_id: str) -> None:
        if module_id not in self._section_index("modules"):
            raise ArchitectureQueryError(
                "ARCH_ENTITY_NOT_FOUND",
                "module id was not found",
                exit_code=5,
                location="/modules",
                details={"section": "modules", "id": module_id},
            )

    def capabilities_for_module(self, module_id: str) -> list[dict[str, JsonValue]]:
        self._require_module(module_id)
        return [
            item
            for item in self._section_index("capabilities").values()
            if item.get("owner_module") == module_id
        ]

    def members_for_module(
        self,
        module_id: str,
        *,
        kinds: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        self._require_module(module_id)
        members: list[dict[str, Any]] = []
        for section in kinds:
            specification = ENTITY_SECTIONS.get(section)
            if specification is None:
                raise ArchitectureQueryError(
                    "ARCH_SECTION_UNKNOWN",
                    "Runtime V3 member section is unknown",
                    exit_code=5,
                    details={"section": section},
                )
            relation = specification.module_relation
            if relation is None:
                raise ArchitectureQueryError(
                    "ARCH_QUERY_INVALID",
                    "section has no declared direct module relation",
                    exit_code=2,
                    details={"section": section},
                )
            for item in self._section_index(section).values():
                if item.get(relation) == module_id:
                    members.append(
                        {
                            "section": section,
                            "relation": relation,
                            "id": item[specification.id_field],
                            "item": item,
                        }
                    )
        return members
