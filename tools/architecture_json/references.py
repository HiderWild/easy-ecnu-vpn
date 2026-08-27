"""Explicit Runtime V3 semantic references and conservative generic references."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Literal

from .errors import ArchitectureQueryError
from .loader import JsonValue, LoadedDocument
from .profiles.runtime_v3 import ENTITY_SECTIONS, RuntimeV3Profile


PathPart = str | int
ReferenceLocation = Literal["value", "key"]


def escape_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def pointer_from_parts(parts: Iterable[PathPart]) -> str:
    encoded = [escape_pointer_token(str(part)) for part in parts]
    return "" if not encoded else "/" + "/".join(encoded)


@dataclass(frozen=True)
class Reference:
    target_section: str
    target_id: str
    source_pointer: str
    relation: str
    location: ReferenceLocation
    reference_kind: str
    source_entity_section: str | None
    source_entity_id: str | None
    source_entity_pointer: str | None

    def to_result(self) -> dict[str, Any]:
        return {
            "target_section": self.target_section,
            "target_id": self.target_id,
            "source_pointer": self.source_pointer,
            "relation": self.relation,
            "location": self.location,
            "reference_kind": self.reference_kind,
            "source_entity": (
                {
                    "section": self.source_entity_section,
                    "id": self.source_entity_id,
                    "pointer": self.source_entity_pointer,
                }
                if self.source_entity_section is not None
                else None
            ),
        }


@dataclass(frozen=True)
class ReferenceRule:
    target_section: str
    pattern: tuple[str, ...]
    relation: str
    location: ReferenceLocation = "value"
    allow_unresolved: bool = False
    source_id: str | None = None


def _value_rule(
    target: str,
    pattern: str,
    relation: str,
    *,
    allow_unresolved: bool = False,
    source_id: str | None = None,
) -> ReferenceRule:
    return ReferenceRule(
        target_section=target,
        pattern=tuple(part for part in pattern.split("/") if part),
        relation=relation,
        allow_unresolved=allow_unresolved,
        source_id=source_id,
    )


def _key_rule(
    target: str, pattern: str, relation: str, *, allow_unresolved: bool = False
) -> ReferenceRule:
    return ReferenceRule(
        target_section=target,
        pattern=tuple(part for part in pattern.split("/") if part),
        relation=relation,
        location="key",
        allow_unresolved=allow_unresolved,
    )


RUNTIME_V3_REFERENCE_RULES: tuple[ReferenceRule, ...] = (
    # Module ownership and caller authority.
    _value_rule(
        "modules", "/state_regions/*/owner_module", "state_region.owner_module"
    ),
    _value_rule(
        "modules", "/type_definitions/*/owner_module", "type_definition.owner_module"
    ),
    _value_rule("modules", "/events/*/source_module", "event.source_module"),
    _value_rule("modules", "/capabilities/*/owner_module", "capability.owner_module"),
    _value_rule(
        "modules", "/capabilities/*/allowed_callers/*", "capability.allowed_caller"
    ),
    _value_rule("modules", "/resources/*/owner_module", "resource.owner_module"),
    # Invocation media.
    _value_rule(
        "transport_media",
        "/capabilities/*/invocation/allowed_media/*",
        "capability.allowed_medium",
    ),
    # Type graph.
    _value_rule(
        "type_definitions", "/type_definitions/*/target", "type_definition.alias_target"
    ),
    _value_rule(
        "type_definitions", "/type_definitions/*/item_type", "type_definition.item_type"
    ),
    _value_rule(
        "type_definitions",
        "/type_definitions/*/fields/*/type",
        "type_definition.field_type",
    ),
    _value_rule(
        "type_definitions",
        "/message_schemas/*/fields/*/type",
        "message_schema.field_type",
    ),
    # Message schemas.
    _value_rule("message_schemas", "/events/*/payload_schema", "event.payload_schema"),
    _value_rule(
        "message_schemas", "/capabilities/*/request_schema", "capability.request_schema"
    ),
    _value_rule(
        "message_schemas",
        "/capabilities/*/response_schema",
        "capability.response_schema",
    ),
    # Events.
    _value_rule("events", "/product_api/actions/*/event", "product_action.event"),
    _value_rule(
        "events", "/capabilities/*/completion_event", "capability.completion_event"
    ),
    _value_rule("events", "/transitions/*/event", "transition.event"),
    _value_rule("events", "/invariants/*/events/*", "invariant.event"),
    _value_rule(
        "events", "/scenario_obligations/*/required_events/*", "scenario.required_event"
    ),
    _value_rule(
        "events",
        "/scenario_obligations/*/interruptions/*",
        "scenario.interruption_event",
    ),
    # Capabilities, including object-key projections.
    _value_rule(
        "capabilities",
        "/completion_requirements/*/capability",
        "completion_requirement.capability",
    ),
    _value_rule(
        "capabilities",
        "/resources/*/acquire_capabilities/*",
        "resource.acquire_capability",
    ),
    _value_rule(
        "capabilities", "/resources/*/release_capability", "resource.release_capability"
    ),
    _value_rule(
        "capabilities", "/composites/*/parent_capability", "composite.parent_capability"
    ),
    _value_rule(
        "capabilities",
        "/composites/*/child_capabilities/*",
        "composite.child_capability",
    ),
    _key_rule(
        "capabilities",
        "/composites/*/child_request_fields",
        "composite.child_request_projection",
    ),
    _key_rule(
        "capabilities",
        "/composites/*/child_success_fields",
        "composite.child_success_projection",
    ),
    _value_rule("capabilities", "/partial_orders/*/nodes/*", "partial_order.node"),
    _value_rule(
        "capabilities", "/partial_orders/*/edges/*/before", "partial_order.before"
    ),
    _value_rule(
        "capabilities", "/partial_orders/*/edges/*/after", "partial_order.after"
    ),
    _value_rule(
        "capabilities",
        "/partial_orders/*/parallel_groups/*/*",
        "partial_order.parallel_member",
    ),
    _value_rule(
        "capabilities",
        "/transitions/*/effects/*/capability",
        "transition.effect_capability",
    ),
    _value_rule(
        "capabilities",
        "/scenario_obligations/*/required_capabilities/*",
        "scenario.required_capability",
    ),
    # Resources.
    _value_rule(
        "resources", "/capabilities/*/acquires_resource", "capability.acquires_resource"
    ),
    _value_rule(
        "resources", "/capabilities/*/releases_resource", "capability.releases_resource"
    ),
    _value_rule(
        "resources",
        "/capabilities/*/reconciles_resources/*",
        "capability.reconciles_resource",
    ),
    _value_rule("resources", "/resources/*/depends_on/*", "resource.depends_on"),
    _value_rule(
        "resources", "/transitions/*/effects/*/resource", "transition.effect_resource"
    ),
    _value_rule(
        "resources",
        "/transitions/*/effects/*/arguments/reconcile_resources/*",
        "transition.reconcile_resource",
    ),
    # Outcome algebra.
    _value_rule(
        "outcome_classes",
        "/capabilities/*/allowed_outcomes/*",
        "capability.allowed_outcome",
    ),
    _value_rule(
        "outcome_classes",
        "/completion_requirements/*/outcomes/*",
        "completion_requirement.outcome",
    ),
    _value_rule(
        "outcome_classes",
        "/composites/*/aggregate_priority/*",
        "composite.aggregate_outcome",
    ),
    _key_rule(
        "outcome_classes",
        "/composites/*/child_outcome_map",
        "composite.child_outcome",
        allow_unresolved=True,
    ),
    _value_rule(
        "outcome_classes",
        "/composites/*/child_outcome_map/*",
        "composite.aggregate_outcome_map",
    ),
    _value_rule("outcome_classes", "/transitions/*/outcomes/*", "transition.outcome"),
    _value_rule(
        "outcome_classes",
        "/scenario_obligations/*/fault_classes/*",
        "scenario.fault_class",
    ),
    _value_rule(
        "outcome_classes",
        "/message_schemas/*/conditional_requirements/*/when/outcome_class",
        "message.outcome_guard",
    ),
    _value_rule(
        "outcome_classes",
        "/type_definitions/*/values/*",
        "outcome_type.value",
        source_id="OutcomeClass",
    ),
    # Invariants and terminal classes.
    _value_rule(
        "invariants", "/transitions/*/guard_invariants/*", "transition.guard_invariant"
    ),
    _value_rule(
        "invariants",
        "/scenario_obligations/*/expected_invariants/*",
        "scenario.expected_invariant",
    ),
    _value_rule(
        "terminal_state_classes",
        "/scenario_obligations/*/terminal_classes/*",
        "scenario.terminal_class",
    ),
    # State-region identity appears both as values and as dynamic object keys.
    _value_rule(
        "state_regions", "/transitions/*/effects/*/region", "transition.effect_region"
    ),
    _value_rule(
        "state_regions",
        "/invariants/*/preserves_regions/*",
        "invariant.preserved_region",
    ),
    _key_rule(
        "state_regions",
        "/product_api/projection_rules/*/when",
        "product_projection.state_region",
    ),
    _key_rule("state_regions", "/transitions/*/from", "transition.source_region"),
    _key_rule("state_regions", "/invariants/*/if", "invariant.if_region"),
    _key_rule("state_regions", "/invariants/*/then", "invariant.then_region"),
    _key_rule(
        "state_regions",
        "/terminal_state_classes/*/any_of/*",
        "terminal_class.state_region",
    ),
    _key_rule(
        "state_regions", "/presentation_rules/*/when", "presentation_rule.state_region"
    ),
)


def _iter_pattern(
    value: JsonValue,
    pattern: tuple[str, ...],
    *,
    path: tuple[PathPart, ...] = (),
) -> Iterable[tuple[tuple[PathPart, ...], JsonValue]]:
    if not pattern:
        yield path, value
        return
    token, remaining = pattern[0], pattern[1:]
    if token == "*":
        if isinstance(value, list):
            for index, child in enumerate(value):
                yield from _iter_pattern(child, remaining, path=path + (index,))
        elif isinstance(value, dict):
            for key, child in value.items():
                yield from _iter_pattern(child, remaining, path=path + (key,))
        return
    if isinstance(value, dict) and token in value:
        yield from _iter_pattern(value[token], remaining, path=path + (token,))


def _source_entity(
    document: LoadedDocument,
    path: tuple[PathPart, ...],
) -> tuple[str | None, str | None, str | None]:
    if len(path) < 2 or not isinstance(path[0], str) or not isinstance(path[1], int):
        return None, None, None
    section = path[0]
    if not isinstance(document.data, dict):
        return None, None, None
    values = document.data.get(section)
    if not isinstance(values, list) or path[1] >= len(values):
        return None, None, None
    entity = values[path[1]]
    if not isinstance(entity, dict) or not isinstance(entity.get("id"), str):
        return None, None, None
    return section, entity["id"], pointer_from_parts(path[:2])


class ReferenceIndex:
    """Incoming/outgoing reference graph bound to one loaded document."""

    def __init__(
        self, document: LoadedDocument, references: Iterable[Reference]
    ) -> None:
        self.document = document
        self.references = tuple(
            sorted(
                references,
                key=lambda item: (
                    item.target_section,
                    item.target_id,
                    item.source_pointer,
                    item.location,
                ),
            )
        )

    def incoming(self, section: str, entity_id: str) -> list[Reference]:
        return [
            item
            for item in self.references
            if item.target_section == section and item.target_id == entity_id
        ]

    def outgoing(self, section: str, entity_id: str) -> list[Reference]:
        return [
            item
            for item in self.references
            if item.source_entity_section == section
            and item.source_entity_id == entity_id
        ]

    def trace(
        self,
        section: str,
        entity_id: str,
        *,
        direction: Literal["incoming", "outgoing", "both"],
        depth: int,
        max_nodes: int = 500,
    ) -> dict[str, Any]:
        if depth < 0 or depth > 8:
            raise ArchitectureQueryError(
                "ARCH_QUERY_INVALID",
                "reference trace depth must be between 0 and 8",
                exit_code=2,
                details={"depth": depth},
            )
        start = (section, entity_id)
        distances = {start: 0}
        pending = [start]
        edge_results: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        while pending:
            current_section, current_id = pending.pop(0)
            distance = distances[(current_section, current_id)]
            if distance >= depth:
                continue
            candidates: list[tuple[str, Reference, tuple[str, str] | None]] = []
            if direction in ("outgoing", "both"):
                candidates.extend(
                    (
                        "outgoing",
                        reference,
                        (reference.target_section, reference.target_id),
                    )
                    for reference in self.outgoing(current_section, current_id)
                )
            if direction in ("incoming", "both"):
                candidates.extend(
                    (
                        "incoming",
                        reference,
                        (
                            reference.source_entity_section,
                            reference.source_entity_id,
                        )
                        if reference.source_entity_section is not None
                        and reference.source_entity_id is not None
                        else None,
                    )
                    for reference in self.incoming(current_section, current_id)
                )
            for traversal, reference, next_node in candidates:
                edge_key = (
                    traversal,
                    reference.target_section,
                    reference.target_id,
                    reference.source_pointer,
                    reference.location,
                )
                edge_results.setdefault(
                    edge_key,
                    {
                        **reference.to_result(),
                        "traversal": traversal,
                        "distance": distance + 1,
                    },
                )
                if next_node is None or next_node in distances:
                    continue
                if len(distances) >= max_nodes:
                    raise ArchitectureQueryError(
                        "ARCH_RESULT_TOO_LARGE",
                        "reference trace exceeds the node safety ceiling",
                        exit_code=6,
                        details={"max_nodes": max_nodes, "depth": depth},
                    )
                distances[next_node] = distance + 1
                pending.append(next_node)
        nodes = [
            {"section": node[0], "id": node[1], "distance": distance}
            for node, distance in sorted(
                distances.items(), key=lambda item: (item[1], item[0])
            )
        ]
        return {
            "kind": "reference_trace",
            "start": {"section": section, "id": entity_id},
            "direction": direction,
            "depth": depth,
            "node_count": len(nodes),
            "edge_count": len(edge_results),
            "nodes": nodes,
            "edges": list(edge_results.values()),
        }


def _runtime_reference_index(document: LoadedDocument) -> ReferenceIndex:
    profile = RuntimeV3Profile(document)
    catalogs = {section: set(profile.ids(section)) for section in ENTITY_SECTIONS}
    references: list[Reference] = []
    seen: set[tuple[str, str, str, str]] = set()
    for rule in RUNTIME_V3_REFERENCE_RULES:
        targets = catalogs[rule.target_section]
        for path, value in _iter_pattern(document.data, rule.pattern):
            source_section, source_id, source_pointer = _source_entity(document, path)
            if rule.source_id is not None and source_id != rule.source_id:
                continue
            if rule.location == "key":
                if not isinstance(value, dict):
                    raise ArchitectureQueryError(
                        "ARCH_MODEL_INVALID",
                        "declared key-reference container is not an object",
                        exit_code=4,
                        location=pointer_from_parts(path),
                        details={"relation": rule.relation},
                    )
                candidates = [
                    (path + (key,), key) for key in value if isinstance(key, str)
                ]
            else:
                candidates = [(path, value)]
            for candidate_path, candidate in candidates:
                if candidate is None:
                    continue
                if not isinstance(candidate, str):
                    raise ArchitectureQueryError(
                        "ARCH_MODEL_INVALID",
                        "declared reference must be a string or null",
                        exit_code=4,
                        location=pointer_from_parts(candidate_path),
                        details={"relation": rule.relation},
                    )
                if candidate not in targets:
                    if rule.allow_unresolved:
                        continue
                    raise ArchitectureQueryError(
                        "ARCH_MODEL_INVALID",
                        "Runtime V3 semantic reference target is unknown",
                        exit_code=4,
                        location=pointer_from_parts(candidate_path),
                        details={
                            "relation": rule.relation,
                            "target_section": rule.target_section,
                            "target_id": candidate,
                        },
                    )
                pointer = pointer_from_parts(candidate_path)
                identity = (rule.target_section, candidate, pointer, rule.location)
                if identity in seen:
                    continue
                seen.add(identity)
                references.append(
                    Reference(
                        target_section=rule.target_section,
                        target_id=candidate,
                        source_pointer=pointer,
                        relation=rule.relation,
                        location=rule.location,
                        reference_kind=f"declared_{rule.location}",
                        source_entity_section=source_section,
                        source_entity_id=source_id,
                        source_entity_pointer=source_pointer,
                    )
                )
    return ReferenceIndex(document, references)


def _generic_reference_index(document: LoadedDocument) -> ReferenceIndex:
    if not isinstance(document.data, dict):
        raise ArchitectureQueryError(
            "ARCH_MODEL_INVALID",
            "generic stable-ID reference indexing requires an object root",
            exit_code=4,
        )
    id_sections: dict[str, list[str]] = {}
    identity_pointers: set[str] = set()
    for section, values in document.data.items():
        if not isinstance(values, list):
            continue
        for index, item in enumerate(values):
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            entity_id = item["id"]
            id_sections.setdefault(entity_id, []).append(section)
            identity_pointers.add(pointer_from_parts((section, index, "id")))

    references: list[Reference] = []

    def visit(value: JsonValue, path: tuple[PathPart, ...] = ()) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_path = path + (key,)
                sections = id_sections.get(key, [])
                if sections:
                    if len(sections) > 1:
                        raise ArchitectureQueryError(
                            "ARCH_REFERENCE_AMBIGUOUS",
                            "generic exact key reference matches IDs in multiple sections",
                            exit_code=4,
                            location=pointer_from_parts(key_path),
                            details={"id": key, "sections": sections},
                        )
                    source_section, source_id, source_pointer = _source_entity(
                        document, key_path
                    )
                    references.append(
                        Reference(
                            target_section=sections[0],
                            target_id=key,
                            source_pointer=pointer_from_parts(key_path),
                            relation="generic.exact_key",
                            location="key",
                            reference_kind="exact_string",
                            source_entity_section=source_section,
                            source_entity_id=source_id,
                            source_entity_pointer=source_pointer,
                        )
                    )
                visit(child, key_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + (index,))
        elif isinstance(value, str):
            pointer = pointer_from_parts(path)
            if pointer in identity_pointers:
                return
            sections = id_sections.get(value, [])
            if not sections:
                return
            if len(sections) > 1:
                raise ArchitectureQueryError(
                    "ARCH_REFERENCE_AMBIGUOUS",
                    "generic exact value reference matches IDs in multiple sections",
                    exit_code=4,
                    location=pointer,
                    details={"id": value, "sections": sections},
                )
            source_section, source_id, source_pointer = _source_entity(document, path)
            references.append(
                Reference(
                    target_section=sections[0],
                    target_id=value,
                    source_pointer=pointer,
                    relation="generic.exact_value",
                    location="value",
                    reference_kind="exact_string",
                    source_entity_section=source_section,
                    source_entity_id=source_id,
                    source_entity_pointer=source_pointer,
                )
            )

    visit(document.data)
    return ReferenceIndex(document, references)


def build_reference_index(document: LoadedDocument) -> ReferenceIndex:
    if document.model_id == "runtime-v3":
        return _runtime_reference_index(document)
    return _generic_reference_index(document)
