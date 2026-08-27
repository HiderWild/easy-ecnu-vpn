#!/usr/bin/env python3
"""Generate the closed product/host semantic boundary from Common contracts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SYSTEM = ROOT / "contracts/system.contract.json"
DEFAULT_MODEL = ROOT / "contracts/runtime_v3/business_flow.model.json"
DEFAULT_CPP = ROOT / "src/contracts/generated/product_semantic_contract.hpp"
DEFAULT_TS = (
    ROOT / "webui/host/shared/generated/product-semantic-contract.ts"
)
DEFAULT_DESKTOP_TS = (
    ROOT / "webui/desktop/shared/generated/product-semantic-contract.ts"
)
DEFAULT_SNAPSHOT = (
    ROOT / "contracts/generated/product_semantic_contract.json"
)

REQUIRED_ACTIONS = {
    "status.get",
    "application.started",
    "product.settings.get",
    "product.settings.apply",
    "credential.replace",
    "credential.clear",
    "onboarding.apply",
    "product.notification.ack",
    "vpn.connect",
    "vpn.connectTemporary",
    "vpn.disconnect",
    "vpn.authInteraction.get",
    "vpn.authInteraction.respond",
    "service.install",
    "service.uninstall",
    "service.repair",
    "drivers.install",
    "core.restart",
    "host.preferences.get",
    "host.preferences.apply",
}

PRODUCT_VALIDATION_ERROR_CODES = {
    "product_forbidden_argument",
    "product_request_invalid",
    "product_response_invalid",
    "product_secret_slots_invalid",
}


class SemanticContractError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def pascal(value: str) -> str:
    result = "".join(
        part[:1].upper() + part[1:]
        for part in re.split(r"[^A-Za-z0-9]+", value)
        if part
    )
    return f"Value{result}" if result[:1].isdigit() else result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SemanticContractError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SemanticContractError(f"{path}: root must be an object")
    return value


def load_system_generator(root: Path):
    path = root / "scripts/generate_contracts.py"
    spec = importlib.util.spec_from_file_location(
        "exv_system_contract_generator", path
    )
    if spec is None or spec.loader is None:
        raise SemanticContractError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise SemanticContractError(f"{path} must be an array")
    return value


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise SemanticContractError(f"{path} must be a non-empty string")
    return value


def index_by_id(values: Any, path: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(require_list(values, path)):
        if not isinstance(value, dict):
            raise SemanticContractError(f"{path}[{index}] must be an object")
        item_id = require_string(value.get("id"), f"{path}[{index}].id")
        if item_id in result:
            raise SemanticContractError(f"duplicate {path} id: {item_id}")
        result[item_id] = value
    return result


def validate_product_validation_error_closure(
    system: dict[str, Any],
) -> None:
    registered = {
        entry.get("code")
        for entry in require_list(
            system.get("error_contracts"),
            "system.error_contracts",
        )
        if isinstance(entry, dict)
    }
    missing = sorted(PRODUCT_VALIDATION_ERROR_CODES - registered)
    if missing:
        raise SemanticContractError(
            "generated product validation error closure is missing "
            f"authoritative system error contracts: {missing}"
        )


def type_dependencies(type_def: dict[str, Any]) -> list[str]:
    kind = type_def.get("kind")
    if kind == "record":
        return [
            require_string(field.get("type"), "type field")
            for field in require_list(type_def.get("fields"), "type fields")
            if isinstance(field, dict)
        ]
    if kind == "list":
        return [require_string(type_def.get("item_type"), "list.item_type")]
    if kind == "alias":
        return [require_string(type_def.get("target"), "alias.target")]
    return []


def referenced_types(
    roots: list[str], types: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    visiting: set[str] = set()
    visited: set[str] = set()
    ordered: list[dict[str, Any]] = []

    def visit(type_id: str) -> None:
        if type_id in visited:
            return
        if type_id in visiting:
            raise SemanticContractError(f"cyclic semantic type: {type_id}")
        definition = types.get(type_id)
        if definition is None:
            raise SemanticContractError(
                f"unknown generated semantic type: {type_id}"
            )
        visiting.add(type_id)
        for dependency in type_dependencies(definition):
            visit(dependency)
        visiting.remove(type_id)
        visited.add(type_id)
        ordered.append(definition)

    for root in roots:
        visit(root)
    return ordered


def build_snapshot(
    system: dict[str, Any],
    model: dict[str, Any],
    root: Path = ROOT,
) -> dict[str, Any]:
    generator = load_system_generator(root)
    validate_product_validation_error_closure(system)
    generator.validate_manifest(system)
    semantic = model.get("semantic_contracts")
    if not isinstance(semantic, dict) or semantic.get("schema_version") != "1.0":
        raise SemanticContractError(
            "semantic_contracts.schema_version must be 1.0"
        )
    types = index_by_id(model.get("type_definitions"), "type_definitions")
    generated_roots = [
        require_string(value, "semantic_contracts.generated_types[]")
        for value in require_list(
            semantic.get("generated_types"),
            "semantic_contracts.generated_types",
        )
    ]
    if len(generated_roots) != len(set(generated_roots)):
        raise SemanticContractError("generated semantic type roots duplicate")

    bindings = index_by_id(
        semantic.get("action_bindings"),
        "semantic_contracts.action_bindings",
    )
    if set(bindings) != REQUIRED_ACTIONS:
        missing = sorted(REQUIRED_ACTIONS - set(bindings))
        extra = sorted(set(bindings) - REQUIRED_ACTIONS)
        raise SemanticContractError(
            f"semantic action closure mismatch; missing={missing}; extra={extra}"
        )
    actions = {
        action["name"]: action
        for action in system["action_contracts"]
    }
    for action_id, binding in bindings.items():
        action = actions.get(action_id)
        if action is None:
            raise SemanticContractError(
                f"semantic action is absent from system contract: {action_id}"
            )
        boundary = require_string(
            binding.get("boundary"), f"action_bindings.{action_id}.boundary"
        )
        if action.get("dispatch_target") != boundary:
            raise SemanticContractError(
                f"semantic action boundary mismatch: {action_id}"
            )
        for key in ("request_type", "response_type"):
            type_id = require_string(
                binding.get(key), f"action_bindings.{action_id}.{key}"
            )
            if type_id not in types:
                raise SemanticContractError(
                    f"{action_id} has unknown {key}: {type_id}"
                )
        slots = require_list(
            binding.get("secret_slots"),
            f"action_bindings.{action_id}.secret_slots",
        )
        if any(not isinstance(slot, str) or not slot for slot in slots):
            raise SemanticContractError(
                f"{action_id} has invalid secret slot"
            )
        if len(slots) != len(set(slots)):
            raise SemanticContractError(
                f"{action_id} has duplicate secret slot"
            )

    conditional_slots = require_list(
        semantic.get("conditional_secret_slots"),
        "semantic_contracts.conditional_secret_slots",
    )
    conditional_actions: set[str] = set()
    for index, rule in enumerate(conditional_slots):
        if not isinstance(rule, dict):
            raise SemanticContractError(
                f"conditional_secret_slots[{index}] must be an object"
            )
        action_id = require_string(
            rule.get("action"),
            f"conditional_secret_slots[{index}].action",
        )
        if action_id not in bindings:
            raise SemanticContractError(
                f"conditional secret action has no binding: {action_id}"
            )
        if action_id in conditional_actions:
            raise SemanticContractError(
                f"duplicate conditional secret action: {action_id}"
            )
        conditional_actions.add(action_id)
        require_string(
            rule.get("discriminator"),
            f"conditional_secret_slots[{index}].discriminator",
        )
        cases = require_list(
            rule.get("cases"),
            f"conditional_secret_slots[{index}].cases",
        )
        if not cases:
            raise SemanticContractError(
                f"conditional secret action has no cases: {action_id}"
            )
        values: set[str] = set()
        allowed_slots = set(bindings[action_id]["secret_slots"])
        for case_index, case in enumerate(cases):
            if not isinstance(case, dict):
                raise SemanticContractError(
                    f"conditional secret case must be an object: {action_id}"
                )
            value = require_string(
                case.get("value"),
                f"conditional_secret_slots[{index}].cases[{case_index}].value",
            )
            if value in values:
                raise SemanticContractError(
                    f"duplicate conditional secret value: {action_id}/{value}"
                )
            values.add(value)
            required_slots = require_list(
                case.get("required_slots"),
                f"conditional_secret_slots[{index}].cases[{case_index}].required_slots",
            )
            if (
                len(required_slots) != len(set(required_slots))
                or any(
                    not isinstance(slot, str) or slot not in allowed_slots
                    for slot in required_slots
                )
            ):
                raise SemanticContractError(
                    f"invalid conditional secret slots: {action_id}/{value}"
                )

    forbidden = require_list(
        semantic.get("forbidden_action_arguments"),
        "semantic_contracts.forbidden_action_arguments",
    )
    forbidden_by_action: dict[str, list[str]] = {}
    for index, entry in enumerate(forbidden):
        if not isinstance(entry, dict):
            raise SemanticContractError(
                f"forbidden_action_arguments[{index}] must be an object"
            )
        action_id = require_string(
            entry.get("action"),
            f"forbidden_action_arguments[{index}].action",
        )
        if action_id not in bindings:
            raise SemanticContractError(
                f"forbidden argument action has no binding: {action_id}"
            )
        fields = [
            require_string(value, "forbidden action field")
            for value in require_list(
                entry.get("fields"),
                f"forbidden_action_arguments[{index}].fields",
            )
        ]
        if len(fields) != len(set(fields)):
            raise SemanticContractError(
                f"duplicate forbidden argument for {action_id}"
            )
        request = types[bindings[action_id]["request_type"]]
        represented = {
            field["name"]
            for field in request.get("fields", [])
            if isinstance(field, dict)
        }
        overlap = represented.intersection(fields)
        if overlap:
            raise SemanticContractError(
                f"forbidden argument is representable by {action_id}: "
                f"{sorted(overlap)}"
            )
        forbidden_by_action[action_id] = fields
    if forbidden_by_action.get("vpn.connect") != ["backend_mode"]:
        raise SemanticContractError(
            "vpn.connect must reject the legacy backend_mode argument"
        )

    notification = semantic.get("notification")
    if not isinstance(notification, dict):
        raise SemanticContractError("semantic notification must be an object")
    notification_type = require_string(
        notification.get("event_schema"), "notification.event_schema"
    )
    if notification_type not in types:
        raise SemanticContractError(
            f"unknown notification event schema: {notification_type}"
        )
    if notification.get("event_type") not in system["surfaces"][
        "desktop_rpc"
    ]["event_types"]:
        raise SemanticContractError(
            "semantic notification event is absent from desktop surface"
        )

    type_roots = list(generated_roots)
    for binding in bindings.values():
        type_roots.extend(
            [binding["request_type"], binding["response_type"]]
        )
    type_roots.append(notification_type)
    projected_types = referenced_types(type_roots, types)

    payload = {
        "schema_version": "1.0",
        "system_contract_digest": generator.contract_digest(system),
        "semantic_contracts": semantic,
        "types": projected_types,
    }
    digest = "sha256:" + hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "1.0",
        "digest": digest,
        **payload,
    }


def cpp_scalar_type(type_id: str, definition: dict[str, Any]) -> str:
    if type_id == "string":
        return "std::string"
    if type_id == "uint64":
        return "std::uint64_t"
    if type_id == "bool":
        return "bool"
    kind = definition["kind"]
    if kind == "opaque":
        return (
            "std::string"
            if definition["wire_form"] == "json_scalar"
            else "nlohmann::json"
        )
    return type_id


def render_cpp(snapshot: dict[str, Any]) -> str:
    types = snapshot["types"]
    by_id = {definition["id"]: definition for definition in types}
    lines = [
        "#pragma once",
        "",
        "#include <nlohmann/json.hpp>",
        "",
        "#include <algorithm>",
        "#include <array>",
        "#include <cstdint>",
        "#include <optional>",
        "#include <string>",
        "#include <string_view>",
        "#include <vector>",
        "",
        "namespace exv::contracts::product_semantic {",
        "",
        f'inline constexpr std::string_view CONTRACT_DIGEST = "{snapshot["digest"]}";',
        f'inline constexpr std::string_view SYSTEM_CONTRACT_DIGEST = "{snapshot["system_contract_digest"]}";',
        "",
    ]
    for definition in types:
        type_id = definition["id"]
        kind = definition["kind"]
        if type_id in {"string", "uint64", "bool"}:
            continue
        if kind == "enum":
            lines.append(f"enum class {type_id} {{")
            lines.extend(
                f"  {pascal(value)}," for value in definition["values"]
            )
            lines.extend(["};", ""])
        elif kind == "record":
            lines.append(f"struct {type_id} {{")
            for field in definition["fields"]:
                field_type = cpp_scalar_type(
                    field["type"], by_id[field["type"]]
                )
                if not field["required"]:
                    field_type = f"std::optional<{field_type}>"
                lines.append(f"  {field_type} {field['name']};")
            lines.extend(
                [
                    f"  bool operator==(const {type_id} &) const = default;",
                    "};",
                    "",
                ]
            )
        elif kind == "list":
            item = definition["item_type"]
            lines.extend(
                [
                    f"using {type_id} = std::vector<{cpp_scalar_type(item, by_id[item])}>;",
                    "",
                ]
            )
        elif kind == "alias":
            target = definition["target"]
            lines.extend(
                [
                    f"using {type_id} = {cpp_scalar_type(target, by_id[target])};",
                    "",
                ]
            )
        elif kind == "opaque":
            lines.extend(
                [
                    f"using {type_id} = {cpp_scalar_type(type_id, definition)};",
                    "",
                ]
            )

    lines.append("namespace detail {")
    lines.append("")
    for definition in types:
        type_id = definition["id"]
        kind = definition["kind"]
        expression = "false"
        if type_id == "string":
            expression = "value.is_string()"
        elif type_id == "uint64":
            expression = (
                "(value.is_number_unsigned() || "
                "(value.is_number_integer() && value.get<std::int64_t>() >= 0))"
            )
        elif type_id == "bool":
            expression = "value.is_boolean()"
        elif kind == "enum":
            allowed = " || ".join(
                f'value == "{item}"' for item in definition["values"]
            )
            expression = f"value.is_string() && ({allowed})"
        elif kind == "opaque":
            wire = definition["wire_form"]
            if wire == "json_scalar":
                expression = "value.is_string()"
                constraints = definition.get("constraints", {})
                if "min_length" in constraints:
                    expression += (
                        f" && value.get_ref<const std::string &>().size() >= "
                        f"{constraints['min_length']}"
                    )
                if "max_length" in constraints:
                    expression += (
                        f" && value.get_ref<const std::string &>().size() <= "
                        f"{constraints['max_length']}"
                    )
            elif wire == "json_object":
                expression = "value.is_object()"
                if type_id == "EmptyObject":
                    expression += " && value.empty()"
            elif wire == "json_array":
                expression = "value.is_array()"
        elif kind == "alias":
            expression = f"validate_{definition['target']}(value)"
        elif kind == "list":
            item = definition["item_type"]
            constraints = definition.get("constraints", {})
            checks = ["value.is_array()"]
            if "min_items" in constraints:
                checks.append(f"value.size() >= {constraints['min_items']}")
            if "max_items" in constraints:
                checks.append(f"value.size() <= {constraints['max_items']}")
            checks.append(
                "std::all_of(value.begin(), value.end(), "
                f"[](const auto &item) {{ return validate_{item}(item); }})"
            )
            expression = " && ".join(checks)
        if kind != "record":
            lines.extend(
                [
                    f"inline bool validate_{type_id}(const nlohmann::json &value) {{",
                    f"  return {expression};",
                    "}",
                    "",
                ]
            )
            continue
        required = [
            field["name"]
            for field in definition["fields"]
            if field["required"]
        ]
        allowed = [field["name"] for field in definition["fields"]]
        lines.append(
            f"inline bool validate_{type_id}(const nlohmann::json &value) {{"
        )
        lines.append("  if (!value.is_object()) { return false; }")
        if allowed:
            allowed_expr = " && ".join(
                f'key != "{field}"' for field in allowed
            )
            lines.extend(
                [
                    "  for (const auto &[key, unused] : value.items()) {",
                    "    (void)unused;",
                    f"    if ({allowed_expr}) {{ return false; }}",
                    "  }",
                ]
            )
        for field in required:
            lines.append(
                f'  if (!value.contains("{field}")) {{ return false; }}'
            )
        for field in definition["fields"]:
            name = field["name"]
            validator = f"validate_{field['type']}"
            if field["required"]:
                lines.append(
                    f'  if (!{validator}(value.at("{name}"))) '
                    "{ return false; }"
                )
            else:
                lines.append(
                    f'  if (value.contains("{name}") && '
                    f'!{validator}(value.at("{name}"))) '
                    "{ return false; }"
                )
        lines.extend(["  return true;", "}", ""])
    lines.extend(["} // namespace detail", ""])

    bindings = list(snapshot["semantic_contracts"]["action_bindings"])
    lines.extend(
        [
            "struct ActionBinding {",
            "  std::string_view action;",
            "  std::string_view boundary;",
            "  std::string_view request_type;",
            "  std::string_view response_type;",
            "  std::string_view mutation;",
            "  bool projection_required;",
            "};",
            "",
            f"inline constexpr std::array<ActionBinding, {len(bindings)}> ACTION_BINDINGS = {{{{",
        ]
    )
    for binding in bindings:
        lines.append(
            '  {"%s", "%s", "%s", "%s", "%s", %s},'
            % (
                binding["id"],
                binding["boundary"],
                binding["request_type"],
                binding["response_type"],
                binding["mutation"],
                str(binding["projection_required"]).lower(),
            )
        )
    lines.extend(
        [
            "}};",
            "",
            "struct ValidationResult {",
            "  bool valid{false};",
            "  std::string error_code;",
            "  std::string field;",
            "};",
            "",
            "[[nodiscard]] inline ValidationResult validate_request(",
            "    std::string_view action, const nlohmann::json &payload,",
            "    const std::vector<std::string> &secret_slots) {",
            "  std::vector<std::string> normalized = secret_slots;",
            "  std::sort(normalized.begin(), normalized.end());",
            "  if (std::adjacent_find(normalized.begin(), normalized.end()) !=",
            "      normalized.end()) {",
            '    return {false, "product_secret_slots_invalid", {}};',
            "  }",
        ]
    )
    forbidden_by_action = {
        entry["action"]: entry["fields"]
        for entry in snapshot["semantic_contracts"][
            "forbidden_action_arguments"
        ]
    }
    conditional_by_action = {
        entry["action"]: entry
        for entry in snapshot["semantic_contracts"][
            "conditional_secret_slots"
        ]
    }
    for binding in bindings:
        expected = sorted(binding["secret_slots"])
        expected_cpp = ", ".join(f'"{slot}"' for slot in expected)
        lines.extend(
            [
                f'  if (action == "{binding["id"]}") {{',
            ]
        )
        for field in forbidden_by_action.get(binding["id"], []):
            lines.extend(
                [
                    f'    if (payload.is_object() && payload.contains("{field}")) {{',
                    f'      return {{false, "product_forbidden_argument", "{field}"}};',
                    "    }",
                ]
            )
        conditional = conditional_by_action.get(binding["id"])
        if conditional:
            discriminator = conditional["discriminator"]
            lines.extend(
                [
                    f'    if (!payload.is_object() || !payload.contains("{discriminator}") ||',
                    f'        !payload.at("{discriminator}").is_string()) {{',
                    '      return {false, "product_request_invalid", {}};',
                    "    }",
                    "    std::vector<std::string> expected;",
                    f'    const auto discriminator = payload.at("{discriminator}").get<std::string>();',
                ]
            )
            for case_index, case in enumerate(conditional["cases"]):
                case_slots = ", ".join(
                    f'"{slot}"' for slot in sorted(case["required_slots"])
                )
                keyword = "if" if case_index == 0 else "else if"
                lines.append(
                    f'    {keyword} (discriminator == "{case["value"]}") {{ expected = {{{case_slots}}}; }}'
                )
            lines.extend(
                [
                    "    else {",
                    '      return {false, "product_request_invalid", {}};',
                    "    }",
                ]
            )
        else:
            lines.append(
                f"    const std::vector<std::string> expected{{{expected_cpp}}};"
            )
        lines.extend(
            [
                "    if (normalized != expected) {",
                '      return {false, "product_secret_slots_invalid", {}};',
                "    }",
                f"    return detail::validate_{binding['request_type']}(payload)",
                "               ? ValidationResult{true, {}, {}}",
                '               : ValidationResult{false, "product_request_invalid", {}};',
                "  }",
            ]
        )
    lines.extend(
        [
            '  return {false, "product_semantic_action_unknown", {}};',
            "}",
            "",
            "[[nodiscard]] inline ValidationResult validate_response(",
            "    std::string_view action, const nlohmann::json &payload) {",
        ]
    )
    for binding in bindings:
        lines.extend(
            [
                f'  if (action == "{binding["id"]}") {{',
                f"    return detail::validate_{binding['response_type']}(payload)",
                "               ? ValidationResult{true, {}, {}}",
                '               : ValidationResult{false, "product_response_invalid", {}};',
                "  }",
            ]
        )
    lines.extend(
        [
            '  return {false, "product_semantic_action_unknown", {}};',
            "}",
            "",
            "} // namespace exv::contracts::product_semantic",
            "",
        ]
    )
    return "\n".join(lines)


def ts_type(type_id: str, definition: dict[str, Any]) -> str:
    if type_id == "string":
        return "string"
    if type_id == "uint64":
        return "number"
    if type_id == "bool":
        return "boolean"
    if definition["kind"] == "opaque":
        return (
            "string"
            if definition["wire_form"] == "json_scalar"
            else "Record<string, unknown>"
        )
    return type_id


def render_ts(snapshot: dict[str, Any]) -> str:
    types = snapshot["types"]
    by_id = {definition["id"]: definition for definition in types}
    lines = [
        "// Generated by scripts/generate_product_semantic_contracts.py.",
        "// Do not edit by hand.",
        "",
        f"export const PRODUCT_SEMANTIC_CONTRACT_DIGEST = '{snapshot['digest']}' as const",
        f"export const PRODUCT_SEMANTIC_SYSTEM_CONTRACT_DIGEST = '{snapshot['system_contract_digest']}' as const",
        "",
    ]
    for definition in types:
        type_id = definition["id"]
        kind = definition["kind"]
        if type_id in {"string", "uint64", "bool"}:
            continue
        if kind == "enum":
            values = " | ".join(repr(value) for value in definition["values"])
            lines.append(f"export type {type_id} = {values}")
        elif kind == "record":
            lines.append(f"export type {type_id} = {{")
            for field in definition["fields"]:
                marker = "" if field["required"] else "?"
                lines.append(
                    f"  {field['name']}{marker}: "
                    f"{ts_type(field['type'], by_id[field['type']])}"
                )
            lines.append("}")
        elif kind == "list":
            item = definition["item_type"]
            lines.append(
                f"export type {type_id} = ReadonlyArray<"
                f"{ts_type(item, by_id[item])}>"
            )
        elif kind == "alias":
            target = definition["target"]
            lines.append(
                f"export type {type_id} = "
                f"{ts_type(target, by_id[target])}"
            )
        elif kind == "opaque":
            lines.append(
                f"export type {type_id} = {ts_type(type_id, definition)}"
            )
        lines.append("")

    bindings = snapshot["semantic_contracts"]["action_bindings"]
    lines.extend(
        [
            "export const PRODUCT_SEMANTIC_ACTIONS = "
            + json.dumps(bindings, ensure_ascii=False, indent=2)
            + " as const",
            "",
            "export type ProductSemanticAction = "
            "(typeof PRODUCT_SEMANTIC_ACTIONS)[number]['id']",
            "",
            "export const PRODUCT_NOTIFICATION_EVENT = "
            "'product-notification' as const",
            "",
            "const PRODUCT_SEMANTIC_TYPE_DEFINITIONS = "
            + json.dumps(
                {definition["id"]: definition for definition in types},
                ensure_ascii=False,
                indent=2,
            )
            + " as const",
            "",
            "const FORBIDDEN_ACTION_ARGUMENTS: Readonly<Record<string, ReadonlyArray<string>>> = "
            + json.dumps(
                {
                    entry["action"]: entry["fields"]
                    for entry in snapshot["semantic_contracts"][
                        "forbidden_action_arguments"
                    ]
                },
                ensure_ascii=False,
                indent=2,
            ),
            "",
            "const CONDITIONAL_SECRET_SLOTS: Readonly<Record<string, { discriminator: string; cases: Readonly<Record<string, ReadonlyArray<string>>> }>> = "
            + json.dumps(
                {
                    entry["action"]: {
                        "discriminator": entry["discriminator"],
                        "cases": {
                            case["value"]: case["required_slots"]
                            for case in entry["cases"]
                        },
                    }
                    for entry in snapshot["semantic_contracts"][
                        "conditional_secret_slots"
                    ]
                },
                ensure_ascii=False,
                indent=2,
            ),
            "",
            "type RuntimeTypeDefinition = {",
            "  kind: string",
            "  wire_form: string",
            "  values?: ReadonlyArray<string>",
            "  target?: string",
            "  item_type?: string",
            "  fields?: ReadonlyArray<{ name: string; type: string; required: boolean }>",
            "  constraints?: { min_length?: number; max_length?: number; min_items?: number; max_items?: number }",
            "}",
            "",
            "function isRecord(value: unknown): value is Record<string, unknown> {",
            "  return typeof value === 'object' && value !== null && !Array.isArray(value)",
            "}",
            "",
            "function validateType(typeId: string, value: unknown): boolean {",
            "  if (typeId === 'string') return typeof value === 'string'",
            "  if (typeId === 'uint64') return Number.isSafeInteger(value) && (value as number) >= 0",
            "  if (typeId === 'bool') return typeof value === 'boolean'",
            "  const definition = PRODUCT_SEMANTIC_TYPE_DEFINITIONS[typeId as keyof typeof PRODUCT_SEMANTIC_TYPE_DEFINITIONS] as RuntimeTypeDefinition | undefined",
            "  if (!definition) return false",
            "  if (definition.kind === 'enum') {",
            "    return typeof value === 'string' && (definition.values ?? []).includes(value)",
            "  }",
            "  if (definition.kind === 'opaque') {",
            "    if (definition.wire_form === 'json_scalar') {",
            "      if (typeof value !== 'string') return false",
            "      const constraints = definition.constraints",
            "      if (typeof constraints?.min_length === 'number' && value.length < constraints.min_length) return false",
            "      if (typeof constraints?.max_length === 'number' && value.length > constraints.max_length) return false",
            "      return true",
            "    }",
            "    if (definition.wire_form === 'json_object') {",
            "      return isRecord(value) && (typeId !== 'EmptyObject' || Object.keys(value).length === 0)",
            "    }",
            "    return Array.isArray(value)",
            "  }",
            "  if (definition.kind === 'alias') return typeof definition.target === 'string' && validateType(definition.target, value)",
            "  if (definition.kind === 'list') {",
            "    if (!Array.isArray(value)) return false",
            "    const constraints = definition.constraints",
            "    if (typeof constraints?.min_items === 'number' && value.length < constraints.min_items) return false",
            "    if (typeof constraints?.max_items === 'number' && value.length > constraints.max_items) return false",
            "    return typeof definition.item_type === 'string' && value.every((item) => validateType(definition.item_type!, item))",
            "  }",
            "  if (definition.kind === 'record') {",
            "    if (!isRecord(value)) return false",
            "    const fields = definition.fields ?? []",
            "    const allowed = new Set(fields.map((field) => field.name))",
            "    if (Object.keys(value).some((key) => !allowed.has(key))) return false",
            "    return fields.every((field) =>",
            "      Object.hasOwn(value, field.name)",
            "        ? validateType(field.type, value[field.name])",
            "        : !field.required,",
            "    )",
            "  }",
            "  return false",
            "}",
            "",
            "export function validateProductSemanticType(typeId: string, value: unknown): boolean {",
            "  return validateType(typeId, value)",
            "}",
            "",
            "export type ProductSemanticValidationResult =",
            "  | { valid: true }",
            "  | { valid: false; code: string; field?: string }",
            "",
            "export function validateProductSemanticRequest(",
            "  action: string,",
            "  payload: unknown,",
            "  secretSlots: ReadonlyArray<string>,",
            "): ProductSemanticValidationResult {",
            "  const binding = PRODUCT_SEMANTIC_ACTIONS.find((candidate) => candidate.id === action)",
            "  if (!binding) return { valid: false, code: 'product_semantic_action_unknown' }",
            "  if (new Set(secretSlots).size !== secretSlots.length) {",
            "    return { valid: false, code: 'product_secret_slots_invalid' }",
            "  }",
            "  const actualSlots = [...secretSlots].sort()",
            "  const conditional = CONDITIONAL_SECRET_SLOTS[action]",
            "  let expectedSlots: ReadonlyArray<string> = binding.secret_slots",
            "  if (conditional) {",
            "    if (!isRecord(payload)) return { valid: false, code: 'product_request_invalid' }",
            "    const discriminator = payload[conditional.discriminator]",
            "    if (typeof discriminator !== 'string' || !(discriminator in conditional.cases)) {",
            "      return { valid: false, code: 'product_request_invalid' }",
            "    }",
            "    expectedSlots = conditional.cases[discriminator]!",
            "  }",
            "  expectedSlots = [...expectedSlots].sort()",
            "  if (actualSlots.length !== expectedSlots.length || actualSlots.some((slot, index) => slot !== expectedSlots[index])) {",
            "    return { valid: false, code: 'product_secret_slots_invalid' }",
            "  }",
            "  if (isRecord(payload)) {",
            "    const forbidden = FORBIDDEN_ACTION_ARGUMENTS[action] ?? []",
            "    const field = forbidden.find((candidate) => Object.hasOwn(payload, candidate))",
            "    if (field) return { valid: false, code: 'product_forbidden_argument', field }",
            "  }",
            "  return validateType(binding.request_type, payload)",
            "    ? { valid: true }",
            "    : { valid: false, code: 'product_request_invalid' }",
            "}",
            "",
            "export function validateProductSemanticResponse(",
            "  action: string,",
            "  payload: unknown,",
            "): ProductSemanticValidationResult {",
            "  const binding = PRODUCT_SEMANTIC_ACTIONS.find((candidate) => candidate.id === action)",
            "  if (!binding) return { valid: false, code: 'product_semantic_action_unknown' }",
            "  return validateType(binding.response_type, payload)",
            "    ? { valid: true }",
            "    : { valid: false, code: 'product_response_invalid' }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def render_snapshot(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"


def write_or_check(path: Path, content: str, check: bool) -> None:
    if check:
        try:
            actual = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SemanticContractError(f"{path}: {exc}") from exc
        if actual != content:
            raise SemanticContractError(f"{path} is not up to date")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def generate(root: Path, check: bool) -> None:
    system = load_json(root / "contracts/system.contract.json")
    model = load_json(
        root / "contracts/runtime_v3/business_flow.model.json"
    )
    snapshot = build_snapshot(system, model, root)
    outputs = {
        root / "src/contracts/generated/product_semantic_contract.hpp":
            render_cpp(snapshot),
        root / "webui/host/shared/generated/product-semantic-contract.ts":
            render_ts(snapshot),
        root / "webui/desktop/shared/generated/product-semantic-contract.ts":
            render_ts(snapshot),
        root / "contracts/generated/product_semantic_contract.json":
            render_snapshot(snapshot),
    }
    for path, content in outputs.items():
        write_or_check(path, content, check)
    if check:
        print("product semantic contract artifacts are up to date")
    else:
        print("generated product semantic contract artifacts")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        generate(args.root.resolve(), args.check)
    except SemanticContractError as exc:
        print(f"PRODUCT_SEMANTIC_CONTRACT_ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
