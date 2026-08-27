#!/usr/bin/env python3
"""Generate checked-in EXV contract artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "contracts" / "system.contract.json"
DEFAULT_SCHEMA = REPO_ROOT / "contracts" / "system.contract.schema.json"
DEFAULT_CPP = REPO_ROOT / "src" / "contracts" / "generated" / "system_contract.hpp"
TS_CONTRACT_OUTPUTS = [
    REPO_ROOT / "webui" / "host" / "shared" / "generated" / "system-contract.ts",
    REPO_ROOT / "webui" / "desktop" / "shared" / "generated" / "system-contract.ts",
]
DEFAULT_SNAPSHOT = REPO_ROOT / "contracts" / "generated" / "system_contract_snapshot.json"


class ContractError(ValueError):
    pass


ACTION_DISPATCH_TARGETS = {
    "core_rpc",
    "product_authority",
    "host_local",
    "renderer_only",
}
ACTION_ALIAS_POLICIES = {"direct", "compat_alias"}
ACTION_SURFACES = (
    "desktop_rpc",
    "core_rpc",
    "internal_core",
    "host_runtime",
)
ACTION_POLICY_FIELDS = (
    "lane",
    "conflict_class",
    "mutation_class",
    "deadline_class",
    "retry_class",
    "idempotency_class",
    "confirmation_class",
)
ACTION_POLICY_VALUES = {
    "lane": {
        "control",
        "read_model",
        "vpn_control",
        "product_state",
        "credential_store",
        "config_store",
        "diagnostics",
        "platform_admin",
        "host_local",
    },
    "conflict_class": {
        "none",
        "vpn_workflow_intent",
        "product_settings_write",
        "credential_write",
        "product_lifecycle",
        "onboarding_write",
        "config_write",
        "platform_admin_write",
        "host_window_write",
        "host_preferences_write",
    },
    "mutation_class": {
        "read_only",
        "state_mutation",
        "destructive_mutation",
        "external_side_effect",
    },
    "deadline_class": {"interactive", "standard", "long_running"},
    "retry_class": {"never", "explicit_safe", "automatic_safe"},
    "idempotency_class": {"read_only", "idempotent", "non_idempotent"},
    "confirmation_class": {"none", "explicit"},
}
ACTION_CAPABILITIES = {
    "core_lifecycle",
    "product_runtime",
    "config_store",
    "route_store",
    "diagnostics_store",
    "service_control",
    "driver_control",
    "runtime_status",
    "cli_integration",
    "window_state",
    "notification_sink",
    "host_preferences",
}
ACTION_PRIVILEGE_CLASSES = {
    "unprivileged",
    "user_authority",
    "machine_admin",
}
ACTION_PRINCIPAL_SCOPES = {"none", "originating_user", "machine"}
ERROR_DOMAINS = {
    "runtime",
    "action",
    "config",
    "auth",
    "network",
    "helper",
    "platform_admin",
    "credential",
    "product",
    "internal",
}
ERROR_RETRYABILITY = {"none", "explicit", "automatic"}
ERROR_DIAGNOSTIC_EXPOSURE = {"correlation_only", "safe_parameters"}
IDENTIFIER_PARTS = re.compile(r"[^A-Za-z0-9]+")
MANIFEST_FIELDS = {
    "contract_id",
    "schema_version",
    "version",
    "ipc_protocol_major",
    "envelopes",
    "surfaces",
    "action_policy_profiles",
    "action_contracts",
    "action_aliases",
    "error_defaults",
    "error_contracts",
    "error_aliases",
    "modules",
}
CANONICAL_ACTION_FIELDS = {
    "name",
    "surfaces",
    "semantic_owner",
    "dispatch_target",
    "response_contract",
    "policy",
    "required_capability",
    "privilege_class",
    "principal_scope",
}
ACTION_ALIAS_FIELDS = {"alias", "canonical", "surfaces"}
ERROR_DEFAULT_FIELDS = {
    "safe_presentation_key_prefix",
    "diagnostic_exposure",
}
ERROR_CONTRACT_REQUIRED_FIELDS = {
    "code",
    "domain",
    "retryability",
    "recovery_action",
}
ERROR_CONTRACT_OPTIONAL_FIELDS = {
    "safe_presentation_key",
    "diagnostic_exposure",
}
ERROR_ALIAS_FIELDS = {"alias", "canonical"}


def require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{path} must be an object")
    return value


def require_array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"{path} must be an array")
    return value


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{path} must be a non-empty string")
    return value


def require_positive_int(value: Any, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ContractError(f"{path} must be a positive integer")
    return value


def validate_object_fields(
    value: dict[str, Any],
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    actual = set(value)
    missing = sorted(required - actual)
    unknown = sorted(actual - required - optional)
    if missing:
        raise ContractError(f"{path} missing field(s): {', '.join(missing)}")
    if unknown:
        raise ContractError(f"{path} has unknown field(s): {', '.join(unknown)}")


def enum_identifier(value: str) -> str:
    parts = [part for part in IDENTIFIER_PARTS.split(value) if part]
    if not parts:
        raise ContractError(f"cannot derive identifier from {value!r}")
    identifier = "".join(part[0].upper() + part[1:] for part in parts)
    if identifier[0].isdigit():
        identifier = "Value" + identifier
    return identifier


def validate_unique_identifiers(values: Iterable[str], path: str) -> None:
    identifiers: dict[str, str] = {}
    for value in values:
        identifier = enum_identifier(value)
        previous = identifiers.get(identifier)
        if previous is not None:
            raise ContractError(
                f"{path} identifier collision: {previous!r} and {value!r}"
            )
        identifiers[identifier] = value


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def contract_digest(manifest: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(manifest).encode("utf-8")
    ).hexdigest()


def field_names(manifest: dict[str, Any], envelope: str, side: str) -> list[str]:
    fields = manifest["envelopes"][envelope][side]["fields"]
    return [require_string(field.get("name"), f"envelopes.{envelope}.{side}.fields[].name")
            for field in fields]


def validate_fields(fields: Any, path: str) -> None:
    seen: set[str] = set()
    for index, value in enumerate(require_array(fields, path)):
        field = require_object(value, f"{path}[{index}]")
        name = require_string(field.get("name"), f"{path}[{index}].name")
        require_string(field.get("type"), f"{path}[{index}].type")
        if not isinstance(field.get("required"), bool):
            raise ContractError(f"{path}[{index}].required must be a boolean")
        if name in seen:
            raise ContractError(f"{path} contains duplicate field {name!r}")
        seen.add(name)


def validate_string_list(values: Any, path: str) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(require_array(values, path)):
        item = require_string(value, f"{path}[{index}]")
        if item in seen:
            raise ContractError(f"{path} contains duplicate value {item!r}")
        seen.add(item)
        result.append(item)
    return result


def validate_error_code_entries(values: Any, path: str) -> None:
    seen_keys: set[str] = set()
    seen_codes: set[str] = set()
    for index, value in enumerate(require_array(values, path)):
        entry = require_object(value, f"{path}[{index}]")
        key = require_string(entry.get("key"), f"{path}[{index}].key")
        code = require_string(entry.get("code"), f"{path}[{index}].code")
        if key in seen_keys:
            raise ContractError(f"{path} contains duplicate key {key!r}")
        if code in seen_codes:
            raise ContractError(f"{path} contains duplicate code {code!r}")
        seen_keys.add(key)
        seen_codes.add(code)


def validate_core_rpc(core_rpc: dict[str, Any]) -> None:
    actions = validate_string_list(core_rpc.get("actions"), "surfaces.core_rpc.actions")
    destructive_actions = validate_string_list(
        core_rpc.get("destructive_actions"),
        "surfaces.core_rpc.destructive_actions",
    )
    validate_string_list(core_rpc.get("error_codes"), "surfaces.core_rpc.error_codes")

    action_names = set(actions)
    for action in destructive_actions:
        if action not in action_names:
            raise ContractError(
                f"surfaces.core_rpc.destructive_actions contains unknown action {action!r}"
            )


def required_public_actions(manifest: dict[str, Any]) -> set[str]:
    surfaces = require_object(manifest.get("surfaces"), "surfaces")
    required = set(validate_string_list(
        require_object(surfaces.get("desktop_rpc"), "surfaces.desktop_rpc").get("actions"),
        "surfaces.desktop_rpc.actions",
    ))
    required.update(validate_string_list(
        require_object(surfaces.get("core_rpc"), "surfaces.core_rpc").get("actions"),
        "surfaces.core_rpc.actions",
    ))
    required.update(validate_string_list(
        require_object(
            surfaces.get("host_runtime"), "surfaces.host_runtime"
        ).get("actions"),
        "surfaces.host_runtime.actions",
    ))

    modules = require_object(manifest.get("modules"), "modules")
    config = require_object(modules.get("config"), "modules.config")
    for action in require_array(config.get("actions"), "modules.config.actions"):
        required.add(require_string(
            require_object(action, "modules.config.actions[]").get("name"),
            "modules.config.actions[].name",
        ))
    for alias in require_array(config.get("aliases"), "modules.config.aliases"):
        required.add(require_string(
            require_object(alias, "modules.config.aliases[]").get("alias"),
            "modules.config.aliases[].alias",
        ))

    for name, value in modules.items():
        if isinstance(value, dict) and value.get("shallow") is True:
            required.update(validate_string_list(value.get("actions"), f"modules.{name}.actions"))
    return required


def validate_action_policy_profiles(
    manifest: dict[str, Any],
) -> dict[str, dict[str, str]]:
    profiles = require_object(
        manifest.get("action_policy_profiles"), "action_policy_profiles"
    )
    if not profiles:
        raise ContractError("action_policy_profiles must be nonempty")
    result: dict[str, dict[str, str]] = {}
    for profile_name, value in profiles.items():
        path = f"action_policy_profiles.{profile_name}"
        if not isinstance(profile_name, str) or not profile_name:
            raise ContractError("action_policy_profiles keys must be nonempty")
        profile = require_object(value, path)
        missing = sorted(set(ACTION_POLICY_FIELDS) - set(profile))
        extra = sorted(set(profile) - set(ACTION_POLICY_FIELDS))
        if missing:
            raise ContractError(f"{path} missing field(s): {', '.join(missing)}")
        if extra:
            raise ContractError(f"{path} has unknown field(s): {', '.join(extra)}")
        resolved: dict[str, str] = {}
        for field in ACTION_POLICY_FIELDS:
            item = require_string(profile.get(field), f"{path}.{field}")
            if item not in ACTION_POLICY_VALUES[field]:
                raise ContractError(
                    f"{path}.{field} has unsupported value {item!r}"
                )
            resolved[field] = item
        if (
            resolved["idempotency_class"] == "read_only"
            and resolved["mutation_class"] != "read_only"
        ):
            raise ContractError(
                f"{path} read_only idempotency requires read_only mutation"
            )
        if (
            resolved["confirmation_class"] == "explicit"
            and resolved["mutation_class"] == "read_only"
        ):
            raise ContractError(
                f"{path} explicit confirmation cannot protect a read-only action"
            )
        result[profile_name] = resolved
    return result


def validate_action_surfaces(value: Any, path: str) -> list[str]:
    surfaces = validate_string_list(value, path)
    if not surfaces:
        raise ContractError(f"{path} must be nonempty")
    for surface in surfaces:
        if surface not in ACTION_SURFACES:
            raise ContractError(f"{path} has unsupported value {surface!r}")
    return surfaces


def validate_action_contracts(manifest: dict[str, Any]) -> None:
    profiles = validate_action_policy_profiles(manifest)
    entries = require_array(manifest.get("action_contracts"), "action_contracts")
    contracts: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(entries):
        path = f"action_contracts[{index}]"
        entry = require_object(value, path)
        name = require_string(entry.get("name"), f"{path}.name")
        if name in contracts:
            raise ContractError(f"action_contracts contains duplicate action {name!r}")
        contracts[name] = entry
        for forbidden in ("alias", "alias_policy", "canonical"):
            if forbidden in entry:
                raise ContractError(
                    f"{path}.{forbidden} is forbidden on canonical actions"
                )
        validate_object_fields(entry, path, CANONICAL_ACTION_FIELDS)
        validate_action_surfaces(entry.get("surfaces"), f"{path}.surfaces")
        require_string(entry.get("semantic_owner"), f"{path}.semantic_owner")
        target = require_string(
            entry.get("dispatch_target"), f"{path}.dispatch_target"
        )
        if target not in ACTION_DISPATCH_TARGETS:
            raise ContractError(
                f"{path}.dispatch_target has unsupported value {target!r}"
            )
        require_string(entry.get("response_contract"), f"{path}.response_contract")
        policy = require_string(entry.get("policy"), f"{path}.policy")
        if policy not in profiles:
            raise ContractError(f"{path}.policy targets unknown profile {policy!r}")
        capability = require_string(
            entry.get("required_capability"), f"{path}.required_capability"
        )
        if capability not in ACTION_CAPABILITIES:
            raise ContractError(
                f"{path}.required_capability has unsupported value {capability!r}"
            )
        privilege = require_string(
            entry.get("privilege_class"), f"{path}.privilege_class"
        )
        if privilege not in ACTION_PRIVILEGE_CLASSES:
            raise ContractError(
                f"{path}.privilege_class has unsupported value {privilege!r}"
            )
        principal = require_string(
            entry.get("principal_scope"), f"{path}.principal_scope"
        )
        if principal not in ACTION_PRINCIPAL_SCOPES:
            raise ContractError(
                f"{path}.principal_scope has unsupported value {principal!r}"
            )
        if privilege == "machine_admin" and principal != "machine":
            raise ContractError(
                f"{path} machine_admin requires machine principal_scope"
            )

    aliases = require_array(manifest.get("action_aliases"), "action_aliases")
    alias_by_name: dict[str, dict[str, Any]] = {}
    forbidden_alias_policy = {
        "semantic_owner",
        "dispatch_target",
        "response_contract",
        "policy",
        "required_capability",
        "privilege_class",
        "principal_scope",
    }
    for index, value in enumerate(aliases):
        path = f"action_aliases[{index}]"
        alias = require_object(value, path)
        name = require_string(alias.get("alias"), f"{path}.alias")
        canonical = require_string(alias.get("canonical"), f"{path}.canonical")
        if name in contracts or name in alias_by_name:
            raise ContractError(f"action_aliases contains duplicate action {name!r}")
        if canonical not in contracts:
            raise ContractError(f"{path}.canonical targets unknown action {canonical!r}")
        validate_action_surfaces(alias.get("surfaces"), f"{path}.surfaces")
        inherited = sorted(forbidden_alias_policy & set(alias))
        if inherited:
            raise ContractError(
                f"{path} alias cannot own policy field(s): {', '.join(inherited)}"
            )
        validate_object_fields(alias, path, ACTION_ALIAS_FIELDS)
        alias_by_name[name] = alias
    validate_unique_identifiers(contracts, "action_contracts")

    submitted = set(contracts) | set(alias_by_name)
    required = required_public_actions(manifest)
    missing = sorted(required - submitted)
    if missing:
        raise ContractError(
            "action contracts missing public action(s): " + ", ".join(missing)
        )
    undeclared = sorted(submitted - required)
    if undeclared:
        raise ContractError(
            "action contracts contain non-public action(s): "
            + ", ".join(undeclared)
        )

    for surface in ("desktop_rpc", "core_rpc", "host_runtime"):
        declared = set(
            validate_string_list(
                manifest["surfaces"][surface].get("actions"),
                f"surfaces.{surface}.actions",
            )
        )
        derived = {
            entry["name"]
            for entry in contracts.values()
            if surface in entry["surfaces"]
        } | {
            entry["alias"]
            for entry in alias_by_name.values()
            if surface in entry["surfaces"]
        }
        if declared != derived:
            missing_surface = sorted(derived - declared)
            extra_surface = sorted(declared - derived)
            detail = []
            if missing_surface:
                detail.append("missing " + ", ".join(missing_surface))
            if extra_surface:
                detail.append("extra " + ", ".join(extra_surface))
            raise ContractError(
                f"surfaces.{surface}.actions differs from action descriptors: "
                + "; ".join(detail)
            )

    expected_destructive = {
        name
        for name in manifest["surfaces"]["core_rpc"]["actions"]
        if profiles[
            contracts[
                alias_by_name.get(name, {}).get("canonical", name)
            ]["policy"]
        ]["confirmation_class"]
        == "explicit"
    }
    declared_destructive = set(
        manifest["surfaces"]["core_rpc"]["destructive_actions"]
    )
    if declared_destructive != expected_destructive:
        raise ContractError(
            "surfaces.core_rpc.destructive_actions differs from generated "
            "confirmation policy"
        )


def surface_error_codes(manifest: dict[str, Any]) -> set[str]:
    desktop = require_object(
        require_object(manifest.get("surfaces"), "surfaces").get("desktop_rpc"),
        "surfaces.desktop_rpc",
    )
    core = require_object(manifest["surfaces"].get("core_rpc"),
                          "surfaces.core_rpc")
    result = {
        require_string(
            require_object(entry, "surfaces.desktop_rpc.error_codes[]").get("code"),
            "surfaces.desktop_rpc.error_codes[].code",
        )
        for entry in require_array(
            desktop.get("error_codes"), "surfaces.desktop_rpc.error_codes"
        )
    }
    result.update(validate_string_list(
        core.get("error_codes"), "surfaces.core_rpc.error_codes"
    ))
    return result


def validate_error_contracts(manifest: dict[str, Any]) -> None:
    defaults = require_object(manifest.get("error_defaults"), "error_defaults")
    validate_object_fields(
        defaults,
        "error_defaults",
        ERROR_DEFAULT_FIELDS,
    )
    presentation_prefix = require_string(
        defaults.get("safe_presentation_key_prefix"),
        "error_defaults.safe_presentation_key_prefix",
    )
    if not presentation_prefix.endswith("."):
        raise ContractError(
            "error_defaults.safe_presentation_key_prefix must end with '.'"
        )
    default_exposure = require_string(
        defaults.get("diagnostic_exposure"),
        "error_defaults.diagnostic_exposure",
    )
    if default_exposure not in ERROR_DIAGNOSTIC_EXPOSURE:
        raise ContractError(
            "error_defaults.diagnostic_exposure has unsupported value "
            f"{default_exposure!r}"
        )
    contracts = require_array(manifest.get("error_contracts"),
                              "error_contracts")
    by_code: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(contracts):
        path = f"error_contracts[{index}]"
        entry = require_object(value, path)
        validate_object_fields(
            entry,
            path,
            ERROR_CONTRACT_REQUIRED_FIELDS,
            ERROR_CONTRACT_OPTIONAL_FIELDS,
        )
        code = require_string(entry.get("code"), f"{path}.code")
        if code in by_code:
            raise ContractError(f"error_contracts contains duplicate code {code!r}")
        domain = require_string(entry.get("domain"), f"{path}.domain")
        if domain not in ERROR_DOMAINS:
            raise ContractError(f"{path}.domain has unsupported value {domain!r}")
        retryability = require_string(
            entry.get("retryability"), f"{path}.retryability"
        )
        if retryability not in ERROR_RETRYABILITY:
            raise ContractError(
                f"{path}.retryability has unsupported value {retryability!r}"
            )
        require_string(entry.get("recovery_action"), f"{path}.recovery_action")
        presentation_key = entry.get(
            "safe_presentation_key", presentation_prefix + code
        )
        require_string(presentation_key, f"{path}.safe_presentation_key")
        exposure = entry.get("diagnostic_exposure", default_exposure)
        if exposure not in ERROR_DIAGNOSTIC_EXPOSURE:
            raise ContractError(
                f"{path}.diagnostic_exposure has unsupported value {exposure!r}"
            )
        by_code[code] = entry
    validate_unique_identifiers(by_code, "error_contracts")

    declared_surface_codes = surface_error_codes(manifest)
    missing = sorted(declared_surface_codes - set(by_code))
    if missing:
        raise ContractError(
            "error_contracts missing surface code(s): " + ", ".join(missing)
        )
    unused = sorted(set(by_code) - declared_surface_codes)
    if unused:
        raise ContractError(
            "error_contracts contains undeclared code(s): " + ", ".join(unused)
        )

    aliases = require_array(manifest.get("error_aliases"), "error_aliases")
    seen_aliases: set[str] = set()
    for index, value in enumerate(aliases):
        path = f"error_aliases[{index}]"
        entry = require_object(value, path)
        validate_object_fields(entry, path, ERROR_ALIAS_FIELDS)
        alias = require_string(entry.get("alias"), f"{path}.alias")
        canonical = require_string(entry.get("canonical"), f"{path}.canonical")
        if alias in seen_aliases or alias in by_code:
            raise ContractError(f"error_aliases contains duplicate code {alias!r}")
        if canonical not in by_code:
            raise ContractError(
                f"{path}.canonical targets unknown code {canonical!r}"
            )
        seen_aliases.add(alias)


def validate_config(config: dict[str, Any]) -> None:
    actions = require_array(config.get("actions"), "modules.config.actions")
    action_names: set[str] = set()
    for index, value in enumerate(actions):
        action = require_object(value, f"modules.config.actions[{index}]")
        name = require_string(action.get("name"), f"modules.config.actions[{index}].name")
        if name in action_names:
            raise ContractError(f"modules.config.actions contains duplicate action {name!r}")
        action_names.add(name)

    aliases = require_array(config.get("aliases"), "modules.config.aliases")
    seen_aliases: set[str] = set()
    for index, value in enumerate(aliases):
        alias = require_object(value, f"modules.config.aliases[{index}]")
        alias_name = require_string(alias.get("alias"), f"modules.config.aliases[{index}].alias")
        target = require_string(alias.get("target"), f"modules.config.aliases[{index}].target")
        if alias_name in seen_aliases:
            raise ContractError(f"modules.config.aliases contains duplicate alias {alias_name!r}")
        if target not in action_names:
            raise ContractError(f"modules.config.aliases[{index}] targets unknown action {target!r}")
        seen_aliases.add(alias_name)
    validate_string_list(config.get("errors"), "modules.config.errors")


def validate_helper(helper: dict[str, Any]) -> None:
    validate_string_list(helper.get("messages"), "modules.helper.messages")
    validate_string_list(helper.get("capabilities"), "modules.helper.capabilities")
    validate_string_list(helper.get("errors"), "modules.helper.errors")

    ops = require_array(helper.get("ops"), "modules.helper.ops")
    op_names: set[str] = set()
    op_codes: set[int] = set()
    for index, value in enumerate(ops):
        op = require_object(value, f"modules.helper.ops[{index}]")
        name = require_string(op.get("name"), f"modules.helper.ops[{index}].name")
        code = op.get("code")
        if not isinstance(code, int) or isinstance(code, bool):
            raise ContractError(f"modules.helper.ops[{index}].code must be an integer")
        if not isinstance(op.get("requires_session"), bool):
            raise ContractError(f"modules.helper.ops[{index}].requires_session must be a boolean")
        require_string(op.get("request"), f"modules.helper.ops[{index}].request")
        require_string(op.get("response"), f"modules.helper.ops[{index}].response")
        if name in op_names:
            raise ContractError(f"modules.helper.ops contains duplicate op {name!r}")
        if code in op_codes:
            raise ContractError(f"modules.helper.ops contains duplicate code {code}")
        op_names.add(name)
        op_codes.add(code)

    security = require_object(helper.get("security"), "modules.helper.security")
    if security.get("no_credentials") is not True:
        raise ContractError("modules.helper.security.no_credentials must be true")
    forbidden = validate_string_list(security.get("forbidden_fields"),
                                     "modules.helper.security.forbidden_fields")
    for required in ("password", "cookie", "token", "auth_token", "credential"):
        if required not in forbidden:
            raise ContractError(
                f"modules.helper.security.forbidden_fields must include {required!r}"
            )


def validate_tunnel_controller(tunnel: dict[str, Any]) -> None:
    phases = require_array(tunnel.get("phases"), "modules.tunnel_controller.phases")
    seen_phase_names: set[str] = set()
    seen_wire_names: set[str] = set()
    for index, value in enumerate(phases):
        phase = require_object(value, f"modules.tunnel_controller.phases[{index}]")
        name = require_string(phase.get("name"),
                              f"modules.tunnel_controller.phases[{index}].name")
        wire_name = require_string(
            phase.get("wire_name"),
            f"modules.tunnel_controller.phases[{index}].wire_name",
        )
        for field in ("running", "connected", "network_ready"):
            if not isinstance(phase.get(field), bool):
                raise ContractError(
                    f"modules.tunnel_controller.phases[{index}].{field} must be a boolean"
                )
        if name in seen_phase_names:
            raise ContractError(
                f"modules.tunnel_controller.phases contains duplicate phase {name!r}"
            )
        if wire_name in seen_wire_names:
            raise ContractError(
                "modules.tunnel_controller.phases contains duplicate wire name "
                f"{wire_name!r}"
            )
        seen_phase_names.add(name)
        seen_wire_names.add(wire_name)

    validate_string_list(tunnel.get("events"), "modules.tunnel_controller.events")
    validate_string_list(tunnel.get("disconnect_reasons"),
                         "modules.tunnel_controller.disconnect_reasons")
    validate_string_list(tunnel.get("error_domains"),
                         "modules.tunnel_controller.error_domains")
    validate_string_list(tunnel.get("status_fields"),
                         "modules.tunnel_controller.status_fields")


def validate_runtime_presentation(presentation: dict[str, Any]) -> None:
    if presentation.get("schema_version") != 1:
        raise ContractError("modules.runtime_presentation.schema_version must be 1")
    validate_string_list(presentation.get("event_kinds"),
                         "modules.runtime_presentation.event_kinds")
    validate_string_list(presentation.get("severities"),
                         "modules.runtime_presentation.severities")
    validate_string_list(presentation.get("desired_states"),
                         "modules.runtime_presentation.desired_states")
    validate_string_list(presentation.get("vpn_states"),
                         "modules.runtime_presentation.vpn_states")
    validate_string_list(presentation.get("error_domains"),
                         "modules.runtime_presentation.error_domains")
    validate_string_list(presentation.get("retry_policies"),
                         "modules.runtime_presentation.retry_policies")
    validate_string_list(presentation.get("actions"),
                         "modules.runtime_presentation.actions")
    validate_string_list(presentation.get("wire_fields"),
                         "modules.runtime_presentation.wire_fields")
    forbidden = validate_string_list(
        presentation.get("forbidden_alert_fields"),
        "modules.runtime_presentation.forbidden_alert_fields",
    )
    for required in ("message", "diagnostics", "recommended_action"):
        if required not in forbidden:
            raise ContractError(
                "modules.runtime_presentation.forbidden_alert_fields "
                f"must include {required!r}"
            )


def validate_src_organization(src_organization: dict[str, Any]) -> None:
    boundary = require_object(src_organization.get("boundary"),
                              "modules.src_organization.boundary")
    validate_string_list(boundary.get("accepts"),
                         "modules.src_organization.boundary.accepts")
    validate_string_list(boundary.get("rejects"),
                         "modules.src_organization.boundary.rejects")
    validate_string_list(boundary.get("emits"),
                         "modules.src_organization.boundary.emits")
    validate_string_list(src_organization.get("allowed_top_level_dirs"),
                         "modules.src_organization.allowed_top_level_dirs")
    validate_string_list(src_organization.get("forbidden_patterns"),
                         "modules.src_organization.forbidden_patterns")


def validate_manifest(manifest: dict[str, Any]) -> None:
    validate_object_fields(manifest, "manifest", MANIFEST_FIELDS)
    if manifest.get("contract_id") != "exv.system":
        raise ContractError("contract_id must be exv.system")
    if manifest.get("schema_version") != 2:
        raise ContractError("schema_version must be 2")
    require_string(manifest.get("version"), "version")
    require_positive_int(manifest.get("ipc_protocol_major"), "ipc_protocol_major")

    envelopes = require_object(manifest.get("envelopes"), "envelopes")
    for envelope in ("desktop_rpc", "core_rpc"):
        envelope_obj = require_object(envelopes.get(envelope), f"envelopes.{envelope}")
        for side in ("request", "response"):
            side_obj = require_object(envelope_obj.get(side), f"envelopes.{envelope}.{side}")
            validate_fields(side_obj.get("fields"), f"envelopes.{envelope}.{side}.fields")

    surfaces = require_object(manifest.get("surfaces"), "surfaces")
    desktop = require_object(surfaces.get("desktop_rpc"), "surfaces.desktop_rpc")
    validate_string_list(desktop.get("actions"), "surfaces.desktop_rpc.actions")
    validate_string_list(desktop.get("event_types"), "surfaces.desktop_rpc.event_types")
    validate_error_code_entries(desktop.get("error_codes"), "surfaces.desktop_rpc.error_codes")
    validate_core_rpc(require_object(surfaces.get("core_rpc"), "surfaces.core_rpc"))
    host_runtime = require_object(
        surfaces.get("host_runtime"), "surfaces.host_runtime"
    )
    validate_string_list(
        host_runtime.get("actions"), "surfaces.host_runtime.actions"
    )

    modules = require_object(manifest.get("modules"), "modules")
    validate_config(require_object(modules.get("config"), "modules.config"))
    validate_helper(require_object(modules.get("helper"), "modules.helper"))
    validate_tunnel_controller(require_object(modules.get("tunnel_controller"),
                                              "modules.tunnel_controller"))
    validate_runtime_presentation(require_object(
        modules.get("runtime_presentation"),
        "modules.runtime_presentation",
    ))
    validate_src_organization(require_object(modules.get("src_organization"),
                                             "modules.src_organization"))
    for name in ("vpn", "service", "routes", "runtime", "logs"):
        module = require_object(modules.get(name), f"modules.{name}")
        if module.get("shallow") is not True:
            raise ContractError(f"modules.{name}.shallow must be true")
        validate_string_list(module.get("actions"), f"modules.{name}.actions")
    validate_action_contracts(manifest)
    validate_error_contracts(manifest)


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{path}: invalid JSON: {exc}") from exc
    manifest = require_object(value, "manifest")
    validate_manifest(manifest)
    return manifest


def load_schema(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"{path}: invalid JSON schema: {exc}") from exc
    schema = require_object(value, "schema")
    defs = require_object(schema.get("$defs"), "schema.$defs")
    enum_expectations = {
        "surface": set(ACTION_SURFACES),
        "executionPolicy.lane": ACTION_POLICY_VALUES["lane"],
        "executionPolicy.conflict_class": ACTION_POLICY_VALUES["conflict_class"],
        "executionPolicy.mutation_class": ACTION_POLICY_VALUES["mutation_class"],
        "executionPolicy.deadline_class": ACTION_POLICY_VALUES["deadline_class"],
        "executionPolicy.retry_class": ACTION_POLICY_VALUES["retry_class"],
        "executionPolicy.idempotency_class": ACTION_POLICY_VALUES[
            "idempotency_class"
        ],
        "executionPolicy.confirmation_class": ACTION_POLICY_VALUES[
            "confirmation_class"
        ],
        "canonicalAction.required_capability": ACTION_CAPABILITIES,
        "canonicalAction.dispatch_target": ACTION_DISPATCH_TARGETS,
        "canonicalAction.privilege_class": ACTION_PRIVILEGE_CLASSES,
        "canonicalAction.principal_scope": ACTION_PRINCIPAL_SCOPES,
        "diagnosticExposure": ERROR_DIAGNOSTIC_EXPOSURE,
        "errorContract.domain": ERROR_DOMAINS,
        "errorContract.retryability": ERROR_RETRYABILITY,
    }
    for dotted, expected in enum_expectations.items():
        parts = dotted.split(".")
        node = require_object(defs.get(parts[0]), f"schema.$defs.{parts[0]}")
        if len(parts) == 2:
            properties = require_object(
                node.get("properties"),
                f"schema.$defs.{parts[0]}.properties",
            )
            node = require_object(
                properties.get(parts[1]),
                f"schema.$defs.{dotted}",
            )
        actual = set(
            validate_string_list(node.get("enum"), f"schema.$defs.{dotted}.enum")
        )
        if actual != set(expected):
            raise ContractError(f"schema enum drift at {dotted}")
    required_policy = set(
        validate_string_list(
            defs["executionPolicy"].get("required"),
            "schema.$defs.executionPolicy.required",
        )
    )
    if required_policy != set(ACTION_POLICY_FIELDS):
        raise ContractError("schema executionPolicy required fields drift")
    return schema


def config_actions(manifest: dict[str, Any]) -> list[str]:
    return [action["name"] for action in manifest["modules"]["config"]["actions"]]


def core_rpc(manifest: dict[str, Any]) -> dict[str, Any]:
    return manifest["surfaces"]["core_rpc"]


def core_rpc_actions(manifest: dict[str, Any]) -> list[str]:
    return core_rpc(manifest)["actions"]


def destructive_core_rpc_actions(manifest: dict[str, Any]) -> list[str]:
    return core_rpc(manifest)["destructive_actions"]


def standard_error_codes(manifest: dict[str, Any]) -> list[str]:
    return core_rpc(manifest)["error_codes"]


def config_aliases(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (alias["alias"], alias["target"])
        for alias in manifest["modules"]["config"]["aliases"]
    ]


def action_contracts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return manifest["action_contracts"]


def action_aliases(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return manifest["action_aliases"]


def action_policy_profiles(
    manifest: dict[str, Any],
) -> dict[str, dict[str, str]]:
    return manifest["action_policy_profiles"]


def resolved_canonical_action_contracts(
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    profiles = action_policy_profiles(manifest)
    result = []
    for entry in action_contracts(manifest):
        resolved = dict(entry)
        resolved["id"] = enum_identifier(entry["name"])
        resolved["execution_policy"] = dict(profiles[entry["policy"]])
        result.append(resolved)
    return result


def resolved_action_contracts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    contracts = action_contracts(manifest)
    by_name = {entry["name"]: entry for entry in contracts}
    profiles = action_policy_profiles(manifest)
    resolved: list[dict[str, Any]] = []
    for entry in contracts:
        resolved.append({
            "name": entry["name"],
            "canonical": entry["name"],
            "action_id": enum_identifier(entry["name"]),
            "surfaces": list(entry["surfaces"]),
            "semantic_owner": entry["semantic_owner"],
            "dispatch_target": entry["dispatch_target"],
            "response_contract": entry["response_contract"],
            "execution_policy": dict(profiles[entry["policy"]]),
            "required_capability": entry["required_capability"],
            "privilege_class": entry["privilege_class"],
            "principal_scope": entry["principal_scope"],
            "alias_policy": "direct",
        })
    for alias in action_aliases(manifest):
        canonical_entry = by_name[alias["canonical"]]
        resolved.append({
            "name": alias["alias"],
            "canonical": alias["canonical"],
            "action_id": enum_identifier(alias["canonical"]),
            "surfaces": list(alias["surfaces"]),
            "semantic_owner": canonical_entry["semantic_owner"],
            "dispatch_target": canonical_entry["dispatch_target"],
            "response_contract": canonical_entry["response_contract"],
            "execution_policy": dict(profiles[canonical_entry["policy"]]),
            "required_capability": canonical_entry["required_capability"],
            "privilege_class": canonical_entry["privilege_class"],
            "principal_scope": canonical_entry["principal_scope"],
            "alias_policy": "compat_alias",
        })
    return resolved


def compat_action_aliases(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (entry["alias"], entry["canonical"])
        for entry in action_aliases(manifest)
    ]


def error_contracts(manifest: dict[str, Any]) -> list[dict[str, str]]:
    defaults = manifest["error_defaults"]
    return [
        {
            **entry,
            "safe_presentation_key": entry.get(
                "safe_presentation_key",
                defaults["safe_presentation_key_prefix"] + entry["code"],
            ),
            "diagnostic_exposure": entry.get(
                "diagnostic_exposure", defaults["diagnostic_exposure"]
            ),
        }
        for entry in manifest["error_contracts"]
    ]


def error_aliases(manifest: dict[str, Any]) -> list[dict[str, str]]:
    return manifest["error_aliases"]


def helper_ops(manifest: dict[str, Any]) -> list[str]:
    return [op["name"] for op in manifest["modules"]["helper"]["ops"]]


def tunnel_controller(manifest: dict[str, Any]) -> dict[str, Any]:
    return manifest["modules"]["tunnel_controller"]


def runtime_presentation(manifest: dict[str, Any]) -> dict[str, Any]:
    return manifest["modules"]["runtime_presentation"]


def tunnel_phase_names(manifest: dict[str, Any]) -> list[str]:
    return [phase["name"] for phase in tunnel_controller(manifest)["phases"]]


def desktop_error_code_map(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        entry["key"]: entry["code"]
        for entry in manifest["surfaces"]["desktop_rpc"]["error_codes"]
    }


def desktop_error_codes(manifest: dict[str, Any]) -> list[str]:
    return list(desktop_error_code_map(manifest).values())


def cpp_string(value: str) -> str:
    return json.dumps(value)


def cpp_array(name: str, values: Iterable[str]) -> str:
    items = list(values)
    body = ", ".join(cpp_string(value) for value in items)
    return f"inline constexpr std::array<std::string_view, {len(items)}> {name} = {{{{{body}}}}};"


def cpp_bool(value: bool) -> str:
    return "true" if value else "false"


def cpp_enum(enum_type: str, value: str) -> str:
    return f"{enum_type}::{enum_identifier(value)}"


def action_surface_mask(surfaces: Iterable[str]) -> int:
    selected = set(surfaces)
    return sum(
        1 << index
        for index, surface in enumerate(ACTION_SURFACES)
        if surface in selected
    )


def cpp_enum_declaration(name: str, values: Iterable[str]) -> list[str]:
    return [
        f"enum class {name} : std::uint16_t {{",
        *[f"    {enum_identifier(value)}," for value in values],
        "};",
    ]


def render_cpp(manifest: dict[str, Any]) -> str:
    aliases = config_aliases(manifest)
    actions = resolved_action_contracts(manifest)
    canonical_actions = resolved_canonical_action_contracts(manifest)
    expected_actions_by_target = {
        target: [
            entry for entry in canonical_actions
            if entry["dispatch_target"] == target
        ]
        for target in sorted(ACTION_DISPATCH_TARGETS)
    }
    errors = error_contracts(manifest)
    aliases_by_error = error_aliases(manifest)
    tunnel = tunnel_controller(manifest)
    presentation = runtime_presentation(manifest)
    return "\n".join([
        "// Generated from contracts/system.contract.json. Do not edit manually.",
        "#pragma once",
        "",
        "#include <array>",
        "#include <cstddef>",
        "#include <cstdint>",
        "#include <span>",
        "#include <string_view>",
        "",
        "namespace exv::contracts::generated {",
        "",
        f"inline constexpr std::string_view CONTRACT_VERSION = {cpp_string(manifest['version'])};",
        f"inline constexpr std::string_view SYSTEM_CONTRACT_DIGEST = {cpp_string(contract_digest(manifest))};",
        f"inline constexpr std::uint32_t IPC_PROTOCOL_MAJOR = {manifest['ipc_protocol_major']};",
        "",
        cpp_array("DESKTOP_RPC_REQUEST_FIELDS", field_names(manifest, "desktop_rpc", "request")),
        cpp_array("DESKTOP_RPC_RESPONSE_FIELDS", field_names(manifest, "desktop_rpc", "response")),
        cpp_array("CORE_RPC_REQUEST_FIELDS", field_names(manifest, "core_rpc", "request")),
        cpp_array("CORE_RPC_RESPONSE_FIELDS", field_names(manifest, "core_rpc", "response")),
        "",
        cpp_array("CORE_RPC_ACTIONS", core_rpc_actions(manifest)),
        cpp_array("DESTRUCTIVE_CORE_RPC_ACTIONS", destructive_core_rpc_actions(manifest)),
        cpp_array("STANDARD_ERROR_CODES", standard_error_codes(manifest)),
        cpp_array("DESKTOP_RPC_ACTIONS", manifest["surfaces"]["desktop_rpc"]["actions"]),
        cpp_array("HOST_RUNTIME_ACTIONS", manifest["surfaces"]["host_runtime"]["actions"]),
        cpp_array("DESKTOP_RPC_EVENT_TYPES", manifest["surfaces"]["desktop_rpc"]["event_types"]),
        cpp_array("DESKTOP_RPC_ERROR_CODES", desktop_error_codes(manifest)),
        cpp_array("CONFIG_ACTIONS", config_actions(manifest)),
        cpp_array("CONFIG_LEGACY_ALIASES", [alias for alias, _ in aliases]),
        cpp_array("HELPER_OPS", helper_ops(manifest)),
        cpp_array("TUNNEL_PHASES", tunnel_phase_names(manifest)),
        cpp_array("TUNNEL_EVENTS", tunnel["events"]),
        cpp_array("TUNNEL_DISCONNECT_REASONS", tunnel["disconnect_reasons"]),
        cpp_array("TUNNEL_ERROR_DOMAINS", tunnel["error_domains"]),
        cpp_array("TUNNEL_STATUS_FIELDS", tunnel["status_fields"]),
        cpp_array("RUNTIME_PRESENTATION_EVENT_KINDS", presentation["event_kinds"]),
        cpp_array("RUNTIME_PRESENTATION_SEVERITIES", presentation["severities"]),
        cpp_array("RUNTIME_PRESENTATION_DESIRED_STATES", presentation["desired_states"]),
        cpp_array("RUNTIME_PRESENTATION_VPN_STATES", presentation["vpn_states"]),
        cpp_array("RUNTIME_PRESENTATION_ERROR_DOMAINS", presentation["error_domains"]),
        cpp_array("RUNTIME_PRESENTATION_RETRY_POLICIES", presentation["retry_policies"]),
        cpp_array("RUNTIME_PRESENTATION_ACTIONS", presentation["actions"]),
        cpp_array("RUNTIME_PRESENTATION_WIRE_FIELDS", presentation["wire_fields"]),
        cpp_array("RUNTIME_PRESENTATION_FORBIDDEN_ALERT_FIELDS",
                  presentation["forbidden_alert_fields"]),
        cpp_array("SRC_ALLOWED_TOP_LEVEL_DIRS",
                  manifest["modules"]["src_organization"]["allowed_top_level_dirs"]),
        cpp_array("SRC_FORBIDDEN_PATTERNS",
                  manifest["modules"]["src_organization"]["forbidden_patterns"]),
        cpp_array("HELPER_FORBIDDEN_CREDENTIAL_FIELDS",
                  manifest["modules"]["helper"]["security"]["forbidden_fields"]),
        "",
        *cpp_enum_declaration(
            "ActionId", [entry["name"] for entry in canonical_actions]
        ),
        "",
        *cpp_enum_declaration(
            "DispatchTarget", sorted(ACTION_DISPATCH_TARGETS)
        ),
        "",
        f"inline constexpr std::array<DispatchTarget, {len(ACTION_DISPATCH_TARGETS)}> ALL_DISPATCH_TARGETS = {{{{",
        *[
            f"    {cpp_enum('DispatchTarget', target)},"
            for target in sorted(ACTION_DISPATCH_TARGETS)
        ],
        "}};",
        "",
        "enum class ActionSurface : std::uint32_t {",
        *[
            f"    {enum_identifier(surface)} = {1 << index}U,"
            for index, surface in enumerate(ACTION_SURFACES)
        ],
        "};",
        "",
        *cpp_enum_declaration(
            "ExecutionLane", sorted(ACTION_POLICY_VALUES["lane"])
        ),
        "",
        *cpp_enum_declaration(
            "ConflictClass", sorted(ACTION_POLICY_VALUES["conflict_class"])
        ),
        "",
        *cpp_enum_declaration(
            "MutationClass", sorted(ACTION_POLICY_VALUES["mutation_class"])
        ),
        "",
        *cpp_enum_declaration(
            "DeadlineClass", sorted(ACTION_POLICY_VALUES["deadline_class"])
        ),
        "",
        *cpp_enum_declaration(
            "RetryClass", sorted(ACTION_POLICY_VALUES["retry_class"])
        ),
        "",
        *cpp_enum_declaration(
            "IdempotencyClass",
            sorted(ACTION_POLICY_VALUES["idempotency_class"]),
        ),
        "",
        *cpp_enum_declaration(
            "ConfirmationClass",
            sorted(ACTION_POLICY_VALUES["confirmation_class"]),
        ),
        "",
        *cpp_enum_declaration(
            "RequiredCapability", sorted(ACTION_CAPABILITIES)
        ),
        "",
        *cpp_enum_declaration(
            "PrivilegeClass", sorted(ACTION_PRIVILEGE_CLASSES)
        ),
        "",
        *cpp_enum_declaration(
            "PrincipalScope", sorted(ACTION_PRINCIPAL_SCOPES)
        ),
        "",
        "struct ExecutionPolicyDescriptor {",
        "    ExecutionLane lane;",
        "    ConflictClass conflict_class;",
        "    MutationClass mutation_class;",
        "    DeadlineClass deadline_class;",
        "    RetryClass retry_class;",
        "    IdempotencyClass idempotency_class;",
        "    ConfirmationClass confirmation_class;",
        "};",
        "",
        "struct CanonicalActionDescriptor {",
        "    ActionId id;",
        "    std::string_view name;",
        "    std::uint32_t surface_mask;",
        "    std::string_view semantic_owner;",
        "    DispatchTarget dispatch_target;",
        "    std::string_view response_contract;",
        "    ExecutionPolicyDescriptor execution_policy;",
        "    RequiredCapability required_capability;",
        "    PrivilegeClass privilege_class;",
        "    PrincipalScope principal_scope;",
        "};",
        "",
        f"inline constexpr std::array<CanonicalActionDescriptor, {len(canonical_actions)}> CANONICAL_ACTION_DESCRIPTORS = {{{{",
        *[
            "    {"
            f"{cpp_enum('ActionId', entry['name'])}, "
            f"{cpp_string(entry['name'])}, "
            f"{action_surface_mask(entry['surfaces'])}U, "
            f"{cpp_string(entry['semantic_owner'])}, "
            f"{cpp_enum('DispatchTarget', entry['dispatch_target'])}, "
            f"{cpp_string(entry['response_contract'])}, "
            "{"
            f"{cpp_enum('ExecutionLane', entry['execution_policy']['lane'])}, "
            f"{cpp_enum('ConflictClass', entry['execution_policy']['conflict_class'])}, "
            f"{cpp_enum('MutationClass', entry['execution_policy']['mutation_class'])}, "
            f"{cpp_enum('DeadlineClass', entry['execution_policy']['deadline_class'])}, "
            f"{cpp_enum('RetryClass', entry['execution_policy']['retry_class'])}, "
            f"{cpp_enum('IdempotencyClass', entry['execution_policy']['idempotency_class'])}, "
            f"{cpp_enum('ConfirmationClass', entry['execution_policy']['confirmation_class'])}"
            "}, "
            f"{cpp_enum('RequiredCapability', entry['required_capability'])}, "
            f"{cpp_enum('PrivilegeClass', entry['privilege_class'])}, "
            f"{cpp_enum('PrincipalScope', entry['principal_scope'])}"
            "},"
            for entry in canonical_actions
        ],
        "}};",
        "",
        *[
            line
            for target, target_actions in expected_actions_by_target.items()
            for line in [
                f"inline constexpr std::array<ActionId, {len(target_actions)}> "
                f"EXPECTED_{target.upper()}_ACTION_IDS = {{{{",
                *[
                    f"    {cpp_enum('ActionId', entry['name'])},"
                    for entry in target_actions
                ],
                "}};",
                "",
            ]
        ],
        "struct SubmittedActionDescriptor {",
        "    std::string_view submitted_name;",
        "    ActionId canonical_id;",
        "    std::uint32_t surface_mask;",
        "    bool compatibility_alias;",
        "};",
        "",
        f"inline constexpr std::array<SubmittedActionDescriptor, {len(actions)}> SUBMITTED_ACTION_DESCRIPTORS = {{{{",
        *[
            "    {"
            f"{cpp_string(entry['name'])}, "
            f"{cpp_enum('ActionId', entry['canonical'])}, "
            f"{action_surface_mask(entry['surfaces'])}U, "
            f"{cpp_bool(entry['alias_policy'] == 'compat_alias')}"
            "},"
            for entry in actions
        ],
        "}};",
        "",
        "struct ActionIngressTestVector {",
        "    std::string_view submitted_name;",
        "    ActionSurface surface;",
        "    ActionId canonical_id;",
        "    bool allowed;",
        "};",
        "",
        f"inline constexpr std::array<ActionIngressTestVector, {len(actions) * len(ACTION_SURFACES)}> ACTION_INGRESS_TEST_VECTORS = {{{{",
        *[
            "    {"
            f"{cpp_string(entry['name'])}, "
            f"{cpp_enum('ActionSurface', surface)}, "
            f"{cpp_enum('ActionId', entry['canonical'])}, "
            f"{cpp_bool(surface in entry['surfaces'])}"
            "},"
            for entry in actions
            for surface in ACTION_SURFACES
        ],
        "}};",
        "",
        "struct ActionDispatchContract {",
        "    std::string_view name;",
        "    std::string_view canonical;",
        "    std::string_view semantic_owner;",
        "    std::string_view dispatch_target;",
        "    std::string_view response_contract;",
        "    std::string_view alias_policy;",
        "};",
        "",
        f"inline constexpr std::array<ActionDispatchContract, {len(actions)}> ACTION_CONTRACTS = {{{{",
        *[
            "    {"
            f"{cpp_string(entry['name'])}, "
            f"{cpp_string(entry['canonical'])}, "
            f"{cpp_string(entry['semantic_owner'])}, "
            f"{cpp_string(entry['dispatch_target'])}, "
            f"{cpp_string(entry['response_contract'])}, "
            f"{cpp_string(entry['alias_policy'])}"
            "},"
            for entry in actions
        ],
        "}};",
        "",
        *cpp_enum_declaration(
            "ErrorId", [entry["code"] for entry in errors]
        ),
        "",
        *cpp_enum_declaration("ErrorDomain", sorted(ERROR_DOMAINS)),
        "",
        *cpp_enum_declaration(
            "ErrorRetryability", sorted(ERROR_RETRYABILITY)
        ),
        "",
        *cpp_enum_declaration(
            "DiagnosticExposure", sorted(ERROR_DIAGNOSTIC_EXPOSURE)
        ),
        "",
        "struct TypedErrorDescriptor {",
        "    ErrorId id;",
        "    std::string_view code;",
        "    ErrorDomain domain;",
        "    ErrorRetryability retryability;",
        "    std::string_view recovery_action;",
        "    std::string_view safe_presentation_key;",
        "    DiagnosticExposure diagnostic_exposure;",
        "};",
        "",
        f"inline constexpr std::array<TypedErrorDescriptor, {len(errors)}> TYPED_ERROR_DESCRIPTORS = {{{{",
        *[
            "    {"
            f"{cpp_enum('ErrorId', entry['code'])}, "
            f"{cpp_string(entry['code'])}, "
            f"{cpp_enum('ErrorDomain', entry['domain'])}, "
            f"{cpp_enum('ErrorRetryability', entry['retryability'])}, "
            f"{cpp_string(entry['recovery_action'])}, "
            f"{cpp_string(entry['safe_presentation_key'])}, "
            f"{cpp_enum('DiagnosticExposure', entry['diagnostic_exposure'])}"
            "},"
            for entry in errors
        ],
        "}};",
        "",
        "struct ErrorContract {",
        "    std::string_view code;",
        "    std::string_view domain;",
        "    std::string_view retryability;",
        "    std::string_view recovery_action;",
        "    std::string_view safe_presentation_key;",
        "    std::string_view diagnostic_exposure;",
        "};",
        "",
        f"inline constexpr std::array<ErrorContract, {len(errors)}> ERROR_CONTRACTS = {{{{",
        *[
            "    {"
            f"{cpp_string(entry['code'])}, "
            f"{cpp_string(entry['domain'])}, "
            f"{cpp_string(entry['retryability'])}, "
            f"{cpp_string(entry['recovery_action'])}, "
            f"{cpp_string(entry['safe_presentation_key'])}, "
            f"{cpp_string(entry['diagnostic_exposure'])}"
            "},"
            for entry in errors
        ],
        "}};",
        "",
        "struct ErrorAliasContract {",
        "    std::string_view alias;",
        "    std::string_view canonical;",
        "};",
        "",
        f"inline constexpr std::array<ErrorAliasContract, {len(aliases_by_error)}> ERROR_ALIASES = {{{{",
        *[
            f"    {{{cpp_string(entry['alias'])}, {cpp_string(entry['canonical'])}}},"
            for entry in aliases_by_error
        ],
        "}};",
        "",
        "struct HelperOpContract {",
        "    std::string_view name;",
        "    std::uint32_t code;",
        "    bool requires_session;",
        "};",
        "",
        f"inline constexpr std::array<HelperOpContract, {len(manifest['modules']['helper']['ops'])}> HELPER_OP_CONTRACTS = {{{{",
        *[
            f"    {{{cpp_string(op['name'])}, {op['code']}, {'true' if op['requires_session'] else 'false'}}},"
            for op in manifest["modules"]["helper"]["ops"]
        ],
        "}};",
        "",
        "struct ConfigAlias {",
        "    std::string_view alias;",
        "    std::string_view target;",
        "};",
        "",
        f"inline constexpr std::array<ConfigAlias, {len(aliases)}> CONFIG_ALIASES = {{{{",
        *[f"    {{{cpp_string(alias)}, {cpp_string(target)}}}," for alias, target in aliases],
        "}};",
        "",
        "struct TunnelPhaseContract {",
        "    std::string_view name;",
        "    std::string_view wire_name;",
        "    bool running;",
        "    bool connected;",
        "    bool network_ready;",
        "};",
        "",
        f"inline constexpr std::array<TunnelPhaseContract, {len(tunnel['phases'])}> TUNNEL_PHASE_CONTRACTS = {{{{",
        *[
            "    {"
            f"{cpp_string(phase['name'])}, "
            f"{cpp_string(phase['wire_name'])}, "
            f"{'true' if phase['running'] else 'false'}, "
            f"{'true' if phase['connected'] else 'false'}, "
            f"{'true' if phase['network_ready'] else 'false'}"
            "},"
            for phase in tunnel["phases"]
        ],
        "}};",
        "",
        "template <std::size_t N>",
        "constexpr bool contains(const std::array<std::string_view, N>& values, std::string_view value) {",
        "    for (const auto item : values) {",
        "        if (item == value) {",
        "            return true;",
        "        }",
        "    }",
        "    return false;",
        "}",
        "",
        "constexpr std::uint32_t action_surface_mask(ActionSurface surface) {",
        "    return static_cast<std::uint32_t>(surface);",
        "}",
        "",
        "constexpr std::span<const ActionId> expected_action_ids_for(DispatchTarget target) {",
        "    switch (target) {",
        *[
            line
            for target in sorted(ACTION_DISPATCH_TARGETS)
            for line in [
                f"    case {cpp_enum('DispatchTarget', target)}:",
                f"        return std::span<const ActionId>(EXPECTED_{target.upper()}_ACTION_IDS);",
            ]
        ],
        "    }",
        "    return {};",
        "}",
        "",
        "constexpr bool is_expected_action_for_target(ActionId id, DispatchTarget target) {",
        "    for (const auto expected : expected_action_ids_for(target)) {",
        "        if (expected == id) {",
        "            return true;",
        "        }",
        "    }",
        "    return false;",
        "}",
        "",
        "constexpr const CanonicalActionDescriptor* canonical_action_descriptor_for(ActionId id) {",
        "    for (const auto& item : CANONICAL_ACTION_DESCRIPTORS) {",
        "        if (item.id == id) {",
        "            return &item;",
        "        }",
        "    }",
        "    return nullptr;",
        "}",
        "",
        "constexpr const SubmittedActionDescriptor* submitted_action_descriptor_for(std::string_view action) {",
        "    for (const auto& item : SUBMITTED_ACTION_DESCRIPTORS) {",
        "        if (item.submitted_name == action) {",
        "            return &item;",
        "        }",
        "    }",
        "    return nullptr;",
        "}",
        "",
        "constexpr bool is_action_allowed_on(std::string_view action, ActionSurface surface) {",
        "    const auto* submitted = submitted_action_descriptor_for(action);",
        "    return submitted != nullptr &&",
        "           (submitted->surface_mask & action_surface_mask(surface)) != 0U;",
        "}",
        "",
        "constexpr const CanonicalActionDescriptor* resolve_action(std::string_view action, ActionSurface surface) {",
        "    const auto* submitted = submitted_action_descriptor_for(action);",
        "    if (submitted == nullptr ||",
        "        (submitted->surface_mask & action_surface_mask(surface)) == 0U) {",
        "        return nullptr;",
        "    }",
        "    return canonical_action_descriptor_for(submitted->canonical_id);",
        "}",
        "",
        "constexpr bool is_desktop_rpc_action(std::string_view action) {",
        "    return is_action_allowed_on(action, ActionSurface::DesktopRpc);",
        "}",
        "",
        "constexpr bool is_host_runtime_action(std::string_view action) {",
        "    return is_action_allowed_on(action, ActionSurface::HostRuntime);",
        "}",
        "",
        "constexpr const ActionDispatchContract* action_contract_for(std::string_view action) {",
        "    for (const auto& item : ACTION_CONTRACTS) {",
        "        if (item.name == action) {",
        "            return &item;",
        "        }",
        "    }",
        "    return nullptr;",
        "}",
        "",
        "constexpr bool is_public_action(std::string_view action) {",
        "    return action_contract_for(action) != nullptr;",
        "}",
        "",
        "constexpr std::string_view canonical_action_for(std::string_view action) {",
        "    const auto* contract = action_contract_for(action);",
        "    return contract == nullptr ? std::string_view{} : contract->canonical;",
        "}",
        "",
        "constexpr std::string_view semantic_owner_for(std::string_view action) {",
        "    const auto* contract = action_contract_for(action);",
        "    return contract == nullptr ? std::string_view{} : contract->semantic_owner;",
        "}",
        "",
        "constexpr std::string_view dispatch_target_for(std::string_view action) {",
        "    const auto* contract = action_contract_for(action);",
        "    return contract == nullptr ? std::string_view{} : contract->dispatch_target;",
        "}",
        "",
        "constexpr std::string_view response_contract_for(std::string_view action) {",
        "    const auto* contract = action_contract_for(action);",
        "    return contract == nullptr ? std::string_view{} : contract->response_contract;",
        "}",
        "",
        "constexpr bool is_dispatch_target(std::string_view action, std::string_view target) {",
        "    return dispatch_target_for(action) == target;",
        "}",
        "",
        "constexpr bool is_compat_alias(std::string_view action) {",
        "    const auto* contract = action_contract_for(action);",
        "    return contract != nullptr && contract->alias_policy == \"compat_alias\";",
        "}",
        "",
        "constexpr std::string_view canonical_error_code_for(std::string_view code) {",
        "    for (const auto& item : ERROR_CONTRACTS) {",
        "        if (item.code == code) {",
        "            return item.code;",
        "        }",
        "    }",
        "    for (const auto& item : ERROR_ALIASES) {",
        "        if (item.alias == code) {",
        "            return item.canonical;",
        "        }",
        "    }",
        "    return {};",
        "}",
        "",
        "constexpr const TypedErrorDescriptor* typed_error_descriptor_for(std::string_view code) {",
        "    const auto canonical = canonical_error_code_for(code);",
        "    for (const auto& item : TYPED_ERROR_DESCRIPTORS) {",
        "        if (item.code == canonical) {",
        "            return &item;",
        "        }",
        "    }",
        "    return nullptr;",
        "}",
        "",
        "constexpr const TypedErrorDescriptor* typed_error_descriptor_for(ErrorId id) {",
        "    for (const auto& item : TYPED_ERROR_DESCRIPTORS) {",
        "        if (item.id == id) {",
        "            return &item;",
        "        }",
        "    }",
        "    return nullptr;",
        "}",
        "",
        "constexpr const ErrorContract* error_contract_for(std::string_view code) {",
        "    const auto canonical = canonical_error_code_for(code);",
        "    for (const auto& item : ERROR_CONTRACTS) {",
        "        if (item.code == canonical) {",
        "            return &item;",
        "        }",
        "    }",
        "    return nullptr;",
        "}",
        "",
        "constexpr std::string_view error_domain_for(std::string_view code) {",
        "    const auto* contract = error_contract_for(code);",
        "    return contract == nullptr ? std::string_view{} : contract->domain;",
        "}",
        "",
        "constexpr bool is_core_rpc_action(std::string_view action) {",
        "    return is_action_allowed_on(action, ActionSurface::CoreRpc);",
        "}",
        "",
        "constexpr bool is_destructive_core_rpc_action(std::string_view action) {",
        "    return contains(DESTRUCTIVE_CORE_RPC_ACTIONS, action);",
        "}",
        "",
        "constexpr bool is_standard_error_code(std::string_view code) {",
        "    return contains(STANDARD_ERROR_CODES, code);",
        "}",
        "",
        "constexpr bool is_config_action(std::string_view action) {",
        "    return contains(CONFIG_ACTIONS, action);",
        "}",
        "",
        "constexpr bool is_config_alias(std::string_view alias) {",
        "    return contains(CONFIG_LEGACY_ALIASES, alias);",
        "}",
        "",
        "constexpr bool is_helper_op(std::string_view op) {",
        "    return contains(HELPER_OPS, op);",
        "}",
        "",
        "constexpr bool is_tunnel_phase(std::string_view phase) {",
        "    return contains(TUNNEL_PHASES, phase);",
        "}",
        "",
        "constexpr bool is_tunnel_event(std::string_view event) {",
        "    return contains(TUNNEL_EVENTS, event);",
        "}",
        "",
        "constexpr bool is_tunnel_disconnect_reason(std::string_view reason) {",
        "    return contains(TUNNEL_DISCONNECT_REASONS, reason);",
        "}",
        "",
        "constexpr bool is_tunnel_error_domain(std::string_view domain) {",
        "    return contains(TUNNEL_ERROR_DOMAINS, domain);",
        "}",
        "",
        "constexpr bool is_helper_forbidden_credential_field(std::string_view field) {",
        "    return contains(HELPER_FORBIDDEN_CREDENTIAL_FIELDS, field);",
        "}",
        "",
        "} // namespace exv::contracts::generated",
        "",
    ])


def ts_literal(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False)


def render_ts(manifest: dict[str, Any]) -> str:
    aliases = {alias: target for alias, target in config_aliases(manifest)}
    action_aliases = {alias: target for alias, target in compat_action_aliases(manifest)}
    actions = resolved_action_contracts(manifest)
    canonical_actions = resolved_canonical_action_contracts(manifest)
    action_ids = {
        entry["id"]: entry["name"] for entry in canonical_actions
    }
    expected_action_ids_by_target = {
        target: [
            entry["id"] for entry in canonical_actions
            if entry["dispatch_target"] == target
        ]
        for target in sorted(ACTION_DISPATCH_TARGETS)
    }
    error_ids = {
        enum_identifier(entry["code"]): entry["code"]
        for entry in error_contracts(manifest)
    }
    ingress_vectors = [
        {
            "submitted_name": entry["name"],
            "surface": surface,
            "action_id": entry["action_id"],
            "allowed": surface in entry["surfaces"],
        }
        for entry in actions
        for surface in ACTION_SURFACES
    ]
    semantic_owner_map = {
        entry["name"]: entry["semantic_owner"] for entry in actions
    }
    dispatch_target_map = {
        entry["name"]: entry["dispatch_target"] for entry in actions
    }
    helper = manifest["modules"]["helper"]
    tunnel = tunnel_controller(manifest)
    presentation = runtime_presentation(manifest)
    return "\n".join([
        "// Generated from contracts/system.contract.json. Do not edit manually.",
        "",
        f"export const CONTRACT_VERSION = {json.dumps(manifest['version'])} as const",
        f"export const SYSTEM_CONTRACT_DIGEST = {json.dumps(contract_digest(manifest))} as const",
        f"export const IPC_PROTOCOL_MAJOR = {manifest['ipc_protocol_major']} as const",
        "",
        f"export const DESKTOP_RPC_REQUEST_FIELDS = {ts_literal(field_names(manifest, 'desktop_rpc', 'request'))} as const",
        f"export const DESKTOP_RPC_RESPONSE_FIELDS = {ts_literal(field_names(manifest, 'desktop_rpc', 'response'))} as const",
        f"export const CORE_RPC_REQUEST_FIELDS = {ts_literal(field_names(manifest, 'core_rpc', 'request'))} as const",
        f"export const CORE_RPC_RESPONSE_FIELDS = {ts_literal(field_names(manifest, 'core_rpc', 'response'))} as const",
        "",
        f"export const CORE_RPC_ACTIONS = {ts_literal(core_rpc_actions(manifest))} as const",
        f"export const DESTRUCTIVE_CORE_RPC_ACTIONS = {ts_literal(destructive_core_rpc_actions(manifest))} as const",
        f"export const STANDARD_ERROR_CODES = {ts_literal(standard_error_codes(manifest))} as const",
        "",
        f"export const DESKTOP_RPC_ACTIONS = {ts_literal(manifest['surfaces']['desktop_rpc']['actions'])} as const",
        f"export const HOST_RUNTIME_ACTIONS = {ts_literal(manifest['surfaces']['host_runtime']['actions'])} as const",
        f"export const DESKTOP_RPC_EVENT_TYPES = {ts_literal(manifest['surfaces']['desktop_rpc']['event_types'])} as const",
        f"export const DESKTOP_RPC_ERROR_CODES = {ts_literal(desktop_error_codes(manifest))} as const",
        f"export const DESKTOP_RPC_ERROR_CODE_MAP = {ts_literal(desktop_error_code_map(manifest))} as const",
        "",
        f"export const CONFIG_ACTIONS = {ts_literal(config_actions(manifest))} as const",
        f"export const CONFIG_ALIASES = {ts_literal(aliases)} as const",
        f"export const ACTION_IDS = {ts_literal(action_ids)} as const",
        f"export const DISPATCH_TARGETS = {ts_literal(sorted(ACTION_DISPATCH_TARGETS))} as const",
        f"export const ACTION_POLICY_PROFILES = {ts_literal(action_policy_profiles(manifest))} as const",
        f"export const CANONICAL_ACTION_DESCRIPTORS = {ts_literal(canonical_actions)} as const",
        f"export const EXPECTED_ACTION_IDS_BY_DISPATCH_TARGET = {ts_literal(expected_action_ids_by_target)} as const",
        f"export const SUBMITTED_ACTION_DESCRIPTORS = {ts_literal([{'submitted_name': entry['name'], 'canonical': entry['canonical'], 'action_id': entry['action_id'], 'surfaces': entry['surfaces'], 'compatibility_alias': entry['alias_policy'] == 'compat_alias'} for entry in actions])} as const",
        f"export const ACTION_INGRESS_TEST_VECTORS = {ts_literal(ingress_vectors)} as const",
        f"export const ACTION_CONTRACTS = {ts_literal(actions)} as const",
        f"export const ACTION_SEMANTIC_OWNER_MAP = {ts_literal(semantic_owner_map)} as const",
        f"export const ACTION_DISPATCH_TARGET_MAP = {ts_literal(dispatch_target_map)} as const",
        f"export const COMPAT_ACTION_ALIASES = {ts_literal(action_aliases)} as const",
        f"export const ERROR_IDS = {ts_literal(error_ids)} as const",
        f"export const ERROR_CONTRACTS = {ts_literal(error_contracts(manifest))} as const",
        f"export const ERROR_ALIASES = {ts_literal({entry['alias']: entry['canonical'] for entry in error_aliases(manifest)})} as const",
        "",
        f"export const HELPER_OPS = {ts_literal(helper_ops(manifest))} as const",
        f"export const HELPER_OP_CONTRACTS = {ts_literal(helper['ops'])} as const",
        f"export const HELPER_FORBIDDEN_CREDENTIAL_FIELDS = {ts_literal(helper['security']['forbidden_fields'])} as const",
        "",
        f"export const TUNNEL_PHASE_CONTRACTS = {ts_literal(tunnel['phases'])} as const",
        f"export const TUNNEL_EVENTS = {ts_literal(tunnel['events'])} as const",
        f"export const TUNNEL_DISCONNECT_REASONS = {ts_literal(tunnel['disconnect_reasons'])} as const",
        f"export const TUNNEL_ERROR_DOMAINS = {ts_literal(tunnel['error_domains'])} as const",
        f"export const TUNNEL_STATUS_FIELDS = {ts_literal(tunnel['status_fields'])} as const",
        f"export const RUNTIME_PRESENTATION_SCHEMA_VERSION = {presentation['schema_version']} as const",
        f"export const RUNTIME_PRESENTATION_EVENT_KINDS = {ts_literal(presentation['event_kinds'])} as const",
        f"export const RUNTIME_PRESENTATION_SEVERITIES = {ts_literal(presentation['severities'])} as const",
        f"export const RUNTIME_PRESENTATION_DESIRED_STATES = {ts_literal(presentation['desired_states'])} as const",
        f"export const RUNTIME_PRESENTATION_VPN_STATES = {ts_literal(presentation['vpn_states'])} as const",
        f"export const RUNTIME_PRESENTATION_ERROR_DOMAINS = {ts_literal(presentation['error_domains'])} as const",
        f"export const RUNTIME_PRESENTATION_RETRY_POLICIES = {ts_literal(presentation['retry_policies'])} as const",
        f"export const RUNTIME_PRESENTATION_ACTIONS = {ts_literal(presentation['actions'])} as const",
        f"export const RUNTIME_PRESENTATION_WIRE_FIELDS = {ts_literal(presentation['wire_fields'])} as const",
        f"export const RUNTIME_PRESENTATION_FORBIDDEN_ALERT_FIELDS = {ts_literal(presentation['forbidden_alert_fields'])} as const",
        f"export const SRC_ALLOWED_TOP_LEVEL_DIRS = {ts_literal(manifest['modules']['src_organization']['allowed_top_level_dirs'])} as const",
        f"export const SRC_FORBIDDEN_PATTERNS = {ts_literal(manifest['modules']['src_organization']['forbidden_patterns'])} as const",
        "",
        "export type DesktopRpcAction = (typeof DESKTOP_RPC_ACTIONS)[number]",
        "export type HostRuntimeAction = (typeof HOST_RUNTIME_ACTIONS)[number]",
        "export type CoreRpcAction = (typeof CORE_RPC_ACTIONS)[number]",
        "export type DestructiveCoreRpcAction = (typeof DESTRUCTIVE_CORE_RPC_ACTIONS)[number]",
        "export type ConfigAction = (typeof CONFIG_ACTIONS)[number]",
        "export type ActionId = keyof typeof ACTION_IDS",
        "export type ActionSurface = (typeof ACTION_INGRESS_TEST_VECTORS)[number]['surface']",
        "export type ActionSemanticOwner = (typeof ACTION_CONTRACTS)[number]['semantic_owner']",
        "export type ActionDispatchTarget = (typeof ACTION_CONTRACTS)[number]['dispatch_target']",
        "export type ActionExecutionPolicy = (typeof CANONICAL_ACTION_DESCRIPTORS)[number]['execution_policy']",
        "export type ActionPrivilegeClass = (typeof CANONICAL_ACTION_DESCRIPTORS)[number]['privilege_class']",
        "export type ActionPrincipalScope = (typeof CANONICAL_ACTION_DESCRIPTORS)[number]['principal_scope']",
        "export type ErrorId = keyof typeof ERROR_IDS",
        "export type ErrorDomain = (typeof ERROR_CONTRACTS)[number]['domain']",
        "export type ErrorRetryability = (typeof ERROR_CONTRACTS)[number]['retryability']",
        "export type HelperOp = (typeof HELPER_OPS)[number]",
        "export type StandardErrorCode = (typeof STANDARD_ERROR_CODES)[number]",
        "export type TunnelPhase = (typeof TUNNEL_PHASE_CONTRACTS)[number]['name']",
        "export type TunnelEvent = (typeof TUNNEL_EVENTS)[number]",
        "export type RuntimePresentationEventKind = (typeof RUNTIME_PRESENTATION_EVENT_KINDS)[number]",
        "export type RuntimePresentationSeverity = (typeof RUNTIME_PRESENTATION_SEVERITIES)[number]",
        "export type RuntimePresentationDesiredState = (typeof RUNTIME_PRESENTATION_DESIRED_STATES)[number]",
        "export type RuntimePresentationVpnState = (typeof RUNTIME_PRESENTATION_VPN_STATES)[number]",
        "export type RuntimePresentationErrorDomain = (typeof RUNTIME_PRESENTATION_ERROR_DOMAINS)[number]",
        "export type RuntimePresentationRetryPolicy = (typeof RUNTIME_PRESENTATION_RETRY_POLICIES)[number]",
        "export type RuntimePresentationActionKind = (typeof RUNTIME_PRESENTATION_ACTIONS)[number]",
        "",
    ])


def render_snapshot(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def write_text(path: Path, content: str, check: bool) -> bool:
    existing = path.read_text(encoding="utf-8") if path.exists() else None
    if existing == content:
        return False
    if check:
        raise ContractError(f"{path} is not up to date")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return True


def generate(manifest_path: Path, cpp_path: Path, ts_paths: Iterable[Path],
             snapshot_path: Path, check: bool) -> list[Path]:
    schema_path = manifest_path.with_name("system.contract.schema.json")
    if schema_path.is_file():
        load_schema(schema_path)
    manifest = load_manifest(manifest_path)
    outputs = {
        cpp_path: render_cpp(manifest),
        snapshot_path: render_snapshot(manifest),
    }
    ts_content = render_ts(manifest)
    for ts_path in ts_paths:
        outputs[ts_path] = ts_content
    changed: list[Path] = []
    for path in sorted(outputs):
        if write_text(path, outputs[path], check):
            changed.append(path)
    return changed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--cpp", type=Path, default=DEFAULT_CPP)
    parser.add_argument(
        "--ts",
        type=Path,
        action="append",
        default=None,
        help="TypeScript contract output path. May be passed multiple times.",
    )
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ts_paths = args.ts if args.ts is not None else TS_CONTRACT_OUTPUTS
    try:
        changed = generate(args.manifest, args.cpp, ts_paths, args.snapshot, args.check)
    except ContractError as exc:
        print(f"contract generation failed: {exc}")
        return 1

    if args.check:
        print("contract generated files are up to date")
    elif changed:
        print("generated:")
        for path in changed:
            print(f"  {path}")
    else:
        print("generated files already up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
