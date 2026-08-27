#!/usr/bin/env python3
"""Generate the immutable Runtime V3 package identity.

The provider-contract digest is a projection of the platform-neutral model,
not a digest selected by any App/Core/Helper adapter.  Keeping this projection
in one generator makes source checks, native consumers and package inspection
use exactly the same identity.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any


class IdentityError(RuntimeError):
    pass


def canonical_json(value: Any, *, sort_keys: bool = False) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=sort_keys,
        separators=(",", ":"),
    )


def sha256(value: str | bytes) -> str:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load_contract_generator(root: Path):
    script = root / "scripts" / "generate_contracts.py"
    spec = importlib.util.spec_from_file_location(
        "exv_system_contract_generator", script
    )
    if spec is None or spec.loader is None:
        raise IdentityError(f"cannot load system contract generator: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise IdentityError(f"{path} must be a non-empty string")
    return value


def generate_identity(root: Path) -> dict[str, Any]:
    system_path = root / "contracts" / "system.contract.json"
    model_path = root / "contracts" / "runtime_v3" / "business_flow.model.json"
    system = json.loads(system_path.read_text(encoding="utf-8"))
    model = json.loads(model_path.read_text(encoding="utf-8"))

    system_generator = load_contract_generator(root)
    system_generator.validate_manifest(system)
    system_digest = system_generator.contract_digest(system)
    model_digest = sha256(canonical_json(model, sort_keys=True))

    schemas_value = model.get("message_schemas")
    capabilities_value = model.get("capabilities")
    if not isinstance(schemas_value, list) or not isinstance(
        capabilities_value, list
    ):
        raise IdentityError("model message_schemas and capabilities must be arrays")

    schemas: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(schemas_value):
        if not isinstance(value, dict):
            raise IdentityError(f"message_schemas[{index}] must be an object")
        schema_id = require_string(value.get("id"), f"message_schemas[{index}].id")
        if schema_id in schemas:
            raise IdentityError(f"duplicate message schema: {schema_id}")
        schemas[schema_id] = value

    projected_capabilities: list[dict[str, Any]] = []
    seen_capabilities: set[str] = set()
    for index, value in enumerate(capabilities_value):
        if not isinstance(value, dict):
            raise IdentityError(f"capabilities[{index}] must be an object")
        capability_id = require_string(
            value.get("id"), f"capabilities[{index}].id"
        )
        if capability_id in seen_capabilities:
            raise IdentityError(f"duplicate capability: {capability_id}")
        seen_capabilities.add(capability_id)
        request_schema = require_string(
            value.get("request_schema"),
            f"capabilities[{index}].request_schema",
        )
        schema = schemas.get(request_schema)
        if schema is None:
            raise IdentityError(
                f"capability {capability_id} has unknown request schema "
                f"{request_schema}"
            )
        fields = schema.get("fields")
        if not isinstance(fields, list):
            raise IdentityError(
                f"request schema {request_schema} fields must be an array"
            )
        secret_slots: list[str] = []
        for field_index, field in enumerate(fields):
            if not isinstance(field, dict):
                raise IdentityError(
                    f"request schema {request_schema} field {field_index} "
                    "must be an object"
                )
            if field.get("secret", False):
                secret_slots.append(
                    require_string(
                        field.get("name"),
                        f"message_schemas.{request_schema}.fields[{field_index}].name",
                    )
                )

        invocation = value.get("invocation")
        if not isinstance(invocation, dict) or not isinstance(
            invocation.get("allowed_media"), list
        ):
            raise IdentityError(
                f"capability {capability_id} invocation.allowed_media "
                "must be an array"
            )
        allowed_media = [
            require_string(
                medium,
                f"capabilities[{index}].invocation.allowed_media[{medium_index}]",
            )
            for medium_index, medium in enumerate(invocation["allowed_media"])
        ]
        principal_scope = require_string(
            value.get("principal_scope"),
            f"capabilities[{index}].principal_scope",
        )
        if principal_scope not in {"none", "originating_user", "machine"}:
            raise IdentityError(
                f"capability {capability_id} has invalid principal scope "
                f"{principal_scope}"
            )
        side_effect = require_string(
            value.get("side_effect_class"),
            f"capabilities[{index}].side_effect_class",
        )
        execution_class = (
            "observation"
            if side_effect in {"observation", "pure"}
            else "serialized_effect"
        )
        projected_capabilities.append(
            {
                "capability_id": capability_id,
                "owner_module": require_string(
                    value.get("owner_module"),
                    f"capabilities[{index}].owner_module",
                ),
                "request_schema": request_schema,
                "response_schema": require_string(
                    value.get("response_schema"),
                    f"capabilities[{index}].response_schema",
                ),
                "completion_event": require_string(
                    value.get("completion_event"),
                    f"capabilities[{index}].completion_event",
                ),
                "allowed_media": allowed_media,
                "secret_slots": secret_slots,
                "principal_scope": principal_scope,
                "execution_class": execution_class,
            }
        )

    projection = {
        "schema_version": "1.0",
        "model_schema_version": require_string(
            model.get("schema_version"), "model.schema_version"
        ),
        "model_digest": model_digest,
        "system_contract_digest": system_digest,
        "capabilities": projected_capabilities,
    }
    # nlohmann::json uses an ordered key map, so its compact dump sorts every
    # object key.  Match that canonical byte sequence exactly.
    provider_digest = sha256(canonical_json(projection, sort_keys=True))
    return {
        "schema_version": "1.0",
        "requirement_id": "vpn-common-v3-runtime-boundary-decoupling",
        "identity": {
            "model_schema_version": projection["model_schema_version"],
            "model_digest": model_digest,
            "system_contract_digest": system_digest,
            "provider_contract_digest": provider_digest,
        },
        "provider_contract_projection": projection,
    }


def render_json(identity: dict[str, Any]) -> str:
    return json.dumps(
        identity, ensure_ascii=False, sort_keys=True, indent=2
    ) + "\n"


def render_cpp(identity: dict[str, Any]) -> str:
    values = identity["identity"]
    return f"""#pragma once

#include <string_view>

namespace exv::runtime_v3::generated {{

inline constexpr std::string_view RUNTIME_V3_MODEL_SCHEMA_VERSION =
    {json.dumps(values["model_schema_version"])};
inline constexpr std::string_view RUNTIME_V3_MODEL_DIGEST =
    {json.dumps(values["model_digest"])};
inline constexpr std::string_view RUNTIME_V3_SYSTEM_CONTRACT_DIGEST =
    {json.dumps(values["system_contract_digest"])};
inline constexpr std::string_view RUNTIME_V3_PROVIDER_CONTRACT_DIGEST =
    {json.dumps(values["provider_contract_digest"])};

}} // namespace exv::runtime_v3::generated
"""


def write_or_check(path: Path, rendered: str, check: bool) -> None:
    if check:
        if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
            raise IdentityError(f"generated runtime identity is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
        path.write_text(rendered, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=Path("contracts/generated/runtime_contract_identity.json"),
    )
    parser.add_argument(
        "--cpp",
        type=Path,
        default=Path("src/contracts/generated/runtime_contract_identity.hpp"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    json_output = args.json if args.json.is_absolute() else root / args.json
    cpp_output = args.cpp if args.cpp.is_absolute() else root / args.cpp
    try:
        identity = generate_identity(root)
        write_or_check(json_output, render_json(identity), args.check)
        write_or_check(cpp_output, render_cpp(identity), args.check)
    except (IdentityError, json.JSONDecodeError, OSError, ValueError) as error:
        print(f"runtime contract identity error: {error}")
        return 1
    if args.check:
        print("runtime contract identity is complete and up to date")
    else:
        print(f"generated {json_output}")
        print(f"generated {cpp_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
