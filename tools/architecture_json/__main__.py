"""Command-line entry point for bounded architecture JSON queries and mutations."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any, Sequence

from .dependencies import (
    MUTATION_DEPENDENCIES,
    READ_DEPENDENCIES,
    dependency_report,
)
from .errors import ArchitectureQueryError
from .loader import (
    JsonValue,
    LoadedDocument,
    discover_repo_root,
    document_absolute_path,
    load_document,
    parse_json_text,
)
from .mutation import (
    PointerAddition,
    PointerReplacement,
    execute_mutation,
    plan_create,
    plan_delete,
    plan_rename,
    plan_update,
)
from .output import (
    CONTRACT_VERSION,
    failure_envelope,
    render_json,
    render_jsonl,
    render_text,
    success_envelope,
)
from .profiles.runtime_v3 import RuntimeV3Profile
from .query import (
    ExactFieldPredicate,
    describe_tree,
    document_summary,
    list_section,
    paginate_values,
    project_fields,
    resolve_pointer,
    section_inventory,
    select_jmespath,
)
from .references import build_reference_index


class _AgentArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ArchitectureQueryError(
            "ARCH_USAGE_INVALID",
            message,
            exit_code=2,
        )


def _comma_values(value: str | None, *, option: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    values = tuple(part.strip() for part in value.split(",") if part.strip())
    if not values:
        raise ArchitectureQueryError(
            "ARCH_USAGE_INVALID",
            f"{option} requires at least one non-empty value",
            exit_code=2,
        )
    return values


def _where_predicates(values: Sequence[str]) -> tuple[ExactFieldPredicate, ...]:
    predicates: list[ExactFieldPredicate] = []
    for value in values:
        if "=" not in value:
            raise ArchitectureQueryError(
                "ARCH_USAGE_INVALID",
                "--where must use FIELD=JSON_VALUE",
                exit_code=2,
                details={"where": value},
            )
        field, encoded = value.split("=", 1)
        field = field.strip()
        if not field:
            raise ArchitectureQueryError(
                "ARCH_USAGE_INVALID",
                "--where field cannot be empty",
                exit_code=2,
            )
        try:
            expected = json.loads(encoded)
        except json.JSONDecodeError as error:
            raise ArchitectureQueryError(
                "ARCH_USAGE_INVALID",
                "--where value must be a JSON scalar",
                exit_code=2,
                details={"where": value, "reason": str(error)},
            ) from error
        if isinstance(expected, (list, dict)):
            raise ArchitectureQueryError(
                "ARCH_USAGE_INVALID",
                "--where value must be a JSON scalar",
                exit_code=2,
                details={"where": value},
            )
        predicates.append(ExactFieldPredicate(field, expected))
    return tuple(predicates)


def _mutation_value(encoded: str, *, option: str) -> JsonValue:
    try:
        return parse_json_text(encoded, location=option, kind="mutation value")
    except ArchitectureQueryError as error:
        raise ArchitectureQueryError(
            "ARCH_MUTATION_INVALID",
            f"{option} must contain strict JSON",
            exit_code=2,
            details={"option": option, "reason": error.details.get("reason")},
        ) from error


def _pointer_replacements(values: Sequence[str]) -> tuple[PointerReplacement, ...]:
    replacements: list[PointerReplacement] = []
    for value in values:
        if "=" not in value:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "--set must use /RFC6901/POINTER=JSON_VALUE",
                exit_code=2,
                details={"set": value},
            )
        pointer, encoded = value.split("=", 1)
        replacements.append(
            PointerReplacement(
                pointer=pointer,
                value=_mutation_value(encoded, option="--set"),
            )
        )
    return tuple(replacements)


def _pointer_additions(values: Sequence[str]) -> tuple[PointerAddition, ...]:
    additions: list[PointerAddition] = []
    for value in values:
        if "=" not in value:
            raise ArchitectureQueryError(
                "ARCH_MUTATION_INVALID",
                "--add must use /RFC6901/POINTER=JSON_VALUE",
                exit_code=2,
                details={"add": value},
            )
        pointer, encoded = value.split("=", 1)
        additions.append(
            PointerAddition(
                pointer=pointer,
                value=_mutation_value(encoded, option="--add"),
            )
        )
    return tuple(additions)


def _add_mutation_guards(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--expected-sha256",
        required=True,
        help="required canonical source digest from summary or a prior mutation",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="atomically write the validated candidate; default is dry-run",
    )


def _build_parser() -> _AgentArgumentParser:
    parser = _AgentArgumentParser(
        prog="python3 -m tools.architecture_json",
        description="Bounded queries and guarded mutations over architecture JSON.",
    )
    parser.add_argument("--repo", type=Path)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--model", choices=("runtime-v3",))
    source.add_argument("--file", type=Path)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--validation", choices=("schema", "parse"))
    parser.add_argument("--format", choices=("json", "jsonl", "text"), default="json")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--debug", action="store_true")

    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="report external runtime dependencies")
    doctor.add_argument(
        "--require",
        choices=("read", "mutate", "all"),
        default="read",
        help="capability that must be ready for a successful exit",
    )
    commands.add_parser("summary", help="show source identity and high-level counts")
    commands.add_parser("sections", help="list top-level JSON sections")

    pointer = commands.add_parser("pointer", help="resolve an RFC 6901 JSON Pointer")
    pointer.add_argument("pointer")

    select = commands.add_parser("select", help="run a JMESPath projection")
    select.add_argument("expression")

    listing = commands.add_parser("list", help="list a top-level array section")
    listing.add_argument("section")
    listing.add_argument("--where", action="append", default=[])
    listing.add_argument("--fields")
    listing.add_argument("--sort")
    listing.add_argument("--offset", type=int, default=0)
    listing.add_argument("--limit", type=int, default=50)

    get = commands.add_parser("get", help="get one stable-id entity")
    get.add_argument("section")
    get.add_argument("entity_id")

    tree = commands.add_parser(
        "tree", help="describe JSON hierarchy without dumping leaves"
    )
    tree.add_argument("pointer", nargs="?", default="")
    tree.add_argument("--depth", type=int, default=2)
    tree.add_argument("--include-values", action="store_true")

    capabilities = commands.add_parser(
        "capabilities", help="list capabilities owned by one Runtime V3 module"
    )
    capabilities.add_argument("--module", required=True, dest="module_id")
    capabilities.add_argument("--fields")
    capabilities.add_argument("--offset", type=int, default=0)
    capabilities.add_argument("--limit", type=int, default=50)

    members = commands.add_parser(
        "members", help="list declared semantic members related to a Runtime V3 module"
    )
    members.add_argument("--module", required=True, dest="module_id")
    members.add_argument(
        "--kinds",
        default="capabilities,events,state_regions,resources",
    )
    members.add_argument("--offset", type=int, default=0)
    members.add_argument("--limit", type=int, default=50)

    refs = commands.add_parser(
        "refs", help="list incoming/outgoing stable-ID references"
    )
    refs.add_argument("section")
    refs.add_argument("entity_id")
    refs.add_argument(
        "--direction",
        choices=("incoming", "outgoing", "both"),
        default="both",
    )
    refs.add_argument("--offset", type=int, default=0)
    refs.add_argument("--limit", type=int, default=50)

    trace = commands.add_parser(
        "trace", help="walk the bounded stable-ID semantic reference graph"
    )
    trace.add_argument("section")
    trace.add_argument("entity_id")
    trace.add_argument(
        "--direction",
        choices=("incoming", "outgoing", "both"),
        default="outgoing",
    )
    trace.add_argument("--depth", type=int, default=2)

    create = commands.add_parser(
        "create", help="append one stable-id entity after validation"
    )
    create.add_argument("section")
    create.add_argument("--value", required=True)
    _add_mutation_guards(create)

    update = commands.add_parser(
        "update", help="replace existing fields on one stable-id entity"
    )
    update.add_argument("section")
    update.add_argument("entity_id")
    update.add_argument("--set", action="append", default=[], dest="replacements")
    update.add_argument("--add", action="append", default=[], dest="additions")
    _add_mutation_guards(update)

    delete = commands.add_parser(
        "delete", help="remove one unreferenced stable-id entity"
    )
    delete.add_argument("section")
    delete.add_argument("entity_id")
    delete.add_argument(
        "--cascade",
        action="store_true",
        help="delete the transitive stable-ID dependent entity closure",
    )
    _add_mutation_guards(delete)

    rename = commands.add_parser(
        "rename", help="rename a stable ID and all indexed semantic references"
    )
    rename.add_argument("section")
    rename.add_argument("entity_id")
    rename.add_argument("new_id")
    _add_mutation_guards(rename)

    commands.add_parser("validate", help="parse and validate the selected document")
    return parser


def _doctor_envelope(requirement: str) -> tuple[dict[str, Any], int]:
    dependencies = dependency_report()
    availability = {item["name"]: item["available"] for item in dependencies}
    read_ready = all(availability[name] for name in READ_DEPENDENCIES)
    mutate_ready = read_ready and all(
        availability[name] for name in MUTATION_DEPENDENCIES
    )
    required_names = (
        READ_DEPENDENCIES
        if requirement == "read"
        else READ_DEPENDENCIES + MUTATION_DEPENDENCIES
    )
    available = all(availability[name] for name in required_names)
    envelope: dict[str, Any] = {
        "contract": CONTRACT_VERSION,
        "ok": available,
        "result": {
            "kind": "diagnostic",
            "python": {
                "version": sys.version.split()[0],
                "executable": sys.executable,
            },
            "dependencies": dependencies,
            "capabilities": {"read": read_ready, "mutate": mutate_ready},
            "required_capability": requirement,
            "repository_manages_dependencies": False,
        },
        "diagnostics": [],
    }
    if not available:
        envelope["error"] = {
            "code": "ARCH_DEPENDENCY_MISSING",
            "message": "one or more external Python architecture packages are unavailable",
            "details": {
                "missing": [name for name in required_names if not availability[name]]
            },
        }
    return envelope, 0 if available else 7


def _generic_get(document: LoadedDocument, section: str, entity_id: str) -> Any:
    page = list_section(
        document,
        section=section,
        where=(ExactFieldPredicate("id", entity_id),),
        offset=0,
        limit=2,
    )
    if page.total == 0:
        raise ArchitectureQueryError(
            "ARCH_ENTITY_NOT_FOUND",
            "entity id was not found",
            exit_code=5,
            location=f"/{section}",
            details={"section": section, "id": entity_id},
        )
    if page.total > 1:
        raise ArchitectureQueryError(
            "ARCH_DUPLICATE_ID",
            "entity id is duplicated",
            exit_code=4,
            location=f"/{section}",
            details={"section": section, "id": entity_id},
        )
    return page.items[0]


def _query_result(
    args: argparse.Namespace, document: LoadedDocument
) -> tuple[dict[str, Any], dict[str, Any]]:
    command = args.command
    if command == "summary":
        return document_summary(document), {}
    if command == "sections":
        return section_inventory(document).to_result(), {}
    if command == "pointer":
        if args.pointer == "":
            raise ArchitectureQueryError(
                "ARCH_RESULT_TOO_LARGE",
                "whole-document pointer output is forbidden; use summary, sections, or tree",
                exit_code=6,
                details={"pointer": "", "reason": "whole_document"},
            )
        return {"kind": "value", "data": resolve_pointer(document, args.pointer)}, {
            "pointer": args.pointer
        }
    if command == "select":
        return {"kind": "value", "data": select_jmespath(document, args.expression)}, {
            "expression": args.expression
        }
    if command == "list":
        fields = _comma_values(args.fields, option="--fields")
        sort = _comma_values(args.sort, option="--sort")
        predicates = _where_predicates(args.where)
        page = list_section(
            document,
            section=args.section,
            where=predicates,
            fields=fields,
            sort=sort,
            offset=args.offset,
            limit=args.limit,
        )
        return page.to_result(), {
            "section": args.section,
            "where": [
                {"field": item.field, "expected": item.expected} for item in predicates
            ],
            "fields": list(fields) if fields else None,
            "sort": list(sort) if sort else None,
            "offset": args.offset,
            "limit": args.limit,
        }
    if command == "get":
        if document.model_id == "runtime-v3":
            value = RuntimeV3Profile(document).get_entity(args.section, args.entity_id)
        else:
            value = _generic_get(document, args.section, args.entity_id)
        return {"kind": "value", "data": value}, {
            "section": args.section,
            "id": args.entity_id,
        }
    if command == "tree":
        tree = describe_tree(
            document,
            pointer=args.pointer,
            depth=args.depth,
            include_values=args.include_values,
        )
        return {"kind": "tree", "data": tree}, {
            "pointer": args.pointer,
            "depth": args.depth,
            "include_values": args.include_values,
        }
    if command == "capabilities":
        profile = RuntimeV3Profile(document)
        fields = _comma_values(args.fields, option="--fields")
        values = [
            project_fields(item, fields)
            for item in profile.capabilities_for_module(args.module_id)
        ]
        page = paginate_values(values, offset=args.offset, limit=args.limit)
        return page.to_result(), {
            "module": args.module_id,
            "fields": list(fields) if fields else None,
            "offset": args.offset,
            "limit": args.limit,
        }
    if command == "members":
        profile = RuntimeV3Profile(document)
        kinds = _comma_values(args.kinds, option="--kinds")
        assert kinds is not None
        values = profile.members_for_module(args.module_id, kinds=kinds)
        page = paginate_values(values, offset=args.offset, limit=args.limit)
        return page.to_result(), {
            "module": args.module_id,
            "kinds": list(kinds),
            "offset": args.offset,
            "limit": args.limit,
        }
    if command == "refs":
        if document.model_id == "runtime-v3":
            RuntimeV3Profile(document).get_entity(args.section, args.entity_id)
        else:
            _generic_get(document, args.section, args.entity_id)
        reference_index = build_reference_index(document)
        references = []
        if args.direction in ("incoming", "both"):
            references.extend(reference_index.incoming(args.section, args.entity_id))
        if args.direction in ("outgoing", "both"):
            references.extend(reference_index.outgoing(args.section, args.entity_id))
        unique = {
            (
                item.target_section,
                item.target_id,
                item.source_pointer,
                item.location,
            ): item
            for item in references
        }
        values = [item.to_result() for item in unique.values()]
        page = paginate_values(values, offset=args.offset, limit=args.limit)
        return page.to_result(), {
            "section": args.section,
            "id": args.entity_id,
            "direction": args.direction,
            "offset": args.offset,
            "limit": args.limit,
        }
    if command == "trace":
        if document.model_id == "runtime-v3":
            RuntimeV3Profile(document).get_entity(args.section, args.entity_id)
        else:
            _generic_get(document, args.section, args.entity_id)
        result = build_reference_index(document).trace(
            args.section,
            args.entity_id,
            direction=args.direction,
            depth=args.depth,
        )
        return result, {
            "section": args.section,
            "id": args.entity_id,
            "direction": args.direction,
            "depth": args.depth,
        }
    if command == "validate":
        return {
            "kind": "validation",
            "valid": True,
            "mode": document.validation,
        }, {}
    raise ArchitectureQueryError(
        "ARCH_USAGE_INVALID",
        "command is unknown",
        exit_code=2,
        details={"command": command},
    )


def _mutation_result(
    args: argparse.Namespace, document: LoadedDocument
) -> tuple[dict[str, Any], dict[str, Any]]:
    path = document_absolute_path(document)
    try:
        source_bytes = path.read_bytes()
        source_text = source_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ArchitectureQueryError(
            "ARCH_WRITE_FAILED",
            "unable to read mutation source text",
            exit_code=10,
            details={"path": document.path.as_posix(), "reason": str(error)},
        ) from error

    if args.command == "create":
        value = _mutation_value(args.value, option="--value")
        plan = plan_create(
            document,
            section=args.section,
            value=value,
            source_text=source_text,
        )
        parameters = {
            "section": args.section,
            "expected_sha256": args.expected_sha256,
            "apply": args.apply,
        }
    elif args.command == "update":
        replacements = _pointer_replacements(args.replacements)
        additions = _pointer_additions(args.additions)
        plan = plan_update(
            document,
            section=args.section,
            entity_id=args.entity_id,
            replacements=replacements,
            additions=additions,
            source_text=source_text,
        )
        parameters = {
            "section": args.section,
            "id": args.entity_id,
            "set_pointers": [item.pointer for item in replacements],
            "add_pointers": [item.pointer for item in additions],
            "expected_sha256": args.expected_sha256,
            "apply": args.apply,
        }
    elif args.command == "delete":
        plan = plan_delete(
            document,
            section=args.section,
            entity_id=args.entity_id,
            source_text=source_text,
            cascade=args.cascade,
        )
        parameters = {
            "section": args.section,
            "id": args.entity_id,
            "expected_sha256": args.expected_sha256,
            "apply": args.apply,
            "cascade": args.cascade,
        }
    elif args.command == "rename":
        plan = plan_rename(
            document,
            section=args.section,
            entity_id=args.entity_id,
            new_id=args.new_id,
            source_text=source_text,
        )
        parameters = {
            "section": args.section,
            "id": args.entity_id,
            "new_id": args.new_id,
            "expected_sha256": args.expected_sha256,
            "apply": args.apply,
        }
    else:
        raise ArchitectureQueryError(
            "ARCH_USAGE_INVALID",
            "mutation command is unknown",
            exit_code=2,
            details={"command": args.command},
        )

    return (
        execute_mutation(
            document,
            plan=plan,
            expected_sha256=args.expected_sha256,
            apply=args.apply,
        ),
        parameters,
    )


def _emit(envelope: dict[str, Any], *, output_format: str, pretty: bool) -> None:
    if output_format == "json":
        sys.stdout.write(render_json(envelope, pretty=pretty))
    elif output_format == "jsonl":
        sys.stdout.write(render_jsonl(envelope))
    else:
        destination = sys.stdout if envelope.get("ok") else sys.stderr
        destination.write(render_text(envelope))


def _emit_error(
    error: ArchitectureQueryError, *, output_format: str, pretty: bool
) -> None:
    envelope = failure_envelope(error)
    if output_format == "text":
        sys.stderr.write(render_text(envelope))
    else:
        sys.stdout.write(render_json(envelope, pretty=pretty))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args: argparse.Namespace | None = None
    try:
        args = parser.parse_args(argv)
        if args.command == "doctor":
            envelope, exit_code = _doctor_envelope(args.require)
            if args.format == "jsonl":
                raise ArchitectureQueryError(
                    "ARCH_USAGE_INVALID",
                    "doctor does not support JSONL output",
                    exit_code=2,
                )
            _emit(envelope, output_format=args.format, pretty=args.pretty)
            return exit_code

        mutation_commands = {"create", "update", "delete", "rename"}
        if args.command in mutation_commands and args.format == "jsonl":
            raise ArchitectureQueryError(
                "ARCH_USAGE_INVALID",
                "mutations do not support JSONL output",
                exit_code=2,
            )

        repo_root = discover_repo_root(args.repo)
        model = args.model
        file = args.file
        if model is None and file is None:
            model = "runtime-v3"
        validation = args.validation
        if validation is None:
            validation = (
                "schema" if model is not None or args.schema is not None else "parse"
            )
        document = load_document(
            repo_root=repo_root,
            model=model,
            file=file,
            schema=args.schema,
            validation=validation,
        )
        if args.command in mutation_commands:
            result, parameters = _mutation_result(args, document)
        else:
            result, parameters = _query_result(args, document)
        envelope = success_envelope(
            source=document.source_metadata(),
            command=args.command,
            parameters=parameters,
            result=result,
        )
        _emit(envelope, output_format=args.format, pretty=args.pretty)
        return 0
    except ArchitectureQueryError as error:
        output_format = getattr(args, "format", "json") if args is not None else "json"
        pretty = bool(getattr(args, "pretty", False)) if args is not None else False
        _emit_error(error, output_format=output_format, pretty=pretty)
        return error.exit_code
    except Exception as error:
        if args is not None and getattr(args, "debug", False):
            traceback.print_exc(file=sys.stderr)
        internal = ArchitectureQueryError(
            "ARCH_INTERNAL_ERROR",
            "unexpected architecture-query failure",
            exit_code=70,
            details={"exception_type": type(error).__name__},
        )
        output_format = getattr(args, "format", "json") if args is not None else "json"
        pretty = bool(getattr(args, "pretty", False)) if args is not None else False
        _emit_error(internal, output_format=output_format, pretty=pretty)
        return internal.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
