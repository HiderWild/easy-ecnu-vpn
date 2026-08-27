"""把旧提交尾注报告为历史观察，绝不把它们当作宿主真实验收。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


HOSTS = ("darwin", "win32")
_TRAILER_PATTERN = re.compile(r"^([A-Za-z][A-Za-z-]*):[ \t]+(.+)$")
_LEGACY_CHANGE_KINDS = {
    "host-repair": "LEGACY_HOST_REPAIR_HISTORICAL",
    "agile-host-repair": "LEGACY_AGILE_HOST_REPAIR_HISTORICAL",
    "host-repair-integration": "LEGACY_HOST_REPAIR_INTEGRATION_HISTORICAL",
}


class AcceptanceError(ValueError):
    """真实 Git 范围或仓库无法读取时的局部错误。"""

    def __init__(self, code: str, field: str, message: str) -> None:
        self.code = code
        self.field = field
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class HistoricalEvent:
    """一个只供展示的旧尾注观察，不包含验收状态或证据。"""

    commit: str
    requirement_id: str | None
    change_kind: str | None
    trailers: tuple[tuple[str, str], ...]

    @property
    def host_acceptance(self) -> tuple[str, ...]:
        return tuple(
            value for key, value in self.trailers if key == "Host-Acceptance"
        )


def _git_bytes(repo: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *arguments],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AcceptanceError(
            "ACCEPTANCE_GIT_ERROR",
            "git",
            detail or "git command failed",
        )
    return completed.stdout


def _git(repo: Path, *arguments: str) -> str:
    return _git_bytes(repo, *arguments).decode("utf-8", errors="strict")


def resolve_repository(repo: Path) -> Path:
    if not repo.is_dir():
        raise AcceptanceError(
            "ACCEPTANCE_REPOSITORY_INVALID",
            "repo",
            "repository path does not name a directory",
        )
    return Path(_git(repo, "rev-parse", "--show-toplevel").strip()).resolve()


def _first_value(
    trailers: tuple[tuple[str, str], ...], field: str
) -> str | None:
    return next((value for key, value in trailers if key == field), None)


def parse_commit_message(commit: str, message: str) -> HistoricalEvent | None:
    """读取可识别的旧尾注，不验证、修复或推导它们的语义。"""

    normalized = message.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return None
    trailer_lines = re.split(r"\n[ \t]*\n", normalized)[-1].splitlines()
    parsed_trailers: list[tuple[str, str]] = []
    for line in trailer_lines:
        if not line.strip():
            continue
        match = _TRAILER_PATTERN.fullmatch(line)
        if match is None:
            return None
        parsed_trailers.append((match.group(1), match.group(2).strip()))
    trailers = tuple(parsed_trailers)
    if not trailers:
        return None
    requirement_id = _first_value(trailers, "Requirement-ID")
    change_kind = _first_value(trailers, "Common-Change-Kind")
    if requirement_id is None and change_kind is None and not any(
        key == "Host-Acceptance" for key, _ in trailers
    ):
        return None
    return HistoricalEvent(
        commit=commit,
        requirement_id=requirement_id,
        change_kind=change_kind,
        trailers=trailers,
    )


def _events_for_revision(repo: Path, revision: str) -> list[HistoricalEvent]:
    raw = _git_bytes(
        repo,
        "log",
        "--reverse",
        "--format=%H%x00%B%x00",
        revision,
    )
    fields = raw.split(b"\0")
    events: list[HistoricalEvent] = []
    for index in range(0, len(fields) - 1, 2):
        commit_bytes = fields[index].strip()
        if not commit_bytes:
            continue
        event = parse_commit_message(
            commit_bytes.decode("ascii", errors="strict"),
            fields[index + 1].decode("utf-8", errors="strict"),
        )
        if event is not None:
            events.append(event)
    return events


def read_events(repo: Path, head: str = "HEAD") -> list[HistoricalEvent]:
    """兼容旧调用者：返回历史观察，绝不返回验收状态。"""

    return _events_for_revision(repo, head)


def read_range_events(
    repo: Path, base: str, head: str
) -> list[HistoricalEvent]:
    """兼容旧调用者：读取真实 Git 范围内的历史观察。"""

    return _events_for_revision(repo, f"{base}..{head}")


def _serialize_event(event: HistoricalEvent) -> dict[str, Any]:
    return {
        "commit": event.commit,
        "requirement_id": event.requirement_id,
        "change_kind": event.change_kind,
        "trailers": [
            {"name": name, "value": value} for name, value in event.trailers
        ],
    }


def _legacy_warnings(events: list[HistoricalEvent]) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    for change_kind, code in _LEGACY_CHANGE_KINDS.items():
        matching = [event for event in events if event.change_kind == change_kind]
        if not matching:
            continue
        warnings.append(
            {
                "code": code,
                "message": (
                    f"发现 {len(matching)} 条 {change_kind} 历史声明；"
                    "它们只作展示，不创建修补待办、整合分支或跨宿主结论"
                ),
            }
        )
    return warnings


def _historical_host_acceptance_warnings(
    events: list[HistoricalEvent],
) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    for event in events:
        if not event.host_acceptance:
            continue
        warnings.append(
            {
                "code": "HOST_ACCEPTANCE_HISTORICAL_DECLARATION",
                "commit": event.commit,
                "message": (
                    "Host-Acceptance 仅是历史 declaration，"
                    "不构成宿主真实业务回执或验收证据"
                ),
            }
        )
    return warnings


def _requirement_events(
    events: list[HistoricalEvent], requirement_id: str
) -> list[HistoricalEvent]:
    return [event for event in events if event.requirement_id == requirement_id]


def validate_requirement(
    *,
    repo: Path,
    requirement_id: str,
    host: str,
    head: str = "HEAD",
) -> dict[str, Any]:
    """报告指定需求的旧尾注；开发始终不因缺少真实回执而被阻塞。"""

    repository = resolve_repository(repo)
    if host not in (*HOSTS, "all"):
        raise AcceptanceError(
            "ACCEPTANCE_HOST_INVALID",
            "host",
            f"unsupported host: {host}",
        )
    observations = _requirement_events(read_events(repository, head), requirement_id)
    warnings = [
        {
            "code": "HOST_REAL_EVIDENCE_MISSING",
            "message": (
                "本脚本不拥有或伪造宿主真实业务回执；"
                "缺少回执只禁止宣称宿主真实通过，不阻塞开发"
            ),
        },
        *_historical_host_acceptance_warnings(observations),
        *_legacy_warnings(observations),
    ]
    return {
        "ok": True,
        "status": "historical_non_authoritative",
        "requirement_id": requirement_id,
        "host": host,
        "development_ok": True,
        "host_real_passed": False,
        "host_real_evidence": [],
        "historical_observations": [_serialize_event(event) for event in observations],
        "warnings": warnings,
    }


def validate_range(
    *,
    repo: Path,
    base: str,
    head: str,
) -> dict[str, Any]:
    """只验证 Git 范围可读取，并报告其中旧尾注的历史性质。"""

    repository = resolve_repository(repo)
    # 显式验证两个 revision，保留真正的本地 Git 范围错误，而不引入状态机。
    for field, revision in (("base", base), ("head", head)):
        try:
            _git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}")
        except AcceptanceError as error:
            raise AcceptanceError(
                error.code,
                field,
                f"git cannot resolve {field} revision {revision!r}: {error.message}",
            ) from error
    events = read_range_events(repository, base, head)
    _git(repository, "diff", "--name-only", "--no-renames", f"{base}..{head}")
    return {
        "ok": True,
        "status": "historical_non_authoritative_range",
        "development_ok": True,
        "requirements": sorted(
            {
                event.requirement_id
                for event in events
                if event.requirement_id is not None
            }
        ),
        "historical_observations": [_serialize_event(event) for event in events],
        "warnings": [
            *_historical_host_acceptance_warnings(events),
            *_legacy_warnings(events),
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--requirement", required=True)
    parser.add_argument("--host", choices=(*HOSTS, "all"), required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _emit(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
        return
    if payload["ok"]:
        print(
            "HISTORICAL_NON_AUTHORITATIVE: "
            "development_ok=true; host_real_passed=false"
        )
        return
    print(
        f"{payload['code']}: {payload.get('field', '')}: "
        f"{payload.get('message', '')}"
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = validate_requirement(
            repo=args.repo,
            requirement_id=args.requirement,
            host=args.host,
            head=args.head,
        )
    except (AcceptanceError, OSError, UnicodeError) as error:
        payload = {
            "ok": False,
            "status": "historical_report_error",
            "code": getattr(error, "code", "ACCEPTANCE_IO_ERROR"),
            "field": getattr(error, "field", ""),
            "message": str(error),
        }
        _emit(payload, args.format)
        return 1
    _emit(payload, args.format)
    return 0


if __name__ == "__main__":
    sys.exit(main())
