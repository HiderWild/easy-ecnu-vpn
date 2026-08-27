#!/usr/bin/env python3
"""Generate C++ and TypeScript distribution constants from one JSON file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REQUIRED_TOP_LEVEL = {
    "id",
    "app_name",
    "brand_subtitle",
    "author",
    "repository",
    "default_vpn_server",
    "vpn_servers",
    "default_routes",
    "default_user_agents",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default=str(root / "distribution" / "ecnu.json"),
        help="Distribution JSON source.",
    )
    parser.add_argument(
        "--cpp-output",
        default=str(root / "src" / "generated" / "distribution_config.hpp"),
        help="Generated C++ header.",
    )
    parser.add_argument(
        "--ts-output",
        default=str(root / "webui" / "src" / "generated" / "distribution.ts"),
        help="Generated TypeScript module.",
    )
    return parser.parse_args()


def require_string(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def validate(data: dict[str, Any]) -> None:
    missing = sorted(REQUIRED_TOP_LEVEL - set(data))
    if missing:
        raise ValueError(f"missing top-level keys: {', '.join(missing)}")

    for key in ["id", "app_name", "brand_subtitle", "author", "default_vpn_server"]:
        require_string(data, key)

    repository = data["repository"]
    if not isinstance(repository, dict):
        raise ValueError("repository must be an object")
    require_string(repository, "label")
    require_string(repository, "url")

    vpn_servers = data["vpn_servers"]
    if not isinstance(vpn_servers, list) or not vpn_servers:
        raise ValueError("vpn_servers must be a non-empty array")
    seen_servers: set[str] = set()
    for index, item in enumerate(vpn_servers):
        if not isinstance(item, dict):
            raise ValueError(f"vpn_servers[{index}] must be an object")
        value = require_string(item, "value")
        require_string(item, "label")
        seen_servers.add(value)

    if data["default_vpn_server"] not in seen_servers:
        raise ValueError("default_vpn_server must appear in vpn_servers")

    default_routes = data["default_routes"]
    if not isinstance(default_routes, list) or not default_routes:
        raise ValueError("default_routes must be a non-empty array")
    for index, route in enumerate(default_routes):
        if not isinstance(route, str) or not route:
            raise ValueError(f"default_routes[{index}] must be a non-empty string")

    user_agents = data["default_user_agents"]
    if not isinstance(user_agents, dict):
        raise ValueError("default_user_agents must be an object")
    for key in ["windows", "macos", "linux"]:
        require_string(user_agents, key)


def cpp_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def ts_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def generated_comment(source_path: Path) -> str:
    rel = source_path.relative_to(repo_root()).as_posix()
    return f"Generated from {rel} by scripts/generate_distribution_config.py."


def render_cpp(data: dict[str, Any], source_path: Path) -> str:
    vpn_servers = ",\n".join(
        f"    {cpp_string(item['value'])}" for item in data["vpn_servers"]
    )
    routes = ",\n".join(f"    {cpp_string(route)}" for route in data["default_routes"])
    user_agents = data["default_user_agents"]
    return f"""// {generated_comment(source_path)}
// Do not edit by hand.
#pragma once

#include <array>
#include <string_view>

namespace exv::distribution {{

inline constexpr std::string_view kId = {cpp_string(data["id"])};
inline constexpr std::string_view kAppName = {cpp_string(data["app_name"])};
inline constexpr std::string_view kBrandSubtitle = {cpp_string(data["brand_subtitle"])};
inline constexpr std::string_view kAuthor = {cpp_string(data["author"])};
inline constexpr std::string_view kRepositoryLabel = {cpp_string(data["repository"]["label"])};
inline constexpr std::string_view kRepositoryUrl = {cpp_string(data["repository"]["url"])};
inline constexpr std::string_view kDefaultVpnServer = {cpp_string(data["default_vpn_server"])};

inline constexpr std::array<std::string_view, {len(data["vpn_servers"])}> kVpnServers = {{
{vpn_servers}
}};

inline constexpr std::array<std::string_view, {len(data["default_routes"])}> kDefaultRoutes = {{
{routes}
}};

inline constexpr std::string_view kDefaultWindowsUserAgent = {cpp_string(user_agents["windows"])};
inline constexpr std::string_view kDefaultMacosUserAgent = {cpp_string(user_agents["macos"])};
inline constexpr std::string_view kDefaultLinuxUserAgent = {cpp_string(user_agents["linux"])};

#if defined(EXV_PLATFORM_WINDOWS)
inline constexpr std::string_view kDefaultUserAgent = kDefaultWindowsUserAgent;
#elif defined(EXV_PLATFORM_DARWIN)
inline constexpr std::string_view kDefaultUserAgent = kDefaultMacosUserAgent;
#else
inline constexpr std::string_view kDefaultUserAgent = kDefaultLinuxUserAgent;
#endif

}} // namespace exv::distribution
"""


def render_ts(data: dict[str, Any], source_path: Path) -> str:
    vpn_servers = ",\n".join(
        "    { label: "
        + ts_string(item["label"])
        + ", value: "
        + ts_string(item["value"])
        + " }"
        for item in data["vpn_servers"]
    )
    routes = ",\n".join(f"    {ts_string(route)}" for route in data["default_routes"])
    user_agents = data["default_user_agents"]
    return f"""// {generated_comment(source_path)}
// Do not edit by hand.

export const distributionConfig = {{
  id: {ts_string(data["id"])},
  appName: {ts_string(data["app_name"])},
  brandSubtitle: {ts_string(data["brand_subtitle"])},
  author: {ts_string(data["author"])},
  repository: {{
    label: {ts_string(data["repository"]["label"])},
    url: {ts_string(data["repository"]["url"])},
  }},
  defaultVpnServer: {ts_string(data["default_vpn_server"])},
  vpnServers: [
{vpn_servers},
  ],
  defaultRoutes: [
{routes},
  ],
  defaultUserAgents: {{
    windows: {ts_string(user_agents["windows"])},
    macos: {ts_string(user_agents["macos"])},
    linux: {ts_string(user_agents["linux"])},
  }},
}} as const

export type DistributionConfig = typeof distributionConfig
"""


def write_if_changed(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.write_text(content, encoding="utf-8", newline="\n")


def main() -> int:
    args = parse_args()
    input_path = Path(args.input).resolve()
    cpp_output = Path(args.cpp_output).resolve()
    ts_output = Path(args.ts_output).resolve()

    data = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("distribution config must be a JSON object")
    validate(data)

    write_if_changed(cpp_output, render_cpp(data, input_path))
    write_if_changed(ts_output, render_ts(data, input_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
