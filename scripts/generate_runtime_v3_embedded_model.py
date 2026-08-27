#!/usr/bin/env python3
"""Generate the embedded Common V3 business-flow model artifact.

The generated representation is deliberately segmented so that the logical
artifact does not depend on a compiler's maximum string-literal size.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DEFAULT_MAX_SEGMENT_BYTES = 8 * 1024
DEFAULT_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
RAW_LITERAL_DELIMITER = "EXV_V3_MODEL"


def canonical_model_bytes(input_path: Path) -> bytes:
    source = json.loads(input_path.read_text(encoding="utf-8"))
    return json.dumps(
        source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def split_utf8_segments(payload: bytes, max_segment_bytes: int) -> list[str]:
    if max_segment_bytes <= 0:
        raise ValueError("max_segment_bytes must be positive")

    segments: list[str] = []
    start = 0
    while start < len(payload):
        end = min(start + max_segment_bytes, len(payload))
        while end > start:
            try:
                segment = payload[start:end].decode("utf-8")
                break
            except UnicodeDecodeError:
                end -= 1
        if end == start:
            raise RuntimeError("unable to split canonical model at a UTF-8 boundary")
        segments.append(segment)
        start = end
    return segments


def render_header(canonical_bytes: bytes, max_segment_bytes: int) -> str:
    if not canonical_bytes or len(canonical_bytes) > DEFAULT_MAX_CANONICAL_BYTES:
        raise ValueError(
            "canonical model must be non-empty and no larger than "
            f"{DEFAULT_MAX_CANONICAL_BYTES} bytes"
        )
    canonical = canonical_bytes.decode("utf-8")
    digest = "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
    delimiter = RAW_LITERAL_DELIMITER
    if f"){delimiter}\"" in canonical:
        raise RuntimeError("embedded model contains the raw literal delimiter")

    segments = split_utf8_segments(canonical_bytes, max_segment_bytes)
    entries = ",\n".join(
        f'    detail::EmbeddedBusinessFlowModelSegment{{{index}, '
        f'R"{delimiter}({segment}){delimiter}"}}'
        for index, segment in enumerate(segments)
    )
    return f"""#pragma once

#include "common/runtime_v3/model_bundle_internal.hpp"

#include <array>
#include <cstddef>
#include <string_view>

namespace exv::runtime_v3::generated {{

inline constexpr std::array<detail::EmbeddedBusinessFlowModelSegment,
                            {len(segments)}>
    kBusinessFlowModelSegments = {{{{
{entries}
}}}};
inline constexpr std::size_t kBusinessFlowModelCanonicalByteSize =
    {len(canonical_bytes)};
inline constexpr std::string_view kBusinessFlowModelDigest = \"{digest}\";

}} // namespace exv::runtime_v3::generated
"""


def generate(input_path: Path, output_path: Path,
             max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES) -> None:
    generated = render_header(
        canonical_model_bytes(input_path),
        max_segment_bytes,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists() and output_path.read_text(encoding="utf-8") == generated:
        return
    output_path.write_text(generated, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--max-segment-bytes",
        type=int,
        default=DEFAULT_MAX_SEGMENT_BYTES,
    )
    args = parser.parse_args()

    generate(args.input, args.output, args.max_segment_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
