# Common-first migration register

This register is a migration inventory, not a machine verdict. The canonical
JSON manifest and lane-record files remain the sole authority for governed
common-first decisions; a row here cannot make work complete, green, or
governed.

## Historical branches retained as `legacy_unmanaged`

| Branch | Actual role/evidence inventory | Migration state |
| --- | --- | --- |
| `origin/codex/darwin-d2-real-machine-20260718` | Darwin D2/X2c real-machine recovery and incident-ledger evidence. | `legacy_unmanaged` |
| `origin/feature/darwin-elevated-service-install` | Darwin elevated-service installation implementation history. | `legacy_unmanaged` |
| `origin/codex/review-darwin-network-architecture` | Darwin network-architecture review history, including the branch's Windows/MSVC release-evidence record. | `legacy_unmanaged` |

These entries are historical inventory only. They are not retroactive common
acceptance and do not assert any delivery verdict.

## Current integration baseline

`origin/develop` at `9d9cd65` is the current integration baseline. This role
does not prove that historical work used this governance and is not retroactive
compliance.

## Governance adoption branch

`origin/codex/common-first-delivery-governance` is the adoption common branch.
It records adoption of the common-first governance framework; it does not
reclassify unrelated historical branches. It is adoption machinery, not a
historical governed baseline, and does not create a metadata-only self-governed
baseline.

| Stage | Commit/state |
| --- | --- |
| Design | `4a5d538` |
| Phase A | `554d3b4` |
| Phase B | `18e3e04` |
| Phase C | `c447cc7` |
| Task 9 repair | `9b26ffa` |

## Adoption rule for new work

Any continuation, amendment, repair, or release that introduces a new
top-level requirement starts on a common branch. First commit the accepted
common implementation; then make a metadata-only accepted-baseline manifest
commit. Only then fork independent Windows and Darwin branches from that
accepted metadata baseline. Platform branches do not modify common files; a
common need becomes a new top-level requirement rather than a platform-side
exception.
