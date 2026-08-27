"""回归保护：业务流优先的宿主修复治理政策。"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "docs/superpowers/governance/business-first-host-repair-policy.md"
ACTIVE_ENTRY_POINTS = (
    ROOT / "AGENTS.md",
    ROOT / "docs/superpowers/governance/README.md",
    ROOT / "docs/superpowers/governance/platform-acceptance-campaign.md",
)
HISTORICAL_SPECS = (
    ROOT
    / "docs/superpowers/specs/2026-07-19-common-first-cross-platform-delivery-governance-design.md",
    ROOT
    / "docs/superpowers/specs/2026-08-03-agile-common-host-repair-integration-governance-design.md",
)
HISTORICAL_COMMON_FIRST_TEMPLATES = (
    ROOT / "docs/superpowers/templates/top-level-requirement-template.md",
    ROOT / "docs/superpowers/templates/common-architecture-template.md",
    ROOT / "docs/superpowers/templates/common-implementation-plan-template.md",
)
HISTORICAL_COMMON_FIRST_LANE_RECORD_TEMPLATE = (
    ROOT / "docs/superpowers/templates/platform-lane-record.template.json"
)
ORDINARY_REQUIREMENT_DESIGN_PATH = (
    ROOT
    / "docs/superpowers/specs/2026-08-11-platform-first-ordinary-requirement-governance-design.md"
)
ORDINARY_REQUIREMENT_PLAN_PATH = (
    ROOT
    / "docs/superpowers/plans/2026-08-11-platform-first-ordinary-requirement-governance.md"
)
MARKDOWN_LINK_TARGET = re.compile(r"\[[^\]\n]+\]\(([^)\n]+)\)")
DEPRECATED_ACTIVE_ENTRY_IDENTIFIERS = (
    ("blocked_by_common", ("blocked_by_common",)),
    ("Host-Acceptance", ("host-acceptance",)),
    ("agile-host-repair", ("agile-host-repair",)),
    ("host-repair-integration", ("host-repair-integration",)),
    ("model explorer", ("model explorer", "model_explorer")),
)
ORDINARY_REQUIREMENT_PREREQUISITE_CASES = (
    (
        "ordinary-requirement-common-foundation-prerequisite",
        r"Common\s+基底",
        "普通需求开始前必须先创建 Common 基底。",
    ),
    (
        "ordinary-requirement-common-specification-prerequisite",
        r"Common\s+规格",
        "Common 规格是普通需求开工的前提。",
    ),
    (
        "ordinary-requirement-common-plan-prerequisite",
        r"Common\s+计划",
        "普通需求继续需要先有 Common 计划。",
    ),
    (
        "ordinary-requirement-common-manifest-prerequisite",
        r"Common\s+manifest",
        "提交普通需求必须先有 Common manifest。",
    ),
    (
        "ordinary-requirement-common-branch-prerequisite",
        r"Common\s+分支",
        "普通需求必须在 Common 分支创建后才可开始。",
    ),
    (
        "ordinary-requirement-other-host-branch-prerequisite",
        r"另一宿主分支",
        "另一宿主分支是普通需求继续的门槛。",
    ),
    (
        "ordinary-requirement-other-host-result-prerequisite",
        r"另一宿主结果",
        "普通需求提交以另一宿主结果为条件。",
    ),
    (
        "ordinary-requirement-path-allowlist-prerequisite",
        r"路径白名单",
        "路径白名单构成普通需求开始的先决条件。",
    ),
    (
        "ordinary-requirement-dedicated-promotion-record-prerequisite",
        r"专用推进记录",
        "普通需求开工前须创建专用推进记录。",
    ),
)
ORDINARY_REQUIREMENT_AFFIRMATIVE_GATE_FIXTURES = (
    (
        "ordinary-requirement-common-foundation-prerequisite",
        "普通需求开始前必须先创建 Common 基底。",
    ),
    (
        "ordinary-requirement-common-specification-prerequisite",
        "普通需求开始前必须先创建 Common 规格。",
    ),
    (
        "ordinary-requirement-common-plan-prerequisite",
        "普通需求开始前必须先创建 Common 计划。",
    ),
    (
        "ordinary-requirement-common-manifest-prerequisite",
        "普通需求开始前必须先创建 Common manifest。",
    ),
    (
        "ordinary-requirement-common-branch-prerequisite",
        "普通需求开始前必须先创建 Common 分支。",
    ),
    (
        "ordinary-requirement-other-host-branch-prerequisite",
        "普通需求开始前必须先创建 另一宿主分支。",
    ),
    (
        "ordinary-requirement-other-host-result-prerequisite",
        "普通需求开始前必须先具备 另一宿主结果。",
    ),
    (
        "ordinary-requirement-path-allowlist-prerequisite",
        "普通需求开始前必须先具备 路径白名单。",
    ),
    (
        "ordinary-requirement-dedicated-promotion-record-prerequisite",
        "普通需求开始前必须先创建 专用推进记录。",
    ),
)
ORDINARY_REQUIREMENT_NON_GATE_FIXTURES = (
    (
        "ordinary-requirement-common-foundation-prerequisite",
        "普通需求不需要 Common 基底即可开始。",
    ),
    (
        "ordinary-requirement-common-specification-prerequisite",
        "普通需求无需 Common 规格即可继续。",
    ),
    (
        "ordinary-requirement-common-plan-prerequisite",
        "普通需求不需要 Common 计划即可开始。",
    ),
    (
        "ordinary-requirement-common-manifest-prerequisite",
        "普通需求无需 Common manifest 即可继续。",
    ),
    (
        "ordinary-requirement-common-branch-prerequisite",
        "普通需求不需要 Common 分支即可开始。",
    ),
    (
        "ordinary-requirement-other-host-branch-prerequisite",
        "普通需求无需另一宿主分支即可继续。",
    ),
    (
        "ordinary-requirement-other-host-result-prerequisite",
        "普通需求不需要另一宿主结果即可开始。",
    ),
    (
        "ordinary-requirement-path-allowlist-prerequisite",
        "普通需求无需路径白名单即可继续。",
    ),
    (
        "ordinary-requirement-dedicated-promotion-record-prerequisite",
        "普通需求不需要专用推进记录即可开始。",
    ),
)
PLATFORM_FIRST_NON_GATE_FIXTURES = (
    "没有 Common 基底并不意味着普通需求不能继续。",
    "普通需求开始时是否需要 Common 基底仍在调查。",
    "是否需要 Common 基底才能开始普通需求？",
    "选择宿主不需要跨平台价值说明。",
    "未知状态本身绝不触发暂停普通需求。",
    "历史说明：旧规则“普通需求开始前必须先创建 Common manifest。”已被废止。",
    "讨论：普通需求开始前必须先创建 Common manifest 是否仍然适用？",
)
PLATFORM_FIRST_PURE_QUESTION_FIXTURES = (
    "普通需求必须先创建 Common manifest 吗？",
    "普通需求开始前必须先创建 Common manifest 吗？",
    "在创建 Common manifest 之前不得开始普通需求吗？",
    "选择宿主时必须提供跨平台价值说明吗？",
    "普通需求在未知状态时必须暂停吗？",
    "普通需求必须先创建 Common manifest 吗?   ",
)
PLATFORM_FIRST_AFFIRMATIVE_GATE_VARIANTS = (
    (
        "ordinary-requirement-common-manifest-prerequisite",
        "普通需求必须先创建 Common manifest。",
    ),
    (
        "ordinary-requirement-common-manifest-prerequisite",
        "普通需求开始前需先建立 Common manifest。",
    ),
    (
        "host-selection-cross-platform-justification",
        "选择宿主时必须提供跨平台价值说明。",
    ),
    (
        "unknown-state-ordinary-requirement-pause",
        "普通需求在未知状态时必须暂停。",
    ),
    (
        "ordinary-requirement-common-manifest-prerequisite",
        "普通需求开始前先建立 Common manifest 后才能继续。",
    ),
    (
        "ordinary-requirement-common-manifest-prerequisite",
        "在创建 Common manifest 之前不得开始普通需求。",
    ),
)
ORDINARY_REQUIREMENT_AFFIRMATIVE_TRAILING_QUESTION_FIXTURES = tuple(
    (expected_name, f"{text.rstrip('。')}，是否理解？")
    for expected_name, text in ORDINARY_REQUIREMENT_AFFIRMATIVE_GATE_FIXTURES
)
PLATFORM_FIRST_AFFIRMATIVE_TRAILING_QUESTION_VARIANTS = (
    (
        "ordinary-requirement-common-manifest-prerequisite",
        "普通需求必须先创建 Common manifest，是否理解？",
    ),
    (
        "host-selection-cross-platform-justification",
        "选择宿主时必须提供跨平台价值说明，是否理解？",
    ),
    (
        "unknown-state-ordinary-requirement-pause",
        "普通需求在未知状态时必须暂停，是否理解？",
    ),
)
ORDINARY_REQUIREMENT_AFFIRMATIVE_GATE_TEMPLATES = (
    r"(?:普通需求(?:开始|开工|继续|提交)?前?|"
    r"(?:开始|开工|继续|提交)(?:当前)?普通需求)"
    r"(?:必须|须|需要|应当|需)(?:先)?(?:创建|建立|具备|有)\s*{condition}",
    r"普通需求(?:开始|开工|继续|提交)?前先(?:创建|建立|具备)\s*{condition}\s*"
    r"后才(?:可|能)?(?:开始|开工|继续|提交)",
    r"普通需求(?:必须|须|需要|应当|需)在\s*{condition}\s*"
    r"(?:创建|建立|具备)?后才(?:可|能)?(?:开始|开工|继续|提交)",
    r"在(?:创建|建立|具备)\s*{condition}\s*之前(?:不得|不能|不可)"
    r"(?:开始|开工|继续|提交)(?:当前)?普通需求",
    r"{condition}(?:是|为|构成)\s*普通需求(?:开始|开工|继续|提交)(?:的)?"
    r"(?:前提|条件|门槛|先决条件)",
    r"普通需求(?:开始|开工|继续|提交)(?:的)?(?:前提|条件|门槛|先决条件)"
    r"(?:是|为)\s*{condition}",
    r"(?:普通需求(?:开始|开工|继续|提交)|"
    r"(?:开始|开工|继续|提交)(?:当前)?普通需求)以\s*{condition}\s*为条件",
)
ORDINARY_REQUIREMENT_PREREQUISITE_PATTERNS = tuple(
    (
        name,
        re.compile(
            "(?:"
            + "|".join(
                template.format(
                    condition=condition,
                )
                for template in ORDINARY_REQUIREMENT_AFFIRMATIVE_GATE_TEMPLATES
            )
            + ")",
        ),
    )
    for name, condition, _ in ORDINARY_REQUIREMENT_PREREQUISITE_CASES
)
PLATFORM_FIRST_PREREQUISITE_PATTERNS = (
    *ORDINARY_REQUIREMENT_PREREQUISITE_PATTERNS,
    (
        "host-selection-cross-platform-justification",
        re.compile(
            r"选择宿主(?:前|时)?(?:必须|须|需要|应当|需)(?:提供)?"
            r"跨平台(?:价值|风险|资格)(?:说明|评估|证明)?"
        ),
    ),
    (
        "unknown-state-ordinary-requirement-pause",
        re.compile(
            r"(?:未知状态(?:下|时)?(?:必须|须|需要|应当|需)"
            r"(?:暂停|阻塞|停止)(?:当前)?普通需求|"
            r"普通需求在未知状态(?:下|时)?(?:必须|须|需要|应当|需)"
            r"(?:暂停|阻塞|停止))"
        ),
    ),
)
NON_ENFORCING_STATEMENT_PREFIX = re.compile(
    r"^\s*(?:历史(?:说明|记录|规则)?|旧规则|已废止|被废止|讨论|示例|引用)"
)
PURE_TERMINAL_QUESTION = re.compile(r"吗[？?]\s*$")
STATEMENT_SPLITTER = re.compile(r"[。；\n]+")
EXPECTED_LEGACY_LANE_RECORD_TEMPLATE = {
    "schema_version": "1.0",
    "requirement_id": "example-network-coexistence",
    "platform": "windows",
    "lane_branch": "codex/windows-example-network-coexistence",
    "accepted_common_implementation_commit": "0123456789abcdef0123456789abcdef01234567",
    "common_baseline_record_commit": "89abcdef0123456789abcdef0123456789abcdef",
    "lane_status": "in_progress",
    "delivery_verdict": "pending_evidence",
    "unfinished_subrequirements": [
        {
            "id": "native-network-integration",
            "state": "open",
        }
    ],
    "blockers": [],
    "production_verifications": [
        {
            "id": "PV-01",
            "status": "not_run",
            "evidence": [],
        }
    ],
    "skip_mock_items": [],
}


def resolved_markdown_links(source_path: Path, text: str) -> tuple[Path, ...]:
    return tuple(
        (source_path.parent / Path(target.strip())).resolve()
        for target in MARKDOWN_LINK_TARGET.findall(text)
    )


def deprecated_active_entry_identifiers(text: str) -> tuple[str, ...]:
    folded = text.casefold()
    return tuple(
        identifier
        for identifier, variants in DEPRECATED_ACTIVE_ENTRY_IDENTIFIERS
        if any(variant in folded for variant in variants)
    )


def positive_platform_first_prerequisites(text: str) -> tuple[str, ...]:
    statements = tuple(
        statement.strip()
        for statement in STATEMENT_SPLITTER.split(text)
        if statement.strip()
        and not NON_ENFORCING_STATEMENT_PREFIX.search(statement)
        and not PURE_TERMINAL_QUESTION.search(statement)
    )
    return tuple(
        name
        for name, pattern in PLATFORM_FIRST_PREREQUISITE_PATTERNS
        if any(pattern.search(statement) for statement in statements)
    )


class BusinessFirstHostRepairPolicyTest(unittest.TestCase):
    def assert_no_positive_platform_first_prerequisites(self, text: str) -> None:
        self.assertEqual((), positive_platform_first_prerequisites(text))

    def assert_thin_active_entry(self, entry_point: Path, text: str) -> None:
        self.assertIn("唯一活跃正文", text)
        resolved_links = resolved_markdown_links(entry_point, text)
        self.assertEqual(1, resolved_links.count(POLICY_PATH.resolve()))
        self.assertEqual((), deprecated_active_entry_identifiers(text))
        self.assert_no_positive_platform_first_prerequisites(text)

    def assert_historical_common_first_template_marker(
        self,
        template_path: Path,
        marker: str,
    ) -> None:
        self.assertIn("历史/已被取代", marker)
        self.assertIn("唯一活跃正文", marker)
        self.assertIn("不得作为当前普通需求的 Common 前置条件", marker)
        self.assertEqual(
            (POLICY_PATH.resolve(),),
            resolved_markdown_links(template_path, marker),
        )

    def assert_historical_common_first_lane_record_template(
        self,
        template: dict[object, object],
    ) -> None:
        self.assertEqual("$comment", next(iter(template)))
        comment = template["$comment"]

        self.assertIn("历史/已被取代", comment)
        self.assertIn("business-first-host-repair-policy.md", comment)
        self.assertIn("不得作为当前普通需求的前置条件", comment)
        self.assertEqual(
            EXPECTED_LEGACY_LANE_RECORD_TEMPLATE,
            {key: value for key, value in template.items() if key != "$comment"},
        )

    def test_active_policy_preserves_business_first_governance(self) -> None:
        policy = POLICY_PATH.read_text(encoding="utf-8")

        self.assert_no_positive_platform_first_prerequisites(policy)

        required_phrases = (
            "开放世界和真实错误驱动",
            "未知或未建模状态本身绝不触发阻塞、强制核验、补偿、穷举或完整性证明",
            "少数已知允许状态组成白名单",
            "已观察到的具体错误类型",
            "真实发生但原因未知的错误可以如实报告为未知",
            "重试、重启、重装、日志反馈",
            "完整因果链",
            "经过的层和模块",
            "不应有的动作",
            "用户业务影响",
            "不得编造根因、来源或修复路径",
            "尚未证明安全",
            "低概率对抗性文件系统风险",
            "宿主机已经失陷",
            "不构成业务阻塞",
            "定期倒查设计文档和需求文档",
            "禁止跨模块、跨系统、跨进程、跨宿主联合状态机",
            "执行、投影、诊断、验收或离线模型检查",
            "局部模块的有限状态校验",
            "具体疑难问题排查",
            "紧凑微内核种子",
            "顶层业务逻辑、稳定契约、纯逻辑和小端口",
            "不长臂规定宿主机制",
            "不确定是否重叠的逻辑通过小端口留给宿主",
            "宿主真实业务流优先",
            "首次实现宿主可以任意选择且无需理由",
            "选择宿主不受跨平台价值、风险预测、资格或另一宿主状态管辖",
            "也不需要预声明复用",
            "开始、继续或提交普通需求不以创建 Common 基底、规格、计划、manifest、Common 分支、另一宿主分支、另一宿主结果、路径白名单或专用推进记录为条件",
            "不以创建 Common 基底、规格、计划、manifest、Common 分支、另一宿主分支、另一宿主结果、路径白名单或专用推进记录为条件",
            "失败、未运行或未知不阻塞不依赖它的开发",
            "当前宿主真实用户业务流跑通后，才可以被后续独立整合工作作为 Common 分析或候选迁移的正输入",
            "不自动决定 Common 归属，不自动接线、修改或宣称另一宿主通过",
            "不构成跨宿主状态机、白名单、专用登记或自动推进",
            "直接修 Common、共享构建、契约和测试",
            "治理和证据权威",
            "观察事实、当前修补、当前活动接线",
            "若开发者选择留下宿主记录",
            "记录不是开始、继续或提交普通需求的条件",
            "不得增加强制性的保留/摘出类型枚举",
            "不能决定未来归属或另一宿主",
            "按可审计增量勤提交",
            "各宿主分别已经跑通的真实用户级业务流才是 Common 整合正输入",
            "失败或未验证仅是缺陷证据",
            "专门整合分支或智能体独立决定",
            "某一宿主对 Common 的修补幅度显著",
            "边界过宽或偏向单一平台",
            "同时评估两侧摘出",
            "不是自动归属结论",
            "回到相关原生宿主重跑真实流",
            "双轨版本可在普通目录长期共存",
            "一个具体业务路径只接一版",
            "当前未接线、活动路径、文档链接、重新启用须重跑真实流",
            "不得用 #error、#warning 或 validator 逼删",
            "稳定多个 tag 后由开发者判断删除，无固定期限",
            "模块测试和真实用户业务流测试",
            "commit trailer、SHA、mock、模型或模块测试不能声明宿主真实通过",
            "缺证据只禁止宣称通过，不阻塞开发",
            "固定流程脚本参数化",
            "保留 No GitHub Actions",
            "BusinessFlowMachine 仍接线",
            "宿主真实业务迁移的已知对象",
            "撤销其治理、验收和离线穷举权",
            "不得谎称生产路径已退役",
        )
        for phrase in required_phrases:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, policy)

    def test_active_policy_preserves_honest_common_repair_record(self) -> None:
        policy = POLICY_PATH.read_text(encoding="utf-8")

        honest_record_phrases = (
            "诚实记录",
            "修改位置",
            "目的",
            "必要性",
            "随提交固化",
            "供后续独立整合工作核实",
            "记录本身不产生验收结论",
            "不替其他宿主",
        )
        for phrase in honest_record_phrases:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, policy)

        # 记录是义务而非门禁：不得引入 manifest、前置条件或推进记录等新阻塞
        self.assert_no_positive_platform_first_prerequisites(policy)

    def test_design_and_plan_limit_lane_comment_to_non_authoritative_compatibility_metadata(
        self,
    ) -> None:
        for path in (ORDINARY_REQUIREMENT_DESIGN_PATH, ORDINARY_REQUIREMENT_PLAN_PATH):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("$comment", text)
                self.assertIn("唯一可选的非权威历史显示元数据", text)
                self.assertIn("仅为兼容读取允许", text)
                self.assertIn("不参与任何判定", text)

    def test_negated_uncertain_and_historical_text_is_not_a_platform_first_gate(
        self,
    ) -> None:
        fixtures = (
            *(text for _, text in ORDINARY_REQUIREMENT_NON_GATE_FIXTURES),
            *PLATFORM_FIRST_NON_GATE_FIXTURES,
        )

        for text in fixtures:
            with self.subTest(text=text):
                self.assertEqual((), positive_platform_first_prerequisites(text))

    def test_pure_platform_first_questions_are_not_gates(self) -> None:
        for text in PLATFORM_FIRST_PURE_QUESTION_FIXTURES:
            with self.subTest(text=text):
                self.assertEqual((), positive_platform_first_prerequisites(text))

    def test_explicit_affirmative_platform_first_gates_are_detected(
        self,
    ) -> None:
        fixtures = (
            *ORDINARY_REQUIREMENT_AFFIRMATIVE_GATE_FIXTURES,
            *PLATFORM_FIRST_AFFIRMATIVE_GATE_VARIANTS,
            *ORDINARY_REQUIREMENT_AFFIRMATIVE_TRAILING_QUESTION_FIXTURES,
            *PLATFORM_FIRST_AFFIRMATIVE_TRAILING_QUESTION_VARIANTS,
        )

        for expected_name, text in fixtures:
            with self.subTest(expected_name=expected_name, text=text):
                self.assertEqual(
                    (expected_name,),
                    positive_platform_first_prerequisites(text),
                )

    def test_active_entry_points_defer_without_deprecated_identifiers(self) -> None:
        for entry_point in ACTIVE_ENTRY_POINTS:
            text = entry_point.read_text(encoding="utf-8")
            with self.subTest(entry_point=entry_point):
                self.assert_thin_active_entry(entry_point, text)

    def test_markdown_links_resolve_relative_to_the_containing_document(self) -> None:
        source_path = HISTORICAL_SPECS[0]
        relative_target = Path("relative") / "policy.md"

        self.assertEqual(
            ((source_path.parent / relative_target).resolve(),),
            resolved_markdown_links(
                source_path,
                "[政策](relative/policy.md)",
            ),
        )

    def test_historical_specs_are_superseded_with_an_active_policy_link(self) -> None:
        for historical_spec in HISTORICAL_SPECS:
            text = historical_spec.read_text(encoding="utf-8")
            with self.subTest(historical_spec=historical_spec):
                lines = text.splitlines()
                self.assertTrue(lines[0].startswith("# "))
                self.assertEqual("", lines[1])
                marker = lines[2]
                self.assertIn("历史/已被取代", marker)
                resolved_links = resolved_markdown_links(historical_spec, marker)
                self.assertEqual((POLICY_PATH.resolve(),), resolved_links)
                self.assertTrue(resolved_links[0].is_file())

    def test_historical_common_first_templates_are_superseded_with_an_active_policy_link(
        self,
    ) -> None:
        for template_path in HISTORICAL_COMMON_FIRST_TEMPLATES:
            text = template_path.read_text(encoding="utf-8")
            with self.subTest(template_path=template_path):
                lines = text.splitlines()
                self.assertTrue(lines[0].startswith("# "))
                self.assertEqual("", lines[1])
                marker = lines[2]
                self.assert_historical_common_first_template_marker(
                    template_path,
                    marker,
                )

    def test_historical_common_first_lane_record_template_has_a_retirement_comment(
        self,
    ) -> None:
        template = json.loads(
            HISTORICAL_COMMON_FIRST_LANE_RECORD_TEMPLATE.read_text(encoding="utf-8")
        )
        self.assert_historical_common_first_lane_record_template(template)

    def test_historical_common_first_template_marker_rejects_reversed_prerequisite(
        self,
    ) -> None:
        template_path = HISTORICAL_COMMON_FIRST_TEMPLATES[0]
        marker = template_path.read_text(encoding="utf-8").splitlines()[2]
        reversed_marker = marker.replace(
            "本模板不得作为当前普通需求的 Common 前置条件",
            "本模板是当前普通需求的 Common 前置条件",
        )

        self.assertIn("历史/已被取代", reversed_marker)
        self.assertIn("唯一活跃正文", reversed_marker)
        self.assertEqual(
            (POLICY_PATH.resolve(),),
            resolved_markdown_links(template_path, reversed_marker),
        )
        with self.assertRaises(AssertionError):
            self.assert_historical_common_first_template_marker(
                template_path,
                reversed_marker,
            )

    def test_historical_common_first_lane_record_template_rejects_moved_comment(
        self,
    ) -> None:
        template = json.loads(
            HISTORICAL_COMMON_FIRST_LANE_RECORD_TEMPLATE.read_text(encoding="utf-8")
        )
        moved_comment_template = {
            key: value for key, value in template.items() if key != "$comment"
        }
        moved_comment_template["$comment"] = template["$comment"]

        self.assertIn("历史/已被取代", moved_comment_template["$comment"])
        self.assertIn(
            "business-first-host-repair-policy.md",
            moved_comment_template["$comment"],
        )
        self.assertIn(
            "不得作为当前普通需求的前置条件",
            moved_comment_template["$comment"],
        )
        with self.assertRaises(AssertionError):
            self.assert_historical_common_first_lane_record_template(
                moved_comment_template
            )

    def test_historical_common_first_lane_record_template_rejects_changed_lane_status(
        self,
    ) -> None:
        template = json.loads(
            HISTORICAL_COMMON_FIRST_LANE_RECORD_TEMPLATE.read_text(encoding="utf-8")
        )
        changed_lane_status_template = dict(template)
        changed_lane_status_template["lane_status"] = "delivered"

        self.assertIn("历史/已被取代", changed_lane_status_template["$comment"])
        self.assertIn(
            "business-first-host-repair-policy.md",
            changed_lane_status_template["$comment"],
        )
        self.assertIn(
            "不得作为当前普通需求的前置条件",
            changed_lane_status_template["$comment"],
        )
        with self.assertRaises(AssertionError):
            self.assert_historical_common_first_lane_record_template(
                changed_lane_status_template
            )

    def test_thin_entry_rejects_injected_deprecated_identifiers(self) -> None:
        thin_entry = (
            "[业务流优先的宿主修复治理政策]"
            "(docs/superpowers/governance/business-first-host-repair-policy.md)\n"
            "唯一活跃正文\n"
        )
        deprecated_injections = (
            "BLOCKED_BY_COMMON",
            "Host-Acceptance",
            "AGILE-HOST-REPAIR",
            "host-repair-integration",
            "MODEL EXPLORER",
            "runtime_v3_model_explorer",
        )

        for deprecated_injection in deprecated_injections:
            with self.subTest(deprecated_injection=deprecated_injection):
                with self.assertRaises(AssertionError):
                    self.assert_thin_active_entry(
                        ROOT / "AGENTS.md",
                        thin_entry + deprecated_injection,
                    )

    def test_thin_entry_rejects_injected_platform_first_prerequisites(self) -> None:
        thin_entry = (
            "[业务流优先的宿主修复治理政策]"
            "(docs/superpowers/governance/business-first-host-repair-policy.md)\n"
            "唯一活跃正文\n"
        )
        prerequisite_injections = (
            *(injection for _, _, injection in ORDINARY_REQUIREMENT_PREREQUISITE_CASES),
            "选择宿主必须提供跨平台价值说明。",
            "未知状态必须暂停当前普通需求。",
        )

        for prerequisite_injection in prerequisite_injections:
            with self.subTest(prerequisite_injection=prerequisite_injection):
                with self.assertRaises(AssertionError):
                    self.assert_thin_active_entry(
                        ROOT / "AGENTS.md",
                        thin_entry + prerequisite_injection,
                    )

    def test_active_policy_rejects_each_injected_ordinary_requirement_prerequisite(
        self,
    ) -> None:
        policy = POLICY_PATH.read_text(encoding="utf-8")

        self.assert_no_positive_platform_first_prerequisites(policy)
        for name, _, injection in ORDINARY_REQUIREMENT_PREREQUISITE_CASES:
            with self.subTest(name=name):
                with self.assertRaises(AssertionError):
                    self.assert_no_positive_platform_first_prerequisites(
                        policy + "\n" + injection
                    )

    def test_active_policy_rejects_injected_affirmative_trailing_questions(
        self,
    ) -> None:
        policy = POLICY_PATH.read_text(encoding="utf-8")

        self.assert_no_positive_platform_first_prerequisites(policy)
        for name, injection in (
            *ORDINARY_REQUIREMENT_AFFIRMATIVE_TRAILING_QUESTION_FIXTURES,
            *PLATFORM_FIRST_AFFIRMATIVE_TRAILING_QUESTION_VARIANTS,
        ):
            with self.subTest(name=name, injection=injection):
                with self.assertRaises(AssertionError):
                    self.assert_no_positive_platform_first_prerequisites(
                        policy + "\n" + injection
                    )


if __name__ == "__main__":
    unittest.main()
