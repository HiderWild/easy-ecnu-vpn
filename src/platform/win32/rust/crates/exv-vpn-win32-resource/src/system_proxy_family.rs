// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 系统代理 family 的纯逻辑层（设计 §5.3 接入 apply/restore 家族；TK1a 拆小前半）。
//!
//! `EXV_PAC_FAMILY_PENDING`: engine 侧 PAC 包装接线另立任务
//! （v1 不接线 PAC：Automatic 分支只产出 typed skip [`FamilyAction::PacDetectedSkip`]，
//! 不做设计 §5.6 的脚本包装 / loopback 端点 / `AutoConfigURL` 改写）。
//!
//! 本模块零 Win32 依赖、零 IO，只做三类纯决策：
//!
//! - [`decide`]：快照 + 期望豁免条目 → family 动作（Disabled 零动作零账本，
//!   对齐拍板结论 4；Manual/Mixed 合并写入；Automatic typed skip）；
//! - [`SystemProxyFamilyStep`]：apply 成功前经 `journal_store::append_synced`
//!   落盘的步骤记录，手写字节编解码对齐 journal 的 `payload: Vec<u8>` 惯例；
//! - [`compute_restore`]：teardown / crash recovery 统一的 compare-and-restore
//!   还原语义——当前值指纹 == 我们写入的指纹才精确还原（存在 → 字节级写回；
//!   原不存在 → 删除该值），第三方中途改动是 typed skip，绝不强写（设计 §5.3）。
//!
//! Win32 写入、广播刷新与 journal 落盘本身由后续 engine 接线任务组合本层结果完成。

use crate::native_error::{NativeError, NativeErrorKind};
use crate::system_proxy::{RawInternetSettings, RawValue, SystemProxyMode, SystemProxySnapshot};
use crate::system_proxy_override::merge_bypass_entries;

/// 错误码 token：family 层收到的快照自洽性破坏（如 Manual 却无端点）。
pub const ERROR_SYSTEM_PROXY_FAMILY_MALFORMED: &str = "system_proxy_family_malformed";

/// 错误码 token：步骤记录 payload 截断。
pub const ERROR_SYSTEM_PROXY_FAMILY_PAYLOAD_TRUNCATED: &str =
    "system_proxy_family_payload_truncated";

/// 错误码 token：步骤记录 payload 版本或字段标记非法。
pub const ERROR_SYSTEM_PROXY_FAMILY_PAYLOAD_INVALID: &str = "system_proxy_family_payload_invalid";

/// typed 错误码编码：`NativeError.code` 高位保留标记（非 Win32 原生码空间），
/// 低 16 位放模块内子码。对齐 `system_proxy.rs` 的既有惯例。
const NATIVE_CODE_FLAG: u32 = 0x8000_0000;

/// 子码：`system_proxy_family_malformed`。
const NATIVE_CODE_FAMILY_MALFORMED: u32 = 0x0000_0001;

/// 子码：payload 截断。
const NATIVE_CODE_PAYLOAD_TRUNCATED: u32 = 0x0000_0002;

/// 子码：payload 版本 / 标记非法。
const NATIVE_CODE_PAYLOAD_INVALID: u32 = 0x0000_0003;

/// family 步骤的 prestate：五注册表原始值的 exists/type/data 快照。
///
/// [`RawInternetSettings`] 正是设计要求的五值结构（其文档已注明「journal prestate
/// 直接复用本结构」），按「已有等价类型则复用勿重复」以类型别名接入。值的
/// 「不存在」由 [`RawValue::Absent`] 表达，无需再包一层 `Option`。
pub type SystemProxyPrestate = RawInternetSettings;

/// apply 成功前落盘的系统代理 family 步骤记录（journal payload 形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProxyFamilyStep {
    /// 连接前五原始值的 exists/type/data 快照（精确还原的唯一依据）。
    pub prestate: SystemProxyPrestate,
    /// 本次要合并进 `ProxyOverride` 的期望豁免条目（顺序敏感）。
    pub desired_entries: Vec<String>,
    /// 发起连接的用户 SID（写入必须发生在该用户 HKU 而非 SYSTEM profile）。
    pub originating_sid: String,
    /// 连接瞬间是否检测到 PAC / WPAD（v1 仅记账，供 engine 侧后续接线观察）。
    pub pac_detected: bool,
}

/// payload 格式版本（不兼容变更时递增；旧版本拒绝解码，不猜）。
// 0x02: Other 变体由「仅类型码」改为「type + 数据字节」（字节级还原契约）。
const PAYLOAD_VERSION: u8 = 0x02;

/// [`RawValue`] 编码标记：不存在。
const TAG_ABSENT: u8 = 0;
/// [`RawValue`] 编码标记：DWORD。
const TAG_DWORD: u8 = 1;
/// [`RawValue`] 编码标记：其他类型（记原始类型码）。
const TAG_OTHER: u8 = 2;
/// [`RawValue`] 编码标记：REG_SZ（UTF-16LE 单元序列，保字节还原语义）。
const TAG_SZ: u8 = 3;

impl SystemProxyFamilyStep {
    /// apply 是否产生了系统代理效果（false = SkipNoOp/PacDetectedSkip 类零动作
    /// 步骤，teardown 无需还原）。
    #[must_use]
    pub fn prestate_has_effect(&self) -> bool {
        // 语义是「apply 时系统代理处于活动状态」（Disabled → 零动作）：以
        // snapshot_from_raw 的 mode 判定同源——端点或 PAC/WPAD 任一存在即活动；
        // ProxyEnable=0 且无端点无 PAC 的 Disabled 快照不产生效果。
        let proxy_enabled = self.prestate.proxy_enable.as_dword().unwrap_or(0) != 0;
        let has_endpoint = self.prestate.proxy_server.as_sz().is_some();
        let has_pac = self.prestate.auto_config_url.as_sz().is_some()
            || self.prestate.auto_detect.as_dword().unwrap_or(0) != 0;
        proxy_enabled && (has_endpoint || has_pac)
    }

    /// 写入后指纹的字节视图（journal 记录不直接携带——由 engine 接线把
    /// [`crate::system_proxy_family_exec::SystemProxyApplyOutcome`] 的指纹与
    /// 本记录一并落盘；此处提供 prestate 指纹作为「未写入」缺省基准）。
    /// 完整语义：`written_fingerprint == fingerprint(prestate)` 表示写入未生效，
    /// 还原为幂等 no-op。
    #[must_use]
    pub fn written_fingerprint_bytes(&self) -> Vec<u8> {
        crate::system_proxy_family_exec::fingerprint_prestate(&self.prestate)
    }

    /// 序列化为 journal record payload（确定性字节布局，小端）：
    /// `version(1) | sid(len+bytes) | pac_detected(1) | desired(count + entries)
    /// | 五个 RawValue（固定顺序 ProxyEnable/ProxyServer/ProxyOverride/
    /// AutoConfigURL/AutoDetect，各为 tag+data）`。
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(PAYLOAD_VERSION);
        push_len_bytes(&mut buf, self.originating_sid.as_bytes());
        buf.push(u8::from(self.pac_detected));
        push_u32(
            &mut buf,
            u32::try_from(self.desired_entries.len()).unwrap_or(u32::MAX),
        );
        for entry in &self.desired_entries {
            push_len_bytes(&mut buf, entry.as_bytes());
        }
        for value in [
            &self.prestate.proxy_enable,
            &self.prestate.proxy_server,
            &self.prestate.proxy_override,
            &self.prestate.auto_config_url,
            &self.prestate.auto_detect,
        ] {
            push_raw_value(&mut buf, value);
        }
        buf
    }

    /// 从 journal record payload 反序列化。截断 / 版本或标记非法均为 typed
    /// 错误（fail-closed，不做部分恢复）。
    ///
    /// # Errors
    ///
    /// payload 截断返回 [`ERROR_SYSTEM_PROXY_FAMILY_PAYLOAD_TRUNCATED`]；
    /// 版本字节或值标记非法返回 [`ERROR_SYSTEM_PROXY_FAMILY_PAYLOAD_INVALID`]。
    pub fn from_payload(bytes: &[u8]) -> Result<Self, NativeError> {
        let mut reader = Reader {
            bytes,
            pos: usize::default(),
        };
        let version = reader.read_u8()?;
        if version != PAYLOAD_VERSION {
            return Err(invalid_payload("未知 payload 版本"));
        }
        let sid_bytes = reader.read_len_bytes()?;
        let originating_sid = std::str::from_utf8(sid_bytes)
            .map_err(|_| invalid_payload("SID 非 UTF-8"))?
            .to_owned();
        let pac_byte = reader.read_u8()?;
        if pac_byte > 1 {
            return Err(invalid_payload("pac_detected 标记非法"));
        }
        let desired_count = reader.read_u32()?;
        let mut desired_entries = Vec::with_capacity(desired_count.min(4096) as usize);
        for _ in 0..desired_count {
            let entry = reader.read_len_bytes()?;
            desired_entries.push(
                std::str::from_utf8(entry)
                    .map_err(|_| invalid_payload("豁免条目非 UTF-8"))?
                    .to_owned(),
            );
        }
        let proxy_enable = reader.read_raw_value()?;
        let proxy_server = reader.read_raw_value()?;
        let proxy_override = reader.read_raw_value()?;
        let auto_config_url = reader.read_raw_value()?;
        let auto_detect = reader.read_raw_value()?;
        if reader.pos != reader.bytes.len() {
            return Err(invalid_payload("payload 存在尾部冗余字节"));
        }
        Ok(Self {
            prestate: RawInternetSettings {
                proxy_enable,
                proxy_server,
                proxy_override,
                auto_config_url,
                auto_detect,
            },
            desired_entries,
            originating_sid,
            pac_detected: pac_byte == 1,
        })
    }
}

/// family 步骤决策结果（apply 侧唯一出口；engine 接线按变体分派）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyAction {
    /// Disabled：零动作、零账本记录（拍板结论 4：T0/T2 不扰动）。
    SkipNoOp,
    /// Manual / Mixed 且 ProxyEnable=true：把 `merged` 字节级写入
    /// `ProxyOverride` 并广播刷新（先落账本再写入）。
    MergeAndWrite {
        /// `merge_bypass_entries` 的合并结果（原条目无损 + EXV 条目追加）。
        merged: String,
    },
    /// Automatic（PAC URL 或 WPAD）：v1 不接线 PAC，typed skip 并提示。
    PacDetectedSkip,
}

/// 纯决策函数：规范化快照 + 期望豁免条目 → family 动作。
///
/// - `Disabled` → [`FamilyAction::SkipNoOp`]（零动作零账本，结论 4）；
/// - `Manual` / `Mixed` → [`FamilyAction::MergeAndWrite`]。Manual/Mixed 蕴含
///   `ProxyEnable=true`：[`crate::system_proxy::snapshot_from_raw`] 的自洽性
///   校验保证 ProxyEnable=false 时端点直接报 malformed；
/// - `Automatic`（`pac_url` 或 `auto_detect` 任一）→ [`FamilyAction::PacDetectedSkip`]。
///
/// # Errors
///
/// 手拼快照破坏自洽性（Manual/Mixed 却无端点）报
/// [`ERROR_SYSTEM_PROXY_FAMILY_MALFORMED`]；`merge_bypass_entries` 对非法条目
/// （含分号 / 空 / 超长 / 超上限）的类型化错误原样向上传播——上游解析失败的
/// typed 错误同样经由该传播路径到达调用方。
pub fn decide(
    snapshot: &SystemProxySnapshot,
    desired: &[String],
) -> Result<FamilyAction, NativeError> {
    match snapshot.mode {
        SystemProxyMode::Disabled => Ok(FamilyAction::SkipNoOp),
        SystemProxyMode::Automatic => Ok(FamilyAction::PacDetectedSkip),
        SystemProxyMode::Manual | SystemProxyMode::Mixed => {
            if snapshot.endpoints.is_empty() {
                // snapshot_from_raw 构造保证不可达；此处防御手拼快照，fail-closed 不猜。
                return Err(family_malformed("Manual/Mixed 快照却解析不出端点"));
            }
            // bypass_entries 是 ProxyOverride 按 `;` 拆分且空段跳过的结果；
            // 重join后喂给冻结契约的 merge，空段语义与直读原文一致。
            let original = snapshot.bypass_entries.join(";");
            Ok(FamilyAction::MergeAndWrite {
                merged: merge_bypass_entries(&original, desired)?,
            })
        }
    }
}

/// 五个受管注册表值的名字（还原操作的目标标识）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueName {
    /// `ProxyEnable`。
    ProxyEnable,
    /// `ProxyServer`。
    ProxyServer,
    /// `ProxyOverride`。
    ProxyOverride,
    /// `AutoConfigURL`。
    AutoConfigUrl,
    /// `AutoDetect`。
    AutoDetect,
}

impl ValueName {
    /// 注册表值名字面量。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProxyEnable => "ProxyEnable",
            Self::ProxyServer => "ProxyServer",
            Self::ProxyOverride => "ProxyOverride",
            Self::AutoConfigUrl => "AutoConfigURL",
            Self::AutoDetect => "AutoDetect",
        }
    }
}

/// 单个值的精确还原操作（设计 §5.3「精确还原语义」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOp {
    /// prestate 中存在 → 按 type+data 字节级写回（绝不无条件覆盖）。
    WriteBack {
        /// 目标值名。
        value_name: ValueName,
        /// 原始 exists/type/data。
        value: RawValue,
    },
    /// prestate 中原本不存在 → 还原时删除该值。
    DeleteValue {
        /// 目标值名。
        value_name: ValueName,
    },
}

/// compare-and-restore 决策结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreDecision {
    /// 当前值指纹 == 我们写入的指纹 → 执行逐值精确还原。
    Restore {
        /// 五值各自的还原操作（顺序固定：`ProxyEnable` → `AutoDetect`）。
        ops: Vec<RestoreOp>,
    },
    /// 指纹不等 → 第三方中途改动，typed skip（记 `restore_failures`），不强写。
    TypedSkip,
}

/// 纯还原函数：compare-and-restore。
///
/// 指纹相等 → [`RestoreDecision::Restore`]，其中 prestate 里存在的值字节级
/// 写回、原本不存在的值进删除分支；不等 → [`RestoreDecision::TypedSkip`]。
#[must_use]
pub fn compute_restore(
    prestate: &SystemProxyPrestate,
    current_fingerprint: &[u8],
    written_fingerprint: &[u8],
) -> RestoreDecision {
    if current_fingerprint != written_fingerprint {
        return RestoreDecision::TypedSkip;
    }
    let fields = [
        (ValueName::ProxyEnable, &prestate.proxy_enable),
        (ValueName::ProxyServer, &prestate.proxy_server),
        (ValueName::ProxyOverride, &prestate.proxy_override),
        (ValueName::AutoConfigUrl, &prestate.auto_config_url),
        (ValueName::AutoDetect, &prestate.auto_detect),
    ];
    RestoreDecision::Restore {
        ops: fields
            .into_iter()
            .map(|(value_name, value)| match value {
                RawValue::Absent => RestoreOp::DeleteValue { value_name },
                _ => RestoreOp::WriteBack {
                    value_name,
                    value: value.clone(),
                },
            })
            .collect(),
    }
}

/// family 自洽性 typed 错误（kind 走既有 Storage 分类；code 用保留高位标记）。
fn family_malformed(message: &str) -> NativeError {
    NativeError {
        kind: NativeErrorKind::Storage,
        code: NATIVE_CODE_FLAG | NATIVE_CODE_FAMILY_MALFORMED,
        message: format!("{ERROR_SYSTEM_PROXY_FAMILY_MALFORMED}: {message}"),
    }
}

/// payload 截断 typed 错误。
fn truncated_payload(context: &str) -> NativeError {
    NativeError {
        kind: NativeErrorKind::Storage,
        code: NATIVE_CODE_FLAG | NATIVE_CODE_PAYLOAD_TRUNCATED,
        message: format!("{ERROR_SYSTEM_PROXY_FAMILY_PAYLOAD_TRUNCATED}: {context}"),
    }
}

/// payload 版本 / 标记非法 typed 错误。
fn invalid_payload(message: &str) -> NativeError {
    NativeError {
        kind: NativeErrorKind::Storage,
        code: NATIVE_CODE_FLAG | NATIVE_CODE_PAYLOAD_INVALID,
        message: format!("{ERROR_SYSTEM_PROXY_FAMILY_PAYLOAD_INVALID}: {message}"),
    }
}

/// 小端 u32 追加。
fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// 长度前缀字节串追加。
fn push_len_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    push_u32(buf, len);
    buf.extend_from_slice(bytes);
}

/// 单个 [`RawValue`] 编码（`REG_SZ` 以 UTF-16LE 单元序列存储，保字节还原）。
fn push_raw_value(buf: &mut Vec<u8>, value: &RawValue) {
    match value {
        RawValue::Absent => buf.push(TAG_ABSENT),
        RawValue::Dword(dword) => {
            buf.push(TAG_DWORD);
            push_u32(buf, *dword);
        }
        RawValue::Other { r#type, data } => {
            buf.push(TAG_OTHER);
            push_u32(buf, *r#type);
            push_len_bytes(buf, data);
        }
        RawValue::Sz(text) => {
            buf.push(TAG_SZ);
            let mut units = Vec::new();
            for unit in text.encode_utf16() {
                units.extend_from_slice(&unit.to_le_bytes());
            }
            push_len_bytes(buf, &units);
        }
    }
}

/// 线性读取器（越界即 typed 截断错误，无 panic 路径）。
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    /// 取恰好 `len` 字节。
    fn take(&mut self, len: usize) -> Result<&[u8], NativeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| truncated_payload("长度溢出"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| truncated_payload("payload 提前结束"))?;
        self.pos = end;
        Ok(slice)
    }

    /// 读单字节。
    fn read_u8(&mut self) -> Result<u8, NativeError> {
        Ok(self.take(1)?[0])
    }

    /// 读小端 u32。
    fn read_u32(&mut self) -> Result<u32, NativeError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// 读长度前缀字节串。
    fn read_len_bytes(&mut self) -> Result<&[u8], NativeError> {
        let len = self.read_u32()? as usize;
        self.take(len)
    }

    /// 读单个 [`RawValue`]。
    fn read_raw_value(&mut self) -> Result<RawValue, NativeError> {
        match self.read_u8()? {
            TAG_ABSENT => Ok(RawValue::Absent),
            TAG_DWORD => Ok(RawValue::Dword(self.read_u32()?)),
            TAG_OTHER => {
                let r#type = self.read_u32()?;
                let data = self.read_len_bytes()?.to_vec();
                Ok(RawValue::Other { r#type, data })
            }
            TAG_SZ => {
                let units_bytes = self.read_len_bytes()?;
                if units_bytes.len() % 2 != 0 {
                    return Err(invalid_payload("REG_SZ 单元序列长度为奇数"));
                }
                let units: Vec<u16> = units_bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                String::from_utf16(&units)
                    .map(RawValue::Sz)
                    .map_err(|_| invalid_payload("REG_SZ 含非法 UTF-16 序列"))
            }
            _ => Err(invalid_payload("未知 RawValue 标记")),
        }
    }
}
