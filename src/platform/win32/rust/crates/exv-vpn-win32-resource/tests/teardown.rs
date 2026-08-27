// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W24-T Terra: teardown（WindowsTeardown）契约测试。test names 是
// docs/superpowers/plans/2026-08-12-vpn-rust-native-runtime-mvp-terra-oracle-plan.md §6.1
// `W24-T` 行的**完整且精确**集合（Terra 不得改名/增删/合并）；frozen seam 是
// `WindowsTeardown`（exv-vpn-win32-resource crate 的 teardown 模块）。Win32 子计划
// §7 `W24-T/I` 行的必测行为：pure cancel、journaled unblock、child join、final handle、
// reverse compare-restore、proof；生产文件 `teardown.rs,cleanup_proof.rs`；killer
// mutants：**destructive before journal**、**final handle before join**、**failure signs
// proof**（以及 join-before-cancel，见 oracle 测试）。
//
// 本测试对 seam 追加的契约（W24-I 必须满足，否则 GREEN 编译失败）：
//   exv_vpn_win32_resource::teardown::TeardownStage
//     { PureCancel, JournaledUnblock, ChildJoin, ReverseRestore, FinalHandle, Proof }
//     （Debug/Clone/Copy/PartialEq/Eq）——架构 §6.2 的六类步骤
//   teardown::TeardownPlan {
//       pub stages: Vec<TeardownStage>,
//       pub restore_steps: Vec<FamilyStep>,   // apply_tunnel 类型（组合，不重新实现）
//   }（Debug/Clone/PartialEq/Eq）
//   teardown::build_teardown_plan(apply: &ApplyPlan, has_packet_children: bool) -> TeardownPlan
//     —— 纯逻辑：stages 恒为 [PureCancel] + （有 child 时 [JournaledUnblock, ChildJoin]）
//        + [ReverseRestore, FinalHandle, Proof]（ChildJoin 严格先于 FinalHandle）；
//       restore_steps == apply_tunnel::build_restore_plan(apply)（逆族序组合，绝不重新实现）
//   teardown::TeardownError { DestructiveBeforeJournal, StageOutOfOrder, ProofUnavailable }
//     （Debug/Clone/Copy/PartialEq/Eq）
//   teardown::WindowsTeardown（frozen seam）
//     WindowsTeardown::new(aggregate: Option<Aggregate>, saga: RetirementSaga,
//       plan: TeardownPlan, children: Vec<PacketWorker>) -> Self
//       —— 组合 W22（Aggregate/apply_tunnel）+ J53（RetirementSaga）+ W17（PacketWorker）；
//         纯状态机构造（非提权可测）；None aggregate = 无实状态（no-op teardown）
//     WindowsTeardown::pure_cancel(&mut self) -> Result<(), TeardownError>
//       —— 纯 cancel/wakeup：不写 journal、不改变资源所有权、**不是** cleanup completion
//         （spec §6.2 step 2）；不得在此 join child（join 是后续 stage）
//     WindowsTeardown::begin(&mut self, retirement_operation_id: RetirementOperationId,
//       trigger: CleanupTrigger, origin_subject: ErrorSubject,
//       prior_platform_ownership: PlatformOwnershipRef,
//       canonical_inventory_digest: InventoryDigest) -> Result<(), TeardownError>
//       —— journaled start（saga.begin，expected obligations = 9 项 canonical 的判别值，
//         u8 cast——与 cleanup_proof::verify_cleanup_proof 同一映射）；幂等：第二次调用
//         合并到同一 saga 并返回 Ok（spec §6.1：相同 Stop 幂等、不同 Stop 合并，不创建
//         第二次 destructive cleanup）；必须位于 pure_cancel 之后（cancel 先于 journal
//         记录，spec §5.6）
//     WindowsTeardown::unblock_native_read(&mut self) -> Result<(), TeardownError>
//       —— journaled unblock（spec §6.2 step 4/5）：未 begin -> DestructiveBeforeJournal
//     WindowsTeardown::join_children(&mut self) -> Result<(), TeardownError>
//       —— 依赖 child join（spec §6.2 step 4：先发取消信号、RetirementStarted 后 join）
//     WindowsTeardown::restore_owned_resources(&mut self) -> Result<(), TeardownError>
//       —— 逆族序 compare-and-restore（委托 apply_tunnel::restore，不重新实现）
//     WindowsTeardown::drop_final_handle(&mut self) -> Result<(), TeardownError>
//       —— aggregate/final handle 销毁：session 先 EndSession、adapter 后 close（W17
//         语义）；必须位于全部 child join 之后（越序 -> StageOutOfOrder）
//     WindowsTeardown::aggregate(&self) -> Option<&Aggregate>
//       —— final handle 前可读（测试在 restore 后、drop 前 capture 验证逆序恢复）
//     WindowsTeardown::is_complete(&self) -> bool   // 全部 stage（含 proof）完成
//     WindowsTeardown::cleanup_proof(&mut self, input: ProveCleanInput,
//       predicates: &[CleanupPredicate]) -> Result<CleanupProof, TeardownError>
//       —— 未完成或任何 stage 曾失败 -> Err(ProofUnavailable)（failure signs proof =
//         mutant）；成功路径委托 cleanup_proof::verify_cleanup_proof
//     —— 错误优先级：journaled 步骤未 begin -> DestructiveBeforeJournal（先于越序检查）；
//       已 begin 但越序 -> StageOutOfOrder。Drop 契约：children 先 join、aggregate 后
//       销毁（W17 SAFETY-ORDER），panic 早退自清理、无残留。
//   exv_vpn_win32_resource::cleanup_proof::CleanupPredicate {
//       pub item: InventoryItem, pub verified: bool, pub evidence: &'static str }
//     （Debug/Clone/PartialEq/Eq）
//   cleanup_proof::CleanupProof {
//       pub clean: CleanProof,               // exv_vpn_domain::ports（J53 组合）
//       pub inventory_digest: InventoryDigest,
//       pub predicates: Vec<CleanupPredicate> }
//     （Debug/Clone/PartialEq/Eq）
//   cleanup_proof::verify_cleanup_proof(inventory: &[InventoryItem],
//     predicates: &[CleanupPredicate], canonical_inventory_digest: InventoryDigest,
//     saga: &mut RetirementSaga, input: ProveCleanInput)
//     -> Result<CleanupProof, &'static str>
//     —— 纯逻辑：inventory 必须 is_complete（9 项 canonical）；predicates 必须逐项覆盖
//        inventory 且各自 verified（缺项/未验证/未知项 -> Err）；随后
//        saga.observe_cleanup + prove_clean 成功才签发（J53 组合；失败不签发 =
//        'failure signs proof' mutant 反例）
//
// 冻结事实继承（native-wintun-facts.md §2 / native-network-settings-facts.md）：
//   - 0.14.1 的 WintunEndSession 销毁 session 对象：child worker 必须**先 join 再
//     EndSession**，否则 receive 是 UAF（实测 ntdll AV）；
//   - 创建者 WintunCloseAdapter 即移除 adapter（无独立 delete export），adapter 移除
//     级联清除其全部 address/MTU/route/DNS；
//   - EndSession 关闭 session 拥有的 read-wait event：结束后 WaitForSingleObject 返回
//     WAIT_FAILED（0xFFFFFFFF）——真实 child 可观测的"会话已终止"谓词；
//   - 清理必须是 compare-and-restore：当前状态 != applied 指纹（第三方修改）时 typed
//     跳过，绝不无条件覆盖；
//   - cleanup 按安装顺序**逆序**：最后应用的族先恢复，隧道路由先于 bypass 删除。
//
// 纯逻辑测试（阶段顺序、计划构建、proof 门禁、幂等、no-op）任何宿主都必须通过。真实
// teardown（scratch adapter/session + apply 全族 + 真实 read-blocked child worker）需要
// admin；非 elevated 宿主短路为 `not_run / blocked_by_environment`（明确输出，不伪造
// 假绿）。所有真实测试自清理：WindowsTeardown 的 Drop（children 先 join、aggregate 后
// drop）在 panic 早退时同样执行；teardown 结束后独立验证 Get-NetAdapter /
// Get-NetIPAddress / netsh 无残留（W16 冻结事实：创建者 close 移除 adapter 及其全部
// 配置），并断言 child 从未观察到 WAIT_FAILED（final handle before join mutant 的
// native 化身）。

use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{
    EvidenceDigest, InventoryDigest, OperationId, OperationLookupKey, OperationMethod,
    OwnershipVersion, PrincipalDigest, RequestDigest, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::model::PlatformOwnershipRef;
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CleanupTrigger, CleanupTriggerDigest,
    ExternalOperationDigest, JournalRevision, JournalRootDigest, PlatformAuthorityInstanceId,
    VersionedPlatformEvidence,
};
use exv_vpn_resource::retirement::{ProveCleanInput, RetirementSaga};
use exv_vpn_win32_resource::aggregate::Aggregate;
use exv_vpn_win32_resource::apply_tunnel::{
    apply, build_apply_plan, build_restore_plan, ApplyPlan, FamilyStep,
};
use exv_vpn_win32_resource::cleanup_proof::{verify_cleanup_proof, CleanupPredicate, CleanupProof};
use exv_vpn_win32_resource::dns::DnsApplier;
use exv_vpn_win32_resource::dns_types::DnsSettings;
use exv_vpn_win32_resource::inventory::{is_complete, InventoryItem, COMPLETE_INVENTORY};
use exv_vpn_win32_resource::ip_helper_types::IpAddressRow;
use exv_vpn_win32_resource::mtu::{MtuController, MtuFamily, MtuSnapshot};
use exv_vpn_win32_resource::packet_worker::PacketWorker;
use exv_vpn_win32_resource::routes::RouteRow;
use exv_vpn_win32_resource::teardown::{
    build_teardown_plan, TeardownError, TeardownStage, WindowsTeardown,
};
use exv_vpn_win32_resource::wintun_adapter::{AdapterOpen, WintunAdapter};
use exv_vpn_win32_resource::wintun_api::WintunLibrary;
use exv_vpn_win32_resource::wintun_session::WintunSession;

use uuid::Uuid;
use windows::core::GUID;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED};
use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid;
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, WaitForSingleObject};

/// 冻结的 amd64 wintun-0.14.1 DLL 精确路径（WSP3/WSP4 冻结路径；PATH DLL 是 mutant）。
const FROZEN_DLL_PATH: &str = "C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll";
/// WintunCreateAdapter 的 TunnelType 参数（WSP4 冻结值）。
const TUNNEL_TYPE: &str = "EXV VPN";
/// Wintun ring capacity 官方下限（wintun.h：min 0x20000；W17-T 同款）。
const RING_CAPACITY: u32 = 131072;
/// 测试网络常量（WSP3/WSP4 冻结，与 W18/W20/W21/W22-T 完全一致）。
const PROBE_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 88, 1);
const TUNNEL_NET: Ipv4Addr = Ipv4Addr::new(10, 99, 99, 0);
const TUNNEL_PREFIX: u8 = 24;
const TUNNEL_METRIC: u32 = 5;
const ROUTE_NETWORK: &str = "10.99.99.0/24";
/// MTU 应用值（WSP4 冻结：1420/1280/576/65535 可写）。
const MTU_APPLY: u32 = 1420;
/// DNS 测试值（WSP4 冻结，W21-T 同款）。
const DNS_SERVER: &str = "10.88.88.53";
const DNS_SEARCH: &str = "exv.test";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 取 Ok 并 panic 掉意外 Err（不给 T 强加 Debug bound）。
fn expect_ok<T>(r: Result<T, impl std::fmt::Debug>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{ctx}: 失败 {e:?}"),
    }
}

/// 取 Err 并 panic 掉意外 Ok（TeardownError 断言）。
fn expect_teardown_err(r: Result<(), TeardownError>, ctx: &str) -> TeardownError {
    match r {
        Err(e) => e,
        Ok(()) => panic!("{ctx}: 必须返回 Err(TeardownError)"),
    }
}

/// 确定性 authority fence（epoch 1、instance 1、watermark 0、revision 0；J53 同款）。
fn fence() -> AuthorityFence {
    AuthorityFence {
        authority_epoch: AuthorityEpoch::try_from(1).expect("epoch 1"),
        platform_authority_instance_id: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(1))
            .expect("non-nil instance"),
        admission_watermark: AdmissionWatermark::try_from(0).expect("watermark 0"),
        journal_revision: JournalRevision::try_from(0).expect("revision 0"),
    }
}

/// 确定性 32 字节 digest 其首字节随 `n` 不同（非 nil）。
fn digest32(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

/// 确定性 durable retirement id（跨 `n` 不同）。
fn retirement_id(n: u128) -> RetirementOperationId {
    RetirementOperationId::try_from(Uuid::from_u128(n)).expect("non-nil retirement id")
}

/// 确定性 runtime epoch（跨 `n` 不同）。
fn runtime_epoch(n: u128) -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(n)).expect("non-nil epoch")
}

/// 确定性非零 ownership version。
fn ownership_version(n: u64) -> OwnershipVersion {
    OwnershipVersion::try_from(n).expect("non-zero version")
}

/// 确定性 canonical inventory digest（跨 `n` 不同）。
fn inventory_digest(n: u8) -> InventoryDigest {
    InventoryDigest::try_from(digest32(n)).expect("digest")
}

/// 确定性 platform ownership ref（非 nil）。
fn platform_ownership() -> PlatformOwnershipRef {
    PlatformOwnershipRef::try_from((
        ResourceIdentityDigest::try_from(digest32(0x31)).expect("digest"),
        ownership_version(1),
        TokenDigest::try_from(digest32(0x32)).expect("digest"),
    ))
    .expect("ownership ref")
}

/// 确定性 external-stop cleanup trigger（J53 同款）。
fn cleanup_trigger() -> CleanupTrigger {
    CleanupTrigger::ExternalStop {
        lookup_key: OperationLookupKey::try_from((
            PrincipalDigest::try_from(digest32(0x41)).expect("digest"),
            OperationMethod::Stop,
            runtime_epoch(1),
            OperationId::try_from(Uuid::from_u128(3)).expect("non-nil op"),
        ))
        .expect("key"),
        request_digest: RequestDigest::try_from(digest32(0x42)).expect("digest"),
    }
}

/// 确定性 origin subject（runtime epoch）。
fn origin_subject() -> ErrorSubject {
    ErrorSubject::Runtime(runtime_epoch(1))
}

/// 完整绑定的 ProveCleanInput（全部名义 digest 类型互异；J53 同款）。
fn prove_input() -> ProveCleanInput {
    ProveCleanInput {
        runtime_epoch: runtime_epoch(1),
        cleanup_trigger_digest: CleanupTriggerDigest::try_from(digest32(0x0a)).expect("digest"),
        external_trigger_operation_identity_digest_if_present: Some(
            ExternalOperationDigest::try_from(digest32(0x0b)).expect("digest"),
        ),
        journal_root_or_projection_digest: JournalRootDigest::try_from(digest32(0x0c))
            .expect("digest"),
        platform_evidence: VersionedPlatformEvidence {
            kind_version: 1,
            digest: EvidenceDigest::try_from(digest32(0x0d)).expect("digest"),
        },
        prior_platform_ownership_token_digest_if_issued: Some(
            TokenDigest::try_from(digest32(0x0e)).expect("digest"),
        ),
    }
}

/// 9 项 canonical obligation 的判别值标签（label = InventoryItem 的 u8 cast；begin 的
/// expected_obligations 与 verify_cleanup_proof 的 observe_cleanup 必须同一映射）。
fn all_labels() -> Vec<u8> {
    COMPLETE_INVENTORY.iter().map(|item| *item as u8).collect()
}

/// 全 verified 的 9 项 CleanupPredicate（覆盖 COMPLETE_INVENTORY）。
fn complete_predicates() -> Vec<CleanupPredicate> {
    COMPLETE_INVENTORY
        .iter()
        .map(|item| CleanupPredicate {
            item: *item,
            verified: true,
            evidence: "teardown 完成且 native 观察确认无残留",
        })
        .collect()
}

/// 空 apply 计划（nothing set up —— no-op teardown 的输入）。
fn empty_apply_plan() -> ApplyPlan {
    build_apply_plan(
        Vec::new(),
        1500,
        None,
        Vec::new(),
        Vec::new(),
        DnsSettings::new(Vec::new(), Vec::new()),
    )
}

/// 含 bypass 的完整 apply 计划（纯逻辑顺序断言用；bypass 族必须先于 routes 族）。
fn full_apply_plan() -> ApplyPlan {
    let bypass = RouteRow::new(
        Ipv4Addr::UNSPECIFIED,
        0,
        Ipv4Addr::new(198, 18, 0, 2),
        0xABC,
        0,
    );
    let t1 = RouteRow::new(TUNNEL_NET, TUNNEL_PREFIX, PROBE_IP, 0x7777, TUNNEL_METRIC);
    let t2 = RouteRow::new(
        Ipv4Addr::new(10, 88, 88, 0),
        24,
        PROBE_IP,
        0x7777,
        TUNNEL_METRIC,
    );
    build_apply_plan(
        vec![IpAddressRow::new(PROBE_IP, 0x7777, TUNNEL_PREFIX)],
        MTU_APPLY,
        Some(MTU_APPLY),
        vec![bypass],
        vec![t1, t2],
        DnsSettings::new(vec![DNS_SERVER.to_string()], vec![DNS_SEARCH.to_string()]),
    )
}

/// 构造纯逻辑 WindowsTeardown（aggregate = None：无实状态；children 传入真实 worker）。
fn new_teardown(apply_plan: &ApplyPlan, children: Vec<PacketWorker>) -> WindowsTeardown {
    let plan = build_teardown_plan(apply_plan, !children.is_empty());
    WindowsTeardown::new(
        None,
        RetirementSaga::new(fence(), ownership_version(1)),
        plan,
        children,
    )
}

/// 热循环递增计数器的确定性 child worker：join 前持续递增、join 后冻结。
fn counting_worker(counter: Arc<AtomicU64>) -> PacketWorker {
    PacketWorker::spawn(move || {
        counter.fetch_add(1, Ordering::Relaxed);
    })
}

/// 当前进程是否 elevated（admin token）——模式与 W22-T / W23B-T 一致。
fn is_elevated() -> bool {
    // SAFETY: GetCurrentProcess 返回伪句柄，无需关闭。
    let proc_h = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    let ok = unsafe { OpenProcessToken(proc_h, TOKEN_QUERY, &mut token) };
    if ok.is_err() {
        return false;
    }
    let mut elevated = false;
    let mut size = 0u32;
    // SAFETY: 首次查询请求所需缓冲区大小（输出为 size）。
    unsafe {
        let _ = GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::null_mut()),
            0,
            &mut size,
        );
    }
    let mut buff = vec![0u8; size as usize];
    // SAFETY: buff 是有效缓冲；TokenElevation 返回 TOKEN_ELEVATION { TokenIsElevated: BOOL }。
    let ok2 = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            buff.len() as u32,
            &mut size,
        )
    };
    if ok2.is_ok() && buff.len() >= 4 {
        elevated = u32::from_ne_bytes(buff[0..4].try_into().unwrap_or([0u8; 4])) != 0;
    }
    // SAFETY: token 是本进程新打开句柄，使用后关闭。
    unsafe { let _ = CloseHandle(token); }
    elevated
}

/// 动态断言的前置：非 elevated 时输出显式 `not_run / blocked_by_environment` 并短路。
fn require_admin(test: &str) -> bool {
    if is_elevated() {
        return true;
    }
    eprintln!(
        "[not_run/blocked_by_environment] {test}: 创建 scratch adapter/session 并执行真实 \
         teardown 需要提权（elevated admin token）；当前进程非 elevated，跳过动态断言"
    );
    false
}

/// 唯一 adapter 名（按测试用途分前缀，pid 防并行/残留碰撞；W17-T 同款）。
fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", std::process::id())
}

/// 加载冻结 DLL 的便捷入口（W16/W17-T 同款；LoadLibraryW 引用计数安全）。
fn load_frozen() -> WintunLibrary {
    expect_ok(
        WintunLibrary::load(Path::new(FROZEN_DLL_PATH)),
        "load 冻结 wintun.dll",
    )
}

/// 创建真实 adapter（创建者 owned；drop 即移除 adapter——W16 事实）。
fn create_named_adapter(lib: &WintunLibrary, name: &str) -> WintunAdapter {
    let (adapter, opened) = expect_ok(WintunAdapter::create(lib, name, TUNNEL_TYPE), "create adapter");
    assert!(
        matches!(opened, AdapterOpen::Created),
        "create 必须返回 AdapterOpen::Created"
    );
    adapter
}

/// 在真实 adapter 上以冻结容量启动 session。
fn start_session(lib: &WintunLibrary, adapter: &WintunAdapter) -> WintunSession {
    expect_ok(
        WintunSession::start(lib, adapter, RING_CAPACITY),
        "start session",
    )
}

/// LUID -> 接口 GUID（DNS API 的键；WSP4 冻结：LUID → ConvertInterfaceLuidToGuid）。
fn luid_to_guid(luid: u64) -> Option<GUID> {
    let l = NET_LUID_LH { Value: luid };
    let mut guid = GUID::zeroed();
    // SAFETY: guid 由系统填充（ConvertInterfaceLuidToGuid 成功即有效 GUID）。
    if unsafe { ConvertInterfaceLuidToGuid(&l, &mut guid) }.0 != 0 {
        return None;
    }
    Some(guid)
}

/// 带 watchdog 的子进程调用：超时后 kill 子进程并返回 None（WSP3 spike 同款；
/// 本机实测 netsh 在 Wintun 接口上可能无限阻塞，必须 watchdog）。
/// 返回 (退出成功, stdout+stderr 文本)。
fn run_cmd_checked(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Option<(bool, String)> {
    use std::io::Read;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None; // 超时
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(_) => return None,
        }
    };
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    let _ = child.wait();
    Some((status.success(), format!("{out}{err}")))
}

/// Get-NetAdapter 中 scratch adapter 是否已消失（残留检查；watchdog）。
fn adapter_absent_from_netadapter(name: &str) -> bool {
    let ps = format!(
        "(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue | Measure-Object).Count"
    );
    let args = ["-NoProfile", "-Command", ps.as_str()].map(String::from);
    matches!(
        run_cmd_checked("powershell", &args, Duration::from_secs(15)),
        Some((true, out)) if out.trim() == "0"
    )
}

/// Get-NetIPAddress 中 scratch 接口地址是否已消失（残留检查；watchdog）。
fn scratch_address_absent(name: &str) -> bool {
    let ps = format!(
        "(Get-NetIPAddress -InterfaceAlias '{name}' -ErrorAction SilentlyContinue | Measure-Object).Count"
    );
    let args = ["-NoProfile", "-Command", ps.as_str()].map(String::from);
    matches!(
        run_cmd_checked("powershell", &args, Duration::from_secs(15)),
        Some((true, out)) if out.trim() == "0"
    )
}

/// 路由表是否已无隧道路由（10.99.99.0/24；残留检查；watchdog）。
fn tunnel_route_absent() -> bool {
    let args = ["interface", "ipv4", "show", "route"].map(String::from);
    match run_cmd_checked("netsh", &args, Duration::from_secs(15)) {
        Some((true, out)) => !out.contains(ROUTE_NETWORK),
        _ => false,
    }
}

/// teardown 后确定性无残留：无 adapter、无接口地址、无隧道路由。
fn no_scratch_residue(lib: &WintunLibrary, name: &str) {
    assert!(
        WintunAdapter::open(lib, name).is_err(),
        "残留: adapter '{name}' 仍可按名打开（创建者 close 必须移除 adapter）"
    );
    assert!(
        adapter_absent_from_netadapter(name),
        "残留: Get-NetAdapter 仍能看到 '{name}'"
    );
    assert!(
        scratch_address_absent(name),
        "残留: Get-NetIPAddress 仍能看到 '{name}' 的地址"
    );
    assert!(
        tunnel_route_absent(),
        "残留: 路由表仍存在 {ROUTE_NETWORK}（隧道路由未清理）"
    );
}

// ---------------------------------------------------------------------------
// 1. pure cancel（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// pure cancel/wakeup 本身不是 cleanup completion：cancel 之后 teardown 未完成、不得
/// 签发 proof；只有全部 stage（含 proof）完成后才 complete。空状态（nothing set up）的
/// teardown 必须 no-op 完成并正常签发 proof（无实状态、无 children 也绝不半途失败）。
/// 杀死 'pure cancel 被当作 cleanup completion / cancel 即完成'。
#[test]
fn pure_cancel_is_not_cleanup_completion() {
    let mut td = new_teardown(&empty_apply_plan(), Vec::new());
    assert!(
        !td.is_complete(),
        "teardown 尚未开始不得 complete"
    );

    td.pure_cancel()
        .expect("pure cancel 必须成功（不写 journal、不改变资源所有权）");
    assert!(
        !td.is_complete(),
        "pure cancel 不是 cleanup completion——cancel 后 teardown 不得 complete"
    );
    assert!(
        td.cleanup_proof(prove_input(), &complete_predicates()).is_err(),
        "cancel 后未完成 teardown 不得签发 proof（pure cancel 不是完成）"
    );

    // 空状态 teardown：journaled begin + no-op restore + no-op final handle。
    td.begin(
        retirement_id(1),
        cleanup_trigger(),
        origin_subject(),
        platform_ownership(),
        inventory_digest(1),
    )
    .expect("journaled begin 必须成功");
    td.restore_owned_resources()
        .expect("无 applied 状态时 restore 必须幂等 no-op");
    td.drop_final_handle()
        .expect("无 aggregate 时 final handle 必须幂等 no-op");
    assert!(
        !td.is_complete(),
        "proof 签发前不得 complete"
    );

    let proof = td
        .cleanup_proof(prove_input(), &complete_predicates())
        .expect("完整 teardown 后必须可签发 proof");
    assert_eq!(
        proof.clean.unresolved_obligation_count, 0,
        "CleanProof 不得携带未解决 obligation"
    );
    assert!(td.is_complete(), "proof 签发后 teardown 才 complete");
}

// ---------------------------------------------------------------------------
// 2. journaled unblock（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// session-end/close 的 unblock 必须先 durable journaled（RetirementStarted）——
/// 任何 destructive 步骤（unblock/join/restore/final handle）在 begin 之前必须拒绝
/// （DestructiveBeforeJournal）。begin 幂等：第二次 Stop 意图合并到同一 saga 并返回 Ok，
/// 不创建第二次 destructive cleanup（spec §6.1）。杀死 'destructive before journal'。
#[test]
fn session_end_is_journaled_before_unblocking_native_read() {
    let counter = Arc::new(AtomicU64::new(0));
    let mut td = new_teardown(&empty_apply_plan(), vec![counting_worker(Arc::clone(&counter))]);
    td.pure_cancel().expect("pure cancel 不需 journal");

    let err = expect_teardown_err(
        td.unblock_native_read(),
        "未 journaled begin 的 unblock（session end 先于 journal 是 mutant）",
    );
    assert!(
        matches!(err, TeardownError::DestructiveBeforeJournal),
        "未 begin 的 unblock 必须 DestructiveBeforeJournal, got {err:?}"
    );

    // 首次 begin：durable journaled start。
    td.begin(
        retirement_id(1),
        cleanup_trigger(),
        origin_subject(),
        platform_ownership(),
        inventory_digest(1),
    )
    .expect("首次 journaled begin 必须成功");
    // 第二次 begin：幂等合并（相同 Stop 幂等返回同一事实；不同 Stop 合并为 current
    // stop intent——spec §6.1，不创建第二次 destructive cleanup）。
    td.begin(
        retirement_id(1),
        cleanup_trigger(),
        origin_subject(),
        platform_ownership(),
        inventory_digest(1),
    )
    .expect("第二次 Stop 意图必须合并到同一 saga（幂等，不得 Err）");

    td.unblock_native_read()
        .expect("journaled begin 后 unblock 必须成功");

    // 收尾（真实 worker 自清理；join 后 proof）。
    td.join_children().expect("join children");
    td.restore_owned_resources().expect("restore");
    td.drop_final_handle().expect("final handle");
    let proof = td
        .cleanup_proof(prove_input(), &complete_predicates())
        .expect("完整 teardown 后必须可签发 proof");
    assert_eq!(proof.clean.unresolved_obligation_count, 0);
}

// ---------------------------------------------------------------------------
// 3. child join 与 final handle（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// 全部 packet children 必须在 final handle 销毁之前 join：计划序中 ChildJoin 严格先于
/// FinalHandle（无 child 时无 unblock/join 阶段）；运行时 drop_final_handle 在 join 之前
/// 必须拒绝（StageOutOfOrder）。真实 PacketWorker 观察：pure cancel 后 child 仍活着
/// （counter 继续推进——cancel 不 join），join 后 counter 冻结（线程确实终止）。
/// 杀死 'final handle before join' + 'join before cancel'。
#[test]
fn all_packet_children_join_before_final_handle_drop() {
    // ---- 计划序（纯逻辑） ----
    let with_children = build_teardown_plan(&empty_apply_plan(), true);
    assert_eq!(
        with_children.stages,
        vec![
            TeardownStage::PureCancel,
            TeardownStage::JournaledUnblock,
            TeardownStage::ChildJoin,
            TeardownStage::ReverseRestore,
            TeardownStage::FinalHandle,
            TeardownStage::Proof,
        ],
        "有 child 时阶段序必须完全冻结（cancel → journaled unblock → join → restore → \
         final handle → proof）"
    );
    let join_at = with_children
        .stages
        .iter()
        .position(|s| *s == TeardownStage::ChildJoin)
        .expect("有 child 计划必须含 ChildJoin 阶段");
    let final_at = with_children
        .stages
        .iter()
        .position(|s| *s == TeardownStage::FinalHandle)
        .expect("计划必须含 FinalHandle 阶段");
    assert!(
        join_at < final_at,
        "child join 必须严格先于 final handle（final handle before join mutant）"
    );

    let no_children = build_teardown_plan(&empty_apply_plan(), false);
    assert_eq!(
        no_children.stages,
        vec![
            TeardownStage::PureCancel,
            TeardownStage::ReverseRestore,
            TeardownStage::FinalHandle,
            TeardownStage::Proof,
        ],
        "无 child 时不得出现 unblock/join 阶段"
    );
    assert!(
        !no_children.stages.contains(&TeardownStage::ChildJoin),
        "无 child 计划不得含 ChildJoin 阶段"
    );

    // ---- 运行时（纯逻辑 + 真实 PacketWorker 线程） ----
    let counter = Arc::new(AtomicU64::new(0));
    let mut td = new_teardown(&empty_apply_plan(), vec![counting_worker(Arc::clone(&counter))]);
    td.pure_cancel().expect("pure cancel");
    td.begin(
        retirement_id(1),
        cleanup_trigger(),
        origin_subject(),
        platform_ownership(),
        inventory_digest(1),
    )
    .expect("journaled begin");

    // final handle 先于 child join -> StageOutOfOrder（mutant 反例）。
    let err = expect_teardown_err(
        td.drop_final_handle(),
        "join 之前的 final handle 销毁",
    );
    assert!(
        matches!(err, TeardownError::StageOutOfOrder),
        "join 前的 final handle 必须 StageOutOfOrder, got {err:?}"
    );

    // pure cancel 之后 child 仍活着：cancel 不得 join（join 是后续 stage）。
    let before = counter.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(100));
    let after = counter.load(Ordering::Relaxed);
    assert!(
        after > before,
        "pure cancel 不得 join child：counter 必须继续推进（join before cancel mutant）"
    );

    td.unblock_native_read().expect("journaled unblock");
    td.join_children().expect("join children 必须成功");
    let joined = counter.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        counter.load(Ordering::Relaxed),
        joined,
        "child 必须已 join：counter 冻结（join 后线程不得再运行）"
    );

    td.restore_owned_resources().expect("restore");
    td.drop_final_handle()
        .expect("children 已 join 后 final handle 必须成功");
    let proof = td
        .cleanup_proof(prove_input(), &complete_predicates())
        .expect("完整 teardown 后必须可签发 proof");
    assert_eq!(proof.clean.unresolved_obligation_count, 0);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        counter.load(Ordering::Relaxed),
        joined,
        "teardown 结束后 child 线程必须已终止（无泄漏线程）"
    );
}

// ---------------------------------------------------------------------------
// 4. 逆族序 compare-and-restore（纯逻辑 + 真实，提权）
// ---------------------------------------------------------------------------

/// owned resources 按安装顺序**精确逆序**清理：restore_steps 必须组合
/// apply_tunnel::build_restore_plan（绝不重新实现 restore 顺序），隧道路由族先于 bypass
/// 族删除（最后应用的族先恢复）。真实段：scratch adapter 上 apply 全族（address/MTU/
/// tunnel route/DNS）后完整 teardown，restore 后 capture 必须回到原始快照（逆序
/// compare-and-restore 的 read-back proof），final handle 后无残留且 child 从未观察到
/// WAIT_FAILED（EndSession 前已 join）。杀死 'restore 按 forward family order' +
/// 'final handle before join'。
#[test]
fn owned_resources_clean_in_reverse_compare_restore_order() {
    // ---- 纯逻辑部分（非提权） ----
    let full = full_apply_plan();
    let td_plan = build_teardown_plan(&full, true);
    assert_eq!(
        td_plan.restore_steps,
        build_restore_plan(&full),
        "teardown 的 restore 顺序必须组合 apply_tunnel::build_restore_plan（不重新实现）"
    );
    let mut expected = full.steps.clone();
    expected.reverse();
    assert_eq!(
        td_plan.restore_steps, expected,
        "restore 必须是 apply 步骤的精确逆序（最后应用的族先恢复）"
    );
    let routes_at = td_plan
        .restore_steps
        .iter()
        .position(|s| *s == FamilyStep::Routes)
        .expect("restore 计划必须含 routes 族");
    let bypass_at = td_plan
        .restore_steps
        .iter()
        .position(|s| *s == FamilyStep::Bypass)
        .expect("restore 计划必须含 bypass 族");
    assert!(
        routes_at < bypass_at,
        "逆序 restore 中隧道路由族必须先于 bypass 族删除（bypass 最后删）"
    );

    // ---- 真实部分（提权；非提权记为 not_run） ----
    if !require_admin("owned_resources_clean_in_reverse_compare_restore_order") {
        return;
    }
    let lib = load_frozen();
    let name = unique_name("ExvW24Reverse");
    let adapter = create_named_adapter(&lib, &name);
    let luid = adapter.luid();
    let session = start_session(&lib, &adapter);
    let mut agg = Aggregate::new(adapter, session);
    let original = expect_ok(agg.capture(), "capture 原始状态");

    let addr = IpAddressRow::new(PROBE_IP, luid, TUNNEL_PREFIX);
    let tunnel = RouteRow::new(TUNNEL_NET, TUNNEL_PREFIX, PROBE_IP, luid, TUNNEL_METRIC);
    let dns = DnsSettings::new(vec![DNS_SERVER.to_string()], vec![DNS_SEARCH.to_string()]);
    let plan = build_apply_plan(
        vec![addr.clone()],
        MTU_APPLY,
        None,
        Vec::new(),
        vec![tunnel.clone()],
        dns.clone(),
    );
    expect_ok(apply(&mut agg, &plan), "aggregate apply 全族配置");
    let applied = expect_ok(agg.capture(), "apply 后 capture");
    assert!(
        applied.address_rows.iter().any(|r| r.address == PROBE_IP
            && r.interface_luid == luid
            && r.on_link_prefix_length == TUNNEL_PREFIX),
        "apply 后 address 必须真实回读（API success 不是 proof）"
    );
    assert_eq!(
        applied.mtu_v4,
        MtuSnapshot::new(luid, MtuFamily::V4, MTU_APPLY),
        "apply 后 MTU 必须真实回读"
    );
    assert!(
        applied.routes.contains(&tunnel),
        "apply 后隧道路由必须真实回读（精确行）"
    );
    assert_eq!(applied.dns, dns, "apply 后 DNS 必须真实回读");

    // 真实 read-blocked child：只持有 session 管理的 read-wait event（不调用 receive——
    // EndSession 关闭 event 后任何 Wait 返回 WAIT_FAILED，child 可观测"会话已终止"）。
    let ev = agg.session().read_wait_event();
    let saw_wait_failed = Arc::new(AtomicBool::new(false));
    let swf = Arc::clone(&saw_wait_failed);
    let worker = PacketWorker::spawn(move || {
        // SAFETY: ev 是 session 管理的有效事件句柄（本 worker 不 CloseHandle；
        // EndSession 关闭之——冻结事实 readwait.*）。
        let r = unsafe { WaitForSingleObject(ev, 100) };
        if r == WAIT_FAILED {
            swf.store(true, Ordering::Relaxed);
        }
    });

    let mut td = WindowsTeardown::new(
        Some(agg),
        RetirementSaga::new(fence(), ownership_version(1)),
        build_teardown_plan(&plan, true),
        vec![worker],
    );
    td.pure_cancel().expect("pure cancel");
    td.begin(
        retirement_id(1),
        cleanup_trigger(),
        origin_subject(),
        platform_ownership(),
        inventory_digest(1),
    )
    .expect("journaled begin");
    td.unblock_native_read().expect("journaled unblock");
    td.join_children().expect("child join（EndSession 之前）");
    td.restore_owned_resources()
        .expect("逆族序 compare-and-restore");

    // restore 后、final handle 前：接口仍存活，capture 必须回到原始快照。
    let restored = expect_ok(
        td.aggregate().expect("final handle 前 aggregate 必须存活").capture(),
        "restore 后 capture",
    );
    assert_eq!(
        restored, original,
        "逆族序 compare-and-restore 必须回到原始快照（address/mtu/dns 严格相等、\
         隧道路由无残留）"
    );

    td.drop_final_handle().expect("final handle（children 已 join）");
    assert!(
        td.aggregate().is_none(),
        "final handle 后 aggregate 必须已销毁"
    );
    assert!(
        !saw_wait_failed.load(Ordering::Relaxed),
        "child 不得在 EndSession 前未 join：任何 WAIT_FAILED 观测 = final handle before \
         join mutant"
    );

    // 确定性无残留：无 adapter、无地址、无隧道路由。
    no_scratch_residue(&lib, &name);
    let proof = td
        .cleanup_proof(prove_input(), &complete_predicates())
        .expect("完整 teardown 后必须可签发 proof");
    assert_eq!(proof.clean.unresolved_obligation_count, 0);
}

// ---------------------------------------------------------------------------
// 5. 第三方修改在 cleanup 中存活（真实，提权）
// ---------------------------------------------------------------------------

/// compare-and-restore：第三方修改（当前状态 != applied 指纹）必须 typed 跳过、绝不
/// 覆盖——teardown 的逆序 restore 只清 own obligations（隧道路由、owned 地址），MTU 与
/// DNS 的第三方值原样保留。杀死 'unconditional restore'（W21 语义在 teardown 层的化身）。
#[test]
fn third_party_changes_survive_cleanup() {
    if !require_admin("third_party_changes_survive_cleanup") {
        return;
    }
    let lib = load_frozen();
    let name = unique_name("ExvW24ThirdParty");
    let adapter = create_named_adapter(&lib, &name);
    let luid = adapter.luid();
    let session = start_session(&lib, &adapter);
    let mut agg = Aggregate::new(adapter, session);
    let original = expect_ok(agg.capture(), "capture 原始状态");

    let addr = IpAddressRow::new(PROBE_IP, luid, TUNNEL_PREFIX);
    let tunnel = RouteRow::new(TUNNEL_NET, TUNNEL_PREFIX, PROBE_IP, luid, TUNNEL_METRIC);
    let dns = DnsSettings::new(vec![DNS_SERVER.to_string()], vec![DNS_SEARCH.to_string()]);
    let plan = build_apply_plan(
        vec![addr.clone()],
        MTU_APPLY,
        None,
        Vec::new(),
        vec![tunnel.clone()],
        dns.clone(),
    );
    expect_ok(apply(&mut agg, &plan), "aggregate apply 全族配置");

    // 第三方修改（WSP4 冻结模式）：MTU 改 1400、DNS 改 10.88.88.54 —— 与 applied
    // 指纹（1420 / 10.88.88.53）不同。
    expect_ok(
        MtuController::new(luid, MtuFamily::V4).apply(1400),
        "第三方修改 MTU 为 1400",
    );
    let guid = luid_to_guid(luid).expect("scratch adapter LUID -> GUID");
    let third_party_dns = DnsSettings::new(
        vec!["10.88.88.54".to_string()],
        vec![DNS_SEARCH.to_string()],
    );
    expect_ok(
        DnsApplier::apply(&guid, &third_party_dns),
        "第三方修改 DNS 为 10.88.88.54",
    );

    let ev = agg.session().read_wait_event();
    let saw_wait_failed = Arc::new(AtomicBool::new(false));
    let swf = Arc::clone(&saw_wait_failed);
    let worker = PacketWorker::spawn(move || {
        // SAFETY: ev 是 session 管理的有效事件句柄（本 worker 不 CloseHandle）。
        let r = unsafe { WaitForSingleObject(ev, 100) };
        if r == WAIT_FAILED {
            swf.store(true, Ordering::Relaxed);
        }
    });

    let mut td = WindowsTeardown::new(
        Some(agg),
        RetirementSaga::new(fence(), ownership_version(1)),
        build_teardown_plan(&plan, true),
        vec![worker],
    );
    td.pure_cancel().expect("pure cancel");
    td.begin(
        retirement_id(1),
        cleanup_trigger(),
        origin_subject(),
        platform_ownership(),
        inventory_digest(1),
    )
    .expect("journaled begin");
    td.unblock_native_read().expect("journaled unblock");
    td.join_children().expect("child join（EndSession 之前）");
    td.restore_owned_resources()
        .expect("逆族序 compare-and-restore");

    // 第三方修改必须存活：MTU 保持 1400、DNS 保持 10.88.88.54（compare-and-restore
    // typed 跳过——无条件恢复旧快照 = mutant）；own 隧道路由与 owned 地址被清。
    let after = expect_ok(
        td.aggregate().expect("final handle 前 aggregate 必须存活").capture(),
        "teardown restore 后 capture",
    );
    assert_eq!(
        after.mtu_v4,
        MtuSnapshot::new(luid, MtuFamily::V4, 1400),
        "第三方 MTU 修改（1400）必须存活——不得无条件恢复旧快照"
    );
    assert_eq!(
        after.dns, third_party_dns,
        "第三方 DNS 修改（10.88.88.54）必须存活——不得无条件恢复旧快照"
    );
    assert!(
        !after
            .routes
            .iter()
            .any(|r| r.network == TUNNEL_NET && r.prefix_len == TUNNEL_PREFIX),
        "own 隧道路由必须已清理（逆序 restore 只清 owned）"
    );
    assert_eq!(
        after.address_rows,
        original.address_rows,
        "own 地址必须已删除（第三方未触碰的行指纹不变 -> compare-delete）"
    );

    td.drop_final_handle().expect("final handle（children 已 join）");
    assert!(
        !saw_wait_failed.load(Ordering::Relaxed),
        "child 不得在 EndSession 前未 join（final handle before join mutant）"
    );
    no_scratch_residue(&lib, &name);
    let proof = td
        .cleanup_proof(prove_input(), &complete_predicates())
        .expect("完整 teardown 后必须可签发 proof");
    assert_eq!(proof.clean.unresolved_obligation_count, 0);
}

// ---------------------------------------------------------------------------
// 6. proof 门禁（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// CleanProof 只对完整 inventory + 全 verified predicate 签发：缺任一项 canonical
/// obligation、任一 predicate 未验证、teardown 未完成都必须拒绝（failure signs proof =
/// mutant）。成功 proof 必须绑定 begin 时的 canonical inventory digest 且
/// unresolved_obligation_count == 0。
#[test]
fn proof_requires_complete_inventory() {
    // ---- (a) verify 层：inventory 缺任一项 -> 拒绝 ----
    let mut partial: Vec<InventoryItem> = COMPLETE_INVENTORY.to_vec();
    partial.pop(); // 缺 RunningEffect
    assert!(
        !is_complete(&partial),
        "缺项 inventory 必须判 incomplete（前置条件）"
    );
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    let id = retirement_id(1);
    expect_ok(
        saga.begin(
            id.clone(),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            all_labels(),
            inventory_digest(1),
        ),
        "saga begin",
    );
    assert!(
        verify_cleanup_proof(
            &partial,
            &complete_predicates(),
            inventory_digest(1),
            &mut saga,
            prove_input(),
        )
        .is_err(),
        "缺项 inventory 不得签发 proof（caller 不能任意遗漏一项——架构 §7.1）"
    );

    // ---- (b) WindowsTeardown 层：未完成 / predicates 缺项 / 未验证 -> 拒绝 ----
    let mut td = new_teardown(&empty_apply_plan(), Vec::new());
    td.pure_cancel().expect("pure cancel");
    td.begin(
        retirement_id(2),
        cleanup_trigger(),
        origin_subject(),
        platform_ownership(),
        inventory_digest(1),
    )
    .expect("journaled begin");
    assert!(
        td.cleanup_proof(prove_input(), &complete_predicates()).is_err(),
        "teardown 未完成不得签发 proof"
    );
    td.restore_owned_resources().expect("restore");
    td.drop_final_handle().expect("final handle");

    let mut missing_one = complete_predicates();
    missing_one.pop(); // predicates 缺一项
    assert!(
        td.cleanup_proof(prove_input(), &missing_one).is_err(),
        "predicates 缺项不得签发 proof（incomplete inventory mutant）"
    );
    let mut unverified = complete_predicates();
    unverified[0].verified = false;
    assert!(
        td.cleanup_proof(prove_input(), &unverified).is_err(),
        "未验证 predicate 不得签发 proof（API success 不是 proof）"
    );

    // ---- (c) 完整 inventory + 全 verified -> 签发，digest 绑定 ----
    let proof: CleanupProof = td
        .cleanup_proof(prove_input(), &complete_predicates())
        .expect("完整 inventory + 全 verified 必须签发 proof");
    // InventoryDigest 无 Debug（J53 同款）：用 `==` 断言绑定而非 assert_eq!。
    assert!(
        proof.clean.canonical_obligation_inventory_digest == inventory_digest(1),
        "proof 必须绑定 begin 时的 canonical inventory digest"
    );
    assert_eq!(proof.clean.unresolved_obligation_count, 0);
    assert_eq!(proof.predicates.len(), COMPLETE_INVENTORY.len());
    assert!(td.is_complete(), "proof 签发后 teardown complete");
}

// ---------------------------------------------------------------------------
// 7. oracle：pre-journal destroy / false proof（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// killer mutant oracle（Terra plan §6.1 `W24-T` 必杀 Win32 子计划 §7 W24 的 mutant：
/// destructive before journal；final handle before join；failure signs proof）：
///   (a) journaled begin 之前，任何 destructive 步骤（unblock/join/restore/final handle）
///       必须 DestructiveBeforeJournal（先于越序检查）；
///   (b) 曾失败的 teardown 即使其余步骤全部完成，也**不得**签发 proof——失败毒化 proof
///       （failure signs proof mutant）；
///   (c) cancel 先于 journal：begin 在 pure_cancel 之前 -> StageOutOfOrder；join 在
///       cancel/journal 之前 -> DestructiveBeforeJournal（join-before-cancel mutant）；
///   (d) verify 层：任一 predicate 未验证 -> 拒绝（proof 层 false proof mutant 化身）。
#[test]
fn oracle_kills_prejournal_destroy_or_false_proof_mutant() {
    // ---- (a) pre-journal destroy ----
    let counter = Arc::new(AtomicU64::new(0));
    let mut td = new_teardown(&empty_apply_plan(), vec![counting_worker(Arc::clone(&counter))]);
    td.pure_cancel().expect("pure cancel 不需 journal（cancel 先于 journal）");
    for (r, label) in [
        (td.unblock_native_read(), "pre-journal unblock"),
        (td.join_children(), "pre-journal join"),
        (td.restore_owned_resources(), "pre-journal restore"),
        (td.drop_final_handle(), "pre-journal final handle"),
    ] {
        let err = expect_teardown_err(r, label);
        assert!(
            matches!(err, TeardownError::DestructiveBeforeJournal),
            "{label} 必须 DestructiveBeforeJournal（destructive before journal mutant）, got {err:?}"
        );
    }

    // ---- (b) 失败毒化 proof：剩余步骤全部完成后也不得签发 ----
    td.begin(
        retirement_id(1),
        cleanup_trigger(),
        origin_subject(),
        platform_ownership(),
        inventory_digest(1),
    )
    .expect("journaled begin");
    td.unblock_native_read().expect("unblock");
    td.join_children().expect("join");
    td.restore_owned_resources().expect("restore");
    td.drop_final_handle().expect("final handle");
    assert!(
        td.cleanup_proof(prove_input(), &complete_predicates()).is_err(),
        "曾失败的 teardown 不得签发 proof——即使剩余步骤全部完成（failure signs proof mutant）"
    );

    // ---- (c) cancel 先于 journal / join ----
    let (mut td2, _) = {
        let counter = Arc::new(AtomicU64::new(0));
        (
            new_teardown(&empty_apply_plan(), vec![counting_worker(counter)]),
            (),
        )
    };
    let err = expect_teardown_err(
        td2.join_children(),
        "pure cancel 之前的 join（join before cancel mutant）",
    );
    assert!(
        matches!(err, TeardownError::DestructiveBeforeJournal),
        "cancel/journal 之前的 join 必须被拒绝, got {err:?}"
    );
    let mut td3 = new_teardown(&empty_apply_plan(), Vec::new());
    let err = expect_teardown_err(
        td3.begin(
            retirement_id(3),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            inventory_digest(1),
        ),
        "pure cancel 之前的 journaled begin",
    );
    assert!(
        matches!(err, TeardownError::StageOutOfOrder),
        "begin 必须先于 journal 记录 cancel（cancel 先于 journal, spec §5.6）, got {err:?}"
    );

    // ---- (d) verify 层：未验证 predicate -> 拒绝 ----
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    let id = retirement_id(4);
    expect_ok(
        saga.begin(
            id.clone(),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            all_labels(),
            inventory_digest(1),
        ),
        "saga begin",
    );
    let mut bad = complete_predicates();
    bad[2].verified = false; // Address 未验证
    assert!(
        verify_cleanup_proof(
            COMPLETE_INVENTORY,
            &bad,
            inventory_digest(1),
            &mut saga,
            prove_input(),
        )
        .is_err(),
        "未验证 predicate 不得签发 proof（failure signs proof mutant 的 proof 层化身）"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
