// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W27-T terra: 非特权 host + KernelControl（Win32 子计划 §8 `W27-T/I`）。本文件的 test names
// 是 docs/superpowers/plans/2026-08-12-vpn-rust-native-runtime-mvp-terra-oracle-plan.md §6.1
// `W27-T` 行的**完整且精确**集合（Terra 不得改名/增删/合并）；frozen seam 是
// `compose_nonprivileged_host`（exv-core crate 的 composition 模块）。Win32 子计划
// §8 `W27-T/I` 行的必测行为：host token 非提权；controller auth 先于 secret conversion；
// one runtime actor；RPC cancel≠Stop；helper link terminal 触发 admission revoke/teardown；
// host exit triggers Stop。killer mutants：**unauthorized secret dispatch**、
// **helper link lost 仍 Connected**、**第二业务状态机**（以及 RPC drop 自动 Stop，见
// portable `X71K-T` 的 oracle 语义在 host 组合层的继承）。
//
// 依赖：`W12-I`（exv-vpn-win32-ipc 的 plane isolation）、`W15-I`（helper OwnerLeaseManager）、
// `X71K-I`（exv-vpn-local-rpc kernel adapter）、`P43-I`（exv-vpn-cstp priority mux）、
// `R31-I`（exv-vpn-runtime 唯一状态写者）。host 组合（H80-I portable `exv_vpn_host::composition`
// 已 GREEN）是本测试的**下层组合**：Win32 host 只包一个 portable runtime actor，绝不新增
// 第二业务状态机。WSP1 §6 冻结事实继承：host 必须绑定已验 helper 的 PID+SID（反 fake-helper，
// endpoint 名 alone 不是 capability）。
//
// 本测试对 seam 追加的契约（W27-I 必须满足，否则 GREEN 编译失败）：
//   exv_core::composition（frozen seam `compose_nonprivileged_host`）
//     compose_nonprivileged_host(helper: &VerifiedPipePeer) -> Result<HostComposition, VpnError>
//       —— 纯组合（无真实 pipe/session I/O）：绑定已验 helper 身份、观测当前进程 token
//          elevation 事实、包**恰好一个** runtime actor（portable H80 组合）与一个
//          KernelControlGate；真实 helper pipe 连接由 main.rs 在组合后建立
//     （composition 还 `pub use` portable `exv_vpn_host::composition` 的
//      `HostEvent` / `HostEffect` / `HostPhase`——win32 测试不直接 import portable crate，
//      类型经 win32 seam re-export 进入）
//     HostComposition::process_token_is_elevated(&self) -> bool
//       —— compose 时从真实进程 token（TokenElevation）记录的观测事实，不得硬编码
//     HostComposition::helper_process_id(&self) -> u32
//     HostComposition::helper_user_sid(&self) -> &str
//       —— 组合绑定的已验 helper PID/SID（WSP1 §6）
//     HostComposition::runtime_actor_count(&self) -> usize
//       —— 必须恰好为 1（第二业务状态机是 mutant）
//     HostComposition::kernel_control_owns_state_machine(&self) -> bool
//       —— 必须为 false：KernelControl 只路由命令，不得拥有第二业务状态机
//     HostComposition::kernel_gate(&mut self) -> &mut KernelControlGate
//     HostComposition::bind_controller(&mut self, peer: PeerContext, capability: PeerCapability)
//       —— 绑定已授权 acceptance controller（对应 KernelControl 的 transport peer 验证）
//     HostComposition::apply(&mut self, event: HostEvent) -> HostEffect
//       —— 委托唯一 runtime actor 的确定性事件应用（portable H80 语义）
//     HostComposition::phase(&self) -> HostPhase
//     HostComposition::admission_open(&self) -> bool
//     HostComposition::packet_attachment_active(&self) -> bool
//       —— ProtocolEstablished 后为 true；helper link terminal / host exit 必须撤销为 false
//     HostComposition::on_rpc_waiter_cancel(&mut self)
//       —— 只取消 RPC 等待；绝不发出业务 Stop（RPC cancel ≠ Stop，spec §8.3/§9.1）
//     HostComposition::stop_requests(&self) -> u64
//       —— 发出的业务 Stop 请求计数（唯一业务取消是 KernelControl.Stop）
//     HostComposition::on_helper_link_terminal(&mut self)
//       —— 撤销 admission、撤销 packet leg、启动 teardown；helper link lost 后仍 Connected 是 mutant
//     HostComposition::teardown_started(&self) -> bool
//     HostComposition::exit(&mut self)
//       —— host 进程退出路径：触发恰好一次业务 Stop（幂等），关闭 admission，撤销 packet leg
//   exv_core::kernel_control（KernelControlGate）
//     KernelControlGate::new() -> Self
//     KernelControlGate::authorize(&mut self, peer: &VerifiedPipePeer) -> Result<(), VpnError>
//       —— controller transport peer 身份验证（X71K：secret 解码前先 auth，fail closed）
//     KernelControlGate::is_authorized(&self) -> bool
//     KernelControlGate::convert_secret(&mut self, secret: &[u8]) -> Result<ClearableSecret, VpnError>
//       —— 未授权必拒（auth 先于 secret conversion，spec §5.2/§9.1）；被拒无 dispatch 副作用；
//          授权后 secret 移入可清零槽（generated message 随即清空）
//     ClearableSecret::as_bytes(&self) -> &[u8]
//     ClearableSecret::clear(&mut self)
//
// 本文件 RED / test-only：引用 win32 host crate 的**空模块** `composition` / `kernel_control`，
// 在 W27-I 实现 seam 前必须编译失败（E0432，diagnostic 含 frozen seam
// `compose_nonprivileged_host`）。PURE + deterministic：无真实 pipe/session/I-O、无 sleep、
// 无随机；唯一 native 读是进程 token elevation 事实（TokenElevation），且只在 elevated
// harness 下显式 `not_run / blocked_by_environment` 短路，绝不冒充 RED 或 GREEN。GREEN
// 固定为 `7 passed; 0 failed; 0 ignored`。

use std::ffi::c_void;

use exv_vpn_domain::identity::{ConnectionBindingDigest, OperationMethod, PrincipalDigest};
use exv_vpn_domain::ports::{AuthorityEpoch, MonotonicTick};
use exv_vpn_resource::authority::{
    ConnectionBinding, PeerCapability, PeerContext, VerifiedConnectionMetadata,
};
// NOTE: 所有 portable host 类型（HostEvent/HostEffect/HostPhase）都经 win32 composition seam
// re-export 进入——测试不直接 import `exv_vpn_host`，W27-I 在 composition.rs 中 `pub use`
// 它们（并相应在 manifest 引入 exv-vpn-host 依赖）。
use exv_core::composition::{
    compose_nonprivileged_host, HostComposition, HostEffect, HostEvent, HostPhase,
};
use exv_core::kernel_control::{ClearableSecret, KernelControlGate};
use exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 确定性已验 helper peer（WSP1 §6：host 只对已验 helper 的 PID+SID 组合；字段公开可直接构造）。
fn helper_peer() -> VerifiedPipePeer {
    VerifiedPipePeer {
        process_id: 4242,
        user_sid: "S-1-5-21-3980489076-1253412212-3874560562-1002".to_string(),
        logon_sid: Some("S-1-5-5-0-323470".to_string()),
        account_name: "EXV VPN Helper".to_string(),
    }
}

/// 确定性 controller peer + capability（portable H80 测试同款构造，固定字面量）。
fn controller_peer_and_capability() -> (PeerContext, PeerCapability) {
    let principal = PrincipalDigest::try_from([0u8; 32]).unwrap();
    let binding = ConnectionBindingDigest::try_from([1u8; 32]).unwrap();
    let metadata =
        VerifiedConnectionMetadata::try_from((principal.clone(), binding.clone())).unwrap();
    let peer = PeerContext::try_from(metadata).unwrap();
    let connection = ConnectionBinding::try_from(binding).unwrap();
    let capability = PeerCapability::try_from((
        connection,
        principal,
        AuthorityEpoch::try_from(7u64).unwrap(),
        OperationMethod::Connect,
        MonotonicTick::try_from(42u64).unwrap(),
    ))
    .unwrap();
    (peer, capability)
}

/// 当前进程是否 elevated（admin token）——模式与 W17-T / W23B-T 一致。
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
        let _ = GetTokenInformation(token, TokenElevation, None, 0, &mut size);
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

/// 非特权前提的动态门：elevated 时输出显式 `not_run / blocked_by_environment` 并短路——
/// 非特权 host 前提无法在提权 harness 中证明（与 require_admin 对称，方向相反）。
fn require_non_elevated(test: &str) -> bool {
    if !is_elevated() {
        return true;
    }
    eprintln!(
        "[not_run/blocked_by_environment] {test}: host 必须非提权运行（提权是 helper 的职责）；\
         当前测试进程是 elevated admin token，无法证明非特权前提，跳过动态断言"
    );
    false
}

/// 构造已绑定 controller peer/capability 并推进到 Connected 的组合。
fn connected_composition() -> (HostComposition, HostEffect) {
    let mut composition =
        compose_nonprivileged_host(&helper_peer()).expect("compose_nonprivileged_host");
    let (peer, capability) = controller_peer_and_capability();
    composition.bind_controller(peer, capability);
    let _ = composition.apply(HostEvent::Connect);
    let effect = composition.apply(HostEvent::ProtocolEstablished);
    (composition, effect)
}

// ---------------------------------------------------------------------------
// 1. host token 非提权（进程事实；elevated harness 记 not_run，不冒充）
// ---------------------------------------------------------------------------

/// host 进程 token 必须非提权：非特权 host 只经已验 helper 执行 native mutation（W26 侧）。
/// composition 必须记录 compose 时观测的**真实**进程 token elevation 事实（不能硬编码）；
/// 非提权 harness 下断言非提权；elevated harness 显式 not_run / blocked_by_environment。
/// 杀死 'host 运行在提权 token / elevation 事实硬编码'。
#[test]
fn host_process_token_is_not_elevated() {
    let helper = helper_peer();
    let composition = compose_nonprivileged_host(&helper).expect("compose_nonprivileged_host");
    assert_eq!(
        composition.helper_process_id(),
        helper.process_id,
        "host 必须绑定已验 helper 的 PID（WSP1 §6 反 fake-helper）"
    );
    assert_eq!(
        composition.helper_user_sid(),
        helper.user_sid,
        "host 必须绑定已验 helper 的 SID（endpoint 名 alone 不是 capability）"
    );
    assert_eq!(
        composition.process_token_is_elevated(),
        is_elevated(),
        "composition 必须记录真实进程 token elevation 观测事实，不能硬编码"
    );
    if !require_non_elevated("host_process_token_is_not_elevated") {
        return;
    }
    assert!(
        !composition.process_token_is_elevated(),
        "host 进程 token 必须非提权（提权是 helper 的职责；非特权 host 是 W27 前提）"
    );
}

// ---------------------------------------------------------------------------
// 2. controller auth 先于 secret conversion（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// KernelControl 的 transport peer 身份验证必须先于任何 secret 转换/派发（spec §5.2/§9.1、
/// X71K：secret decode 在 auth 前是 mutant）。未授权的 convert_secret 必须拒绝，且被拒
/// 路径不得有任何 dispatch 副作用（授权状态、业务状态、Stop 计数都不变）；授权后 secret
/// 才可转换并移入可清零槽。
/// 杀死 'unauthorized secret dispatch / secret converted before controller auth'。
#[test]
fn controller_authorization_precedes_secret_conversion() {
    let mut composition =
        compose_nonprivileged_host(&helper_peer()).expect("compose_nonprivileged_host");
    {
        let gate = composition.kernel_gate();
        assert!(
            !gate.is_authorized(),
            "fresh KernelControlGate 必须未授权（fail closed）"
        );
        assert!(
            gate.convert_secret(b"password").is_err(),
            "authorize 之前 secret 不得转换（controller auth 先于 secret conversion）"
        );
        assert!(
            !gate.is_authorized(),
            "被拒的 secret 转换不得改变授权状态（无 dispatch 副作用）"
        );
        gate.authorize(&helper_peer())
            .expect("已验证 controller peer 必须通过 authorize");
        assert!(gate.is_authorized(), "authorize 后 gate 已授权");
        let mut secret = gate
            .convert_secret(b"password")
            .expect("authorize 后 secret 可以转换");
        assert_eq!(
            secret.as_bytes(),
            b"password",
            "转换后的 secret 槽必须携带原 secret 字节"
        );
        secret.clear();
        assert!(
            secret.as_bytes().iter().all(|&b| b == 0),
            "clear 后 secret 槽必须清零（secret 不保留明文）"
        );
    }
    // 拒绝路径从未派发到业务状态机：无 Stop、业务 phase 保持 Idle。
    assert_eq!(
        composition.stop_requests(),
        0,
        "unauthorized secret 路径不得派发任何业务 Stop"
    );
    assert_eq!(
        composition.phase(),
        HostPhase::Idle,
        "unauthorized secret 路径不得改变业务状态"
    );
}

// ---------------------------------------------------------------------------
// 3. one runtime actor（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// host 组合必须恰好包含一个 runtime actor（portable H80 组合为唯一业务状态机）；
/// KernelControl 只路由命令，绝不拥有第二业务状态机。两个独立组合各自恰好一个 actor
/// （无共享单例）；完整生命周期（Idle -> Connecting -> Connected -> helper terminal ->
/// teardown）中 actor 数不变。杀死 '第二业务状态机'。
#[test]
fn host_contains_exactly_one_runtime_actor() {
    let composition =
        compose_nonprivileged_host(&helper_peer()).expect("compose_nonprivileged_host");
    assert_eq!(
        composition.runtime_actor_count(),
        1,
        "host 组合必须恰好一个 runtime actor（第二业务状态机是 mutant）"
    );
    assert!(
        !composition.kernel_control_owns_state_machine(),
        "KernelControl 不得拥有第二业务状态机"
    );
    // 两个独立组合各自恰好一个 actor（无共享单例，也无第二状态机）。
    let second = compose_nonprivileged_host(&helper_peer()).expect("second compose");
    assert_eq!(second.runtime_actor_count(), 1);
    assert!(!second.kernel_control_owns_state_machine());

    // 完整生命周期中 actor 数恒为 1。
    let (mut driven, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected, "组合推进到 Connected");
    assert_eq!(driven.runtime_actor_count(), 1);
    assert!(!driven.kernel_control_owns_state_machine());
    driven.on_helper_link_terminal();
    assert_eq!(driven.runtime_actor_count(), 1);
    assert!(!driven.kernel_control_owns_state_machine());
    driven.exit();
    assert_eq!(driven.runtime_actor_count(), 1);
    assert!(!driven.kernel_control_owns_state_machine());
}

// ---------------------------------------------------------------------------
// 4. RPC cancel ≠ Stop（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// RPC waiter 被取消只停止等待，绝不触发业务 Stop（spec §8.3：client cancel 只停止等待，
/// 不撤销 server task；唯一业务取消是 KernelControl.Stop；X71K mutant：RPC drop 自动 Stop）。
/// 业务状态（Connected）、admission 与 Stop 计数都必须不受 waiter cancel 影响；只有显式
/// 业务 Stop（Disconnect）才发出 Stop。
#[test]
fn rpc_waiter_cancel_is_not_business_stop() {
    let (mut composition, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected, "组合推进到 Connected");
    assert_eq!(composition.phase(), HostPhase::Connected);
    assert!(composition.admission_open());
    assert!(composition.packet_attachment_active());

    // RPC waiter 取消：只取消等待，绝不发出业务 Stop。
    composition.on_rpc_waiter_cancel();
    assert_eq!(
        composition.stop_requests(),
        0,
        "RPC waiter cancel 不得发出业务 Stop——RPC cancel ≠ Stop（spec §8.3/§9.1）"
    );
    assert_eq!(
        composition.phase(),
        HostPhase::Connected,
        "waiter cancel 不得改变业务状态（Connected 保持）"
    );
    assert!(
        composition.admission_open(),
        "waiter cancel 不得关闭 admission"
    );
    assert!(
        composition.packet_attachment_active(),
        "waiter cancel 不得撤销 packet leg"
    );

    // 只有显式业务 Stop 才发出 Stop（恰好一次）。
    assert_eq!(
        composition.apply(HostEvent::Disconnect),
        HostEffect::TeardownInitiated
    );
    assert_eq!(
        composition.stop_requests(),
        1,
        "显式业务 Stop 恰好发出一次"
    );
}

// ---------------------------------------------------------------------------
// 5. helper link terminal → admission revoke + teardown（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// helper pipe link 丢失（terminal）必须撤销 admission 并启动有界完整 teardown（spec §8.3：
/// packet boundary terminal 必须触发 teardown，不仅是停一个 data task），packet leg 一并撤销；
/// Connected 必须失效。terminal 之后的新 Connect 必须被拒绝（admission 已撤销）。
/// 杀死 'helper link lost 仍 Connected'。
#[test]
fn helper_link_terminal_revokes_admission_and_starts_teardown() {
    let (mut composition, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected, "组合推进到 Connected");
    assert_eq!(composition.phase(), HostPhase::Connected);
    assert!(composition.admission_open());
    assert!(composition.packet_attachment_active());

    composition.on_helper_link_terminal();
    assert!(
        !composition.admission_open(),
        "helper link terminal 必须撤销 admission（revoke）"
    );
    assert!(
        composition.teardown_started(),
        "helper link terminal 必须启动 teardown（bounded complete teardown，spec §8.3）"
    );
    assert_ne!(
        composition.phase(),
        HostPhase::Connected,
        "helper link 丢失后不得仍 Connected（mutant：helper link lost 仍 Connected）"
    );
    assert!(
        !composition.packet_attachment_active(),
        "helper link terminal 必须撤销 packet leg"
    );

    // admission 撤销后新 Connect 必须被拒绝。
    assert!(
        matches!(
            composition.apply(HostEvent::Connect),
            HostEffect::ConnectRefused(_)
        ),
        "admission 撤销后 Connect 必须被拒绝"
    );
}

// ---------------------------------------------------------------------------
// 6. host exit → Stop（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// host 进程退出路径必须触发业务 Stop：关闭 admission、恰好一次 Stop、撤销 packet leg、
/// Connected 失效；exit 幂等（重复 exit 不重复触发 Stop）。
/// 杀死 'host exit 不触发 Stop / exit 后仍 Connected'。
#[test]
fn host_exit_triggers_stop() {
    let (mut composition, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected, "组合推进到 Connected");
    assert!(composition.packet_attachment_active());

    composition.exit();
    assert_eq!(
        composition.stop_requests(),
        1,
        "host exit 必须恰好触发一次业务 Stop"
    );
    assert!(
        !composition.admission_open(),
        "host exit 后 admission 必须关闭"
    );
    assert_ne!(
        composition.phase(),
        HostPhase::Connected,
        "host exit 后 Connected 必须失效"
    );
    assert!(
        !composition.packet_attachment_active(),
        "host exit 必须撤销 packet leg（host 退出后不得继续传输）"
    );

    // exit 幂等：第二次 exit 不重复触发 Stop。
    composition.exit();
    assert_eq!(
        composition.stop_requests(),
        1,
        "exit 幂等——业务 Stop 只触发一次"
    );
}

// ---------------------------------------------------------------------------
// 7. oracle：第二业务状态机 / unauthorized secret dispatch（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// killer mutant oracle（Win32 子计划 §8 `W27-T/I` 的 mutant：unauthorized secret dispatch；
/// helper link lost 仍 Connected；第二业务状态机）：
///   (a) 第二业务状态机：任何生命周期阶段 runtime_actor_count 恒为 1 且
///       kernel_control_owns_state_machine 恒为 false；
///   (b) unauthorized secret dispatch：授权前的 secret 转换必须拒绝且无副作用（不派发
///       Stop、不改业务状态）；
///   (c) helper link lost 后 Connected 必须失效（oracle 复述第 5 测；双保险）。
#[test]
fn oracle_kills_second_runtime_or_unauthorized_secret_mutant() {
    // (a) 完整生命周期中不出现第二业务状态机。
    let (mut driven, _) = connected_composition();
    let _ = driven.apply(HostEvent::Connect);
    assert_eq!(driven.runtime_actor_count(), 1);
    assert!(!driven.kernel_control_owns_state_machine());
    let _ = driven.apply(HostEvent::ProtocolEstablished);
    assert_eq!(driven.runtime_actor_count(), 1);
    assert!(!driven.kernel_control_owns_state_machine());
    driven.on_helper_link_terminal();
    assert_eq!(driven.runtime_actor_count(), 1);
    assert!(!driven.kernel_control_owns_state_machine());
    driven.exit();
    assert_eq!(driven.runtime_actor_count(), 1);
    assert!(!driven.kernel_control_owns_state_machine());

    // (b) unauthorized secret dispatch：未授权 convert_secret 必须拒绝且零副作用。
    let mut gate_composition =
        compose_nonprivileged_host(&helper_peer()).expect("compose_nonprivileged_host");
    {
        let gate = gate_composition.kernel_gate();
        assert!(
            gate.convert_secret(b"credential").is_err(),
            "unauthorized secret 不得转换/派发（unauthorized secret dispatch 是 mutant）"
        );
        assert!(
            !gate.is_authorized(),
            "被拒后仍必须未授权（fail closed）"
        );
    }
    assert_eq!(
        gate_composition.stop_requests(),
        0,
        "被拒的 secret 不得派发业务 Stop"
    );
    assert_eq!(
        gate_composition.phase(),
        HostPhase::Idle,
        "被拒的 secret 不得改变业务状态"
    );

    // (c) helper link lost 仍 Connected 是 mutant（与第 5 测双保险）。
    let (mut lost, _) = connected_composition();
    assert_eq!(lost.phase(), HostPhase::Connected);
    lost.on_helper_link_terminal();
    assert_ne!(
        lost.phase(),
        HostPhase::Connected,
        "helper link lost 后 Connected 必须失效（oracle 复述）"
    );
    assert!(!lost.packet_attachment_active());
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
