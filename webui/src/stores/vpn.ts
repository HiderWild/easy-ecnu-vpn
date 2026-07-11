import { computed, nextTick, ref } from 'vue'
import { defineStore } from 'pinia'
import api from '../api/host'
import { useUiStore } from './ui'
import { useConfigStore } from './config'

const SERVICE_STATUS_REFRESH_TIMEOUT_MS = 2500

export interface UpstreamVirtualAdapter {
  name: string
  detail: string
  kind?: string
  role?: string
  if_index?: string
  route_reason?: string
}

interface UpstreamVirtualDisplay {
  detected: boolean
  label: string
}

export interface VpnStatusLastError {
  domain?: string
  code?: string
  message?: string
  recoverable?: boolean
  recommended_action?: string
  native_code?: string | number
  native_api?: string
}

export type ConnectProgressStepState =
  | 'pending'
  | 'active'
  | 'done'
  | 'failed'
  | 'skipped'

export interface ConnectProgressStep {
  key: string
  label: string
  description: string
  state: ConnectProgressStepState
  priority: number
  visual:
    | 'shield'
    | 'helper'
    | 'server'
    | 'key'
    | 'adapter'
    | 'routes'
    | 'packet'
    | 'check'
    | string
}

export interface ConnectProgress {
  active_key: string
  steps: ConnectProgressStep[]
}

export type DtlsMode = 'auto' | 'enabled' | 'disabled'
export type ActiveDataChannel = 'cstp_tls' | 'dtls'

export interface VpnStatus {
  connected: boolean
  process_running?: boolean
  server: string
  username: string
  pid: number
  network_ready: boolean
  interface: string
  internal_ip: string
  route_count: number
  mtu: number
  uptime_seconds: number
  rx_bytes: number
  tx_bytes: number
  upstream_virtual_detected: boolean
  upstream_virtual_adapters: UpstreamVirtualAdapter[]
  upstream_virtual_message: string
  route_policy: string
  Finnished?: boolean
  log_path?: string
  mode?: 'helper' | 'direct' | 'elevated' | 'disconnected'
  backend?: unknown
  phase?: string
  dtls_mode?: DtlsMode
  active_data_channel?: ActiveDataChannel
  dtls_state?: string
  dtls_fallback_reason?: string
  dtls_fallback_count?: number
  error?: string
  error_code?: string
  error_recoverable?: boolean
  last_error?: VpnStatusLastError
  connect_progress?: ConnectProgress
}

export interface VpnConnectAccepted {
  accepted: true
  phase?: string
  job_id?: string
  active_job_id?: string
  active?: boolean
  coalesced?: boolean
  cancelling?: boolean
  user_cancelled?: boolean
  desired_connected?: boolean
  intent_epoch?: number
}

export interface RouteEntry {
  cidr: string
}

export interface LogEntry {
  seq?: number
  timestamp: string
  level: 'info' | 'warn' | 'error' | 'debug'
  message: string
}

export interface ServiceStatus {
  installed: boolean
  running: boolean
  path: string
  available: boolean
  capabilities?: {
    service_mode?: boolean
    oneshot_mode?: boolean
    temporary_connect?: boolean
    direct_fallback?: boolean
    helper_binary?: boolean
  }
  mode?: string
  endpoint?: string
  label?: string
  binary_path?: string
  service_state?: number
  warning?: string
  health?: string
  diagnostic_code?: string
  last_start_api?: string
  last_start_native_error?: number
  consecutive_start_failures?: number
  start_suppressed?: boolean
  start_retry_after_ms?: number
  recommended_action?: string
  operation_state?: ServiceOperationOutcome
}

type ServiceOperationCommand = 'install' | 'uninstall' | 'repair'
type ServiceOperationOutcome = 'completed' | 'in_progress' | 'warning'

export interface ServiceOperationResult {
  operation?: {
    success?: boolean
    exit_code?: number
    message?: string
    status?: ServiceOperationOutcome
    in_progress?: boolean
    warning?: string
    connect_can_continue?: boolean
    service_installed?: boolean
    service_available?: boolean
    service_start?: unknown
  }
  service_status?: ServiceStatus
  handoff?: unknown
}

export interface ServiceProgressEntry {
  command: 'install' | 'uninstall' | 'repair'
  message: string
  timestamp: string
}

export interface CliInstallStatus {
  installed: boolean
  installPath: string
  targetPath: string
  availableInPath: boolean
  warning?: string
}

export type ConnectionProgressStageSource = 'backend' | 'local'

export interface ConnectionProgressStage {
  key: string
  label: string
  description: string
  state: ConnectProgressStepState
  priority: number
  visual: ConnectProgressStep['visual']
  source: ConnectionProgressStageSource
}

export interface AuthInteraction {
  id: string
  kind: string
  label: string
  input_type: string
  options: string[]
}

export interface AuthInteractionPollResponse {
  ok: true
  pending: boolean
  interaction?: AuthInteraction
}

export type VpnErrorType =
  | 'elevation_required'
  | 'elevation_cancelled'
  | 'elevation_denied'
  | 'runtime_missing'
  | 'config_invalid'
  | 'service_missing'
  | 'service_already_installed'
  | 'vpn_session_active'
  | 'auth_protocol_mismatch'
  | 'auth_failed'
  | 'auth_rejected'
  | 'auth_challenge_required'
  | 'auth_group_required'
  | 'auth_expired'
  | 'csd_required_unsupported'
  | 'dtls_unavailable'
  | 'tunnel_disconnected'
  | 'session_timeout'
  | 'idle_timeout'
  | 'rekey_unsupported'
  | 'cstp_compressed_unsupported'
  | 'unsupported_extra_args'
  | 'tls_verify_failed'
  | 'wintun_missing'
  | 'utun_permission_denied'
  | 'unsupported_dtls'
  | 'permission_denied'
  | 'helper_unavailable'
  | 'network_unreachable'
  | 'connection_attempt_active'
  | 'user_cancelled'
  | 'invalid_request'
  | 'connection_failed'
  | 'native_failure'
  | 'parse_failure'
  | 'unknown_action'

export interface VpnError {
  ok: false
  error_type: VpnErrorType
  message: string
  recoverable: boolean
  recommended_action: string
  timestamp?: number
}

export type ConnectMode = 'helper' | 'elevated' | 'direct'

export type DashboardState =
  | 'service-ready disconnected'
  | 'service-missing disconnected'
  | 'helper connected'
  | 'direct connected'
  | 'elevated connected'
  | 'elevated connecting'
  | 'error recoverable'
  | 'error blocking'
  | 'loading'

export interface DashboardAction {
  label: string
  action: () => void
  variant?: 'primary' | 'secondary' | 'destructive'
}

type ConnectProgressStepCopy = Pick<ConnectionProgressStage, 'label' | 'description'>

const connectProgressStepCopy: Record<string, ConnectProgressStepCopy> = {
  intent: {
    label: '准备连接',
    description: '接受连接请求并确认本次连接流程',
  },
  helper: {
    label: '准备 helper',
    description: '启动或连接本地辅助进程',
  },
  auth: {
    label: '完成认证',
    description: '提交凭据并完成网关认证',
  },
  server: {
    label: '连接 VPN 服务器',
    description: '建立到 VPN 网关的加密通道',
  },
  adapter: {
    label: '准备虚拟网卡',
    description: '创建或打开 EXV 隧道接口',
  },
  routes: {
    label: '写入网络配置',
    description: '应用地址、DNS 和路由策略',
  },
  packet: {
    label: '启动数据转发',
    description: '启动隧道数据包转发',
  },
  check: {
    label: '确认连接可用',
    description: '等待连接进入可用状态',
  },
}

function normalizeBackendConnectionProgressSteps(steps: ConnectProgressStep[]): ConnectionProgressStage[] {
  return steps
    .map((step, originalIndex) => ({ step, originalIndex }))
    .sort((a, b) => (a.step.priority - b.step.priority) || (a.originalIndex - b.originalIndex))
    .map(({ step }) => {
      const copy = connectProgressStepCopy[step.key]
      return {
        key: step.key,
        label: copy?.label ?? step.label,
        description: copy?.description ?? step.description,
        state: step.state,
        priority: step.priority,
        visual: step.visual,
        source: 'backend',
      }
    })
}

function selectConnectionProgressStage(
  steps: ConnectionProgressStage[],
  activeKey: string | undefined,
  fallback: ConnectionProgressStage,
) {
  return (activeKey ? steps.find((step) => step.key === activeKey) : undefined)
    ?? steps.find((step) => step.state === 'active')
    ?? steps.find((step) => step.state === 'failed')
    ?? [...steps].reverse().find((step) => step.state === 'done' || step.state === 'skipped')
    ?? steps[0]
    ?? fallback
}

export function isVpnError(data: unknown): data is VpnError {
  return data != null && typeof data === 'object' && 'error_type' in (data as object)
}

function isVpnConnectAccepted(data: unknown): data is VpnConnectAccepted {
  return data != null &&
    typeof data === 'object' &&
    (data as Record<string, unknown>).accepted === true
}

function serviceStatusFromOperationResult(data: ServiceStatus | ServiceOperationResult) {
  if (
    data &&
    typeof data === 'object' &&
    'service_status' in data &&
    (data as ServiceOperationResult).service_status
  ) {
    return (data as ServiceOperationResult).service_status as ServiceStatus
  }
  return data as ServiceStatus
}

function hasOwnField(source: object, field: string) {
  return Object.prototype.hasOwnProperty.call(source, field)
}

function upstreamVirtualDisplayFromStatus(nextStatus: VpnStatus): UpstreamVirtualDisplay | null {
  if (
    !hasOwnField(nextStatus, 'upstream_virtual_detected') &&
    !hasOwnField(nextStatus, 'upstream_virtual_adapters') &&
    !hasOwnField(nextStatus, 'upstream_virtual_message')
  ) {
    return null
  }

  const adapters = Array.isArray(nextStatus.upstream_virtual_adapters)
    ? nextStatus.upstream_virtual_adapters
    : []
  const adapterLabel = adapters.map((adapter) => adapter.name).filter(Boolean).join('、')
  const detected = Boolean(nextStatus.upstream_virtual_detected || adapters.length > 0)

  return {
    detected,
    label: detected
      ? adapterLabel || nextStatus.upstream_virtual_message || '已检测到'
      : nextStatus.upstream_virtual_message || '--',
  }
}

function serviceOperationEnvelope(data: ServiceStatus | ServiceOperationResult) {
  if (data && typeof data === 'object' && 'operation' in data) {
    return (data as ServiceOperationResult).operation
  }
  return undefined
}

function serviceOperationOutcome(
  command: ServiceOperationCommand,
  data: ServiceStatus | ServiceOperationResult,
  nextStatus: ServiceStatus,
): ServiceOperationOutcome {
  const operation = serviceOperationEnvelope(data)
  if (
    operation?.status === 'completed' ||
    operation?.status === 'in_progress' ||
    operation?.status === 'warning'
  ) {
    return operation.status
  }
  if (operation?.in_progress) return 'in_progress'
  if (operation?.success === false || operation?.warning || nextStatus.warning) {
    return 'warning'
  }
  if (command === 'install' || command === 'repair') {
    return nextStatus.available ? 'completed' : 'in_progress'
  }
  return nextStatus.installed ? 'in_progress' : 'completed'
}

function serviceOperationMessage(
  command: ServiceOperationCommand,
  outcome: ServiceOperationOutcome,
  data: ServiceStatus | ServiceOperationResult,
  nextStatus: ServiceStatus,
) {
  const operation = serviceOperationEnvelope(data)
  if (operation?.message) return operation.message
  if (operation?.warning) return operation.warning
  if (nextStatus.warning) return nextStatus.warning
  if (outcome === 'warning') return '辅助服务操作返回警告，请刷新状态后确认。'
  if (command === 'install') return '辅助服务安装已启动，正在等待系统服务状态更新。'
  if (command === 'uninstall') return '辅助服务卸载已启动，正在等待系统服务状态更新。'
  return '辅助服务修复已启动，正在等待系统服务状态更新。'
}

function isElevationCancelledMessage(message: string) {
  const normalized = message.toLowerCase()
  return message.includes('用户已取消') ||
    message.includes('使用者已取消') ||
    message.includes('操作已取消') ||
    normalized.includes('user canceled') ||
    normalized.includes('user cancelled') ||
    normalized.includes('operation was canceled') ||
    normalized.includes('operation was cancelled') ||
    normalized.includes('cancelled by the user') ||
    normalized.includes('canceled by the user') ||
    normalized.includes('error 1223') ||
    message.includes('(-128)')
}

function isAuthFailureMessage(message: string) {
  const normalized = message.toLowerCase()
  return normalized.includes('auth_failed') ||
    normalized.includes('auth_rejected') ||
    normalized.includes('auth_expired') ||
    normalized.includes('login failed') ||
    normalized.includes('authentication failed') ||
    normalized.includes('invalid password') ||
    normalized.includes('password is incorrect')
}

function isCredentialFailureType(type: VpnErrorType) {
  return type === 'auth_failed' || type === 'auth_rejected'
}

function isBenignCancelTransportError(error: VpnError) {
  const message = error.message.toLowerCase()
  return error.error_type === 'user_cancelled' ||
    (
      (error.error_type === 'native_failure' || error.error_type === 'connection_failed') &&
      (
        message.includes('transport_closed') ||
        message.includes('core rpc transport is closed') ||
        message.includes('core_comm_broken') ||
        message.includes('core_unresponsive')
      )
    )
}

const serviceDisconnectPhases = new Set([
  'connecting',
  'preparing_helper',
  'authenticating',
  'connecting_cstp',
  'opening_packet_device',
  'applying_network_config',
  'connected',
  'reconnecting',
  'disconnecting',
  'cleaning_up',
])

type NativeErrorDescriptor = {
  error_type: VpnErrorType
  message: string
  recommended_action: string
  recoverable: boolean
}

// Single source of truth: every canonical backend code maps to one user-facing
// descriptor. The backend (feedback module) always sends `code`, `recoverable`
// and `recommended_action`; this table supplies the localized label and a
// sensible default action when the backend omits one.
const contractErrorMap: Record<string, NativeErrorDescriptor> = {
  auth_protocol_mismatch: {
    error_type: 'auth_protocol_mismatch',
    message: 'VPN 网关返回了不支持的认证协议响应，请查看日志确认服务器入口是否正确。',
    recommended_action: 'view_logs',
    recoverable: false,
  },
  auth_failed: {
    error_type: 'auth_failed',
    message: '登录失败，请核对您的用户名和密码。',
    recommended_action: 'retry_password',
    recoverable: true,
  },
  auth_rejected: {
    error_type: 'auth_rejected',
    message: 'VPN 认证被服务器拒绝，请检查账号、密码或二次认证信息后重试。',
    recommended_action: 'retry_password',
    recoverable: true,
  },
  auth_challenge_required: {
    error_type: 'auth_challenge_required',
    message: 'VPN 需要继续完成二次认证。',
    recommended_action: 'complete_auth_challenge',
    recoverable: true,
  },
  auth_group_required: {
    error_type: 'auth_group_required',
    message: 'VPN 需要选择认证组。',
    recommended_action: 'complete_group_selection',
    recoverable: true,
  },
  auth_expired: {
    error_type: 'auth_expired',
    message: '认证会话已过期，请重新输入凭据后连接。',
    recommended_action: 'retry_password',
    recoverable: true,
  },
  csd_required_unsupported: {
    error_type: 'csd_required_unsupported',
    message: 'VPN 网关要求 AnyConnect host-scan，本版本不会执行网关下载的脚本。',
    recommended_action: 'view_logs',
    recoverable: false,
  },
  dtls_unavailable: {
    error_type: 'dtls_unavailable',
    message: '网关提供了 DTLS 信息，但当前原生连接会继续使用 CSTP-only。',
    recommended_action: 'continue_with_cstp',
    recoverable: true,
  },
  tunnel_disconnected: {
    error_type: 'tunnel_disconnected',
    message: 'VPN 服务器主动断开了隧道连接。',
    recommended_action: 'retry_connection',
    recoverable: true,
  },
  session_timeout: {
    error_type: 'session_timeout',
    message: 'VPN 会话已超时，请重新认证后连接。',
    recommended_action: 'retry_password',
    recoverable: true,
  },
  idle_timeout: {
    error_type: 'idle_timeout',
    message: 'VPN 会话因空闲超时断开，请重试连接。',
    recommended_action: 'retry_connection',
    recoverable: true,
  },
  rekey_unsupported: {
    error_type: 'rekey_unsupported',
    message: 'VPN 服务器要求重新协商隧道，请重新连接。',
    recommended_action: 'retry_connection',
    recoverable: true,
  },
  cstp_compressed_unsupported: {
    error_type: 'cstp_compressed_unsupported',
    message: 'VPN 服务器发送了当前不支持的压缩 CSTP 帧。',
    recommended_action: 'view_logs',
    recoverable: false,
  },
  unsupported_extra_args: {
    error_type: 'unsupported_extra_args',
    message: '当前原生引擎不支持部分额外参数，请在设置中移除后重试。',
    recommended_action: 'open_settings',
    recoverable: true,
  },
  tls_verify_failed: {
    error_type: 'tls_verify_failed',
    message: '无法验证 VPN 服务器证书，连接已中止。',
    recommended_action: 'check_server_certificate',
    recoverable: true,
  },
  wintun_missing: {
    error_type: 'wintun_missing',
    message: '缺少 Wintun 网络驱动，无法建立隧道。请安装网络驱动后重试。',
    recommended_action: 'install_wintun_driver',
    recoverable: true,
  },
  utun_permission_denied: {
    error_type: 'utun_permission_denied',
    message: '没有创建虚拟网卡的权限，请以管理员身份运行后重试。',
    recommended_action: 'retry_with_elevation',
    recoverable: true,
  },
  unsupported_dtls: {
    error_type: 'unsupported_dtls',
    message: '当前原生连接使用 CSTP-only，DTLS 后端尚未启用。',
    recommended_action: 'retry_connection',
    recoverable: false,
  },
  permission_denied: {
    error_type: 'permission_denied',
    message: '需要管理员权限才能继续，请在弹出的授权窗口中点击允许。',
    recommended_action: 'retry_with_elevation',
    recoverable: true,
  },
  helper_unavailable: {
    error_type: 'helper_unavailable',
    message: 'VPN 助手服务不可用，请启动或重新安装助手后重试。',
    recommended_action: 'reinstall_helper',
    recoverable: true,
  },
  service_already_installed: {
    error_type: 'service_already_installed',
    message: '辅助服务已安装，无需重复安装。',
    recommended_action: 'refresh_service_status',
    recoverable: true,
  },
  vpn_session_active: {
    error_type: 'vpn_session_active',
    message: 'VPN 连接仍在运行，请先断开连接后再卸载辅助服务。',
    recommended_action: 'disconnect_first',
    recoverable: true,
  },
  network_unreachable: {
    error_type: 'network_unreachable',
    message: '无法连接到 VPN 服务器，请检查网络连接或服务器地址。',
    recommended_action: 'check_network',
    recoverable: true,
  },
  connection_attempt_active: {
    error_type: 'connection_attempt_active',
    message: '已有 VPN 连接流程正在进行，请等待完成或取消后重试。',
    recommended_action: 'cancel_or_wait',
    recoverable: true,
  },
  user_cancelled: {
    error_type: 'user_cancelled',
    message: '操作已取消。',
    recommended_action: '',
    recoverable: true,
  },
  invalid_request: {
    error_type: 'invalid_request',
    message: '请求无效，请检查配置后重试。',
    recommended_action: '',
    recoverable: false,
  },
  connection_failed: {
    error_type: 'connection_failed',
    message: '连接失败，请打开日志（exv logs）查看详细原因后重试。',
    recommended_action: 'view_logs',
    recoverable: true,
  },
  transport_closed: {
    error_type: 'native_failure',
    message: '核心进程连接已关闭，可由程序重启内核后重试。',
    recommended_action: 'restart_core',
    recoverable: true,
  },
  core_comm_broken: {
    error_type: 'native_failure',
    message: '核心进程通信已中断，可由程序重启内核后重试。',
    recommended_action: 'restart_core',
    recoverable: true,
  },
  core_unresponsive: {
    error_type: 'native_failure',
    message: '核心进程无响应，可由程序重启内核后重试。',
    recommended_action: 'restart_core',
    recoverable: true,
  },
  core_restart_required: {
    error_type: 'native_failure',
    message: '核心进程需要重启后才能继续。',
    recommended_action: 'restart_core',
    recoverable: true,
  },
  core_restart_failed: {
    error_type: 'native_failure',
    message: '核心进程重启失败，请稍后重试或重新打开客户端。',
    recommended_action: 'restart_core',
    recoverable: true,
  },
  elevation_denied: {
    error_type: 'permission_denied',
    message: '管理员授权已取消，请允许 UAC 提权后重试。',
    recommended_action: 'retry',
    recoverable: true,
  },
  launch_failed: {
    error_type: 'native_failure',
    message: '启动提权安装进程失败，请以管理员身份重新运行安装。',
    recommended_action: 'reinstall_helper',
    recoverable: true,
  },
  helper_not_found: {
    error_type: 'native_failure',
    message: '未找到 exv-helper.exe，请重新安装客户端。',
    recommended_action: 'reinstall_helper',
    recoverable: true,
  },
  service_installed_not_running: {
    error_type: 'helper_unavailable',
    message: '服务已安装但无法启动。已安装服务模式不会切换到临时 helper，请先尝试修复服务；仍失败时清理后重新安装。',
    recommended_action: 'repair_service',
    recoverable: true,
  },
  core_lease_failed: {
    error_type: 'helper_unavailable',
    message: '辅助服务拒绝了本次连接租约，请尝试修复服务或重启客户端后重试。',
    recommended_action: 'repair_service',
    recoverable: true,
  },
  core_lease_conflict: {
    error_type: 'helper_unavailable',
    message: '辅助服务仍保留上一轮连接租约，请尝试修复服务或重启客户端后重试。',
    recommended_action: 'repair_service',
    recoverable: true,
  },
  core_lease_unauthorized: {
    error_type: 'helper_unavailable',
    message: '辅助服务拒绝了当前核心进程的租约请求，请尝试修复服务或重启客户端后重试。',
    recommended_action: 'repair_service',
    recoverable: true,
  },
  helper_hello_disconnected: {
    error_type: 'helper_unavailable',
    message: '辅助服务在初始化握手时断开，请尝试修复服务或重启客户端后重试。',
    recommended_action: 'repair_service',
    recoverable: true,
  },
  helper_hello_failed: {
    error_type: 'helper_unavailable',
    message: '辅助服务初始化握手失败，请尝试修复服务或重启客户端后重试。',
    recommended_action: 'repair_service',
    recoverable: true,
  },
  vpn_disconnect_timeout: {
    error_type: 'native_failure',
    message: '断开当前 VPN 会话超时，请稍后重试安装。',
    recommended_action: 'retry',
    recoverable: true,
  },
}

// Raw backend codes that historically have not gone through
// feedback::resolve_error_code — or that we want the renderer to defend
// against even if the backend mapping regresses. Each entry rewrites the raw
// code to a canonical key in `contractErrorMap` so the descriptor lookup
// produces the right view (e.g. view_logs) instead of falling through to a
// credential prompt. See docs/AGGREGATE_AUTH_EMPTY_RESPONSE_FIX_PLAN.md §4.
const rawCodeAliases: Record<string, string> = {
  // aggregate-auth framing failures: the gateway response is malformed,
  // not the password.
  auth_response_invalid: 'auth_protocol_mismatch',
  auth_response_too_large: 'auth_protocol_mismatch',
  native_wintun_wintun_missing: 'wintun_missing',
  native_wintun_adapter_open_failed: 'permission_denied',
}

function canonicalizeRawCode(code: string): string {
  return rawCodeAliases[code] ?? code
}

function stripRemoteErrorPrefix(message: string) {
  return message
    .replace(/^Error invoking remote method '[^']+':\s*/i, '')
    .replace(/^Error:\s*/i, '')
    .trim()
}

function truncateMessage(message: string) {
  return message.length > 96 ? `${message.slice(0, 96)}...` : message
}

function isCoreTransportFailureMessage(message: string, lower = message.toLowerCase()) {
  return message.includes('Core RPC transport is closed') ||
    lower.includes('transport_closed') ||
    lower.includes('core_comm_broken') ||
    lower.includes('core_unresponsive') ||
    lower.includes('core_restart_required') ||
    lower.includes('core restart is required')
}

function localizedRawError(message: string): Pick<VpnError, 'error_type' | 'message' | 'recoverable' | 'recommended_action'> {
  const normalized = stripRemoteErrorPrefix(message)
  const lower = normalized.toLowerCase()
  if (isElevationCancelledMessage(normalized)) {
    return {
      error_type: 'elevation_cancelled',
      message: '提权失败：用户已取消授权。',
      recoverable: true,
      recommended_action: '',
    }
  }
  if (isAuthFailureMessage(normalized) || normalized.includes('Login failed.')) {
    return {
      error_type: 'auth_failed',
      message: contractErrorMap.auth_failed.message,
      recoverable: true,
      recommended_action: 'retry_password',
    }
  }
  if (isCoreTransportFailureMessage(normalized, lower)) {
    return {
      error_type: 'native_failure',
      message: contractErrorMap.transport_closed.message,
      recoverable: true,
      recommended_action: 'restart_core',
    }
  }
  if (normalized.includes('Failed to start elevated one-shot helper.')) {
    return {
      error_type: 'helper_unavailable',
      message: '临时助手启动失败，请确认已允许系统授权，或运行 start.ps1 修复本地组件后重试。',
      recoverable: true,
      recommended_action: 'retry_with_elevation',
    }
  }
  if (normalized.includes('A native VPN connection attempt is already active.')) {
    return {
      error_type: 'connection_attempt_active',
      message: contractErrorMap.connection_attempt_active.message,
      recoverable: true,
      recommended_action: 'cancel_or_wait',
    }
  }
  if (normalized.includes('invalid X-CSTP-Session-Timeout value')) {
    return {
      error_type: 'connection_failed',
      message: 'VPN 网关返回了异常的会话超时字段，请查看日志并重试。',
      recoverable: true,
      recommended_action: 'view_logs',
    }
  }
  if (normalized.includes('Native engine session failed to start')) {
    return {
      error_type: 'connection_failed',
      message: 'VPN 隧道启动失败，请确认网络驱动可用后重试。',
      recoverable: true,
      recommended_action: 'view_logs',
    }
  }
  if (
    normalized.includes('failed to open or create Wintun adapter') ||
    lower.includes('failed to open or create wintun adapter') ||
    lower.includes('windows error 5')
  ) {
    return {
      error_type: 'permission_denied',
      message: '需要管理员权限才能继续，请在系统授权窗口中点击允许后重试。',
      recoverable: true,
      recommended_action: 'retry_with_elevation',
    }
  }
  if (lower.includes('bundled wintun.dll is missing') || lower.includes('wintun runtime is missing')) {
    return {
      error_type: 'wintun_missing',
      message: contractErrorMap.wintun_missing.message,
      recoverable: true,
      recommended_action: 'install_wintun_driver',
    }
  }
  if (normalized.includes('elevation_denied')) {
    return {
      error_type: 'elevation_denied',
      message: '需要管理员权限才能继续，请在弹出的授权窗口中点击允许。',
      recoverable: true,
      recommended_action: 'retry_with_elevation',
    }
  }
  return {
    error_type: 'native_failure',
    message: normalized ? `操作失败：${truncateMessage(normalized)}` : '操作失败，请查看日志。',
    recoverable: true,
    recommended_action: 'view_logs',
  }
}

export function normalizeError(raw: unknown): VpnError {
  if (raw && typeof raw === 'object') {
    const obj = raw as Record<string, unknown>
    if (typeof obj.error_type === 'string') {
      const descriptor = contractErrorMap[obj.error_type]
      const localized = descriptor
        ? {
            error_type: descriptor.error_type,
            message: descriptor.message,
            recoverable: descriptor.recoverable,
            recommended_action: descriptor.recommended_action,
          }
        : localizedRawError(String(obj.message || obj.error || '操作失败，请查看日志。'))
      return {
        ok: false,
        error_type: localized.error_type,
        message: localized.message,
        recoverable: obj.recoverable !== undefined ? !!obj.recoverable : localized.recoverable,
        recommended_action: String(obj.recommended_action || localized.recommended_action),
        timestamp: typeof obj.timestamp === 'number' ? obj.timestamp : undefined,
      }
    }
    // Canonical backend code is the single source of truth. The feedback module
    // guarantees a non-empty code plus recoverable/recommended_action; this
    // table only supplies a localized label and default action fallback.
    if (typeof obj.code === 'string') {
      const canonical = canonicalizeRawCode(obj.code)
      if (canonical in contractErrorMap) {
        const descriptor = contractErrorMap[canonical]
        return {
          ok: false,
          error_type: descriptor.error_type,
          message: descriptor.message,
          recoverable: obj.recoverable !== undefined ? !!obj.recoverable : descriptor.recoverable,
          recommended_action: String(obj.recommended_action || descriptor.recommended_action),
          timestamp: typeof obj.timestamp === 'number' ? obj.timestamp : Date.now(),
        }
      }
    }
    if (obj.ok === false && obj.message) {
      const localized = localizedRawError(String(obj.message))
      return {
        ok: false,
        error_type: localized.error_type,
        message: localized.message,
        recoverable: localized.recoverable,
        recommended_action: localized.recommended_action,
        timestamp: typeof obj.timestamp === 'number' ? obj.timestamp : undefined,
      }
    }
  }

  const message = raw instanceof Error ? raw.message : raw ? String(raw) : '操作失败，请查看日志。'
  const localized = localizedRawError(message)
  return {
    ok: false,
    error_type: localized.error_type,
    message: localized.message,
    recoverable: localized.recoverable,
    recommended_action: localized.recommended_action,
    timestamp: Date.now(),
  }
}

function summarizeError(message: string) {
  return localizedRawError(message).message
}

function errorMessageText(raw: unknown) {
  if (raw instanceof Error) return raw.message
  if (raw && typeof raw === 'object') {
    const obj = raw as Record<string, unknown>
    if (typeof obj.message === 'string') return obj.message
    if (typeof obj.error === 'string') return obj.error
  }
  return raw ? String(raw) : ''
}

function isTransientHelperStatusRefreshError(raw: unknown) {
  return errorMessageText(raw).includes('Empty response from helper daemon')
}

export const useVpnStore = defineStore('vpn', () => {
  let progressTimer: ReturnType<typeof setInterval> | null = null
  let uptimeTimer: ReturnType<typeof setInterval> | null = null
  let authInteractionPollTimer: ReturnType<typeof setInterval> | null = null
  let connectStatusPollTimer: ReturnType<typeof setInterval> | null = null
  const runtimeStatusPollTimer = ref<ReturnType<typeof setInterval> | null>(null)
  const ui = useUiStore()
  const config = useConfigStore()

  const status = ref<VpnStatus | null>(null)
  const routes = ref<RouteEntry[]>([])
  const logs = ref<LogEntry[]>([])
  const serviceStatus = ref<ServiceStatus | null>(null)
  const cliStatus = ref<CliInstallStatus | null>(null)
  const serviceProgress = ref<ServiceProgressEntry[]>([])
  const upstreamVirtualDisplay = ref<UpstreamVirtualDisplay>({
    detected: false,
    label: '--',
  })
  const serviceBusy = ref(false)
  const serviceOverlayOperation = ref<'install' | 'uninstall' | 'repair' | null>(null)
  const serviceOperation = ref<'install' | 'uninstall' | 'repair' | null>(null)
  const lastServiceOperation = ref<ServiceOperationResult['operation'] | null>(null)
  const cliOperation = ref<'install' | 'uninstall' | null>(null)
  const loading = ref(false)
  const lastError = ref<string | null>(null)
  const lastErrorType = ref<VpnErrorType | null>(null)
  const lastRecoverable = ref(true)
  const lastRecommendedAction = ref('')
  const lastErrorTime = ref<number | null>(null)
  const lastActionWasElevatedConnect = ref(false)
  const lastFailedConnectMode = ref<'helper' | 'elevated' | null>(null)
  const lastMutatingAction = ref<(() => Promise<unknown>) | null>(null)
  const activeTemporaryBackend = ref<unknown | null>(null)
  const connectInFlight = ref(false)
  const dashboardConnectInFlight = ref(false)
  const disconnectInFlight = ref(false)
  const activeConnectMode = ref<'helper' | 'elevated' | null>(null)
  const pendingAuthInteraction = ref<AuthInteraction | null>(null)
  const authInteractionBusy = ref(false)
  const connectionProgressStartedAt = ref<number | null>(null)
  const connectionProgressStageOffset = ref(0)
  const connectionProgressMaxIndex = ref(0)
  const progressTick = ref(0)
  const uptimeBaseSeconds = ref(0)
  const uptimeStartedAt = ref<number | null>(null)
  const uptimeTick = ref(0)
  const connectShouldHideToTray = ref(false)
  const trayHidePending = ref(false)
  const runtimeHadConnectedSession = ref(false)
  const runtimeDisconnectErrorKey = ref<string | null>(null)

  const connectionProgressStages: ConnectionProgressStage[] = [
    {
      key: 'authorization',
      label: '等待授权',
      description: '请在系统弹窗中确认本次提权请求',
      state: 'pending',
      priority: 10,
      visual: 'shield',
      source: 'local',
    },
    {
      key: 'oneshot-helper',
      label: '正在启动临时 helper',
      description: '授权通过后会创建本次连接专用的本地控制通道',
      state: 'pending',
      priority: 20,
      visual: 'helper',
      source: 'local',
    },
    {
      key: 'vpn-server',
      label: '正在连接 VPN 服务器',
      description: '正在启动 VPN 引擎并完成认证握手',
      state: 'pending',
      priority: 30,
      visual: 'server',
      source: 'local',
    },
    {
      key: 'adapter',
      label: '正在创建虚拟网卡',
      description: '正在准备 Wintun/TAP 隧道接口',
      state: 'pending',
      priority: 40,
      visual: 'adapter',
      source: 'local',
    },
    {
      key: 'routes',
      label: '正在写入路由',
      description: '正在配置校园网路由和本机接口地址',
      state: 'pending',
      priority: 50,
      visual: 'routes',
      source: 'local',
    },
    {
      key: 'network-ready',
      label: '等待网络就绪',
      description: '正在确认内网地址、接口和路由已经生效',
      state: 'pending',
      priority: 60,
      visual: 'check',
      source: 'local',
    },
  ]

  const serviceInstalled = computed(() => serviceStatus.value?.installed ?? false)
  const serviceRunning = computed(() => serviceStatus.value?.running ?? false)
  const serviceAvailable = computed(() => serviceStatus.value?.available ?? false)
  const dashboardConnectGuardHeld = computed(() => dashboardConnectInFlight.value)
  const isDesktop = computed(() => typeof window !== 'undefined' && !!window.exv)
  const canUseElevatedFallback = computed(() => {
    const capabilities = serviceStatus.value?.capabilities
    return isDesktop.value && Boolean(
      capabilities?.temporary_connect || capabilities?.oneshot_mode,
    )
  })
  const recommendedConnectMode = computed<ConnectMode>(() => {
    if (serviceAvailable.value) return 'helper'
    if (canUseElevatedFallback.value) return 'elevated'
    return 'helper'
  })
  const currentSessionMode = computed(() => {
    if (!status.value?.connected) return 'disconnected'
    if (status.value.mode) return status.value.mode
    if (activeTemporaryBackend.value || !serviceRunning.value) return 'elevated'
    return 'helper'
  })

  async function showServiceOverlay(operation: 'install' | 'uninstall' | 'repair') {
    serviceOverlayOperation.value = operation
    await nextTick()
    await new Promise<void>((resolve) => {
      if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(() => resolve())
      } else {
        setTimeout(resolve, 0)
      }
    })
  }

  const displayUptimeSeconds = computed(() => {
    void uptimeTick.value
    if (!status.value?.connected || !uptimeStartedAt.value) return 0
    const elapsed = Math.max(0, Math.floor((Date.now() - uptimeStartedAt.value) / 1000))
    return uptimeBaseSeconds.value + elapsed
  })
  const upstreamVirtualDetected = computed(() => upstreamVirtualDisplay.value.detected)
  const upstreamVirtualLabel = computed(() => upstreamVirtualDisplay.value.label)

  function startUptimeTimer() {
    if (uptimeTimer) return
    uptimeTimer = setInterval(() => {
      uptimeTick.value++
    }, 1000)
  }

  function stopUptimeTimer() {
    if (uptimeTimer) {
      clearInterval(uptimeTimer)
      uptimeTimer = null
    }
  }

  function syncUptime(nextStatus: VpnStatus) {
    if (!nextStatus.connected) {
      uptimeBaseSeconds.value = 0
      uptimeStartedAt.value = null
      stopUptimeTimer()
      return
    }

    const reported = Math.max(0, nextStatus.uptime_seconds || 0)
    if (!uptimeStartedAt.value) {
      uptimeBaseSeconds.value = reported
      uptimeStartedAt.value = Date.now()
    } else if (reported > displayUptimeSeconds.value) {
      uptimeBaseSeconds.value = reported
      uptimeStartedAt.value = Date.now()
    }
    startUptimeTimer()
  }

  function normalizedPhase(nextStatus: VpnStatus) {
    return String(nextStatus.phase ?? '').toLowerCase()
  }

  function statusErrorForConnect(nextStatus: VpnStatus) {
    if (nextStatus.last_error) {
      return {
        code: nextStatus.last_error.code || nextStatus.error_code || 'connection_failed',
        message: nextStatus.last_error.message || nextStatus.error || '连接失败，请打开日志查看详细原因后重试。',
        recoverable: nextStatus.last_error.recoverable ?? nextStatus.error_recoverable ?? true,
        recommended_action: nextStatus.last_error.recommended_action,
      }
    }
    if (nextStatus.error_code || nextStatus.error) {
      return {
        code: nextStatus.error_code || 'connection_failed',
        message: nextStatus.error || '连接失败，请打开日志查看详细原因后重试。',
        recoverable: nextStatus.error_recoverable ?? true,
        recommended_action: undefined,
      }
    }
    if (String(nextStatus.phase ?? '').toLowerCase() === 'failed') {
      return {
        code: 'connection_failed',
        message: '连接失败，请打开日志查看详细原因后重试。',
        recoverable: true,
        recommended_action: undefined,
      }
    }
    return null
  }

  function shouldKeepRuntimeStatusMonitoring(nextStatus: VpnStatus) {
    const phase = normalizedPhase(nextStatus)
    return Boolean(
      nextStatus.connected ||
      nextStatus.process_running ||
      phase === 'connected' ||
      phase === 'reconnecting' ||
      phase === 'disconnecting' ||
      phase === 'cleaning_up',
    )
  }

  function statusErrorForRuntimeDisconnect(nextStatus: VpnStatus) {
    if (!runtimeHadConnectedSession.value) return null
    if (nextStatus.connected) return null
    const phase = normalizedPhase(nextStatus)
    if (phase === 'reconnecting') return null
    return statusErrorForConnect(nextStatus)
  }

  function isTerminalConnectStatus(nextStatus: VpnStatus) {
    return Boolean(
      nextStatus.connected ||
      nextStatus.error_code ||
      nextStatus.error ||
      nextStatus.last_error ||
      String(nextStatus.phase ?? '').toLowerCase() === 'failed',
    )
  }

  function isFullStatusSnapshot(data: Partial<VpnStatus>) {
    return typeof data.connected === 'boolean' &&
      typeof data.process_running === 'boolean' &&
      typeof data.phase === 'string'
  }

  function reconcileAuthoritativeStatusEvent(nextStatus: VpnStatus) {
    const phase = normalizedPhase(nextStatus)
    const fullyDisconnected = !nextStatus.connected && !nextStatus.process_running

    if (
      disconnectInFlight.value &&
      (phase === 'idle' || phase === 'failed' || fullyDisconnected)
    ) {
      disconnectInFlight.value = false
      loading.value = false
    }

    const connectTerminal = Boolean(
      nextStatus.connected ||
      phase === 'failed' ||
      nextStatus.error_code ||
      nextStatus.error ||
      nextStatus.last_error ||
      fullyDisconnected,
    )

    if (connectTerminal) {
      stopConnectStatusPolling()
      stopAuthInteractionPolling()
      stopConnectionProgress()
    }

    if (connectInFlight.value && connectTerminal) {
      finishConnectWorkflow()
    }
  }

  function applyStatus(nextStatus: VpnStatus) {
    const previousStatus = status.value
    status.value = nextStatus
    const upstreamDisplay = upstreamVirtualDisplayFromStatus(nextStatus)
    if (upstreamDisplay) {
      upstreamVirtualDisplay.value = upstreamDisplay
    }
    syncUptime(nextStatus)

    if (nextStatus.connected) {
      runtimeHadConnectedSession.value = true
      runtimeDisconnectErrorKey.value = null
      clearError()
    }

    if (connectInFlight.value && isTerminalConnectStatus(nextStatus)) {
      maybeHideToTrayAfterConnect(nextStatus)
      if (!nextStatus.connected) {
        connectShouldHideToTray.value = false
      }
      const terminalError = statusErrorForConnect(nextStatus)
      if (
        !nextStatus.connected &&
        terminalError &&
        terminalError.code !== 'user_cancelled'
      ) {
        lastFailedConnectMode.value = activeConnectMode.value ?? 'helper'
        setError(normalizeError({
          ok: false,
          code: terminalError.code || 'connection_failed',
          message: terminalError.message || '连接失败，请打开日志查看详细原因后重试。',
          recoverable: terminalError.recoverable,
          recommended_action: terminalError.recommended_action,
        }))
      }
      finishConnectWorkflow({ resetTrayHide: false })
    }

    const phase = normalizedPhase(nextStatus)
    if (!connectInFlight.value && runtimeHadConnectedSession.value) {
      const runtimeError = statusErrorForRuntimeDisconnect(nextStatus)
      if (runtimeError && runtimeError.code !== 'user_cancelled') {
        const errorKey = `${runtimeError.code}:${runtimeError.message}`
        if (runtimeDisconnectErrorKey.value !== errorKey) {
          runtimeDisconnectErrorKey.value = errorKey
          setError(normalizeError({
            ok: false,
            code: runtimeError.code || 'connection_failed',
            message: runtimeError.message || '连接已中断，请打开日志查看详细原因后重试。',
            recoverable: runtimeError.recoverable,
            recommended_action: runtimeError.recommended_action,
          }))
        }
      } else if (phase === 'reconnecting') {
        runtimeDisconnectErrorKey.value = null
      }
    }

    if (shouldKeepRuntimeStatusMonitoring(nextStatus)) {
      startRuntimeStatusMonitoring()
    } else if (!previousStatus?.connected) {
      runtimeHadConnectedSession.value = false
      runtimeDisconnectErrorKey.value = null
      stopRuntimeStatusMonitoring()
    }
  }

  function updateStatusFromEvent(partialStatus: Partial<VpnStatus>) {
    const fullSnapshot = isFullStatusSnapshot(partialStatus)
    const nextStatus = status.value
      ? { ...status.value, ...partialStatus }
      : (partialStatus as VpnStatus)
    applyStatus(nextStatus)
    if (fullSnapshot) {
      reconcileAuthoritativeStatusEvent(nextStatus)
    }
  }

  const localConnectionProgressSteps = computed<ConnectionProgressStage[]>(() => {
    void progressTick.value
    let activeStageIndex = 0

    if (connectionProgressStartedAt.value) {
      const elapsed = Date.now() - connectionProgressStartedAt.value
      const elapsedStage = elapsed < 1500
        ? 0
        : elapsed < 3500
          ? 1
          : elapsed < 5500
            ? 2
            : elapsed < 7500
              ? 3
              : elapsed < 9500
                ? 4
                : 5
      activeStageIndex = Math.min(
        connectionProgressStages.length - 1,
        connectionProgressMaxIndex.value,
        connectionProgressStageOffset.value + elapsedStage,
      )
    }

    return connectionProgressStages.map((stage, index) => ({
      ...stage,
      state: index === activeStageIndex ? 'active'
        : index < activeStageIndex ? 'done'
          : 'pending',
      source: 'local',
    }))
  })

  const connectionProgressSteps = computed<ConnectionProgressStage[]>(() => {
    const progress = status.value?.connect_progress
    if (status.value?.connect_progress?.steps?.length && progress) {
      return normalizeBackendConnectionProgressSteps(progress.steps)
    }
    return localConnectionProgressSteps.value
  })

  const connectionProgress = computed<ConnectionProgressStage>(() => {
    return selectConnectionProgressStage(
      connectionProgressSteps.value,
      status.value?.connect_progress?.active_key,
      connectionProgressStages[0],
    )
  })

  const dashboardState = computed<DashboardState>(() => {
    if (lastError.value && lastErrorType.value) {
      if (lastErrorType.value !== 'elevation_required' && lastErrorType.value !== 'service_missing') {
        if (lastErrorType.value === 'runtime_missing') return 'error blocking'
        return lastRecoverable.value ? 'error recoverable' : 'error blocking'
      }
    }

    if (connectInFlight.value) return 'elevated connecting'

    if (status.value?.connected) {
      const mode = currentSessionMode.value
      if (mode === 'helper') return 'helper connected'
      if (mode === 'elevated') return 'elevated connected'
      return 'direct connected'
    }

    if (serviceAvailable.value) return 'service-ready disconnected'
    return 'service-missing disconnected'
  })

  const recoverableErrorAction = computed<DashboardAction | null>(() => {
    switch (lastErrorType.value) {
      case 'elevation_denied':
        return { label: '安装服务', action: () => { void requestInstallService() }, variant: 'primary' }
      case 'config_invalid':
        return { label: '前往设置', action: () => {}, variant: 'primary' }
      case 'auth_failed':
      case 'auth_rejected':
      case 'auth_expired':
        return {
          label: '重新输入用户名和密码',
          action: () => retryConnectAfterAuthFailure(lastFailedConnectMode.value ?? 'helper'),
          variant: 'primary',
        }
      case 'auth_challenge_required':
      case 'auth_group_required':
        return {
          label: '继续',
          action: () => {
            clearError()
            startAuthInteractionPolling()
          },
          variant: 'primary',
        }
      case 'native_failure':
      case 'parse_failure':
        return { label: '重试', action: () => retryLastAction(), variant: 'primary' }
      case 'unsupported_extra_args':
        return { label: '前往设置', action: () => { window.location.hash = '#/settings' }, variant: 'primary' }
      case 'auth_protocol_mismatch':
      case 'csd_required_unsupported':
        return { label: '查看日志', action: () => { window.location.hash = '#/logs' }, variant: 'primary' }
      case 'helper_unavailable':
        return {
          label: '尝试修复服务',
          action: () => { void repairService() },
          variant: 'primary',
        }
      default:
        return { label: '重试', action: () => retryLastAction(), variant: 'primary' }
    }
  })

  const dashboardPrimaryAction = computed<DashboardAction | null>(() => {
    switch (dashboardState.value) {
      case 'service-ready disconnected':
        return { label: '连接', action: () => connect(), variant: 'primary' }
      case 'service-missing disconnected':
        return { label: '安装服务（推荐）', action: () => { void requestInstallService() }, variant: 'primary' }
      case 'helper connected':
        return { label: '断开连接', action: () => disconnect(), variant: 'destructive' }
      case 'direct connected':
      case 'elevated connected':
        return { label: '断开连接', action: () => disconnectElevated(), variant: 'destructive' }
      case 'elevated connecting':
        return null
      case 'error recoverable':
        return recoverableErrorAction.value
      case 'error blocking':
        return { label: '关闭', action: () => clearError(), variant: 'secondary' }
      default:
        return null
    }
  })

  const dashboardSecondaryAction = computed<DashboardAction | null>(() => {
    switch (dashboardState.value) {
      case 'service-missing disconnected':
        return canUseElevatedFallback.value
          ? { label: '仅本次连接', action: () => connectElevated(), variant: 'secondary' }
          : null
      case 'direct connected':
      case 'elevated connected':
        return { label: '安装服务', action: () => { void requestInstallService() }, variant: 'secondary' }
      case 'error recoverable':
        return { label: '关闭', action: () => clearError(), variant: 'secondary' }
      default:
        return null
    }
  })

  function errorPresentation(err: VpnError) {
    switch (err.error_type) {
      case 'auth_protocol_mismatch':
        return {
          title: '认证协议不匹配',
          primaryLabel: '查看日志',
          onPrimary: () => {
            clearError()
            window.location.hash = '#/logs'
          },
        }
      case 'auth_failed':
      case 'auth_rejected':
      case 'auth_expired':
        return {
          title: err.error_type === 'auth_expired' ? '认证已过期' : '认证失败',
          primaryLabel: '重新输入用户名和密码',
          onPrimary: () => retryConnectAfterAuthFailure(lastFailedConnectMode.value ?? 'helper'),
        }
      case 'auth_challenge_required':
      case 'auth_group_required':
        return {
          title: err.error_type === 'auth_group_required' ? '请选择认证组' : '需要继续认证',
          primaryLabel: '继续',
          onPrimary: () => {
            clearError()
            startAuthInteractionPolling()
          },
        }
      case 'csd_required_unsupported':
      case 'cstp_compressed_unsupported':
        return {
          title: err.error_type === 'csd_required_unsupported' ? 'Host-scan 不受支持' : '协议能力不足',
          primaryLabel: '查看日志',
          onPrimary: () => {
            clearError()
            window.location.hash = '#/logs'
          },
        }
      case 'tunnel_disconnected':
      case 'rekey_unsupported':
        return {
          title: '连接已中断',
          primaryLabel: '重试',
          onPrimary: () => retryLastAction(),
        }
      case 'config_invalid':
      case 'unsupported_extra_args':
        return {
          title: err.error_type === 'unsupported_extra_args' ? '参数不支持' : '配置不完整',
          primaryLabel: '前往设置',
          onPrimary: () => {
            clearError()
            window.location.hash = '#/settings'
          },
        }
      case 'runtime_missing':
        return {
          title: '缺少运行时',
          primaryLabel: '打开设置',
          onPrimary: () => {
            clearError()
            window.location.hash = '#/settings#settings-system'
          },
        }
      case 'elevation_denied':
        return {
          title: '授权被拒绝',
          primaryLabel: '重试',
          onPrimary: () => retryLastAction(),
        }
      case 'tls_verify_failed':
        return {
          title: '证书验证失败',
          primaryLabel: '重试',
          onPrimary: () => retryLastAction(),
        }
      case 'wintun_missing':
        return {
          title: '缺少网络驱动',
          primaryLabel: '重试',
          onPrimary: () => retryLastAction(),
        }
      case 'helper_unavailable':
        return {
          title: '辅助服务不可用',
          primaryLabel: '尝试修复服务',
          onPrimary: () => { void repairService() },
        }
      case 'utun_permission_denied':
        return {
          title: '权限不足',
          primaryLabel: '重试',
          onPrimary: () => retryLastAction(),
        }
      case 'unsupported_dtls':
      case 'dtls_unavailable':
        return {
          title: 'DTLS 不可用',
          primaryLabel: '重试',
          onPrimary: () => retryLastAction(),
        }
      case 'session_timeout':
      case 'idle_timeout':
        return {
          title: err.error_type === 'session_timeout' ? '会话已超时' : '连接空闲超时',
          primaryLabel: '重试',
          onPrimary: () => retryLastAction(),
        }
      default:
        return {
          title: err.recoverable ? '操作失败' : '严重错误',
          primaryLabel: err.recoverable ? '重试' : '知道了',
          onPrimary: err.recoverable ? () => retryLastAction() : undefined,
        }
    }
  }

  function setError(err: VpnError) {
    if (err.error_type === 'elevation_cancelled') {
      clearError()
      ui.addToast(err.message || '提权失败：用户已取消授权。', 'warning')
      return
    }
    if (err.error_type === 'elevation_required' || err.error_type === 'service_missing') {
      clearError()
      return
    }
    lastError.value = err.message
    lastErrorType.value = err.error_type
    lastRecoverable.value = err.recoverable
    lastRecommendedAction.value = err.recommended_action
    lastErrorTime.value = Date.now()
    const presentation = errorPresentation(err)
    ui.requestError({
      title: presentation.title,
      message: summarizeError(err.message),
      primaryLabel: presentation.primaryLabel,
      secondaryLabel: err.recoverable ? '取消' : '知道了',
      onPrimary: presentation.onPrimary,
      onClose: () => clearError(),
    })
  }

  function clearError() {
    lastError.value = null
    lastErrorType.value = null
    lastRecoverable.value = true
    lastRecommendedAction.value = ''
    lastErrorTime.value = null
    lastFailedConnectMode.value = null
  }

  function retryLastAction() {
    clearError()
    lastMutatingAction.value?.()
  }

  function startConnectionProgress(stageOffset = 0, maxStageIndex = 2) {
    connectionProgressStageOffset.value = stageOffset
    connectionProgressMaxIndex.value = Math.max(stageOffset, Math.min(connectionProgressStages.length - 1, maxStageIndex))
    connectionProgressStartedAt.value = Date.now()
    progressTick.value++
    if (progressTimer) clearInterval(progressTimer)
    progressTimer = setInterval(() => {
      progressTick.value++
    }, 500)
  }

  function stopConnectionProgress() {
    connectionProgressStartedAt.value = null
    connectionProgressStageOffset.value = 0
    connectionProgressMaxIndex.value = 0
    if (progressTimer) {
      clearInterval(progressTimer)
      progressTimer = null
    }
  }

  function releaseDashboardConnectGuard() {
    dashboardConnectInFlight.value = false
  }

  function finishConnectWorkflow(options: { resetTrayHide?: boolean } = {}) {
    connectInFlight.value = false
    if (options.resetTrayHide ?? true) {
      connectShouldHideToTray.value = false
    }
    activeConnectMode.value = null
    loading.value = false
    stopConnectStatusPolling()
    stopAuthInteractionPolling()
    stopConnectionProgress()
    releaseDashboardConnectGuard()
  }

  function acceptedConnectWorkflowInFlight() {
    return connectInFlight.value && connectStatusPollTimer !== null
  }

  function handleStatusPollFailure(error: unknown) {
    if (isTransientHelperStatusRefreshError(error)) {
      console.warn('[vpn] transient helper status refresh failed:', error)
      return
    }
    console.error('[vpn] fetchStatus failed:', error)
    if (!connectInFlight.value) return

    lastFailedConnectMode.value = activeConnectMode.value ?? 'helper'
    setError(normalizeError(error))
    finishConnectWorkflow()
  }

  async function fetchStatus() {
    try {
      const { data } = await api.get<VpnStatus>('/status')
      const previous = status.value
      const inferredMode = data.mode
        ?? (data.connected && previous?.connected ? previous.mode : undefined)
        ?? (data.connected && (activeTemporaryBackend.value || !serviceRunning.value) ? 'elevated' : undefined)
      applyStatus({
        ...data,
        mode: inferredMode,
        backend: data.backend ?? (data.connected ? activeTemporaryBackend.value ?? previous?.backend : undefined),
      })
      if (data.connected) clearError()
    } catch (e) {
      handleStatusPollFailure(e)
    }
  }

  function withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    onTimeout?: () => void,
  ): Promise<T | undefined> {
    let timer: ReturnType<typeof setTimeout> | null = null
    const timeout = new Promise<undefined>((resolve) => {
      timer = setTimeout(() => {
        timer = null
        onTimeout?.()
        resolve(undefined)
      }, timeoutMs)
    })
    return Promise.race([
      promise.finally(() => {
        if (timer) {
          clearTimeout(timer)
          timer = null
        }
      }),
      timeout,
    ])
  }

  async function fetchServiceStatusWithTimeout() {
    await withTimeout(
      fetchServiceStatus(),
      SERVICE_STATUS_REFRESH_TIMEOUT_MS,
      () => console.warn('[vpn] fetchServiceStatus timed out; continuing UI state refresh'),
    )
  }

  async function fetchAppShellState() {
    await Promise.allSettled([fetchStatus(), fetchServiceStatusWithTimeout()])
  }

  function startConnectStatusPolling() {
    void fetchStatus()
    if (connectStatusPollTimer) return
    connectStatusPollTimer = setInterval(() => {
      void fetchStatus()
    }, 1000)
  }

  function stopConnectStatusPolling() {
    if (connectStatusPollTimer) {
      clearInterval(connectStatusPollTimer)
      connectStatusPollTimer = null
    }
  }

  async function fetchAuthInteraction() {
    try {
      const { data } = await api.get<AuthInteractionPollResponse>('/vpn/auth-interaction')
      pendingAuthInteraction.value = data.pending ? data.interaction ?? null : null
    } catch (e) {
      console.error('[vpn] fetchAuthInteraction failed:', e)
    }
  }

  function startAuthInteractionPolling() {
    void fetchAuthInteraction()
    if (authInteractionPollTimer) return
    authInteractionPollTimer = setInterval(() => {
      void fetchAuthInteraction()
    }, 1000)
  }

  function stopAuthInteractionPolling() {
    if (authInteractionPollTimer) {
      clearInterval(authInteractionPollTimer)
      authInteractionPollTimer = null
    }
    pendingAuthInteraction.value = null
    authInteractionBusy.value = false
  }

  async function respondAuthInteraction(value: string): Promise<boolean> {
    const interaction = pendingAuthInteraction.value
    if (!interaction || authInteractionBusy.value) return false
    authInteractionBusy.value = true
    try {
      await api.post('/vpn/auth-interaction/response', {
        id: interaction.id,
        value,
      })
      pendingAuthInteraction.value = null
      return true
    } catch (error) {
      setError(normalizeError(error))
      return false
    } finally {
      authInteractionBusy.value = false
    }
  }

  async function resolveConnectCredentials(
    message?: string,
    options: { forcePrompt?: boolean } = {},
  ): Promise<{ password?: string } | null> {
    await config.fetchAuthConfig()
    const auth = config.authConfig
    const missingUsername = options.forcePrompt ? true : !auth.username.trim()
    const missingPassword = options.forcePrompt ? true : !(auth.remember_password && auth.password_stored)

    if (!missingUsername && !missingPassword) return {}

    const credentials = await ui.requestCredentials({
      missingUsername,
      missingPassword,
      username: auth.username,
      rememberPassword: auth.remember_password,
      message,
    })
    if (credentials === null) return null

    const nextUsername = credentials.username ?? auth.username
    const nextPassword = credentials.password ?? ''

    await config.saveAuthConfig({
      server: auth.server,
      username: nextUsername,
      user_agent: auth.user_agent,
      remember_password: credentials.rememberPassword,
      password: credentials.rememberPassword ? credentials.password : '',
    })

    if (missingPassword && !credentials.rememberPassword) {
      return { password: nextPassword }
    }
    return {}
  }

  async function retryConnectAfterAuthFailure(mode: 'helper' | 'elevated'): Promise<boolean> {
    const credentials = await resolveConnectCredentials(
      '认证失败，请重新输入用户名和密码',
      { forcePrompt: true },
    )
    if (credentials === null) return false
    clearError()
    const password = credentials.password
    return mode === 'helper' ? connect(password) : connectElevated(password)
  }

  async function connect(providedPassword?: string): Promise<boolean> {
    loading.value = true
    clearError()
    lastActionWasElevatedConnect.value = false
    lastMutatingAction.value = connect
    connectInFlight.value = true
    activeConnectMode.value = 'helper'
    startConnectionProgress(2)
    startAuthInteractionPolling()
    let acceptedByBackend = false
    try {
      const credentials = providedPassword !== undefined
        ? { password: providedPassword }
        : await resolveConnectCredentials()
      if (credentials === null) return false
      connectShouldHideToTray.value = true

      const { data } = await api.post<VpnStatus | VpnConnectAccepted>(
        '/connect',
        credentials.password === undefined ? undefined : { password: credentials.password },
      )
      if (isVpnConnectAccepted(data)) {
        acceptedByBackend = true
        connectInFlight.value = true
        startConnectStatusPolling()
        loading.value = false
        return true
      }
      applyStatus(data)
      await fetchAppShellState()
      return true
    } catch (error) {
      const normalized = normalizeError(error)
      if (isCredentialFailureType(normalized.error_type)) lastFailedConnectMode.value = 'helper'
      setError(normalized)
    } finally {
      if (!acceptedByBackend) {
        finishConnectWorkflow()
      }
      loading.value = false
    }

    return false
  }

  async function cancelConnect(): Promise<boolean> {
    if (!connectInFlight.value) return false
    finishConnectWorkflow()
    disconnectInFlight.value = false
    clearError()

    try {
      const { data } = await api.post<VpnStatus | VpnConnectAccepted | VpnError>('/disconnect')
      if (isVpnError(data)) {
        if (data.error_type !== 'user_cancelled') setError(data)
        return data.error_type === 'user_cancelled'
      }
      if (isVpnConnectAccepted(data)) {
        return true
      }
      applyStatus(data)
      await fetchAppShellState()
      return true
    } catch (error) {
      const normalized = normalizeError(error)
      if (isBenignCancelTransportError(normalized)) return true
      setError(normalized)
      return false
    } finally {
      finishConnectWorkflow()
      disconnectInFlight.value = false
    }
  }

  async function disconnect(): Promise<boolean> {
    if (connectInFlight.value) {
      return cancelConnect()
    }
    loading.value = true
    disconnectInFlight.value = true
    lastActionWasElevatedConnect.value = false
    lastMutatingAction.value = disconnect
    try {
      const { data } = await api.post<VpnStatus>('/disconnect')
      applyStatus(data)
      clearError()
      await fetchAppShellState()
      return true
    } catch (error) {
      setError(normalizeError(error))
      return false
    } finally {
      disconnectInFlight.value = false
      loading.value = false
    }
  }

  async function connectElevated(providedPassword?: string): Promise<boolean> {
    loading.value = true
    clearError()
    lastActionWasElevatedConnect.value = true
    lastMutatingAction.value = connectElevated
    connectInFlight.value = true
    activeConnectMode.value = 'elevated'
    startConnectionProgress(0, 2)
    startAuthInteractionPolling()
    let acceptedByBackend = false
    try {
      const credentials = providedPassword !== undefined
        ? { password: providedPassword }
        : await resolveConnectCredentials()
      if (credentials === null) return false
      connectShouldHideToTray.value = true

      const { data } = await api.post<VpnStatus | VpnConnectAccepted | VpnError>(
        '/connect/elevated',
        credentials.password === undefined ? undefined : { password: credentials.password },
      )
      if (isVpnError(data)) {
        if (isCredentialFailureType(data.error_type)) lastFailedConnectMode.value = 'elevated'
        setError(data)
      } else if (isVpnConnectAccepted(data)) {
        acceptedByBackend = true
        connectInFlight.value = true
        startConnectStatusPolling()
        loading.value = false
        return true
      } else {
        const elevatedStatus = { ...data, mode: data.mode ?? 'elevated' }
        applyStatus(elevatedStatus)
        activeTemporaryBackend.value = elevatedStatus.backend ?? null
        await fetchAppShellState()
        if (status.value?.connected && !status.value.mode) {
          applyStatus({ ...status.value, mode: 'elevated', backend: activeTemporaryBackend.value })
        }
        return true
      }
    } catch (error) {
      const normalized = normalizeError(error)
      if (isCredentialFailureType(normalized.error_type)) lastFailedConnectMode.value = 'elevated'
      setError(normalized)
    } finally {
      lastActionWasElevatedConnect.value = false
      if (!acceptedByBackend) {
        finishConnectWorkflow()
      }
      loading.value = false
    }

    return false
  }

  async function connectFromDashboard(installServiceFirst: boolean) {
    if (dashboardConnectInFlight.value) return
    dashboardConnectInFlight.value = true
    let acceptedConnectHandoff = false
    try {
      if (status.value?.connected) {
        if (currentSessionMode.value === 'helper') {
          await disconnect()
        } else {
          await disconnectElevated()
        }
        return
      }

      if (serviceAvailable.value) {
        const ok = await connect()
        acceptedConnectHandoff = ok && acceptedConnectWorkflowInFlight()
        return
      }

      const shouldInstallService = installServiceFirst && !serviceInstalled.value && !serviceAvailable.value
      if (shouldInstallService) {
        const canContinue = await installServiceForConnection()
        if (!canContinue) return
        await fetchServiceStatus()
        const ok = await connect()
        acceptedConnectHandoff = ok && acceptedConnectWorkflowInFlight()
        return
      }

      if (serviceInstalled.value && !serviceAvailable.value) {
        await repairService()
        await fetchServiceStatus()
        if (serviceAvailable.value) {
          const ok = await connect()
          acceptedConnectHandoff = ok && acceptedConnectWorkflowInFlight()
          return
        }
        if (canUseElevatedFallback.value) {
          ui.addToast('辅助服务暂不可用，将使用一次性助手继续本次连接。', 'warning')
          const ok = await connectElevated()
          acceptedConnectHandoff = ok && acceptedConnectWorkflowInFlight()
          return
        }
        const ok = await connect()
        acceptedConnectHandoff = ok && acceptedConnectWorkflowInFlight()
        return
      }

      const ok = await connectElevated()
      acceptedConnectHandoff = ok && acceptedConnectWorkflowInFlight()
    } finally {
      if (!acceptedConnectHandoff) {
        releaseDashboardConnectGuard()
      }
    }
  }

  async function disconnectElevated(): Promise<boolean> {
    loading.value = true
    disconnectInFlight.value = true
    lastActionWasElevatedConnect.value = false
    lastMutatingAction.value = disconnectElevated
    try {
      const { data } = await api.post<VpnStatus | VpnError>('/disconnect/elevated', {
        backend: activeTemporaryBackend.value,
      })
      if (isVpnError(data)) {
        setError(data)
        return false
      } else {
        applyStatus(data)
        activeTemporaryBackend.value = null
        clearError()
        await fetchAppShellState()
        return true
      }
    } catch (error) {
      setError(normalizeError(error))
      return false
    } finally {
      disconnectInFlight.value = false
      loading.value = false
    }
  }

  function startRuntimeStatusMonitoring() {
    if (runtimeStatusPollTimer.value) return
    runtimeStatusPollTimer.value = setInterval(() => {
      void fetchStatus()
    }, 2500)
  }

  function stopRuntimeStatusMonitoring() {
    if (runtimeStatusPollTimer.value) {
      clearInterval(runtimeStatusPollTimer.value)
      runtimeStatusPollTimer.value = null
    }
  }

  function maybeHideToTrayAfterConnect(nextStatus: VpnStatus) {
    if (!connectShouldHideToTray.value || !nextStatus.connected) return
    connectShouldHideToTray.value = false
    if (!config.settings.minimize_to_tray_on_connect) return
    if (!window.exv?.window?.hideToTray) return
    if (trayHidePending.value) return

    trayHidePending.value = true
    void nextTick(() => {
      trayHidePending.value = false
      void window.exv?.window?.hideToTray?.()
    })
  }

  function activeVpnWorkflow() {
    return serviceOperationNeedsVpnDisconnect()
  }

  function serviceOperationNeedsVpnDisconnect() {
    return Boolean(
      connectInFlight.value ||
      disconnectInFlight.value ||
      status.value?.connected ||
      status.value?.network_ready ||
      serviceDisconnectPhases.has(status.value?.phase || ''),
    )
  }

  async function disconnectForServiceOperation(operation: 'install' | 'uninstall') {
    if (connectInFlight.value) {
      const cancelled = await cancelConnect()
      if (!cancelled) return false
    }

    await fetchStatus()
    if (serviceOperationNeedsVpnDisconnect()) {
      const disconnected = currentSessionMode.value === 'elevated'
        ? await disconnectElevated()
        : await disconnect()
      if (!disconnected) return false
    }

    await fetchStatus()
    if (serviceOperationNeedsVpnDisconnect()) {
      setError({
        ok: false,
        error_type: 'vpn_session_active',
        message: operation === 'install'
          ? 'VPN 连接仍在运行，请先断开连接后再安装辅助服务。'
          : 'VPN 连接仍在运行，请先断开连接后再卸载辅助服务。',
        recoverable: true,
        recommended_action: 'disconnect_first',
        timestamp: Date.now(),
      })
      return false
    }
    return true
  }

  async function installServiceAfterDisconnect() {
    const ready = await disconnectForServiceOperation('install')
    if (!ready) return false
    return installService()
  }

  async function uninstallServiceAfterDisconnect() {
    const ready = await disconnectForServiceOperation('uninstall')
    if (!ready) return false
    return uninstallService()
  }

  function requestInstallService(options: { confirmWhenInactive?: boolean } = {}) {
    const active = activeVpnWorkflow()
    const message = active
      ? '安装服务必须先断开连接。继续后 EXV 会先断开当前 VPN 连接，然后安装服务。'
      : '将安装 VPN 辅助服务。系统可能会请求管理员权限。'
    if (!active && options.confirmWhenInactive === false) {
      return installService()
    }
    return new Promise<boolean>((resolve) => {
      ui.requestConfirm(
        message,
        () => { void installServiceAfterDisconnect().then(resolve) },
        {
          title: '安装辅助服务',
          confirmLabel: '继续安装',
          cancelLabel: '取消',
          variant: 'primary',
          onCancel: () => resolve(false),
        },
      )
    })
  }

  async function installServiceForConnection(): Promise<boolean> {
    const installed = await requestInstallService({ confirmWhenInactive: false })
    await fetchServiceStatus()
    if (installed) return true

    const operation = lastServiceOperation.value
    const canContinueAfterDegradedInstall =
      operation?.connect_can_continue ||
      (operation?.service_installed && operation.service_available === false) ||
      (serviceStatus.value?.installed && !serviceStatus.value?.available)
    if (canContinueAfterDegradedInstall) {
      ui.addToast('辅助服务已安装但暂不可用，将使用一次性助手继续本次连接。', 'warning')
      return true
    }
    return false
  }

  function requestUninstallService() {
    const message = activeVpnWorkflow()
      ? '卸载服务必须先断开连接。继续后 EXV 会先断开当前 VPN 连接，然后卸载服务。'
      : '将卸载 VPN 辅助服务。系统可能会请求管理员权限。'
    return new Promise<boolean>((resolve) => {
      ui.requestConfirm(
        message,
        () => { void uninstallServiceAfterDisconnect().then(resolve) },
        {
          title: '卸载辅助服务',
          confirmLabel: '继续卸载',
          cancelLabel: '取消',
          variant: 'destructive',
          onCancel: () => resolve(false),
        },
      )
    })
  }

  function rejectActiveVpnForServiceUninstall() {
    if (!status.value?.connected) return false
    setError({
      ok: false,
      error_type: 'native_failure',
      message: 'VPN 连接已建立，请先断开连接再卸载 helper 服务。',
      recoverable: true,
      recommended_action: 'disconnect_first',
      timestamp: Date.now(),
    })
    return true
  }

  async function fetchRoutes() {
    try {
      const { data } = await api.get<RouteEntry[]>('/routes')
      routes.value = data
    } catch (e) {
      console.error('[vpn] fetchRoutes failed:', e)
    }
  }

  async function addRoute(cidr: string) {
    const { data } = await api.post<RouteEntry[]>('/routes', { cidr })
    routes.value = data
  }

  async function removeRoute(cidr: string) {
    const { data } = await api.delete<RouteEntry[]>('/routes', { data: { cidr } })
    routes.value = data
  }

  async function resetRoutes() {
    const { data } = await api.post<RouteEntry[]>('/routes/reset')
    routes.value = data
  }

  async function fetchServiceStatus() {
    try {
      const { data } = await api.get<ServiceStatus>('/service')
      serviceStatus.value = data
    } catch (e) {
      console.error('[vpn] fetchServiceStatus failed:', e)
    }
  }

  async function fetchCliStatus() {
    try {
      const { data } = await api.get<CliInstallStatus>('/cli')
      cliStatus.value = data
    } catch (e) {
      console.error('[vpn] fetchCliStatus failed:', e)
    }
  }

  function applyServiceOperationResult(
    command: ServiceOperationCommand,
    data: ServiceStatus | ServiceOperationResult,
  ) {
    lastServiceOperation.value = serviceOperationEnvelope(data) ?? null
    const nextStatus = serviceStatusFromOperationResult(data)
    serviceStatus.value = nextStatus
    if (nextStatus.warning || !nextStatus.available) {
      // The elevated helper may have launched successfully while SCM state is
      // still converging; classify the result below instead of throwing here.
    }
    const outcome = serviceOperationOutcome(command, data, nextStatus)
    const message = serviceOperationMessage(command, outcome, data, nextStatus)
    serviceStatus.value = outcome === 'completed'
      ? { ...nextStatus, operation_state: outcome }
      : { ...nextStatus, operation_state: outcome, warning: message }
    return outcome
  }

  async function installService() {
    await showServiceOverlay('install')
    try {
      serviceBusy.value = true
      serviceOperation.value = 'install'
      serviceProgress.value = []
      clearError()
      lastServiceOperation.value = null
      lastMutatingAction.value = installService
      try {
        const { data } = await api.post<ServiceStatus | ServiceOperationResult>('/service/install')
        const outcome = applyServiceOperationResult('install', data)
        await fetchAppShellState()
        return outcome === 'completed'
      } catch (error) {
        setError(normalizeError(error))
        return false
      } finally {
        serviceOperation.value = null
        serviceBusy.value = false
      }
    } finally {
      serviceOverlayOperation.value = null
    }
  }

  async function uninstallService() {
    await showServiceOverlay('uninstall')
    try {
      if (rejectActiveVpnForServiceUninstall()) return false
      serviceBusy.value = true
      serviceOperation.value = 'uninstall'
      serviceProgress.value = []
      clearError()
      lastMutatingAction.value = uninstallService
      try {
        const { data } = await api.post<ServiceStatus | ServiceOperationResult>('/service/uninstall')
        const outcome = applyServiceOperationResult('uninstall', data)
        await fetchAppShellState()
        return outcome === 'completed'
      } catch (error) {
        setError(normalizeError(error))
        return false
      } finally {
        serviceOperation.value = null
        serviceBusy.value = false
      }
    } finally {
      serviceOverlayOperation.value = null
    }
  }

  async function disconnectAndUninstallService() {
    return uninstallServiceAfterDisconnect()
  }

  async function repairService() {
    await showServiceOverlay('repair')
    try {
      serviceBusy.value = true
      serviceOperation.value = 'repair'
      serviceProgress.value = []
      clearError()
      lastMutatingAction.value = repairService
      try {
        const { data } = await api.post<ServiceStatus | ServiceOperationResult>('/service/repair')
        const outcome = applyServiceOperationResult('repair', data)
        await fetchAppShellState()
        return outcome === 'completed'
      } catch (error) {
        setError(normalizeError(error))
        return false
      } finally {
        serviceOperation.value = null
        serviceBusy.value = false
      }
    } finally {
      serviceOverlayOperation.value = null
    }
  }

  async function installCli() {
    cliOperation.value = 'install'
    clearError()
    try {
      const { data } = await api.post<CliInstallStatus>('/cli/install')
      cliStatus.value = data
      return true
    } catch (error) {
      setError(normalizeError(error))
      return false
    } finally {
      cliOperation.value = null
    }
  }

  async function uninstallCli() {
    cliOperation.value = 'uninstall'
    clearError()
    try {
      const { data } = await api.post<CliInstallStatus>('/cli/uninstall')
      cliStatus.value = data
      return true
    } catch (error) {
      setError(normalizeError(error))
      return false
    } finally {
      cliOperation.value = null
    }
  }

  function addServiceProgress(entry: ServiceProgressEntry) {
    serviceProgress.value.push(entry)
    if (serviceProgress.value.length > 200) {
      serviceProgress.value = serviceProgress.value.slice(-200)
    }
  }

  function addLog(entry: LogEntry) {
    logs.value.push(entry)
    if (logs.value.length > 1000) logs.value = logs.value.slice(-1000)
  }

  function clearLogs() {
    logs.value = []
  }

  function setLogs(entries: LogEntry[]) {
    logs.value = entries
  }

  return {
    status, loading, routes, logs, serviceStatus, cliStatus, serviceProgress, serviceBusy,
    serviceOverlayOperation,
    serviceOperation, cliOperation,
    lastError, lastErrorType, lastRecoverable, lastRecommendedAction, lastErrorTime,
    serviceInstalled, serviceRunning, serviceAvailable, canUseElevatedFallback,
    recommendedConnectMode, currentSessionMode, displayUptimeSeconds,
    upstreamVirtualDetected, upstreamVirtualLabel,
    connectInFlight, dashboardConnectGuardHeld, disconnectInFlight,
    pendingAuthInteraction, authInteractionBusy,
    connectionProgress, connectionProgressSteps,
    isDesktop, dashboardState, dashboardPrimaryAction, dashboardSecondaryAction,
    fetchStatus, fetchAppShellState, updateStatusFromEvent, connect, disconnect, cancelConnect, connectElevated, disconnectElevated, connectFromDashboard,
    fetchAuthInteraction, respondAuthInteraction,
    fetchRoutes, addRoute, removeRoute, resetRoutes,
    fetchServiceStatus, fetchCliStatus, installService, uninstallService, requestInstallService, requestUninstallService, disconnectAndUninstallService, repairService, installCli, uninstallCli,
    addLog, clearLogs, setLogs, addServiceProgress, clearError, retryLastAction,
  }
})
