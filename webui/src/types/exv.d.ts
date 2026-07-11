import type {
  DesktopDriverInstallTarget,
  DesktopEventType,
  DesktopModalPayload,
  DesktopServiceInstallPromptResult,
  DesktopWindowMode,
} from '../../host/shared/host-contract'
import type {
  AuthConfig,
  DriverStatus,
  KeyStatus,
  RuntimeStatus,
  SettingsConfig,
} from '../stores/config'
import type {
  CliInstallStatus,
  LogEntry,
  RouteEntry,
  ServiceStatus,
  ServiceOperationResult,
  ServiceProgressEntry,
  AuthInteractionPollResponse,
  VpnStatus,
} from '../stores/vpn'

export interface QuickStartRequestEvent {
  reason: 'missing' | 'invalid'
  defaults: {
    server: string
    remember_password: boolean
    install_service: boolean
  }
}

export type DesktopWindowControl = 'minimize' | 'close'
export type DesktopCloseChoice = 'smart' | 'tray' | 'quit'

export interface WindowControlStateEvent {
  control: DesktopWindowControl | null
  pressed: boolean
}

export interface ExvEvent {
  type: DesktopEventType | 'window-control-state'
  data: unknown | ServiceProgressEntry | QuickStartRequestEvent | WindowControlStateEvent
}

export interface DesktopWindowDragStart {
  screenX: number
  screenY: number
  clientX: number
  clientY: number
  viewWidth: number
}

export type VpnErrorType =
  | 'elevation_required'
  | 'elevation_cancelled'
  | 'elevation_denied'
  | 'runtime_missing'
  | 'config_invalid'
  | 'service_missing'
  | 'auth_protocol_mismatch'
  | 'auth_failed'
  | 'auth_rejected'
  | 'auth_challenge_required'
  | 'auth_group_required'
  | 'auth_expired'
  | 'csd_required_unsupported'
  | 'tls_verify_failed'
  | 'wintun_missing'
  | 'utun_permission_denied'
  | 'dtls_unavailable'
  | 'unsupported_dtls'
  | 'session_timeout'
  | 'idle_timeout'
  | 'unsupported_extra_args'
  | 'permission_denied'
  | 'helper_unavailable'
  | 'network_unreachable'
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

export type ConnectMode = 'helper' | 'elevated' | 'direct'

export interface ExvApi {
  status: {
    get(): Promise<VpnStatus>
  }
  vpn: {
    connect(password?: string): Promise<VpnStatus | VpnConnectAccepted>
    disconnect(): Promise<VpnStatus | VpnConnectAccepted>
    connectElevated(password?: string): Promise<VpnStatus | VpnConnectAccepted | VpnError>
    disconnectElevated(backend?: unknown): Promise<VpnStatus | VpnError>
    authInteraction(): Promise<AuthInteractionPollResponse>
    respondAuthInteraction(id: string, value: string): Promise<{ ok: true }>
  }
  config: {
    getAuth(): Promise<AuthConfig>
    saveAuth(input: Partial<AuthConfig>): Promise<AuthConfig>
    getSettings(): Promise<SettingsConfig>
    saveSettings(input: Partial<SettingsConfig>): Promise<SettingsConfig>
    getKey(): Promise<KeyStatus>
    importConfig(input: { format: 'protected' | 'unprotected'; data: string; password?: string }): Promise<{ ok: true }>
    exportConfig(input: { protected: boolean; password?: string }): Promise<{ format: 'protected' | 'unprotected'; data: string }>
    reset(confirm: boolean): Promise<{ ok: true }>
  }
  key: {
    reset(confirm: boolean): Promise<{ ok: true }>
  }
  maintenance: {
    inspectCore(): Promise<{ state: string; risk: 'unknown' | 'low' | 'medium' | 'high'; pid?: number; ipc_path?: string }>
    killStaleCore(confirm: boolean): Promise<{ ok: true }>
  }
  routes: {
    list(): Promise<RouteEntry[]>
    add(cidr: string): Promise<RouteEntry[]>
    remove(cidr: string): Promise<RouteEntry[]>
    reset(): Promise<RouteEntry[]>
  }
  service: {
    status(): Promise<ServiceStatus>
    install(): Promise<ServiceStatus | ServiceOperationResult>
    uninstall(): Promise<ServiceStatus | ServiceOperationResult>
    repair(): Promise<ServiceStatus | ServiceOperationResult>
  }
  cli: {
    status(): Promise<CliInstallStatus>
    install(): Promise<CliInstallStatus>
    uninstall(): Promise<CliInstallStatus>
  }
  logs: {
    list(options?: { lines?: number; limit?: number; after_seq?: number; filter?: string }): Promise<LogEntry[]>
  }
  runtime: {
    status(): Promise<RuntimeStatus>
  }
  drivers: {
    status(): Promise<DriverStatus>
    install(driver: DesktopDriverInstallTarget): Promise<DriverStatus>
  }
  window: {
    setMode(mode: DesktopWindowMode, request?: number): Promise<{ ok: true; mode: DesktopWindowMode }>
    resizeForMode(mode: DesktopWindowMode, request?: number): Promise<{ ok: true; mode: DesktopWindowMode }>
    minimize(): Promise<{ ok: true }>
    hideToTray(): Promise<{ ok: true }>
    requestClose(): Promise<{ ok: true }>
    resolveClosePrompt(result: unknown): Promise<{ ok: true }>
    getClosePreference(): Promise<{ action: DesktopCloseChoice | null }>
    setClosePreference(action: DesktopCloseChoice): Promise<{ ok: true; action: DesktopCloseChoice }>
    resetClosePreference(): Promise<{ ok: true }>
    startDrag(start?: DesktopWindowDragStart): Promise<{ ok: true }>
  }
  shell: {
    openExternal(url: string): Promise<{ ok: true }>
    notify?(payload: { title: string; body: string }): Promise<{ ok: true }>
  }
  modal: {
    serviceInstallPrompt(): Promise<DesktopServiceInstallPromptResult>
    passwordPrompt(message: string): Promise<string | null>
    confirmPrompt(message: string): Promise<boolean>
    getPayload(): Promise<DesktopModalPayload | null>
    resolve(result: unknown): Promise<{ ok: true }>
  }
  events: {
    subscribe(handler: (event: ExvEvent) => void): () => void
  }
  core: {
    restart(): Promise<{ ok: true }>
    quit(): Promise<{ ok: true }>
  }
}

declare global {
  interface Window {
    exv?: ExvApi
  }
}
