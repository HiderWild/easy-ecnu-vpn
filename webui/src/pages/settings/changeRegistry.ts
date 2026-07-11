import type { AuthConfig, SettingsConfig } from '../../stores/config'

type DraftGroup = 'auth' | 'settings'
type BackendGroup = 'auth' | 'settings'

export type SettingChangeKey =
  | 'auth.server'
  | 'auth.username'
  | 'auth.password'
  | 'auth.remember_password'
  | 'auth.user_agent'
  | 'settings.mtu'
  | 'settings.dtls'
  | 'settings.dtls_mode'
  | 'settings.auto_reconnect'
  | 'settings.retry_limit'
  | 'settings.log_path'
  | 'settings.extra_args'
  | 'settings.windows_tunnel_driver'
  | 'settings.windows_tap_interface'
  | 'settings.include_class_a_private_routes'
  | 'settings.include_class_b_private_routes'
  | 'settings.launch_at_login'
  | 'settings.auto_connect_on_launch'
  | 'settings.silent_startup'
  | 'settings.connection_state_notifications'
  | 'settings.minimize_to_tray_on_connect'

interface FieldDescriptor<
  TKey extends SettingChangeKey,
  TGroup extends DraftGroup,
  TField extends string,
> {
  key: TKey
  label: string
  group: TGroup
  field: TField
}

type BackendFieldDescriptor = FieldDescriptor<SettingChangeKey, 'auth' | 'settings', string> & {
  backendGroup: BackendGroup
  backendField: keyof AuthConfig | keyof SettingsConfig
}

export const frontendToBackendFieldMap = {
  'auth.server': {
    key: 'auth.server',
    label: 'VPN 服务器',
    group: 'auth',
    field: 'server',
    backendGroup: 'auth',
    backendField: 'server',
  },
  'auth.username': {
    key: 'auth.username',
    label: '用户名',
    group: 'auth',
    field: 'username',
    backendGroup: 'auth',
    backendField: 'username',
  },
  'auth.password': {
    key: 'auth.password',
    label: '密码',
    group: 'auth',
    field: 'password',
    backendGroup: 'auth',
    backendField: 'password',
  },
  'auth.remember_password': {
    key: 'auth.remember_password',
    label: '记住密码',
    group: 'auth',
    field: 'remember_password',
    backendGroup: 'auth',
    backendField: 'remember_password',
  },
  'auth.user_agent': {
    key: 'auth.user_agent',
    label: '客户端标识',
    group: 'auth',
    field: 'user_agent',
    backendGroup: 'auth',
    backendField: 'user_agent',
  },
  'settings.mtu': {
    key: 'settings.mtu',
    label: 'MTU',
    group: 'settings',
    field: 'mtu',
    backendGroup: 'settings',
    backendField: 'mtu',
  },
  'settings.dtls': {
    key: 'settings.dtls',
    label: 'DTLS',
    group: 'settings',
    field: 'dtls',
    backendGroup: 'settings',
    backendField: 'dtls',
  },
  'settings.auto_reconnect': {
    key: 'settings.auto_reconnect',
    label: '断线重连',
    group: 'settings',
    field: 'auto_reconnect',
    backendGroup: 'settings',
    backendField: 'auto_reconnect',
  },
  'settings.retry_limit': {
    key: 'settings.retry_limit',
    label: '重连尝试次数',
    group: 'settings',
    field: 'retry_limit',
    backendGroup: 'settings',
    backendField: 'retry_limit',
  },
  'settings.log_path': {
    key: 'settings.log_path',
    label: '日志文件路径',
    group: 'settings',
    field: 'log_path',
    backendGroup: 'settings',
    backendField: 'log_path',
  },
  'settings.extra_args': {
    key: 'settings.extra_args',
    label: '额外参数',
    group: 'settings',
    field: 'extra_args',
    backendGroup: 'settings',
    backendField: 'extra_args',
  },
  'settings.windows_tunnel_driver': {
    key: 'settings.windows_tunnel_driver',
    label: 'Windows 隧道驱动',
    group: 'settings',
    field: 'windows_tunnel_driver',
    backendGroup: 'settings',
    backendField: 'windows_tunnel_driver',
  },
  'settings.windows_tap_interface': {
    key: 'settings.windows_tap_interface',
    label: 'TAP 接口',
    group: 'settings',
    field: 'windows_tap_interface',
    backendGroup: 'settings',
    backendField: 'windows_tap_interface',
  },
  'settings.include_class_a_private_routes': {
    key: 'settings.include_class_a_private_routes',
    label: '处理所有 A 类内网地址',
    group: 'settings',
    field: 'include_class_a_private_routes',
    backendGroup: 'settings',
    backendField: 'include_class_a_private_routes',
  },
  'settings.include_class_b_private_routes': {
    key: 'settings.include_class_b_private_routes',
    label: '处理所有 B 类内网地址',
    group: 'settings',
    field: 'include_class_b_private_routes',
    backendGroup: 'settings',
    backendField: 'include_class_b_private_routes',
  },
  'settings.launch_at_login': {
    key: 'settings.launch_at_login',
    label: '开机自启',
    group: 'settings',
    field: 'launch_at_login',
    backendGroup: 'settings',
    backendField: 'launch_at_login',
  },
  'settings.auto_connect_on_launch': {
    key: 'settings.auto_connect_on_launch',
    label: '启动时自动连接',
    group: 'settings',
    field: 'auto_connect_on_launch',
    backendGroup: 'settings',
    backendField: 'auto_connect_on_launch',
  },
  'settings.silent_startup': {
    key: 'settings.silent_startup',
    label: '静默启动',
    group: 'settings',
    field: 'silent_startup',
    backendGroup: 'settings',
    backendField: 'silent_startup',
  },
  'settings.connection_state_notifications': {
    key: 'settings.connection_state_notifications',
    label: '连接状态系统通知',
    group: 'settings',
    field: 'connection_state_notifications',
    backendGroup: 'settings',
    backendField: 'connection_state_notifications',
  },
} as const satisfies Record<string, BackendFieldDescriptor>

type FrontendOnlyFieldDescriptor = FieldDescriptor<SettingChangeKey, 'settings', string>

export const frontendOnlySettingsFields = {
  'settings.dtls_mode': {
    key: 'settings.dtls_mode',
    label: 'DTLS 模式',
    group: 'settings',
    field: 'dtls_mode',
  },
  'settings.minimize_to_tray_on_connect': {
    key: 'settings.minimize_to_tray_on_connect',
    label: '连接后缩小到托盘区',
    group: 'settings',
    field: 'minimize_to_tray_on_connect',
  },
} as const satisfies Record<string, FrontendOnlyFieldDescriptor>

export const settingFieldRegistry = {
  ...frontendToBackendFieldMap,
  ...frontendOnlySettingsFields,
}

export const settingChangeKeys = Object.keys(settingFieldRegistry) as SettingChangeKey[]

export function formatSettingValue(key: SettingChangeKey, value: unknown) {
  if (key === 'auth.password') return value ? '已输入新密码' : '留空'
  if (key === 'settings.dtls_mode') {
    if (value === 'auto') return '自动'
    if (value === 'enabled') return '开启'
    if (value === 'disabled') return '关闭'
  }
  if (typeof value === 'boolean') return value ? '开启' : '关闭'
  const text = value == null ? '' : String(value)
  return text.trim() ? text : '空'
}
