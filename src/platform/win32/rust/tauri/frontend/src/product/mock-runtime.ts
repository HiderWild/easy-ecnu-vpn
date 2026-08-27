import { ref, type Ref } from "vue";

import type { RuntimeSnapshot, ServiceControlAction, ServiceControlReply } from "../lib/ipc";
import { present } from "./presenter";
import type { ProductRuntime } from "./runtime";
import type { ProductStatus, ProductUiState } from "./types";

export type RuntimeSource = "real" | "mock";

/** 预览只能由开发环境中的明确 query 启用，生产地址永远保持真实数据源。 */
export function selectRuntimeSource(dev: boolean, search: string): RuntimeSource {
  return dev && new URLSearchParams(search).get("preview") === "1" ? "mock" : "real";
}

function mockSnapshot(status: ProductStatus, nowMs: number): RuntimeSnapshot {
  const base = {
    monotonic_tick: 1,
    operation_id: null,
    proxy_tun: null,
    service_status: null,
    mode: "auto",
    reconnect: status === "connected"
      ? { auto_reconnect: true, max_attempts: 3, current_attempt: 0, active: false }
      : null,
  };

  switch (status) {
    case "connecting":
      return {
        ...base,
        runtime: { state: "connecting", phase: "connecting_control", phase_index: 2 },
        stats: null,
      };
    case "awaiting":
      return {
        ...base,
        runtime: { state: "awaiting_interaction", prompt_deadline_ms: null },
        stats: null,
      };
    case "connected":
      return {
        ...base,
        runtime: { state: "connected", session_established_at_ms: nowMs - 61_000, summary: null },
        stats: {
          rx_bytes: 4_096,
          tx_bytes: 2_048,
          rx_rate_bps: 2_048,
          tx_rate_bps: 1_024,
          latency_ms: 24,
          phase: "connected",
          engine_sequence: 1,
          sample_tick: 1,
        },
      };
    case "stopping":
      return { ...base, runtime: { state: "stopping", reason: null }, stats: null };
    case "reconciling":
      return {
        ...base,
        runtime: {
          state: "reconciling",
          blocking_error: { code: "ERROR_CODE_OBSERVED_CONFLICT", message: "" },
        },
        stats: null,
      };
    case "failed":
      return {
        ...base,
        runtime: { state: "failed_clean", error: { code: "ERROR_CODE_DEADLINE_EXCEEDED", message: "" } },
        stats: null,
      };
    case "idle":
    default:
      return { ...base, runtime: { state: "idle", last_cleanup_at_ms: null }, stats: null };
  }
}

/**
 * 浏览器预览专用的同构运行时。它不导入 Tauri API，也不假称真实业务数据。
 * `source: 'mock'` 由 main.ts 的开发预览标识显式呈现给设计验收者。
 */
export function createMockRuntime(
  initialStatus: ProductStatus = "idle",
  now: () => number = Date.now,
): ProductRuntime {
  let currentSnapshot = mockSnapshot(initialStatus, now());
  const previewInfo = {
    account: "preview-user",
    vpnServer: "vpn.preview.example",
    campusIp: "10.88.88.5",
  } as const;
  const state: Ref<ProductUiState> = ref(present(currentSnapshot, now(), previewInfo));

  function setStatus(status: ProductStatus): void {
    currentSnapshot = mockSnapshot(status, now());
    state.value = present(currentSnapshot, now(), previewInfo);
  }

  return {
    source: "mock",
    state,
    async start(): Promise<void> {},
    async connect(): Promise<void> {
      setStatus("connecting");
    },
    async stop(): Promise<void> {
      setStatus("idle");
    },
    async triggerLatencyRefresh(): Promise<void> {
      // 模拟运行时不制造虚假延迟样本；保持现有快照（延迟经真实 snapshot 到达）。
    },
    async serviceControl(_action: ServiceControlAction): Promise<ServiceControlReply> {
      // 模拟模式不伪装真实 SCM 操作；返回占位 reply（界面明确「模拟」）。
      return { service_status: null, ok: false, message: "模拟模式不执行真实服务控制。" };
    },
    dispose(): void {},
  };
}
