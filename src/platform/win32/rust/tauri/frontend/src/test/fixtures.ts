import type {
  ConnectPhase,
  RuntimeSnapshot,
  RuntimeState,
  RuntimeStats,
} from "../lib/ipc";

const BASE_STATS: RuntimeStats = {
  rx_bytes: 4_096,
  tx_bytes: 2_048,
  rx_rate_bps: 2_048,
  tx_rate_bps: 1_024,
  latency_ms: 24,
  phase: "connected",
  engine_sequence: 1,
  sample_tick: 1,
};

function snapshot(runtime: RuntimeState, overrides: Partial<RuntimeSnapshot> = {}): RuntimeSnapshot {
  return {
    runtime,
    monotonic_tick: 1,
    stats: null,
    proxy_tun: null,
    operation_id: null,
    service_status: null,
    mode: "auto",
    ...overrides,
  };
}

export function snapshotIdle(overrides: Partial<RuntimeSnapshot> = {}): RuntimeSnapshot {
  return snapshot({ state: "idle", last_cleanup_at_ms: null }, overrides);
}

export function snapshotConnecting(phase: ConnectPhase): RuntimeSnapshot {
  return snapshot({
    state: "connecting",
    phase,
    attempt_id: "attempt-1",
    phase_index: 0,
  });
}

export function snapshotAwaitingInteraction(): RuntimeSnapshot {
  return snapshot({
    state: "awaiting_interaction",
    attempt_id: "attempt-1",
    prompt_deadline_ms: null,
  });
}

export function snapshotConnected(
  stats: Partial<RuntimeStats> = {},
  overrides: Partial<RuntimeSnapshot> = {},
): RuntimeSnapshot {
  return snapshot(
    {
      state: "connected",
      session_established_at_ms: 1_000,
      summary: null,
    },
    {
      stats: { ...BASE_STATS, ...stats },
      ...overrides,
    },
  );
}

export function snapshotStopping(): RuntimeSnapshot {
  return snapshot({ state: "stopping", reason: null });
}

export function snapshotReconciling(): RuntimeSnapshot {
  return snapshot({
    state: "reconciling",
    blocking_error: { code: "ERROR_CODE_OBSERVED_CONFLICT", message: "" },
  });
}

export function snapshotFailedClean(): RuntimeSnapshot {
  return snapshot({
    state: "failed_clean",
    error: { code: "ERROR_CODE_DEADLINE_EXCEEDED", message: "" },
  });
}

export function snapshotFailedDirty(): RuntimeSnapshot {
  return snapshot({
    state: "failed_dirty",
    error: { code: "ERROR_CODE_EFFECT_UNKNOWN", message: "" },
    has_obligation: true,
  });
}

export function snapshotUnauthorized(): RuntimeSnapshot {
  return snapshot({
    state: "failed_clean",
    error: { code: "ERROR_CODE_UNAUTHORIZED", message: "" },
  });
}
