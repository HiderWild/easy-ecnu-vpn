/**
 * 只格式化已验证的运行时数据。null 表示界面必须隐藏该值，不能以 0 或占位数值冒充真实样本。
 */
function isNonNegativeFinite(value: number | null | undefined): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function compactNumber(value: number): string {
  return String(Math.round(value * 100) / 100);
}

export function formatBytes(bytes: number | null | undefined): string | null {
  if (!isNonNegativeFinite(bytes)) return null;

  const units = ["B", "KB", "MB", "GB", "TB"];
  let unitIndex = 0;
  let displayed = bytes;

  while (displayed >= 1024 && unitIndex < units.length - 1) {
    displayed /= 1024;
    unitIndex += 1;
  }

  return `${compactNumber(displayed)} ${units[unitIndex]}`;
}

export function formatRate(bytesPerSecond: number | null | undefined): string | null {
  const formatted = formatBytes(bytesPerSecond);
  return formatted === null ? null : `${formatted}/s`;
}

/** Rust 合同约定 0 表示未知，不能展示为 0 ms。 */
export function formatLatency(milliseconds: number | null | undefined): string | null {
  if (typeof milliseconds !== "number" || !Number.isFinite(milliseconds) || milliseconds <= 0) {
    return null;
  }

  return `${compactNumber(milliseconds)} ms`;
}

/** 返回 null 表示会话起点或当前时钟不可用，不能伪造在线时长。 */
export function formatOnlineDuration(
  sessionEstablishedAtMs: number | null | undefined,
  nowMs: number,
): string | null {
  if (
    typeof sessionEstablishedAtMs !== "number" ||
    !Number.isFinite(sessionEstablishedAtMs) ||
    typeof nowMs !== "number" ||
    !Number.isFinite(nowMs) ||
    sessionEstablishedAtMs < 0 ||
    nowMs < 0
  ) {
    return null;
  }

  const elapsedMs = nowMs - sessionEstablishedAtMs;
  if (elapsedMs < 0) return null;

  const totalSeconds = Math.floor(elapsedMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  return [hours, minutes, seconds].map((part) => String(part).padStart(2, "0")).join(":");
}

export function hasUsableConnectedSample(
  sample: RuntimeStats | null | undefined,
): sample is RuntimeStats {
  if (sample === null || sample === undefined || sample.phase !== "connected") return false;

  // `snapshot.stats` 本身就是 host 附加的最新统计样本。engine_sequence/sample_tick
  // 仅用于引擎或事件顺序，不能被 UI 用来推断用户状态或隐藏已附加的真实统计。
  return [
    sample.rx_bytes,
    sample.tx_bytes,
    sample.rx_rate_bps,
    sample.tx_rate_bps,
  ].every((value) => isNonNegativeFinite(value));
}
import type { RuntimeStats } from "../lib/ipc";
