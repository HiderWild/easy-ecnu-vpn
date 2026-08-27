import type { UnlistenFn } from "@tauri-apps/api/event";
import type { InjectionKey } from "vue";

import { kernel, onLogs, type LogChunk, type LogEvent, type LogsClearReply } from "../lib/ipc";

export interface LogsGateway {
  logsList(afterSeq: number, limit: number): Promise<LogChunk>;
  logsClear(): Promise<LogsClearReply>;
  onLogs(callback: (entry: LogEvent) => void): Promise<UnlistenFn>;
}

/** 应用入口在预览模式下可注入内存日志；生产页面仍默认连接真实 core。 */
export const LOGS_GATEWAY_KEY: InjectionKey<LogsGateway> = Symbol("exv.product.logs-gateway");

/** 生产页面唯一可用的日志读取与未来事件 seam。 */
export function createLogsGateway(): LogsGateway {
  return {
    logsList: (afterSeq, limit) => kernel.logsList(afterSeq, limit),
    logsClear: () => kernel.logsClear(),
    onLogs,
  };
}
