import type { LogEvent } from "../lib/ipc";
import type { CoreConfigGateway, CoreConfigKey } from "./core-config";
import type { LogsGateway } from "./logs";

const previewConfig: ReadonlyArray<{ key: CoreConfigKey; value: string }> = [
  { key: "server", value: "vpn.preview.example" },
  { key: "username", value: "preview-user" },
  { key: "remember_password", value: "false" },
  { key: "routes", value: "10.0.0.0/8,172.16.0.0/12" },
  { key: "user_agent", value: "EXV Tauri Preview" },
  { key: "mtu", value: "1420" },
];

/**
 * 仅供开发预览使用的内存配置。生产入口不会创建它，也不会写入本机或 core。
 */
export function createMockCoreConfigGateway(): CoreConfigGateway {
  const values = new Map(previewConfig.map((item) => [item.key, item.value]));

  return {
    async configGet() {
      return [...values].map(([key, value]) => ({ key, value }));
    },
    async configSet(items) {
      for (const item of items) values.set(item.key, item.value);
      return true;
    },
  };
}

/**
 * 只提供一段静态历史以校验日志布局；不使用定时器或 fake emitter 冒充生产实时流。
 */
export function createMockLogsGateway(now: () => number = Date.now): LogsGateway {
  const timestampMs = now();
  const history: readonly LogEvent[] = [
    {
      level: "info",
      component: "preview",
      code: "preview.history.loaded",
      message: "预览数据：正式运行时由 core 提供历史日志。",
      fields: {},
      timestamp_ms: timestampMs - 18_000,
    },
    {
      level: "info",
      component: "preview",
      code: "preview.layout.ready",
      message: "该记录仅用于检查日志页的密度与排版。",
      fields: {},
      timestamp_ms: timestampMs - 4_000,
    },
  ];

  return {
    async logsList(afterSeq, limit) {
      const start = Math.max(0, Math.floor(afterSeq));
      const safeLimit = Math.max(1, Math.floor(limit));
      const events = history.slice(start, start + safeLimit);
      const nextAfterSeq = start + events.length;
      return {
        events: [...events],
        next_after_seq: nextAfterSeq,
        has_more: nextAfterSeq < history.length,
      };
    },
    async logsClear() {
      return { cleared: true, removed_entries: history.length };
    },
    async onLogs() {
      return () => undefined;
    },
  };
}
