<script setup lang="ts">
import { computed, inject, nextTick, onMounted, onUnmounted, ref } from "vue";

import type { LogEvent } from "../lib/ipc";
import { LOGS_GATEWAY_KEY, createLogsGateway, type LogsGateway } from "../product/logs";
import {
  entries,
  error,
  isVisibleLogEvent,
  loadedOnce,
  loading,
  logCursor,
  logEventKey,
} from "../product/logs-state";

const BASE_LOG_LEVELS = ["trace", "debug", "info", "warn", "error", "fatal"] as const;

const props = defineProps<{
  gateway?: LogsGateway;
}>();

const injectedGateway = inject(LOGS_GATEWAY_KEY, null);
const gateway = props.gateway ?? injectedGateway ?? createLogsGateway();
const selectedLevel = ref("all");
const followLatest = ref(true);
const clearing = ref(false);
const bodyRef = ref<HTMLElement | null>(null);
let unlisten: (() => void) | null = null;
let pollTimer: ReturnType<typeof setInterval> | null = null;
let disposed = false;

const filteredEntries = computed(() =>
  entries.value.filter((entry) => selectedLevel.value === "all" || entry.level === selectedLevel.value),
);

/** 初次无数据时才用加载提示替换表格；后台增量轮询必须保留既有日志节点。 */
const isInitialLoading = computed(() => loading.value && !loadedOnce.value && entries.value.length === 0);

const availableLevels = computed(() => {
  const levels = new Set<string>(BASE_LOG_LEVELS);
  for (const entry of entries.value) {
    const level = entry.level.trim();
    if (level) levels.add(level);
  }
  return [...levels];
});

function formatTime(timestampMs: number): string {
  if (!timestampMs) return "—";
  return new Date(timestampMs).toLocaleTimeString("zh-CN", { hour12: false });
}

function scrollToLatest(): void {
  if (!followLatest.value) return;
  void nextTick(() => {
    if (!disposed && bodyRef.value !== null) {
      bodyRef.value.scrollTop = bodyRef.value.scrollHeight;
    }
  });
}

function appendUnique(rawEntries: ReadonlyArray<LogEvent>): void {
  const seen = new Set(entries.value.map(logEventKey));
  const fresh: LogEvent[] = [];
  for (const entry of rawEntries) {
    if (!isVisibleLogEvent(entry)) continue;
    const key = logEventKey(entry);
    if (seen.has(key)) continue;
    seen.add(key);
    fresh.push(entry);
  }
  if (fresh.length === 0) return;
  entries.value = [...entries.value, ...fresh].slice(-2_000);
  scrollToLatest();
}

/**
 * 懒加载 + 增量：首次打开从 seq 0 全量拉取，之后以日志尾游标取增量。
 * 当前 wire 已有 LogsList，但没有可直接复用的跨进程 StreamLogs；因此用短周期增量轮询
 * 保证页面实时追尾，同时保留 onLogs seam 作为事件到达时的低延迟入口。
 */
async function loadHistory(): Promise<void> {
  if (loading.value || clearing.value) return;

  loading.value = true;
  error.value = false;
  try {
    let afterSeq = loadedOnce.value ? logCursor.value : 0;
    let hasMore = true;
    const nextEntries: LogEvent[] = [];

    while (hasMore) {
      const chunk = await gateway.logsList(afterSeq, 500);
      nextEntries.push(...chunk.events);
      hasMore = chunk.has_more && chunk.next_after_seq !== afterSeq;
      afterSeq = chunk.next_after_seq;
    }

    appendUnique(nextEntries);
    if (afterSeq > logCursor.value) logCursor.value = afterSeq;
    loadedOnce.value = true;
  } catch {
    error.value = true;
  } finally {
    loading.value = false;
  }
}

async function subscribeToFutureEntries(): Promise<void> {
  try {
    unlisten = await gateway.onLogs((entry) => appendUnique([entry]));
  } catch {
    unlisten = null;
  }
}

async function clearLogs(): Promise<void> {
  if (clearing.value) return;
  clearing.value = true;
  error.value = false;
  try {
    const reply = await gateway.logsClear();
    if (!reply.cleared) throw new Error("logs_clear rejected");
    entries.value = [];
    logCursor.value = 0;
    loadedOnce.value = false;
    scrollToLatest();
  } catch {
    error.value = true;
  } finally {
    clearing.value = false;
  }
}

function startPolling(): void {
  if (pollTimer !== null) return;
  pollTimer = setInterval(() => {
    void loadHistory();
  }, 1_000);
}

onMounted(() => {
  void loadHistory();
  void subscribeToFutureEntries();
  startPolling();
});

onUnmounted(() => {
  disposed = true;
  if (pollTimer !== null) clearInterval(pollTimer);
  pollTimer = null;
  unlisten?.();
  unlisten = null;
});
</script>

<template>
  <section class="logs-page" aria-labelledby="logs-title">
    <header class="logs-page__header">
      <div>
        <h1 id="logs-title">日志</h1>
      </div>
      <div class="logs-actions">
        <label class="logs-filter">
          <span>级别</span>
          <select v-model="selectedLevel" data-testid="log-level-filter" aria-label="日志等级筛选">
            <option value="all">全部</option>
            <option v-for="level in availableLevels" :key="level" :value="level">{{ level }}</option>
          </select>
        </label>
        <label class="logs-follow-latest">
          <input v-model="followLatest" type="checkbox" data-testid="logs-follow-latest" />
          <span>跟随最新</span>
        </label>
        <button type="button" data-testid="clear-logs" :disabled="clearing" @click="clearLogs">
          {{ clearing ? "清空中…" : "清空日志" }}
        </button>
      </div>
    </header>

    <div v-if="error && entries.length === 0" class="logs-message logs-message--error">
      <span>暂时无法读取日志。</span>
      <button type="button" data-testid="retry-logs" @click="loadHistory">重试</button>
    </div>
    <p v-else-if="isInitialLoading" class="logs-message">正在读取历史记录…</p>

    <div v-else class="logs-page__table-shell" data-testid="logs-table-shell">
      <div class="log-table" data-testid="log-table">
        <div class="log-row log-row--head" data-testid="logs-table-header" aria-hidden="true">
          <span>时间</span>
          <span>级别</span>
          <span>组件</span>
          <span>消息</span>
        </div>
        <div ref="bodyRef" class="logs-page__body" data-testid="logs-scroll-body">
          <p v-if="filteredEntries.length === 0" class="logs-empty">
            {{ entries.length === 0 ? "暂无日志" : "没有符合筛选条件的日志" }}
          </p>
          <div v-for="entry in filteredEntries" :key="logEventKey(entry)" class="log-row">
            <time :datetime="new Date(entry.timestamp_ms).toISOString()">{{ formatTime(entry.timestamp_ms) }}</time>
            <span class="log-level" :class="`log-level--${entry.level}`">{{ entry.level }}</span>
            <span>{{ entry.component || "—" }}</span>
            <span class="log-message">{{ entry.message }}</span>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.logs-page {
  min-width: 0;
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  margin-top: 0;
  padding: var(--product-page-top-gap) 0 var(--space-4);
}

.logs-page__header {
  display: flex;
  flex: none;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-5);
  min-height: 52px;
  margin: 0;
  padding: 0 0 var(--space-3);
  background: var(--surface-canvas);
}

.logs-page__header h1 {
  margin: 0;
  font-size: clamp(22px, 2.2vw, 30px);
  letter-spacing: -0.02em;
}

.logs-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: var(--space-2);
}

.logs-filter,
.logs-follow-latest {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  color: var(--text-secondary);
  font-size: 12px;
  white-space: nowrap;
}

.logs-filter select {
  min-height: 32px;
  padding: 0 var(--space-2);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--surface-panel);
  color: var(--text-primary);
}

.logs-follow-latest input {
  width: 15px;
  height: 15px;
  accent-color: var(--accent);
}

.logs-message {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
  margin: 0 0 var(--space-4);
  padding: var(--space-3) var(--space-4);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--surface-panel);
  color: var(--text-secondary);
  font-size: 13px;
}

.logs-message--error { color: var(--state-danger); }

.logs-page__table-shell {
  flex: 1;
  min-height: 0;
}

.logs-page__body {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
  scrollbar-gutter: stable;
  scrollbar-width: thin;
}

.log-table {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  overflow: hidden;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  background: var(--surface-panel);
}

.log-row {
  display: grid;
  grid-template-columns: 88px 72px minmax(110px, 0.42fr) minmax(0, 1.58fr);
  gap: var(--space-3);
  align-items: baseline;
  min-width: 0;
  padding: 10px var(--space-4);
  border-top: 1px solid var(--border-subtle);
  font-size: 13px;
}

.log-row--head {
  flex: none;
  border-top: 0;
  background: var(--surface-subtle);
  color: var(--text-secondary);
  font-weight: 650;
}

.log-level {
  color: var(--text-secondary);
  font-family: var(--font-mono);
  font-size: 12px;
  text-transform: uppercase;
}

.log-level--warn { color: var(--state-warning); }
.log-level--error { color: var(--state-danger); }
.log-message { overflow-wrap: anywhere; }

.logs-empty {
  margin: 0;
  padding: var(--space-6);
  color: var(--text-secondary);
  text-align: center;
}

@media (max-width: 700px) {
  .logs-page__header {
    flex-direction: column;
    align-items: flex-start;
    padding: var(--space-3) 0 var(--space-4);
  }

  .logs-actions { justify-content: flex-start; }

  .log-row { grid-template-columns: 72px 64px minmax(0, 1fr); }
  .log-row > :nth-child(3) { display: none; }
}
</style>
