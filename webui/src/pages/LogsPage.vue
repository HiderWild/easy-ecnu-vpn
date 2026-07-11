<script setup lang="ts">
import { ref, onActivated, onDeactivated, onMounted, onUnmounted, nextTick, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useVpnStore, type LogEntry } from '../stores/vpn'
import { usePageStateStore } from '../stores/pageState'
import { useUiStore } from '../stores/ui'
import { useSSE } from '../composables/useSSE'
import { Trash2, Download, ArrowLeft, Copy } from 'lucide-vue-next'

defineOptions({ name: 'LogsPage' })

const vpn = useVpnStore()
const ui = useUiStore()
const pageState = usePageStateStore()
const route = useRoute()
const router = useRouter()
const { connect: sseConnect, disconnect: sseDisconnect } = useSSE()
const autoScroll = ref(pageState.logs.autoScroll)
const logsContainer = ref<HTMLElement | null>(null)
const lastLogSeq = ref(0)
const logsLoading = ref(false)
const LOG_FETCH_LIMIT = 200
const LOG_POLL_INTERVAL_MS = 2000
type LogLevelFilter = 'all' | 'warn_error' | 'error'
const logLevelFilter = ref<LogLevelFilter>(pageState.logs.levelFilter as LogLevelFilter)
let logPollTimer: ReturnType<typeof setInterval> | null = null
let programmaticLogScroll = false

const isContextJump = computed(() => route.query.from === 'dashboard')
const highlightCount = 10 // Number of recent entries to highlight on context jump
const visibleLogs = computed(() => vpn.logs.filter(logMatchesFilter))

onMounted(async () => {
  sseConnect()
  await loadLogChunk(true)
  startLogPolling()

  if (pageState.logs.userScrolled) {
    restoreLogsScroll()
  } else if (autoScroll.value) {
    await scrollToBottom()
  }
})

onUnmounted(() => {
  stopLogPolling()
  sseDisconnect()
})

function logSeq(entry: LogEntry): number {
  return typeof entry.seq === 'number' && Number.isFinite(entry.seq) ? entry.seq : 0
}

function maxLogSeq(entries: LogEntry[]): number {
  return entries.reduce((max, entry) => Math.max(max, logSeq(entry)), 0)
}

function applyLogChunk(entries: LogEntry[], initial: boolean) {
  if (!entries.length) {
    return
  }

  const incomingMaxSeq = maxLogSeq(entries)
  if (initial || (incomingMaxSeq > 0 && incomingMaxSeq <= lastLogSeq.value)) {
    vpn.setLogs(entries)
  } else {
    for (const entry of entries) {
      vpn.addLog(entry)
    }
  }

  if (incomingMaxSeq > 0) {
    lastLogSeq.value = incomingMaxSeq
  }
}

async function loadLogChunk(initial: boolean) {
  if (logsLoading.value) return
  logsLoading.value = true
  try {
    const api = (await import('../api/host')).default
    const params: { limit: number; after_seq?: number } = { limit: LOG_FETCH_LIMIT }
    if (!initial && lastLogSeq.value > 0) {
      params.after_seq = lastLogSeq.value
    }
    const { data } = await api.get<LogEntry[]>('/logs', { params })
    if (Array.isArray(data)) {
      applyLogChunk(data, initial)
    }
  } catch {
  } finally {
    logsLoading.value = false
  }
}

function startLogPolling() {
  stopLogPolling()
  logPollTimer = setInterval(() => { void loadLogChunk(false) }, LOG_POLL_INTERVAL_MS)
}

function stopLogPolling() {
  if (logPollTimer != null) {
    clearInterval(logPollTimer)
    logPollTimer = null
  }
}

async function scrollToBottom() {
  await nextTick()
  const container = logsContainer.value
  if (container) {
    programmaticLogScroll = true
    container.scrollTop = container.scrollHeight
    pageState.logs.scrollTop = container.scrollTop
    if (typeof window !== 'undefined') {
      window.setTimeout(() => {
        programmaticLogScroll = false
      }, 120)
    } else {
      programmaticLogScroll = false
    }
  }
}

function logScrollNearBottom(container: HTMLElement) {
  return container.scrollTop + container.clientHeight >= container.scrollHeight - 8
}

function handleLogsScroll() {
  const container = logsContainer.value
  if (!container || programmaticLogScroll) return
  pageState.logs.scrollTop = container.scrollTop
  pageState.logs.userScrolled = true
  if (!logScrollNearBottom(container) && autoScroll.value) {
    autoScroll.value = false
  }
}

function restoreLogsScroll() {
  const container = logsContainer.value
  if (!container) return
  programmaticLogScroll = true
  container.scrollTop = pageState.logs.scrollTop
  if (typeof window !== 'undefined') {
    window.setTimeout(() => {
      programmaticLogScroll = false
    }, 120)
  } else {
    programmaticLogScroll = false
  }
}

onActivated(() => {
  void nextTick(() => {
    if (pageState.logs.userScrolled) {
      restoreLogsScroll()
      return
    }
    if (autoScroll.value) {
      void scrollToBottom()
      return
    }
    restoreLogsScroll()
  })
})

onDeactivated(() => {
  pageState.logs.scrollTop = logsContainer.value?.scrollTop ?? pageState.logs.scrollTop
})

function clearLogs() {
  vpn.clearLogs()
}

function isErrorLog(entry: LogEntry) {
  return entry.level === 'error' || entry.message.includes('[ERROR]') || entry.message.includes('[error]')
}

function isWarningOrErrorLog(entry: LogEntry) {
  return isErrorLog(entry) || entry.level === 'warn' || entry.message.includes('[WARN]') || entry.message.includes('[warn]')
}

function logMatchesFilter(entry: LogEntry) {
  if (logLevelFilter.value === 'warn_error') return isWarningOrErrorLog(entry)
  if (logLevelFilter.value === 'error') return isErrorLog(entry)
  return true
}

function formatLogs(entries: LogEntry[]) {
  return entries
    .map((e: LogEntry) => `[${e.level.toUpperCase()}] ${e.message}`)
    .join('\n')
}

function downloadLogs() {
  const text = formatLogs(visibleLogs.value)
  const blob = new Blob([text], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `exv-${new Date().toISOString().slice(0, 10)}.log`
  a.click()
  URL.revokeObjectURL(url)
}

function copyTextFallback(text: string) {
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.setAttribute('readonly', 'true')
  textarea.style.position = 'fixed'
  textarea.style.left = '-9999px'
  document.body.appendChild(textarea)
  textarea.select()
  const ok = document.execCommand('copy')
  document.body.removeChild(textarea)
  return ok
}

async function copyLogs() {
  const text = formatLogs(visibleLogs.value)
  if (!text) {
    ui.addToast('暂无日志可复制', 'warning')
    return
  }
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
    } else if (!copyTextFallback(text)) {
      throw new Error('Clipboard API is unavailable.')
    }
    ui.addToast('日志已复制', 'success')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    ui.requestError({ title: '复制日志失败', message })
  }
}

watch(
  () => vpn.logs.length,
  () => {
    if (autoScroll.value) void scrollToBottom()
  },
)

watch(logLevelFilter, (next) => {
  pageState.logs.levelFilter = next
})

watch(autoScroll, (enabled) => {
  pageState.logs.autoScroll = enabled
  if (enabled) {
    pageState.logs.userScrolled = false
    void scrollToBottom()
  }
})

function shouldHighlight(index: number): boolean {
  if (!isContextJump.value) return false
  // Highlight the last `highlightCount` entries
  return index >= visibleLogs.value.length - highlightCount
}
</script>

<template>
  <div class="h-full overflow-hidden py-3">
    <div class="mb-3 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <button
          v-if="isContextJump"
          class="flex items-center gap-1.5 text-xs text-muted hover:text-foreground transition-colors"
          @click="router.push('/')"
        >
          <ArrowLeft class="w-3.5 h-3.5" />
          返回 Dashboard
        </button>
        <h1 class="text-3xl font-semibold text-foreground">
          日志
        </h1>
      </div>
      <div class="flex items-center gap-2">
        <select
          v-model="logLevelFilter"
          class="border border-border bg-surface text-muted rounded-lg px-2.5 py-1.5 text-xs outline-none hover:text-foreground focus:border-accent"
        >
          <option value="all">
            全部显示
          </option>
          <option value="warn_error">
            仅警告和错误
          </option>
          <option value="error">
            仅错误
          </option>
        </select>
        <label class="flex items-center gap-2 text-xs text-muted cursor-pointer">
          <input v-model="autoScroll" type="checkbox" class="w-3.5 h-3.5 accent-accent" />
          自动滚动
        </label>
        <button
          class="flex items-center gap-1.5 border border-border text-muted rounded-lg px-3 py-1.5 text-xs hover:text-foreground transition-colors"
          @click="copyLogs"
        >
          <Copy class="w-3.5 h-3.5" />
          复制
        </button>
        <button
          class="flex items-center gap-1.5 border border-border text-muted rounded-lg px-3 py-1.5 text-xs hover:text-foreground transition-colors"
          @click="downloadLogs"
        >
          <Download class="w-3.5 h-3.5" />
          导出
        </button>
        <button
          class="flex items-center gap-1.5 border border-border text-muted rounded-lg px-3 py-1.5 text-xs hover:text-foreground transition-colors"
          @click="clearLogs"
        >
          <Trash2 class="w-3.5 h-3.5" />
          清空
        </button>
      </div>
    </div>

    <div
      id="logs-container"
      ref="logsContainer"
      class="bg-bg border border-border rounded-xl p-4 h-[calc(100%-3.5rem)] overflow-y-auto font-mono text-xs leading-relaxed"
      @scroll="handleLogsScroll"
    >
      <div v-if="visibleLogs.length === 0" class="text-muted text-center py-8">
        暂无日志
      </div>
      <div
        v-for="(entry, i) in visibleLogs"
        :key="i"
        class="whitespace-pre-wrap break-all"
        :class="[
          shouldHighlight(i) ? 'log-highlight' : '',
          {
            'text-red-400': entry.level === 'error' || entry.message.includes('[ERROR]') || entry.message.includes('[error]'),
            'text-warning': entry.level === 'warn' || entry.message.includes('[WARN]') || entry.message.includes('[warn]'),
            'text-foreground': entry.level === 'info' && !entry.message.includes('[ERROR]') && !entry.message.includes('[error]') && !entry.message.includes('[WARN]') && !entry.message.includes('[warn]'),
          }
        ]"
      >{{ entry.message }}</div>
    </div>
  </div>
</template>

<style scoped>
@keyframes highlight-fade {
  from { background-color: rgba(59, 130, 246, 0.2); }
  to { background-color: transparent; }
}
.log-highlight {
  animation: highlight-fade 2s ease-out forwards;
}
</style>
