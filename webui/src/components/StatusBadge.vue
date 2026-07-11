<script setup lang="ts">
defineProps<{
  status: 'connected' | 'disconnected' | 'connecting' | 'error' | 'installed' | 'running' | 'stopped'
}>()

const statusLabels: Record<string, string> = {
  connected: '已连接',
  disconnected: '未连接',
  connecting: '连接中',
  error: '错误',
  installed: '已安装',
  running: '运行中',
  stopped: '已停止',
}
</script>

<template>
  <span
    :class="[
      'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium',
      status === 'connected' || status === 'running' ? 'bg-accent/20 text-accent' :
      status === 'disconnected' || status === 'stopped' ? 'bg-muted/20 text-muted' :
      status === 'connecting' ? 'bg-warning/20 text-warning' :
      status === 'error' ? 'bg-destructive/20 text-destructive' :
      'bg-primary/20 text-foreground'
    ]"
  >
    <span
      :class="[
        'h-1.5 w-1.5 rounded-full',
        status === 'connected' || status === 'running' ? 'bg-accent' :
        status === 'disconnected' || status === 'stopped' ? 'bg-muted' :
        status === 'connecting' ? 'bg-warning animate-pulse' :
        status === 'error' ? 'bg-destructive' :
        'bg-foreground'
      ]"
    />
    {{ statusLabels[status] || status }}
  </span>
</template>