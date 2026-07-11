<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useVpnStore } from '../stores/vpn'
import { useUiStore } from '../stores/ui'
import { Route, Plus, Trash2 } from 'lucide-vue-next'

const vpn = useVpnStore()
const ui = useUiStore()

const routes = ref<string[]>([])
const newRoute = ref('')
const busy = ref(false)
const message = ref<{ text: string } | null>(null)

onMounted(async () => {
  await vpn.fetchRoutes()
  routes.value = vpn.routes.map(r => r.cidr)
})

async function addRoute() {
  const r = newRoute.value.trim()
  if (!r || routes.value.includes(r) || busy.value) return

  busy.value = true
  message.value = null
  try {
    await vpn.addRoute(r)
    routes.value = vpn.routes.map(route => route.cidr)
    newRoute.value = ''
    message.value = { text: '路由已添加' }
  } catch (e: any) {
    ui.requestError({ title: '添加路由失败', message: e?.message || '添加失败' })
  } finally {
    busy.value = false
  }
}

async function removeRoute(index: number) {
  if (busy.value) return
  const cidr = routes.value[index]
  if (!cidr) return
  busy.value = true
  message.value = null
  try {
    await vpn.removeRoute(cidr)
    routes.value = vpn.routes.map(route => route.cidr)
    message.value = { text: '路由已删除' }
  } catch (e: any) {
    ui.requestError({ title: '删除路由失败', message: e?.message || '删除失败' })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="h-full overflow-hidden py-4">
    <h1 class="text-xl font-semibold text-foreground mb-6 flex items-center gap-2">
      <Route class="w-5 h-5 text-accent" />
      分流路由
    </h1>

    <div class="grid h-[calc(100%-3.5rem)] grid-cols-2 gap-4">
      <div class="bg-surface border border-border rounded-xl p-5">
      <p class="text-sm text-muted mb-4">
        配置分流路由，仅将指定网段的流量通过 VPN 隧道。留空表示全局隧道。
      </p>

      <div class="space-y-3">
        <div
          v-for="(route, index) in routes"
          :key="index"
          class="flex items-center gap-3 bg-bg border border-border rounded-lg px-4 py-2.5"
        >
          <span class="text-sm text-foreground font-mono flex-1">{{ route }}</span>
          <button
            :disabled="busy"
            class="text-muted hover:text-destructive disabled:opacity-50 transition-colors"
            @click="removeRoute(index)"
          >
            <Trash2 class="w-4 h-4" />
          </button>
        </div>
      </div>
      </div>

      <div class="bg-surface border border-border rounded-xl p-5">
      <div class="flex items-center gap-3 mb-4">
        <input
          v-model="newRoute"
          type="text"
          placeholder="例如 10.0.0.0/8"
          class="flex-1 bg-bg border border-border rounded-lg px-4 py-2.5 text-sm text-foreground font-mono placeholder:text-muted focus:outline-none focus:border-accent/50 transition-colors"
          @keyup.enter="addRoute"
        />
        <button
          :disabled="busy"
          class="flex items-center gap-2 border border-border rounded-lg px-4 py-2.5 text-sm text-foreground hover:border-accent/50 disabled:opacity-50 transition-colors"
          @click="addRoute"
        >
          <Plus class="w-4 h-4" />
          添加
        </button>
      </div>

      <div
        v-if="message"
        :class="[
          'text-sm rounded-lg px-4 py-2.5',
          'bg-success/10 text-success'
        ]"
      >
        {{ message.text }}
      </div>
      <p v-else class="text-xs text-muted">
        点击添加或垃圾桶后立即写入配置，无需再保存。
      </p>
      </div>
    </div>
  </div>
</template>
