<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { ChevronDown, Github, Tag, UserRound } from 'lucide-vue-next'
import appIconUrl from '../assets/app-icon.svg'
import { changelogEntries } from '../data/changelog'
import { distributionConfig } from '../generated/distribution'
import { useConfigStore } from '../stores/config'

defineOptions({ name: 'AboutPage' })

const config = useConfigStore()

const versionLabel = computed(() => config.runtimeStatus?.version || 'dev')

async function openRepository() {
  const url = distributionConfig.repository.url
  try {
    const nativeOpen = window.exv?.shell?.openExternal?.(distributionConfig.repository.url)
    if (nativeOpen) {
      await nativeOpen
      return
    }
  } catch {
    // Fall back to browser behavior when the native shell rejects the request.
  }
  window.open(url, '_blank', 'noopener,noreferrer')
}

onMounted(() => {
  void config.fetchRuntimeStatus().catch(() => {})
})
</script>

<template>
  <div class="h-full overflow-hidden py-3">
    <div class="h-full overflow-y-auto">
      <header class="mb-4">
        <h1 class="text-3xl font-semibold text-foreground">关于</h1>
      </header>

      <section class="rounded-xl border border-border bg-surface p-5">
        <div class="flex items-center gap-4 border-b border-border pb-5">
          <div class="flex h-20 w-20 items-center justify-center rounded-2xl bg-accent/10">
            <img class="h-16 w-16" :src="appIconUrl" alt="" />
          </div>
          <div class="min-w-0">
            <p class="text-4xl font-semibold leading-10 text-foreground">{{ distributionConfig.appName }}</p>
            <p class="text-2xl font-medium leading-8 text-muted">{{ distributionConfig.brandSubtitle }}</p>
          </div>
        </div>

        <div class="grid gap-3 py-4 text-sm">
          <div class="flex items-center justify-between gap-4">
            <span class="flex items-center gap-2 text-muted">
              <Tag class="h-4 w-4" />
              版本
            </span>
            <span class="font-medium text-foreground">{{ versionLabel }}</span>
          </div>
          <div class="flex items-center justify-between gap-4">
            <span class="flex items-center gap-2 text-muted">
              <UserRound class="h-4 w-4" />
              作者
            </span>
            <span class="font-medium text-foreground">{{ distributionConfig.author }}</span>
          </div>
        </div>

        <a
          class="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm font-medium text-foreground transition-colors hover:border-accent hover:text-accent"
          :href="distributionConfig.repository.url"
          rel="noreferrer"
          @click.prevent="openRepository"
        >
          <Github class="h-4 w-4" />
          {{ distributionConfig.repository.label }}
        </a>
      </section>

      <section class="mt-4 rounded-xl border border-border bg-surface p-5">
        <div class="mb-4 flex items-start justify-between gap-4">
          <div>
            <h2 class="text-base font-semibold text-foreground">更新日志</h2>
            <p class="mt-1 text-sm leading-6 text-muted">从 3.3.0 起的主要变化，按版本从新到旧排列。</p>
          </div>
          <span class="shrink-0 rounded-full border border-border px-2.5 py-1 text-xs text-muted">
            {{ changelogEntries.length }} 个版本
          </span>
        </div>

        <div class="space-y-2">
          <details
            v-for="(entry, index) in changelogEntries"
            :key="entry.version"
            class="group rounded-lg border border-border bg-bg/40 px-4 py-3"
            :open="index === 0"
          >
            <summary class="flex cursor-pointer list-none items-center justify-between gap-4">
              <span class="min-w-0">
                <span class="flex flex-wrap items-center gap-2">
                  <span class="text-sm font-semibold text-foreground">v{{ entry.version }}</span>
                  <span
                    v-if="entry.inferred"
                    class="rounded-full border border-border px-2 py-0.5 text-[11px] leading-4 text-muted"
                  >
                    历史归纳
                  </span>
                </span>
                <span class="mt-1 block text-sm text-muted">{{ entry.title }}</span>
              </span>
              <span class="flex shrink-0 items-center gap-3 text-xs text-muted">
                {{ entry.dateLabel }}
                <ChevronDown class="h-4 w-4 transition-transform group-open:rotate-180" />
              </span>
            </summary>

            <ul class="mt-3 space-y-2 border-t border-border pt-3 text-sm leading-6 text-muted">
              <li
                v-for="highlight in entry.highlights"
                :key="highlight"
                class="flex gap-2"
              >
                <span class="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />
                <span>{{ highlight }}</span>
              </li>
            </ul>
          </details>
        </div>
      </section>
    </div>
  </div>
</template>
