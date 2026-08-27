<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";

const props = defineProps<{
  sections: readonly { id: string; label: string; icon: string }[];
  activeSection: string;
}>();

const emit = defineEmits<{
  select: [id: string];
}>();

/** 图标路径表（lucide 风格 24×24 描边图标；内联 SVG，不新增依赖）。 */
const ICON_PATHS: Record<string, readonly string[]> = {
  connection: [
    "M12 22v-5",
    "M9 8V2",
    "M15 8V2",
    "M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z",
  ],
  startup: ["M12 2v10", "M18.4 6.6a9 9 0 1 1-12.77.04"],
  appearance: [
    "M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z",
  ],
  diagnostics: ["M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9", "M10.3 21a1.94 1.94 0 0 0 3.4 0"],
  experimental: [
    "M10 2v7.527a2 2 0 0 1-.211.896L4.72 20.55a1 1 0 0 0 .9 1.45h12.76a1 1 0 0 0 .9-1.45l-5.069-10.127A2 2 0 0 1 14 9.527V2",
    "M8.5 2h7",
    "M7 16h10",
  ],
};

function iconPaths(key: string): readonly string[] {
  return ICON_PATHS[key] ?? [];
}

/** 当前展开文字的分区：active 后短暂展开，约 2s 后自动收起。 */
const expandedSection = ref<string | null>(props.activeSection);
let collapseTimer: ReturnType<typeof setTimeout> | null = null;

/** 锚点切换时的飞行小球：active 变更时小球从上一锚点高速飞向新锚点（对齐旧 C++ 版本）。 */
const axisFlight = ref<{ from: string; to: string } | null>(null);
let flightTimer: ReturnType<typeof setTimeout> | null = null;
let activationToken = 0;

function clearCollapseTimer(): void {
  if (collapseTimer !== null) {
    clearTimeout(collapseTimer);
    collapseTimer = null;
  }
}

function clearFlightTimer(): void {
  if (flightTimer !== null) {
    clearTimeout(flightTimer);
    flightTimer = null;
  }
}

/** 锚点在滑轨上的纵向位置（与 rail 的 top/bottom 24px 对齐）。 */
function nodePosition(key: string): string {
  const index = props.sections.findIndex((s) => s.id === key);
  const safeIndex = index >= 0 ? index : 0;
  const denominator = Math.max(props.sections.length - 1, 1);
  const ratio = safeIndex / denominator;
  return `calc(24px + (100% - 48px) * ${ratio})`;
}

const axisFlightStyle = computed(() =>
  axisFlight.value
    ? {
        "--axis-flight-from": axisFlight.value.from,
        "--axis-flight-to": axisFlight.value.to,
      }
    : {},
);

function isActive(key: string): boolean {
  return props.activeSection === key;
}

function isExpanded(key: string): boolean {
  return expandedSection.value === key;
}

/**
 * 轴处于固定悬浮层，鼠标命中图标时滚轮不会自然落到设置滚动容器。
 * 将该滚轮显式交回 .settings-page__layout；轨道空白区域则以 pointer-events 穿透，
 * 保持整页任意位置都能连续滚动。
 */
function forwardWheel(event: WheelEvent): void {
  const root = (event.currentTarget as HTMLElement).closest<HTMLElement>(".settings-page");
  const scrollContainer = root?.querySelector<HTMLElement>(".settings-page__layout");
  if (!scrollContainer) return;

  event.preventDefault();
  scrollContainer.scrollTop = Math.max(0, scrollContainer.scrollTop + event.deltaY);
  scrollContainer.scrollLeft = Math.max(0, scrollContainer.scrollLeft + event.deltaX);
}

watch(
  () => props.activeSection,
  (section, previousSection) => {
    clearCollapseTimer();
    clearFlightTimer();
    const token = ++activationToken;
    if (previousSection && previousSection !== section) {
      // 切换分区：先收起文字，小球 200ms 飞抵新锚点后再展开文字。
      expandedSection.value = null;
      axisFlight.value = {
        from: nodePosition(previousSection),
        to: nodePosition(section),
      };
      flightTimer = setTimeout(() => {
        if (activationToken !== token) return;
        axisFlight.value = null;
        expandedSection.value = section;
        collapseTimer = setTimeout(() => {
          if (expandedSection.value === section) expandedSection.value = null;
        }, 2000);
      }, 200);
      return;
    }
    axisFlight.value = null;
    expandedSection.value = section;
    collapseTimer = setTimeout(() => {
      if (expandedSection.value === section) expandedSection.value = null;
    }, 2000);
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  clearCollapseTimer();
  clearFlightTimer();
});
</script>

<template>
  <nav class="settings-axis" data-testid="settings-section-axis" aria-label="设置分区导航" @wheel="forwardWheel">
    <div class="settings-axis__track">
      <span class="settings-axis__rail" aria-hidden="true" />
      <span v-if="axisFlight" class="axis-flight-orb" :style="axisFlightStyle" aria-hidden="true" />
      <button
        v-for="section in sections"
        :key="section.id"
        type="button"
        class="settings-axis__item"
        :class="{
          'settings-axis__item--active': isActive(section.id),
          'settings-axis__item--expanded': isExpanded(section.id),
        }"
        :aria-current="isActive(section.id) ? 'true' : undefined"
        :aria-label="section.label"
        :title="section.label"
        @click="emit('select', section.id)"
      ><span class="settings-axis__label">{{ section.label }}</span><svg
        class="settings-axis__icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      ><path v-for="(d, index) in iconPaths(section.icon)" :key="index" :d="d" /></svg></button>
    </div>
  </nav>
</template>

<style scoped>
.settings-axis {
  /* 固定悬浮在滚动容器右侧空隙：不占 grid 列、滚动不跟随（滚动观察逻辑仍由父页驱动）。
     top = 标题栏(34px) + 页头高度(52px) + 外层 .product-content 上边距(24px)：
     轴顶与滚动容器顶缘对齐（banner 现落在 .content 顶部、无负 margin 爬升）；
     right = var(--space-5) - 12px = 8px：用户要求锚点轴整体右移 12px（减小 right 才是
     朝窗口右缘移动；此前 +12px 实际向左移，方向做反了）。 */
  position: fixed;
  top: calc(var(--titlebar-height, 34px) + var(--settings-header-height, 52px) + var(--space-6));
  right: calc(var(--space-5) - 12px);
  height: calc(100vh - var(--titlebar-height, 34px) - var(--settings-header-height, 52px) - 2 * var(--space-6));
  /* 轨道空白区完全穿透到底下的页面滚动层；按钮会单独重新启用命中。 */
  pointer-events: none;
}

.settings-axis__track {
  position: relative;
  display: flex;
  height: 100%;
  flex-direction: column;
  align-items: flex-end;
  justify-content: space-between;
  padding-block: var(--space-2);
}

.settings-axis__rail {
  position: absolute;
  top: 24px;
  right: 14px;
  bottom: 24px;
  width: 2px;
  border-radius: 999px;
  background: linear-gradient(
    180deg,
    color-mix(in srgb, var(--accent) 62%, transparent),
    var(--border-strong) 48%,
    color-mix(in srgb, var(--accent) 34%, transparent)
  );
  opacity: 0.85;
  pointer-events: none;
}

/* 锚点切换时的飞行小球：从上一锚点（--axis-flight-from）高速飞向新锚点
   （--axis-flight-to），200ms 内由小变大再消失，落位后展开文字（对齐旧 C++ 版本）。 */
.axis-flight-orb {
  position: absolute;
  /* 飞行球只作为轨道动效，落点时必须藏到真实锚点按钮下方。 */
  z-index: 0;
  top: var(--axis-flight-from);
  right: 7px;
  width: 18px;
  height: 18px;
  border-radius: 999px;
  background: var(--accent);
  box-shadow:
    0 0 0 4px var(--accent-subtle),
    0 0 24px color-mix(in srgb, var(--accent) 62%, transparent);
  opacity: 0;
  pointer-events: none;
  animation: axis-flight 200ms cubic-bezier(0.12, 0.82, 0.18, 1) forwards;
}

@keyframes axis-flight {
  0% {
    top: var(--axis-flight-from);
    opacity: 0.72;
    transform: translateY(-50%) scale(0.58);
  }
  62% {
    opacity: 1;
    transform: translateY(-50%) scale(1);
  }
  100% {
    top: var(--axis-flight-to);
    opacity: 0;
    transform: translateY(-50%) scale(1.65);
  }
}

.settings-axis__item {
  position: relative;
  z-index: 1;
  display: flex;
  height: 32px;
  min-height: 32px;
  max-height: 32px;
  /* 这是纵向轨道的 flex 子项：flex-basis 只负责保持纵向 32px，横向宽度单独由 width 控制。 */
  width: 32px;
  min-width: 32px;
  max-width: 32px;
  flex: 0 0 32px;
  flex-direction: row;
  align-items: center;
  justify-content: center;
  gap: 0;
  padding: 0;
  overflow: hidden;
  border: 1px solid var(--border-subtle);
  border-radius: 999px;
  background: var(--surface-panel);
  color: var(--text-secondary);
  cursor: pointer;
  pointer-events: auto;
  transition:
    width var(--motion-standard) var(--motion-ease),
    background-color var(--motion-fast) var(--motion-ease),
    border-color var(--motion-fast) var(--motion-ease),
    color var(--motion-fast) var(--motion-ease);
}

.settings-axis__item:hover:not(.settings-axis__item--active),
.settings-axis__item:focus-visible:not(.settings-axis__item--active) {
  border-color: color-mix(in srgb, var(--accent) 55%, transparent);
  color: var(--text-primary);
}

.settings-axis__item--active,
.settings-axis__item--expanded {
  border-color: var(--accent);
  background: var(--accent);
  color: var(--accent-on);
}

.settings-axis__item--expanded {
  /* 横向胶囊只向左伸展；纵向轨道上的占位高度始终是 32px，不能把 flex-basis 改成横向宽度。 */
  width: 76px;
  min-width: 76px;
  max-width: 76px;
  height: 32px;
  min-height: 32px;
  max-height: 32px;
  flex: 0 0 32px;
  justify-content: flex-start;
  gap: 6px;
  padding: 0 5px 0 8px;
}

.settings-axis__icon {
  width: 16px;
  height: 16px;
  flex: 0 0 16px;
  margin: 0;
  pointer-events: none;
}

/* 文字默认隐藏；展开时在图标左侧显示，胶囊的右端仍贴着滑轨。 */
.settings-axis__label {
  display: block;
  width: 0;
  flex: 0 0 0;
  max-width: 0;
  margin-right: 0;
  overflow: hidden;
  opacity: 0;
  white-space: nowrap;
  font-size: 12px;
  font-weight: 600;
  transition:
    width var(--motion-standard) var(--motion-ease),
    max-width var(--motion-standard) var(--motion-ease),
    opacity var(--motion-standard) var(--motion-ease),
    margin-right var(--motion-standard) var(--motion-ease);
}

.settings-axis__item--expanded .settings-axis__label {
  /* 文字在左、icon 在右；label 占据中间剩余空间但自身左对齐，不再把短文字放在大圆心。 */
  width: auto;
  flex: 1 1 0;
  min-width: 0;
  max-width: none;
  text-align: left;
  margin-right: 0;
  opacity: 1;
}

.motion-reduced .settings-axis *,
[data-motion="reduced"] .settings-axis * {
  transition-duration: 1ms !important;
  animation-duration: 1ms !important;
}

@media (prefers-reduced-motion: reduce) {
  .settings-axis * {
    transition-duration: 1ms !important;
    animation-duration: 1ms !important;
  }
}

@media (max-width: 760px) {
  .settings-axis {
    position: static;
    height: auto;
  }

  .settings-axis__track {
    flex-direction: row;
    height: auto;
    align-items: center;
    justify-content: space-between;
    padding-block: 0;
    padding-inline: var(--space-2);
  }

  .settings-axis__rail {
    display: none;
  }

  /* 窄窗口：图标常显，文字不展开（title/aria-label 提供可访问名）。 */
  .settings-axis__item,
  .settings-axis__item--expanded {
    width: 32px;
    min-width: 32px;
    max-width: 32px;
    flex: 0 0 32px;
  }

  .settings-axis__label {
    display: none;
  }
}
</style>
