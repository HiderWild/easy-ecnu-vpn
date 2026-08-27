<script setup lang="ts">
import { computed, inject } from "vue";
import ConnectionSidebar from "./ConnectionSidebar.vue";
import { PRODUCT_RUNTIME_KEY } from "../product/runtime";

const items = [{ key: "connect", label: "连接" }, { key: "logs", label: "日志" }, { key: "settings", label: "设置" }, { key: "about", label: "关于" }];
const props = defineProps<{ currentPage: string }>();
const emit = defineEmits<{ navigate: [page: "connect" | "logs" | "settings" | "about"] }>();
function navigate(page: string) { emit("navigate", page as "connect" | "logs" | "settings" | "about"); }
const runtime = inject(PRODUCT_RUNTIME_KEY, null);
const state = computed(() => runtime?.state.value ?? null);
</script>
<template>
  <aside class="product-rail" data-testid="product-rail">
    <div class="product-brand" aria-label="EXV for ECNU"><img src="../assets/exv-logo.svg" alt="产品 Logo" /><div><strong>EXV</strong><span>for ECNU</span></div></div>
    <nav aria-label="主导航"><button v-for="item in items" :key="item.key" :class="{ active: currentPage === item.key }" @click="navigate(item.key)">{{ item.label }}</button></nav>
    <ConnectionSidebar v-if="props.currentPage === 'connect' && state" :state="state" class="product-rail__connection" />
  </aside>
</template>
