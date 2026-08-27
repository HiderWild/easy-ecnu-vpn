/// <reference types="vite/client" />

/** 构建期由 vite.config.ts 注入的产品版本号（来源 app/tauri.conf.json 的 version）。 */
declare const __APP_VERSION__: string | undefined;

declare module "*.vue" {
  import type { DefineComponent } from "vue";
  const component: DefineComponent<Record<string, unknown>, Record<string, unknown>, unknown>;
  export default component;
}
