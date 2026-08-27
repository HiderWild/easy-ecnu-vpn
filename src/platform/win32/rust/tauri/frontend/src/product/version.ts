/**
 * 产品版本号（「关于」页展示）。
 * 单一来源：app/tauri.conf.json 的 version；Vite 在构建/测试期经 define 注入
 * __APP_VERSION__（全局声明见 env.d.ts）。非 Vite 上下文（如纯 TS 运行）回退到
 * 产品版本占位 4.0.0。
 */
export const PRODUCT_VERSION: string =
  typeof __APP_VERSION__ !== "undefined" && __APP_VERSION__ !== ""
    ? __APP_VERSION__
    : "4.0.0";
