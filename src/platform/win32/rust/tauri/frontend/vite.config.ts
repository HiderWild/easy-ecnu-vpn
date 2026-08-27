import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vitest/config";
import vue from "@vitejs/plugin-vue";

// 产品版本号单一来源：app/tauri.conf.json 的 version（打包产物运行时版本由 Tauri 注入；
// 构建/测试期经 define 注入 __APP_VERSION__ 供「关于」页展示）。独立前端构建读不到 app
// 配置时回退到 C++ 产品线占位版本 4.0.0，避免构建失败。
let appVersion = "4.0.0";
try {
  const tauriConfig = JSON.parse(
    readFileSync(resolve(process.cwd(), "../app/tauri.conf.json"), "utf8"),
  ) as { version?: string };
  if (typeof tauriConfig.version === "string" && tauriConfig.version.length > 0) {
    appVersion = tauriConfig.version;
  }
} catch {
  // 前端目录外无 app 配置（独立构建/异常 cwd）→ 使用占位版本。
}

// Tauri 官方 dev 端口约定：devUrl 见 app/tauri.conf.json（http://localhost:1420）。
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [vue()],
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
  },
  test: {
    css: true,
    environment: "happy-dom",
    setupFiles: ["./src/test/setup.ts"],
    clearMocks: true,
    restoreMocks: true,
  },
  // 生产构建输出到 ../frontend/dist（tauri.conf.json frontendDist）。
  build: { target: "es2022" },
  // Tauri 生产模式经 custom protocol（http://tauri.localhost）加载 frontendDist：
  // 绝对路径 `/assets/...` 会解析到裸 localhost 导致 ERR_CONNECTION_REFUSED。
  // 相对 base 使资源从当前页面 URL 解析，不依赖 host。
  base: "./",
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: "ws", host, port: 1421 }
      : undefined,
    watch: { ignored: ["**/src-tauri/**", "**/app/**"] },
  },
});
