import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import {
  APPEARANCE_STORAGE_KEY,
  createBrowserSafeAppearanceStorage,
  createAppearance,
  type AppearanceStorage,
} from "../appearance";

const logoRelativePath = "../../assets/exv-logo.svg";
const logoGuardRelativePath = "../../../scripts/check-product-logo.mjs";
const motionCssRelativePath = "../../styles/motion.css";
const LOGO_URL = new URL(logoRelativePath, import.meta.url);
const LOGO_GUARD_URL = new URL(logoGuardRelativePath, import.meta.url);
const MOTION_CSS_URL = new URL(motionCssRelativePath, import.meta.url);
const EXPECTED_LOGO_HASH = "9f20a0836b75c028d1266caab0ea451d1072f5000615f317a29275340f4c0b52";
const temporaryDirectories: string[] = [];

function createMemoryStorage(): AppearanceStorage {
  const values = new Map<string, string>();
  return {
    getItem(key) {
      return values.get(key) ?? null;
    },
    setItem(key, value) {
      values.set(key, value);
    },
  };
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("减少动效全局守卫", () => {
  it("系统偏好和显式减少动效都会将无限动画限制为一次", () => {
    const motionCss = readFileSync(MOTION_CSS_URL, "utf8");
    const explicitRuleStart = motionCss.indexOf(":root.motion-reduced");
    const systemReducedRule = motionCss.slice(0, explicitRuleStart);
    const explicitReducedRule = motionCss.slice(explicitRuleStart);

    expect(systemReducedRule).toContain("animation-iteration-count: 1 !important;");
    expect(explicitReducedRule).toContain("animation-iteration-count: 1 !important;");
  });
});

describe("产品外观偏好", () => {
  it("只保存主题、高亮色、动效和窗口模式，不会存储 VPN 运行状态", () => {
    const storage = createMemoryStorage();
    const appearance = createAppearance(storage);

    appearance.setTheme("dark");
    appearance.setAccent("jade");
    appearance.setMotion("reduced");
    appearance.setMode("minimal");

    expect(JSON.parse(storage.getItem(APPEARANCE_STORAGE_KEY) ?? "{}"))
      .toEqual({ theme: "dark", accent: "jade", motion: "reduced", mode: "minimal" });
    expect(storage.getItem(APPEARANCE_STORAGE_KEY)).not.toContain("connected");
    expect(storage.getItem(APPEARANCE_STORAGE_KEY)).not.toContain("token");
  });

  it("减少动效只改变外观 CSS 标记，不改变外观以外的产品状态", () => {
    const storage = createMemoryStorage();
    const appearance = createAppearance(storage);

    appearance.setMotion("reduced");

    expect(appearance.documentClass.value).toContain("motion-reduced");
    expect(appearance.state.value).toEqual({
      theme: "system",
      accent: "azure",
      motion: "reduced",
      mode: "advanced",
    });
  });

  it("applyDocument 首次和切换后都将外观状态完整写入真实 DOM 根元素", () => {
    const storage = createMemoryStorage();
    const root = document.createElement("html");
    const appearance = createAppearance(storage);

    appearance.applyDocument(root);
    expect(root.dataset).toMatchObject({
      theme: "system",
      accent: "azure",
      motion: "normal",
      mode: "advanced",
    });
    expect(root.classList.contains("motion-reduced")).toBe(false);

    appearance.setTheme("dark");
    appearance.setAccent("amber");
    appearance.setMotion("reduced");
    appearance.setMode("minimal");
    expect(root.dataset).toMatchObject({
      theme: "dark",
      accent: "amber",
      motion: "reduced",
      mode: "minimal",
    });
    expect(root.classList.contains("motion-reduced")).toBe(true);

    appearance.setMotion("normal");
    expect(root.dataset.motion).toBe("normal");
    expect(root.classList.contains("motion-reduced")).toBe(false);
  });

  it("丢弃旧存储中的业务字段和未知外观值", () => {
    const storage = createMemoryStorage();
    storage.setItem(
      APPEARANCE_STORAGE_KEY,
      JSON.stringify({ theme: "midnight", accent: "jade", connected: true, token: "secret" }),
    );

    const appearance = createAppearance(storage);
    appearance.setMode("minimal");

    expect(appearance.state.value).toEqual({
      theme: "system",
      accent: "jade",
      motion: "normal",
      mode: "minimal",
    });
    expect(JSON.parse(storage.getItem(APPEARANCE_STORAGE_KEY) ?? "{}"))
      .toEqual({ theme: "system", accent: "jade", motion: "normal", mode: "minimal" });
  });

  it("存储属性 getter 抛错时保留本次会话的外观状态且不触及业务键", () => {
    const storage = createBrowserSafeAppearanceStorage(() => {
      throw new Error("SecurityError");
    });
    const appearance = createAppearance(storage);

    expect(() => appearance.setTheme("dark")).not.toThrow();
    expect(appearance.state.value.theme).toBe("dark");
    expect(JSON.parse(storage.getItem(APPEARANCE_STORAGE_KEY) ?? "{}"))
      .toEqual({ theme: "dark", accent: "azure", motion: "normal", mode: "advanced" });
    storage.setItem("vpn.status", "connected");
    expect(storage.getItem("vpn.status")).toBeNull();
  });

  it("存储 getItem 抛错时创建和设置外观都不会抛出", () => {
    const storage = createBrowserSafeAppearanceStorage(() => ({
      getItem() {
        throw new Error("getItem blocked");
      },
      setItem() {},
    }));
    const appearance = createAppearance(storage);

    expect(appearance.state.value).toEqual({
      theme: "system",
      accent: "azure",
      motion: "normal",
      mode: "advanced",
    });
    expect(() => appearance.setAccent("violet")).not.toThrow();
    expect(appearance.state.value.accent).toBe("violet");
    expect(JSON.parse(storage.getItem(APPEARANCE_STORAGE_KEY) ?? "{}"))
      .toEqual({ theme: "system", accent: "violet", motion: "normal", mode: "advanced" });
  });

  it("存储 setItem 抛错时仍保留本次会话中的外观状态", () => {
    const storage = createBrowserSafeAppearanceStorage(() => ({
      getItem() {
        return null;
      },
      setItem() {
        throw new Error("setItem blocked");
      },
    }));
    const appearance = createAppearance(storage);

    expect(() => appearance.setMode("minimal")).not.toThrow();
    expect(appearance.state.value.mode).toBe("minimal");
    expect(JSON.parse(storage.getItem(APPEARANCE_STORAGE_KEY) ?? "{}"))
      .toEqual({ theme: "system", accent: "azure", motion: "normal", mode: "minimal" });
  });
});

describe("产品 Logo 字节守卫", () => {
  it("原始产品 Logo 的守卫输出路径和固定 SHA-256", () => {
    const result = spawnSync(process.execPath, [fileURLToPath(LOGO_GUARD_URL)], {
      encoding: "utf8",
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain(fileURLToPath(LOGO_URL));
    expect(result.stdout).toContain(EXPECTED_LOGO_HASH);
  });

  it("Logo 改动一个字节后守卫失败、报告实际 hash，并清理临时文件", () => {
    const temporaryDirectory = mkdtempSync(join(tmpdir(), "exv-logo-guard-"));
    temporaryDirectories.push(temporaryDirectory);
    const alteredLogoPath = join(temporaryDirectory, "exv-logo.svg");
    copyFileSync(LOGO_URL, alteredLogoPath);

    const alteredBytes = readFileSync(alteredLogoPath);
    alteredBytes[0] ^= 1;
    writeFileSync(alteredLogoPath, alteredBytes);
    const actualHash = createHash("sha256").update(alteredBytes).digest("hex");

    const result = spawnSync(process.execPath, [fileURLToPath(LOGO_GUARD_URL)], {
      encoding: "utf8",
      env: { ...process.env, EXV_LOGO_PATH: alteredLogoPath },
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(alteredLogoPath);
    expect(result.stderr).toContain(actualHash);
    expect(result.stderr).toContain(EXPECTED_LOGO_HASH);

    rmSync(temporaryDirectory, { recursive: true, force: true });
    temporaryDirectories.splice(temporaryDirectories.indexOf(temporaryDirectory), 1);
    expect(existsSync(temporaryDirectory)).toBe(false);
  });
});
