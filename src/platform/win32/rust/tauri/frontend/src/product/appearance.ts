import { computed, ref, type ComputedRef, type InjectionKey, type Ref } from "vue";

export type ThemePreference = "system" | "light" | "dark";
export type AccentPreference = "azure" | "violet" | "jade" | "amber";
export type MotionPreference = "normal" | "reduced";
export type WindowModePreference = "advanced" | "minimal";

export interface AppearanceState {
  theme: ThemePreference;
  accent: AccentPreference;
  motion: MotionPreference;
  mode: WindowModePreference;
}

export interface AppearanceStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export interface Appearance {
  readonly state: Readonly<Ref<AppearanceState>>;
  readonly documentClass: Readonly<ComputedRef<string>>;
  setTheme(theme: ThemePreference): void;
  setAccent(accent: AccentPreference): void;
  setMotion(motion: MotionPreference): void;
  setMode(mode: WindowModePreference): void;
  applyDocument(root: HTMLElement): void;
}

export const APPEARANCE_KEY: InjectionKey<Appearance> = Symbol("exv.product.appearance");

export const APPEARANCE_STORAGE_KEY = "exv.ui.appearance";

type AppearanceStorageGetter = () => AppearanceStorage | null | undefined;

const DEFAULT_APPEARANCE: AppearanceState = {
  theme: "system",
  accent: "azure",
  motion: "normal",
  mode: "advanced",
};

/**
 * 为浏览器存储提供只管理外观数据的安全适配器。
 *
 * 某些隐私环境会让 `window.localStorage` 的属性访问本身抛出异常；其他环境则只会
 * 拒绝具体的读取或写入。无论哪一种，当前会话都应继续保留用户刚刚选择的外观，
 * 而不能让应用在挂载前失败。
 */
export function createBrowserSafeAppearanceStorage(
  getStorage: AppearanceStorageGetter,
): AppearanceStorage {
  const sessionValues = new Map<string, string>();
  let browserStorage: AppearanceStorage | null | undefined;

  function getBrowserStorage(): AppearanceStorage | null {
    if (browserStorage !== undefined) return browserStorage;

    try {
      browserStorage = getStorage() ?? null;
    } catch {
      browserStorage = null;
    }

    return browserStorage;
  }

  return {
    getItem(key) {
      if (key !== APPEARANCE_STORAGE_KEY) return null;

      const sessionValue = sessionValues.get(key);
      if (sessionValue !== undefined) return sessionValue;

      try {
        return getBrowserStorage()?.getItem(key) ?? null;
      } catch {
        return null;
      }
    },
    setItem(key, value) {
      if (key !== APPEARANCE_STORAGE_KEY) return;

      sessionValues.set(key, value);
      try {
        getBrowserStorage()?.setItem(key, value);
      } catch {
        // 浏览器存储不可写时，内存副本仍保留本次会话的外观选择。
      }
    },
  };
}

function isThemePreference(value: unknown): value is ThemePreference {
  return value === "system" || value === "light" || value === "dark";
}

function isAccentPreference(value: unknown): value is AccentPreference {
  return value === "azure" || value === "violet" || value === "jade" || value === "amber";
}

function isMotionPreference(value: unknown): value is MotionPreference {
  return value === "normal" || value === "reduced";
}

function isWindowModePreference(value: unknown): value is WindowModePreference {
  return value === "advanced" || value === "minimal";
}

function readAppearance(storage: AppearanceStorage): AppearanceState {
  try {
    const raw = storage.getItem(APPEARANCE_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_APPEARANCE };

    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return { ...DEFAULT_APPEARANCE };

    const saved = parsed as Partial<AppearanceState>;
    return {
      theme: isThemePreference(saved.theme) ? saved.theme : DEFAULT_APPEARANCE.theme,
      accent: isAccentPreference(saved.accent) ? saved.accent : DEFAULT_APPEARANCE.accent,
      motion: isMotionPreference(saved.motion) ? saved.motion : DEFAULT_APPEARANCE.motion,
      mode: isWindowModePreference(saved.mode) ? saved.mode : DEFAULT_APPEARANCE.mode,
    };
  } catch {
    return { ...DEFAULT_APPEARANCE };
  }
}

/**
 * 仅管理本地视觉偏好。它不读取、保存或派生任何 VPN 运行状态、统计或凭据。
 */
export function createAppearance(storage: AppearanceStorage): Appearance {
  const state = ref<AppearanceState>(readAppearance(storage));
  const documentClass = computed(() => (state.value.motion === "reduced" ? "motion-reduced" : ""));
  let documentRoot: HTMLElement | null = null;

  function persist(): void {
    const { theme, accent, motion, mode } = state.value;
    try {
      storage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify({ theme, accent, motion, mode }));
    } catch {
      // 本地存储不可用时保留当前会话中的外观；不得影响 VPN 业务流程。
    }
  }

  function applyToDocument(): void {
    if (!documentRoot) return;

    const { theme, accent, motion, mode } = state.value;
    documentRoot.dataset.theme = theme;
    documentRoot.dataset.accent = accent;
    documentRoot.dataset.motion = motion;
    documentRoot.dataset.mode = mode;
    documentRoot.classList.toggle("motion-reduced", motion === "reduced");
  }

  function update(next: AppearanceState): void {
    state.value = next;
    persist();
    applyToDocument();
  }

  return {
    state,
    documentClass,
    setTheme(theme) {
      update({ ...state.value, theme });
    },
    setAccent(accent) {
      update({ ...state.value, accent });
    },
    setMotion(motion) {
      update({ ...state.value, motion });
    },
    setMode(mode) {
      update({ ...state.value, mode });
    },
    applyDocument(root) {
      documentRoot = root;
      applyToDocument();
    },
  };
}
