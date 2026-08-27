/**
 * 命令拒绝归一为人类可读文本。
 *
 * Tauri 命令的拒绝来自 serde 标记枚举 `AppError`，形状为普通对象 `{ kind, message }`
 * 而非 JS `Error`；纯浏览器预览的 `invokeTauri` 也抛 `{ kind, message }`。
 * 统一先取 `Error.message`，再取对象 `message` 字符串字段，最后回退到给定文案——
 * 让真实后端错误信息浮出 UI，而不是一律显示通用兜底。
 */
export function commandErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) return error.message.trim();
  if (typeof error === "object" && error !== null) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string" && message.trim()) return message.trim();
  }
  return fallback;
}
