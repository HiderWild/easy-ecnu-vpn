import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const EXPECTED_HASH = "9f20a0836b75c028d1266caab0ea451d1072f5000615f317a29275340f4c0b52";
const target = process.env.EXV_LOGO_PATH || new URL("../src/assets/exv-logo.svg", import.meta.url);

function displayPath(value) {
  if (typeof value === "string") return value;

  const decodedPath = decodeURIComponent(value.pathname);
  return process.platform === "win32" && /^\/[A-Za-z]:\//.test(decodedPath)
    ? decodedPath.slice(1).replaceAll("/", "\\")
    : decodedPath;
}

const targetPath = displayPath(target);

try {
  const actualHash = createHash("sha256").update(readFileSync(target)).digest("hex");
  if (actualHash !== EXPECTED_HASH) {
    console.error(`EXV product logo hash mismatch: ${targetPath}`);
    console.error(`expected: ${EXPECTED_HASH}`);
    console.error(`actual:   ${actualHash}`);
    process.exitCode = 1;
  } else {
    console.log(`EXV product logo OK: ${targetPath} ${actualHash}`);
  }
} catch (error) {
  console.error(`EXV product logo could not be read: ${targetPath}`);
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
