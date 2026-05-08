import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const outDir = path.join(root, "dist-local");
const runtimeMode = process.env.APP_RUNTIME_MODE || "local-app";
const apiBaseUrl = process.env.APP_API_BASE_URL || "";
const publicBaseUrl = process.env.APP_PUBLIC_BASE_URL || apiBaseUrl;

const files = [
  "index.html",
  "shared.html",
  "app.js",
  "shared.js",
  "styles.css",
  "manifest.webmanifest",
  "runtime-config.js",
];

const dirs = ["assets", "src"];

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

for (const file of files) {
  await cp(path.join(root, file), path.join(outDir, file));
}

for (const dir of dirs) {
  await cp(path.join(root, dir), path.join(outDir, dir), { recursive: true });
}

await writeFile(
  path.join(outDir, "runtime-config.js"),
  `window.__APP_RUNTIME__ = window.__APP_RUNTIME__ || ${JSON.stringify({
    mode: runtimeMode,
    apiBaseUrl,
    publicBaseUrl,
  })};\n`,
  "utf8"
);
