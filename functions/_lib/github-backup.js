const DEFAULT_BACKUP_PATH = ".web-2fa-backup/sync/{id}.web2fa-backup.json";
const GITHUB_API_VERSION = "2022-11-28";

export class GithubBackupError extends Error {
  constructor(message, { status = 502, note = "github-backup-failed" } = {}) {
    super(message);
    this.name = "GithubBackupError";
    this.status = status;
    this.note = note;
  }
}

export function getGithubBackupConfig(env = {}) {
  const token = normalizeText(env.GITHUB_BACKUP_TOKEN);
  const repoValue = normalizeText(env.GITHUB_BACKUP_REPO);
  const branch = normalizeText(env.GITHUB_BACKUP_BRANCH);
  const pathTemplate = normalizeBackupPath(env.GITHUB_BACKUP_PATH) || DEFAULT_BACKUP_PATH;
  const anyConfigured = !!(token || repoValue);

  if (!anyConfigured) return { enabled: false };

  const repo = parseRepo(repoValue);
  const missing = [];
  if (!token) missing.push("GITHUB_BACKUP_TOKEN");
  if (!repo) missing.push("GITHUB_BACKUP_REPO");

  if (missing.length) {
    return {
      enabled: true,
      valid: false,
      error: `GitHub 备份配置不完整：${missing.join(", ")}`,
    };
  }

  return {
    enabled: true,
    valid: true,
    token,
    owner: repo.owner,
    repo: repo.repo,
    branch,
    pathTemplate,
  };
}

export function buildGithubBackupDocument(syncId, payload, now = Date.now()) {
  return {
    type: "web-2fa.sync-github-backup",
    version: 1,
    createdAt: now,
    syncId,
    payload,
  };
}

export function renderGithubBackupPath(pathTemplate, syncId) {
  const safeId = String(syncId || "").trim().replaceAll("/", "-");
  const rendered = String(pathTemplate || DEFAULT_BACKUP_PATH)
    .replaceAll("{id}", safeId)
    .replaceAll("{syncId}", safeId);
  return normalizeBackupPath(rendered) || DEFAULT_BACKUP_PATH.replace("{id}", safeId);
}

export async function backupSyncPayloadToGithub(env, syncId, payload, options = {}) {
  const config = getGithubBackupConfig(env);
  if (!config.enabled) return { status: "disabled" };
  if (!config.valid) {
    throw new GithubBackupError(config.error, { status: 500, note: "github-backup-config" });
  }

  const fetcher = options.fetch || globalThis.fetch;
  if (typeof fetcher !== "function") {
    throw new GithubBackupError("GitHub 备份不可用：fetch 不存在");
  }

  const path = renderGithubBackupPath(config.pathTemplate, syncId);
  const document = buildGithubBackupDocument(syncId, payload, options.now || Date.now());
  const content = utf8ToBase64(`${JSON.stringify(document, null, 2)}\n`);
  const sha = await readExistingGithubSha(fetcher, config, path);
  await putGithubBackupFile(fetcher, config, path, content, sha, syncId);

  return { status: "ok", path };
}

async function readExistingGithubSha(fetcher, config, path) {
  const url = githubContentsUrl(config, path, { includeRef: true });
  const res = await fetcher(url, {
    method: "GET",
    headers: githubHeaders(config.token),
  });
  if (res.status === 404) return "";
  if (!res.ok) {
    throw new GithubBackupError(`读取 GitHub 备份文件失败：${res.status}`);
  }
  let body;
  try {
    body = await res.json();
  } catch {
    throw new GithubBackupError("读取 GitHub 备份文件失败：响应格式不正确");
  }
  const sha = typeof body?.sha === "string" ? body.sha.trim() : "";
  if (!sha) throw new GithubBackupError("读取 GitHub 备份文件失败：缺少 sha");
  return sha;
}

async function putGithubBackupFile(fetcher, config, path, content, sha, syncId) {
  const body = {
    message: `chore(backup): 更新 web-2fa ${syncId} 备份`,
    content,
  };
  if (sha) body.sha = sha;
  if (config.branch) body.branch = config.branch;

  const res = await fetcher(githubContentsUrl(config, path), {
    method: "PUT",
    headers: {
      ...githubHeaders(config.token),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new GithubBackupError(`写入 GitHub 备份失败：${res.status}`);
  }
}

function githubContentsUrl(config, path, { includeRef = false } = {}) {
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  const url = new URL(`https://api.github.com/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}/contents/${encodedPath}`);
  if (includeRef && config.branch) url.searchParams.set("ref", config.branch);
  return url.toString();
}

function githubHeaders(token) {
  return {
    "Accept": "application/vnd.github+json",
    "Authorization": `Bearer ${token}`,
    "User-Agent": "web-2fa-authenticator",
    "X-GitHub-Api-Version": GITHUB_API_VERSION,
  };
}

function parseRepo(value) {
  const text = normalizeText(value);
  const match = /^([^/\s]+)\/([^/\s]+)$/.exec(text);
  if (!match) return null;
  return { owner: match[1], repo: match[2] };
}

function normalizeText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeBackupPath(value) {
  const text = normalizeText(value).replace(/^\/+/, "");
  if (!text || text.includes("\0") || text.split("/").some((part) => part === "." || part === "..")) return "";
  return text;
}

function utf8ToBase64(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}
