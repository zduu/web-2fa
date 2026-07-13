// 项目管理：CRUD、切换、汇总视图

import { state, saveSyncProjects, getCurrentProject, persist, normalizeSyncProject } from "../core/storage.js";

export function listProjects() {
  return state.syncProjects.slice();
}

export function detectDuplicateSyncIds() {
  const map = new Map();
  for (const p of state.syncProjects) {
    const k = (p.syncId || "").trim();
    if (!k) continue;
    map.set(k, (map.get(k) || 0) + 1);
  }
  return map;
}

export function createProject({ name, syncId, secret, auto = false, autoInterval = 60000 }) {
  const projectId = `proj_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const newProj = normalizeSyncProject({
    id: projectId,
    name,
    syncId: syncId || `local-${projectId}`,
    secret: secret || createLocalSyncSecret(),
    auto,
    autoInterval,
    lastSyncedAt: 0,
    itemsData: [],
    itemOrder: [],
  });
  state.syncProjects.push(newProj);
  saveSyncProjects();
  return newProj;
}

function createLocalSyncSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return "local-secret-" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function updateProject(id, patch) {
  const p = state.syncProjects.find(x => x.id === id);
  if (!p) return null;
  Object.assign(p, normalizeSyncProject({ ...p, ...patch }));
  saveSyncProjects();
  return p;
}

export function deleteProject(id) {
  state.syncProjects = state.syncProjects.filter(p => p.id !== id);
  if (state.currentProjectId === id) {
    state.currentProjectId = null;
    state.items = [];
  }
  saveSyncProjects();
}

export async function saveCurrentProjectItems() {
  if (!state.currentProjectId || state.currentProjectId === "_all_") return;
  const proj = getCurrentProject();
  if (!proj) return;
  proj.itemsData = (state.items || []).map(it => ({ ...it }));
  proj.itemOrder = normalizeProjectItemOrder(proj.itemOrder, proj.itemsData);
  saveSyncProjects();
}

export async function switchToProject(projectId) {
  // commit current items to its project before switching
  await saveCurrentProjectItems();

  state.currentProjectId = projectId;

  if (projectId === "_all_") {
    // aggregated read-only items
    state.items = [];
    state.syncProjects.forEach(p => {
      if (p && p.itemsData) {
        for (const it of p.itemsData) {
          state.items.push({ ...it, _projectId: p.id, _projectName: projectDisplayName(p.name) });
        }
      }
    });
    saveSyncProjects();
    return;
  }

  const project = state.syncProjects.find(p => p.id === projectId);
  if (!project) return;
  project.itemOrder = normalizeProjectItemOrder(project.itemOrder, project.itemsData || []);
  state.items = (project.itemsData || []).map(it => ({ ...it }));
  saveSyncProjects();
}

export function ensureProjectActive() {
  // If no project exists and no current id, leave items as-is (legacy local-only mode)
  if (!state.currentProjectId && state.syncProjects.length > 0) {
    state.currentProjectId = state.syncProjects[0].id;
    saveSyncProjects();
  }
}

export function normalizeProjectItemOrder(itemOrder, items) {
  const activeItems = (Array.isArray(items) ? items : []).filter((it) => it && it.id && !it.deleted);
  const activeIds = new Set(activeItems.map((it) => it.id));
  const next = [];
  const seen = new Set();

  for (const id of Array.isArray(itemOrder) ? itemOrder : []) {
    if (!activeIds.has(id) || seen.has(id)) continue;
    seen.add(id);
    next.push(id);
  }

  const missing = activeItems
    .filter((it) => !seen.has(it.id))
    .sort((a, b) => projectItemSortKey(a).localeCompare(projectItemSortKey(b)))
    .map((it) => it.id);

  return next.concat(missing);
}

function projectItemSortKey(item) {
  const issuer = String(item?.issuer || "").trim();
  const account = String(item?.account || "").trim();
  return `${issuer}::${account}`;
}

function projectDisplayName(value) {
  return String(value || "").trim() || "未命名";
}
