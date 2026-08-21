/* 威胁建模工作台 - 核心逻辑（多项目版） */
"use strict";

/* ============ 工具 ============ */
const $ = id => document.getElementById(id);
const uid = (p) => p + "-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
const esc = s => String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
const CAT_NAME = {actor:"外部实体",process:"过程",store:"数据存储",flow:"数据流",boundary:"信任边界",global:"全局通用"};
const STRIDE_NAME = {Spoofing:"S 仿冒",Tampering:"T 篡改",Repudiation:"R 抵赖",InformationDisclosure:"I 信息泄露",DenialOfService:"D 拒绝服务",ElevationOfPrivilege:"E 权限提升",Generic:"通用"};
const STORE_KEY = "tm-workbench-v2";
const OLD_KEY = "tm-workbench-v1";

/* ============ 数据模型 ============
storage = { v:2, curProjectId, currentPageId, projects:[project] }
project = { id, name, note, createdAt, updatedAt, threats:[threatRef], pages:[page] }
threatRef = { id(威胁库编号), note(处置说明), status: open|mitigated|na }
page = { id, name, note, funcs:[func] }
func = {
  id, name, note, threats:[threatRef],
  flows:  [{ id, targetFuncId, direction, dataDesc, protocol, threats:[threatRef] }],
  rels:   [{ id, targetFuncId, direction }],
}
targetFuncId 可指向任意项目的功能（跨项目互通）。
flows/rels.direction：downstream=本功能->目标；upstream=目标->本功能。
================================= */
let projects = [];
let curProjectId = null;
let currentPageId = null;
let saveTimer = null;
let curView = "detail";

function curProject() { return projects.find(p => p.id === curProjectId) || null; }

/* ============ 持久化 ============ */
function persist(immediate) {
  const el = $("saveState");
  if (immediate) {
    localStorage.setItem(STORE_KEY, JSON.stringify({ v: 2, curProjectId, currentPageId, projects }));
    el.textContent = "已保存 " + new Date().toLocaleTimeString("zh-CN");
    el.className = "save-state saved";
    refreshStatus();
  } else {
    el.textContent = "保存中...";
    el.className = "save-state";
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => persist(true), 600);
  }
}
function load() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (raw) {
      const data = JSON.parse(raw);
      if (data && data.v === 2 && Array.isArray(data.projects)) {
        projects = data.projects.map(normalizeProject);
        curProjectId = data.curProjectId;
        currentPageId = data.currentPageId;
        if (!curProject()) curProjectId = projects[0] ? projects[0].id : null;
        return true;
      }
    }
    const old = localStorage.getItem(OLD_KEY);
    if (old) {
      const p = normalizeProject(JSON.parse(old));
      projects = [p]; curProjectId = p.id; currentPageId = p.pages[0] ? p.pages[0].id : null;
      persist(true);
      return true;
    }
  } catch (e) { console.warn("load failed", e); }
  return false;
}

/* ============ 查询（含跨项目） ============ */
function getPage(pid) { const pr = curProject(); return pr ? pr.pages.find(p => p.id === pid) : null; }
function findFuncGlobal(fid) {
  for (const pr of projects) for (const pg of pr.pages) {
    const f = (pg.funcs || []).find(x => x.id === fid);
    if (f) return { proj: pr, page: pg, func: f };
  }
  return null;
}
function getFunc(fid) {
  const pr = curProject(); if (!pr) return null;
  for (const pg of pr.pages) {
    const f = (pg.funcs || []).find(x => x.id === fid);
    if (f) return { func: f, page: pg };
  }
  return null;
}
function funcLabel(fid) {
  const hit = findFuncGlobal(fid);
  if (!hit) return "(已删除)";
  const inCur = hit.proj.id === curProjectId;
  const pp = inCur ? "" : hit.proj.name + " / ";
  return pp + hit.page.name + " / " + hit.func.name;
}
function allFuncs() {
  const out = []; const pr = curProject();
  if (pr) pr.pages.forEach(p => (p.funcs || []).forEach(f => out.push({ page: p, func: f })));
  return out;
}
function allFuncsGlobal() {
  const out = [];
  projects.forEach(pr => pr.pages.forEach(p => (p.funcs || []).forEach(f => out.push({ proj: pr, page: p, func: f }))));
  return out;
}
function threatInfo(id) { return THREAT_LIBRARY.find(t => t.id === id) || { id, title: id, sev: "Medium", stride: "Generic", ref: "", desc: "", mitig: "" }; }

/* ============ 渲染：项目选择 + 左侧树 ============ */
function renderProjSelect() {
  const sel = $("projSelect");
  sel.innerHTML = projects.map(p => `<option value="${p.id}" ${p.id===curProjectId?"selected":""}>${esc(p.name)}</option>`).join("")
    || `<option value="">（无项目）</option>`;
}
function renderTree() {
  const box = $("tree");
  const pr = curProject();
  if (!pr) { box.innerHTML = `<div class="empty-tip">先新建项目或载入示例</div>`; return; }
  let html = "";
  pr.pages.forEach(pg => {
    const fc = (pg.funcs || []).length;
    const tc = (pg.funcs || []).reduce((s, f) => s + f.threats.length, 0);
    html += `<div class="page-item ${pg.id===currentPageId?"active":""}" data-pid="${pg.id}">
      <span class="p-name">${esc(pg.name)}</span><span class="tag">${fc}功能/${tc}威胁</span>
      <span class="p-ops">
        <button class="btn sm ghost" data-op="renamePage" data-pid="${pg.id}">改名</button>
        <button class="btn sm danger" data-op="delPage" data-pid="${pg.id}">删</button>
      </span></div>`;
  });
  box.innerHTML = html || `<div class="empty-tip">还没有页面，点击上方"+ 页面"</div>`;
  box.querySelectorAll(".page-item").forEach(el => {
    el.onclick = e => {
      const op = e.target.dataset.op;
      if (op === "renamePage") { renamePage(el.dataset.pid); return; }
      if (op === "delPage") { delPage(el.dataset.pid); return; }
      currentPageId = el.dataset.pid; renderAll();
    };
  });
}

/* ============ 渲染：主区（页面详情） ============ */
function renderMain() {
  const page = getPage(currentPageId);
  const c = $("contentDetail");
  const pr = curProject();
  if (!pr) { setTitle("未创建项目", ""); c.innerHTML = `<div class="empty-tip">点击右上角"新建项目"或"示例项目"开始建模</div>`; return; }
  let html = renderProjectRiskCard(pr);
  if (!page) {
    setTitle("未选择页面", "");
    c.innerHTML = html + `<div class="empty-tip">在左侧选择或新建一个页面</div>`;
    bindProjectRiskCard();
    return;
  }
  setTitle(page.name, `${(page.funcs||[]).length} 个功能` + (page.note ? " · " + page.note : ""));
  html += `<div style="margin-top:4px">`;
  if (!page.funcs || !page.funcs.length) {
    html += `<div class="empty-tip">本页面还没有功能，点击下方按钮新建</div><div><button class="btn" onclick="openFuncModal(null)">+ 新建功能</button></div>`;
  } else {
    page.funcs.forEach(f => { html += renderFuncCard(f); });
    html += `<div style="margin-top:6px"><button class="btn" onclick="openFuncModal(null)">+ 新建功能</button></div>`;
  }
  html += `</div>`;
  c.innerHTML = html;
  bindProjectRiskCard();
  bindFuncCards();
}
/* 项目级风险卡片 */
function renderProjectRiskCard(pr) {
  const th = (pr.threats||[]).map(t => renderThreatItem("", "project", pr.id, t)).join("");
  return `<div class="func-card proj-risk-card" data-pid-card="${pr.id}" style="border-left:4px solid #b45309">
    <div class="fc-head">
      <span class="fname">项目级风险</span>
      <span class="badge count">${(pr.threats||[]).length} 项</span>
      <span class="hint">全局性威胁：密钥管理、日志监控、供应链、配置基线等</span>
      <span class="fc-ops">
        <button class="btn sm ghost" data-op="projThreat">勾选威胁</button>
      </span>
    </div>
    <div class="fc-section"><div class="threat-list">${th || `<span class="hint">未关联项目级威胁（建议至少评估 G-01~G-05 全局通用类）</span>`}</div></div>
  </div>`;
}
function bindProjectRiskCard() {
  const card = document.querySelector(".proj-risk-card");
  if (!card) return;
  const pr = curProject();
  card.querySelector('[data-op="projThreat"]').onclick = () => openThreatModal({ targetKind: "project", projId: pr.id });
  card.querySelectorAll(".threat-item").forEach(ti => {
    const tid = ti.dataset.tid;
    ti.querySelector(".t-remove").onclick = e => {
      e.stopPropagation();
      const idx = pr.threats.findIndex(t => t.id === tid);
      if (idx >= 0) pr.threats.splice(idx, 1);
      persist(); renderAll();
    };
    ti.onclick = () => {
      const t = pr.threats.find(x => x.id === tid);
      const next = {open:"mitigated",mitigated:"na",na:"open"}[t.status||"open"];
      t.status = next; persist(); renderAll();
    };
  });
}
function setTitle(t, m) { $("pageTitle").textContent = t; $("pageMeta").textContent = m; }
function renderFuncCard(f) {
  const th = f.threats.map(t => renderThreatItem(f.id, "func", f.id, t)).join("");
  const flowChips = f.flows.map(fl => {
    const hit = findFuncGlobal(fl.targetFuncId);
    const ext = hit && hit.proj.id !== curProjectId;
    const arrow = fl.direction === "downstream" ? "数据 ->" : "数据 ←";
    const label = `${arrow} ${esc(funcLabel(fl.targetFuncId))}${fl.dataDesc?`（${esc(fl.dataDesc)}）`:""}${fl.protocol?` [${esc(fl.protocol)}]`:""}`;
    return `<div class="flow-panel ${ext?"ext":""}" data-flid="${fl.id}" data-fid="${f.id}">
      <div class="fp-head">
        <span class="fp-arrow">${arrow}</span>
        <span class="fp-label">${label}</span>
        <span class="badge count">${(fl.threats||[]).length} 项威胁</span>
        <span class="fp-ops">
          <button class="btn sm ghost" data-op="flowThreat">威胁</button>
          <button class="btn sm danger" data-op="flowDel">删</button>
        </span>
      </div>
      ${(fl.threats||[]).length ? `<div class="fp-threats">${fl.threats.map(t => renderThreatItem(f.id, "flow", fl.id, t)).join("")}</div>` : ""}
    </div>`;
  }).join("") || `<span class="hint">暂无数据流</span>`;
  const relChips = f.rels.map(r => {
    const hit = findFuncGlobal(r.targetFuncId);
    const ext = hit && hit.proj.id !== curProjectId;
    return `<span class="rel-chip ${ext?"ext":""}">${r.direction==="downstream"?"依赖 ->":"上游 ←"} ${esc(funcLabel(r.targetFuncId))} <span class="x" data-rlid="${r.id}">×</span></span>`;
  }).join("") || `<span class="hint">暂无上下游关系</span>`;
  return `<div class="func-card" data-fid="${f.id}">
    <div class="fc-head">
      <span class="fname">${esc(f.name)}</span>
      <span class="badge count">${f.threats.length} 项威胁</span>
      <span class="fc-ops">
        <button class="btn sm ghost" data-op="editFunc">编辑</button>
        <button class="btn sm ghost" data-op="addThreat">勾选威胁</button>
        <button class="btn sm ghost" data-op="addFlow">+ 数据流</button>
        <button class="btn sm ghost" data-op="addRel">+ 上下游</button>
        <button class="btn sm danger" data-op="delFunc">删除</button>
      </span>
    </div>
    ${f.note ? `<div class="note">${esc(f.note)}</div>` : ""}
    <div class="fc-section"><div class="k">威胁风险（点击条目切换状态）</div><div class="threat-list">${th || `<span class="hint">未关联威胁</span>`}</div></div>
    <div class="fc-section"><div class="k">数据流（威胁挂到具体流上）</div><div class="flow-list">${flowChips}</div></div>
    <div class="fc-section"><div class="k">上下游关系</div><div class="rel-list">${relChips}</div></div>
  </div>`;
}
/* 通用威胁条目渲染：hostKind=func|flow|project, hostId=功能id|流id|项目id */
function renderThreatItem(fid, hostKind, hostId, t) {
  const info = threatInfo(t.id);
  const stLabel = {open:"未处理",mitigated:"已缓解",na:"不适用"}[t.status||"open"];
  return `<div class="threat-item" data-fid="${fid}" data-hk="${hostKind}" data-hid="${hostId}" data-tid="${t.id}">
    <div class="t-line">
      <span class="badge sev ${info.sev}">${info.sev}</span>
      <span class="t-title">${esc(info.id)} ${esc(info.title)}</span>
      <span class="badge" style="background:#eef0f3;color:#374151">${STRIDE_NAME[info.stride]||""}</span>
      <span class="t-ref">${esc(info.ref)}</span>
      <span class="badge ${t.status==="mitigated"?"sev Low":""}" style="${t.status==="mitigated"?"":"background:#eef0f3;color:#374151"}">${stLabel}</span>
      <button class="t-remove" title="移除">移除</button>
    </div>
    <div class="t-detail">
      <div>场景：${esc(info.desc)}</div>
      <div>缓解：${esc(info.mitig)}</div>
      ${t.note ? `<div>处置备注：${esc(t.note)}</div>` : ""}
    </div>
  </div>`;
}
function bindFuncCards() {
  document.querySelectorAll(".func-card").forEach(card => {
    if (card.classList.contains("proj-risk-card")) return; // 项目风险卡由 bindProjectRiskCard 绑定
    const fid = card.dataset.fid;
    card.querySelectorAll("[data-op]").forEach(b => b.onclick = () => {
      const op = b.dataset.op;
      if (op === "editFunc") openFuncModal(fid);
      else if (op === "addThreat") openThreatModal({ targetKind: "func", fid });
      else if (op === "addFlow") openRelModal(fid, "flow");
      else if (op === "addRel") openRelModal(fid, "rel");
      else if (op === "delFunc") delFunc(fid);
    });
    /* 数据流面板操作 */
    card.querySelectorAll(".flow-panel").forEach(fp => {
      const flid = fp.dataset.flid;
      fp.querySelectorAll(".fp-ops [data-op]").forEach(b => b.onclick = e => {
        e.stopPropagation();
        const op = b.dataset.op;
        if (op === "flowThreat") openThreatModal({ targetKind: "flow", fid, flowId: flid });
        else if (op === "flowDel") {
          const f = getFunc(fid).func;
          f.flows = f.flows.filter(x => x.id !== flid);
          persist(); renderAll();
        }
      });
    });
    /* 威胁条目（功能级 + 流级统一处理） */
    card.querySelectorAll(".threat-item").forEach(ti => {
      const tid = ti.dataset.tid, hk = ti.dataset.hk, hid = ti.dataset.hid;
      ti.querySelector(".t-remove").onclick = e => {
        e.stopPropagation();
        let list;
        if (hk === "flow") list = getFunc(fid).func.flows.find(x => x.id === hid).threats;
        else list = getFunc(fid).func.threats;
        const idx = list.findIndex(t => t.id === tid);
        if (idx >= 0) list.splice(idx, 1);
        persist(); renderAll();
      };
      ti.onclick = () => {
        let list;
        if (hk === "flow") list = getFunc(fid).func.flows.find(x => x.id === hid).threats;
        else list = getFunc(fid).func.threats;
        const t = list.find(x => x.id === tid);
        const next = {open:"mitigated",mitigated:"na",na:"open"}[t.status||"open"];
        t.status = next; persist(); renderAll();
      };
    });
    card.querySelectorAll(".rel-chip .x").forEach(x => {
      const f = getFunc(fid).func;
      x.onclick = () => {
        if (x.dataset.rlid) f.rels = f.rels.filter(i => i.id !== x.dataset.rlid);
        persist(); renderAll();
      };
    });
  });
}

/* ============ 渲染：关系图视图 ============ */
function renderGraph() {
  const box = $("contentGraph");
  const pr = curProject();
  const page = getPage(currentPageId);
  if (!pr || !page) { box.innerHTML = `<div class="empty-tip">在左侧选择一个页面后查看关系图</div>`; return; }
  const funcs = page.funcs || [];
  if (!funcs.length) { box.innerHTML = `<div class="empty-tip">本页面还没有功能</div>`; return; }

  const NW = 250, NH = 56, GAP_Y = 26, MARGIN = 30;
  const mainH = Math.max(funcs.length * (NH + GAP_Y) - GAP_Y, NH);

  const edges = [];
  const extGroups = new Map();
  funcs.forEach(f => {
    const list = [];
    f.flows.forEach(fl => list.push({ kind: "flow", it: fl }));
    f.rels.forEach(r => list.push({ kind: "rel", it: r }));
    list.forEach(({ kind, it }) => {
      const hit = findFuncGlobal(it.targetFuncId);
      if (!hit) return;
      const inMain = (hit.page.id === page.id);
      let node;
      if (inMain) {
        node = funcs.find(x => x.id === hit.func.id);
      } else {
        const gkey = hit.proj.id + "|" + hit.page.id;
        if (!extGroups.has(gkey)) extGroups.set(gkey, { proj: hit.proj, page: hit.page, nodes: [] });
        const g = extGroups.get(gkey);
        node = g.nodes.find(n => n.func.id === hit.func.id);
        if (!node) { node = { func: hit.func, proj: hit.proj }; g.nodes.push(node); }
      }
      edges.push({ from: f, to: node, kind, it });
    });
  });

  const extList = [...extGroups.values()];
  const COL_W = NW + 90;
  const colH = extList.map(g => Math.max(g.nodes.length * (NH + GAP_Y) - GAP_Y, NH));
  const totalH = Math.max(mainH, ...colH, 200) + MARGIN * 2 + 40;
  const totalW = MARGIN * 2 + COL_W * (extList.length + 1);

  const pos = new Map();
  funcs.forEach((f, i) => {
    const y = MARGIN + 40 + (mainH - funcs.length * (NH + GAP_Y) + GAP_Y) / 2 + i * (NH + GAP_Y);
    pos.set(f.id, { x: MARGIN, y });
  });
  extList.forEach((g, gi) => {
    const x = MARGIN + COL_W * (gi + 1);
    const gh = colH[gi];
    g.nodes.forEach((n, i) => {
      const y = MARGIN + 40 + (gh - g.nodes.length * (NH + GAP_Y) + GAP_Y) / 2 + i * (NH + GAP_Y);
      pos.set(n.func.id, { x, y });
    });
  });

  let svg = `<svg width="${totalW}" height="${totalH}" viewBox="0 0 ${totalW} ${totalH}" xmlns="http://www.w3.org/2000/svg">
    <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#1a56db"/></marker>
    <marker id="arrg" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/></marker></defs>
    <rect width="${totalW}" height="${totalH}" fill="#f8fafc"/>`;

  const colTitle = (x, w, title, sub) =>
    `<rect x="${x}" y="${MARGIN}" width="${w}" height="${totalH - MARGIN*2}" rx="12" fill="#fff" stroke="#e2e5ea"/>
     <text class="gp-head" x="${x + w/2}" y="${MARGIN + 24}" text-anchor="middle">${esc(title)}</text>
     <text class="gp-sub" x="${x + w/2}" y="${MARGIN + 38}" text-anchor="middle">${esc(sub)}</text>`;

  svg += colTitle(MARGIN, NW, page.name, "本页面");
  extList.forEach((g, gi) => {
    const x = MARGIN + COL_W * (gi + 1);
    const ext = g.proj.id !== curProjectId;
    svg += colTitle(x, NW, (ext ? g.proj.name + " / " : "") + g.page.name, ext ? "跨项目" : "同项目其他页面");
  });

  function nodeSvg(f, isExt) {
    const p = pos.get(f.id);
    if (!p) return "";
    const tc = f.threats.length;
    const meta = `${tc} 威胁 · ${f.flows.length} 数据流 · ${f.rels.length} 上下游`;
    const click = isExt ? "" : ` data-goto="${f.id}"`;
    return `<g class="fnode"${click} style="${isExt?"":"cursor:pointer"}">
      <rect class="gfbox ${isExt?"ext":""}" x="${p.x}" y="${p.y}" width="${NW}" height="${NH}" rx="8"/>
      <text class="gfname" x="${p.x+12}" y="${p.y+23}">${esc(f.name)}</text>
      <text class="gfmeta" x="${p.x+12}" y="${p.y+42}">${esc(meta)}</text>
      <title>${esc(f.name)}（${tc} 项威胁）${f.note?" - "+esc(f.note):""}</title>
    </g>`;
  }
  funcs.forEach(f => svg += nodeSvg(f, false));
  extList.forEach(g => g.nodes.forEach(n => svg += nodeSvg(n.func, true)));

  svg += `<g id="gedges">`;
  edges.forEach(e => {
    const toId = e.to.func ? e.to.func.id : e.to.id;
    const from = pos.get(e.from.id), to = pos.get(toId);
    if (!from || !to) return;
    let x1, y1, x2, y2;
    if (to.x > from.x) { x1 = from.x + NW; y1 = from.y + NH/2; x2 = to.x; y2 = to.y + NH/2; }
    else if (to.x < from.x) { x1 = from.x; y1 = from.y + NH/2; x2 = to.x + NW; y2 = to.y + NH/2; }
    else { x1 = from.x + NW/2; y1 = e.it.direction === "downstream" ? from.y + NH : from.y; x2 = to.x + NW/2; y2 = e.it.direction === "downstream" ? to.y : to.y + NH; }
    const dx = Math.max(Math.abs(x2 - x1) / 2, 40);
    const c1 = e.it.direction === "downstream" ? [x1 + (x2 > x1 ? dx : x2 < x1 ? -dx : 0), y1] : [x1 - (x2 > x1 ? dx : x2 < x1 ? -dx : 0), y1];
    const c2 = e.it.direction === "downstream" ? [x2 - (x2 > x1 ? dx : x2 < x1 ? -dx : 0), y2] : [x2 + (x2 > x1 ? dx : x2 < x1 ? -dx : 0), y2];
    const cls = e.kind === "flow" ? "" : " rel";
    const mk = e.kind === "flow" ? "arr" : "arrg";
    let path;
    if (e.it.direction === "downstream") path = `M ${x1} ${y1} C ${c1[0]} ${c1[1]}, ${c2[0]} ${c2[1]}, ${x2} ${y2}`;
    else path = `M ${x2} ${y2} C ${c2[0]} ${c2[1]}, ${c1[0]} ${c1[1]}, ${x1} ${y1}`;
    const lbl = e.kind === "flow"
      ? (e.it.dataDesc || "") + (e.it.protocol ? " [" + e.it.protocol + "]" : "") + ((e.it.threats||[]).length ? " (" + e.it.threats.length + "威胁)" : "")
      : (e.it.direction === "downstream" ? "依赖" : "上游");
    const lx = (Math.min(x1,x2) + Math.max(x1,x2)) / 2, ly = (y1 + y2) / 2 - 4;
    svg += `<path class="gedge${cls}" d="${path}" marker-end="url(#${mk})"/>`;
    if (e.kind === "flow" && lbl)
      svg += `<text class="glabel" x="${lx}" y="${ly}" text-anchor="middle">${esc(lbl)}</text>`;
  });
  svg += `</g></svg>`;

  box.innerHTML = `<div class="graph-legend">
      <span class="k"><span class="lg-line"></span>数据流（箭头=数据方向）</span>
      <span class="k"><span class="lg-dash"></span>上下游依赖</span>
      <span class="k">虚线框 = 外部功能</span>
      <span class="k">点击本页面功能可跳到其所属页面编辑</span>
    </div>${svg}`;
  box.querySelectorAll("[data-goto]").forEach(n => n.onclick = () => {
    const hit = getFunc(n.dataset.goto);
    if (hit) { currentPageId = hit.page.id; renderAll(); }
  });
}

/* ============ 视图切换 ============ */
function switchView(v) {
  curView = v;
  $("tabDetail").className = "tab" + (v === "detail" ? " active" : "");
  $("tabGraph").className = "tab" + (v === "graph" ? " active" : "");
  $("contentDetail").style.display = v === "detail" ? "" : "none";
  $("contentGraph").style.display = v === "graph" ? "" : "none";
  renderAll();
}
$("tabDetail").onclick = () => switchView("detail");
$("tabGraph").onclick = () => switchView("graph");

function renderAll() {
  renderProjSelect();
  renderTree();
  if (curView === "graph") renderGraph(); else renderMain();
  refreshStatus();
}
function refreshStatus() {
  const pr = curProject();
  if (!pr) { $("statProject").textContent = "未创建项目"; $("statCounts").textContent = ""; return; }
  const fs = allFuncs();
  const tc = fs.reduce((s, x) => s + x.func.threats.length, 0);
  const fc = fs.reduce((s, x) => s + x.func.flows.length, 0);
  const ftc = fs.reduce((s, x) => s + x.func.flows.reduce((k, fl) => k + (fl.threats||[]).length, 0), 0);
  const idx = projects.indexOf(pr) + 1;
  $("statProject").textContent = `项目（${idx}/${projects.length}）：${pr.name}`;
  $("statCounts").textContent = `页面 ${pr.pages.length} · 功能 ${fs.length} · 威胁 ${tc + (pr.threats||[]).length}（项目级 ${(pr.threats||[]).length}）· 数据流 ${fc}（流威胁 ${ftc}）`;
}

/* ============ 通用文本弹层 ============ */
let textCb = null;
function askText(title, label, value, note, cb, withNote) {
  $("tmTitle").textContent = title; $("tmLabel").textContent = label;
  $("tmInput").value = value || "";
  $("tmNote").value = note || "";
  $("tmNoteRow").style.display = withNote ? "" : "none";
  $("textModal").classList.add("show");
  textCb = cb; $("tmInput").focus();
}
$("tmOk").onclick = () => { const v = $("tmInput").value.trim(); if (!v) { alert("名称不能为空"); return; } $("textModal").classList.remove("show"); textCb(v, $("tmNote").value.trim()); };
$("tmCancel").onclick = () => $("textModal").classList.remove("show");

/* ============ 项目操作 ============ */
$("btnNewProject").onclick = () => {
  askText("新建项目", "项目名称", "", "", (name, note) => {
    const p = normalizeProject({ id: uid("proj"), name, note, createdAt: new Date().toISOString(), updatedAt: "", pages: [] });
    projects.push(p); curProjectId = p.id; currentPageId = null;
    persist(true); renderAll();
  }, true);
};
$("projSelect").onchange = () => {
  curProjectId = $("projSelect").value || null;
  const pr = curProject();
  currentPageId = pr && pr.pages[0] ? pr.pages[0].id : null;
  renderAll();
};
$("btnRenameProj").onclick = () => {
  const pr = curProject(); if (!pr) { alert("请先新建项目"); return; }
  askText("项目改名", "项目名称", pr.name, pr.note, (name, note) => { pr.name = name; pr.note = note; persist(true); renderAll(); }, true);
};
$("btnDelProj").onclick = () => {
  const pr = curProject(); if (!pr) { alert("请先新建项目"); return; }
  if (projects.length > 1 && !confirm(`删除项目"${pr.name}"？其他项目指向它的引用也会被清理`)) return;
  const funcIds = new Set();
  pr.pages.forEach(pg => (pg.funcs || []).forEach(f => funcIds.add(f.id)));
  projects = projects.filter(p => p.id !== pr.id);
  projects.forEach(p => p.pages.forEach(pg => (pg.funcs || []).forEach(f => {
    f.flows = f.flows.filter(fl => !funcIds.has(fl.targetFuncId));
    f.rels = f.rels.filter(r => !funcIds.has(r.targetFuncId));
  })));
  curProjectId = projects[0] ? projects[0].id : null;
  currentPageId = null;
  persist(true); renderAll();
};
$("btnSaveNow").onclick = () => persist(true);
$("btnAddPage").onclick = () => {
  const pr = curProject(); if (!pr) { alert("请先新建项目"); return; }
  askText("新建页面", "页面名称（如 /login 登录页）", "", "", (name, note) => {
    const pg = { id: uid("page"), name, note, funcs: [] };
    pr.pages.push(pg); currentPageId = pg.id; persist(true); renderAll();
  }, true);
};
function renamePage(pid) {
  const pg = getPage(pid);
  askText("页面改名", "页面名称", pg.name, pg.note, (name, note) => { pg.name = name; pg.note = note; persist(); renderAll(); }, true);
}
function delPage(pid) {
  const pg = getPage(pid);
  if (!confirm(`删除页面"${pg.name}"及其下所有功能与威胁关联？`)) return;
  const funcIds = new Set((pg.funcs||[]).map(f => f.id));
  const pr = curProject();
  pr.pages = pr.pages.filter(p => p.id !== pid);
  allFuncsGlobal().forEach(({func}) => {
    func.flows = func.flows.filter(fl => !funcIds.has(fl.targetFuncId));
    func.rels = func.rels.filter(r => !funcIds.has(r.targetFuncId));
  });
  if (currentPageId === pid) currentPageId = pr.pages[0] ? pr.pages[0].id : null;
  persist(); renderAll();
}

/* ============ 功能操作 ============ */
let editingFuncId = null;
function openFuncModal(fid) {
  if (!currentPageId) { alert("请先选择页面"); return; }
  editingFuncId = fid;
  const f = fid ? getFunc(fid).func : null;
  $("fmTitle").textContent = f ? "编辑功能" : "新建功能";
  $("fmName").value = f ? f.name : ""; $("fmNote").value = f ? f.note : "";
  $("funcModal").classList.add("show"); $("fmName").focus();
}
$("fmOk").onclick = () => {
  const name = $("fmName").value.trim(); if (!name) { alert("功能名称不能为空"); return; }
  const page = getPage(currentPageId);
  if (editingFuncId) {
    const f = getFunc(editingFuncId).func; f.name = name; f.note = $("fmNote").value.trim();
  } else {
    page.funcs.push({ id: uid("func"), name, note: $("fmNote").value.trim(), threats: [], flows: [], rels: [] });
  }
  $("funcModal").classList.remove("show"); persist(); renderAll();
};
$("fmCancel").onclick = () => $("funcModal").classList.remove("show");
function delFunc(fid) {
  const hit = getFunc(fid);
  if (!confirm(`删除功能"${hit.func.name}"？`)) return;
  const page = hit.page;
  page.funcs = page.funcs.filter(f => f.id !== fid);
  allFuncsGlobal().forEach(({func}) => {
    func.flows = func.flows.filter(fl => fl.targetFuncId !== fid);
    func.rels = func.rels.filter(r => r.targetFuncId !== fid);
  });
  persist(); renderAll();
}

/* ============ 关系（数据流/上下游）弹层 ============ */
let relCtx = null;
function openRelModal(fid, kind) {
  const f = getFunc(fid).func;
  const others = allFuncsGlobal().filter(x => x.func.id !== fid);
  if (!others.length) { alert("当前没有任何其他功能可建立关系，请先创建更多功能"); return; }
  relCtx = { fid, kind };
  $("rmTitle").textContent = kind === "flow" ? `为"${f.name}"添加数据流` : `为"${f.name}"添加上下游关系`;
  $("rmDir").innerHTML = kind === "flow"
    ? `<option value="downstream">数据流向（本功能 -> 目标）</option><option value="upstream">数据来源（目标 -> 本功能）</option>`
    : `<option value="downstream">下游依赖（本功能依赖目标）</option><option value="upstream">上游（目标依赖本功能）</option>`;
  const cur = curProject();
  let opts = `<optgroup label="本项目：${esc(cur.name)}">` +
    others.filter(x => x.proj.id === curProjectId).map(x => `<option value="${x.func.id}">${esc(x.page.name)} / ${esc(x.func.name)}</option>`).join("") + `</optgroup>`;
  const extProjs = [...new Set(others.filter(x => x.proj.id !== curProjectId).map(x => x.proj.id))];
  extProjs.forEach(pid => {
    const pr = projects.find(p => p.id === pid);
    opts += `<optgroup label="跨项目：${esc(pr.name)}">` +
      others.filter(x => x.proj.id === pid).map(x => `<option value="${x.func.id}">${esc(x.page.name)} / ${esc(x.func.name)}</option>`).join("") + `</optgroup>`;
  });
  $("rmTarget").innerHTML = opts;
  $("rmDataExtra").style.display = kind === "flow" ? "" : "none";
  $("rmDataDesc").value = ""; $("rmProtocol").value = "";
  $("relModal").classList.add("show");
}
$("rmOk").onclick = () => {
  const { fid, kind } = relCtx;
  const f = getFunc(fid).func;
  const target = $("rmTarget").value, direction = $("rmDir").value;
  if (kind === "flow") {
    f.flows.push({ id: uid("flow"), targetFuncId: target, direction, dataDesc: $("rmDataDesc").value.trim(), protocol: $("rmProtocol").value.trim() });
  } else {
    f.rels.push({ id: uid("rel"), targetFuncId: target, direction });
  }
  $("relModal").classList.remove("show"); persist(); renderAll();
};
$("rmCancel").onclick = () => $("relModal").classList.remove("show");

/* ============ 威胁选择弹层（通用：功能/数据流/项目级） ============ */
let threatCtx = null;
/* targetKind: "func" | "flow" | "project"；返回当前威胁数组与所属宿主 */
function threatCtxResolve(ctx) {
  if (ctx.targetKind === "project") {
    const pr = projects.find(p => p.id === ctx.projId) || curProject();
    return { host: pr, list: pr.threats };
  }
  if (ctx.targetKind === "flow") {
    const hit = findFuncGlobal(ctx.fid);
    const fl = hit.func.flows.find(x => x.id === ctx.flowId);
    return { host: { name: `数据流（${hit.func.name} ${fl.direction === "downstream" ? "->" : "←"} ${funcLabel(fl.targetFuncId)}）`, raw: fl }, list: fl.threats };
  }
  const hit = findFuncGlobal(ctx.fid);
  return { host: hit.func, list: hit.func.threats };
}
function openThreatModal(ctx) {
  const { host, list } = threatCtxResolve(ctx);
  threatCtx = Object.assign({ picked: new Set(list.map(t => t.id)) }, ctx);
  $("tmFuncName").textContent = "- " + host.name;
  ["tFilterCat","tFilterStride","tFilterSev"].forEach(i => $(i).value = "");
  $("tFilterQ").value = "";
  renderThreatPickList();
  $("threatModal").classList.add("show");
}
function renderThreatPickList() {
  const cat = $("tFilterCat").value, stride = $("tFilterStride").value, sev = $("tFilterSev").value, q = $("tFilterQ").value.trim().toLowerCase();
  const defaultCat = threatCtx.targetKind === "project" ? "global" : threatCtx.targetKind === "flow" ? "flow" : "";
  const useCat = cat || (threatCtx._touched ? cat : defaultCat);
  const list = THREAT_LIBRARY.filter(t =>
    (!useCat || t.cat === useCat) && (!stride || t.stride === stride) && (!sev || t.sev === sev) &&
    (!q || (t.id + t.title + t.desc + t.ref).toLowerCase().includes(q)));
  $("tmList").innerHTML = list.map(t => `<div class="tm-row ${threatCtx.picked.has(t.id)?"picked":""}" data-tid="${t.id}">
    <input type="checkbox" ${threatCtx.picked.has(t.id)?"checked":""}>
    <div><div class="t-name">${esc(t.id)} ${esc(t.title)}</div>
    <div class="t-tags"><span class="badge sev ${t.sev}">${t.sev}</span> ${STRIDE_NAME[t.stride]} · ${CAT_NAME[t.cat]} · ${esc(t.ref)}</div>
    <div class="t-desc">${esc(t.desc)}</div></div></div>`).join("") || `<div class="empty-tip">无匹配威胁项</div>`;
  $("tmList").querySelectorAll(".tm-row").forEach(row => row.onclick = () => {
    const id = row.dataset.tid;
    if (threatCtx.picked.has(id)) threatCtx.picked.delete(id); else threatCtx.picked.add(id);
    renderThreatPickList();
  });
  $("tmPickedCount").textContent = `已选 ${threatCtx.picked.size} 项`;
}
["tFilterCat","tFilterStride","tFilterSev"].forEach(i => $(i).onchange = () => { threatCtx && (threatCtx._touched = true); renderThreatPickList(); });
$("tFilterQ").oninput = renderThreatPickList;
$("tmConfirm").onclick = () => {
  const { host, list } = threatCtxResolve(threatCtx);
  const kept = list.filter(t => threatCtx.picked.has(t.id));
  const added = [...threatCtx.picked].filter(id => !kept.some(t => t.id === id)).map(id => ({ id, note: "", status: "open" }));
  const merged = kept.concat(added);
  if (threatCtx.targetKind === "project") host.threats = merged;
  else if (threatCtx.targetKind === "flow") host.raw.threats = merged;
  else host.threats = merged;
  $("threatModal").classList.remove("show"); persist(); renderAll();
};
$("tmClose").onclick = () => $("threatModal").classList.remove("show");

/* ============ 导出 JSON / 导入 ============ */
$("btnExportJson").onclick = () => {
  const pr = curProject(); if (!pr) { alert("无项目可导出"); return; }
  const out = JSON.stringify({ format: "threat-model-workbench", version: 1, exportedAt: new Date().toISOString(), project: pr }, null, 2);
  downloadFile(pr.name + "-threat-model.json", out, "application/json");
};
$("btnExportAll").onclick = () => {
  if (!projects.length) { alert("无项目可导出"); return; }
  const out = JSON.stringify({ format: "threat-model-workbench", version: 1, exportedAt: new Date().toISOString(), projects }, null, 2);
  downloadFile("全部威胁模型-" + Date.now() + ".json", out, "application/json");
};
$("btnImport").onclick = () => $("fileInput").click();
$("fileInput").onchange = e => {
  const file = e.target.files[0]; if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(reader.result);
      let list;
      if (Array.isArray(data.projects)) list = data.projects;
      else { const p = data.format === "threat-model-workbench" ? data.project : data; if (!p || !Array.isArray(p.pages)) throw new Error("格式不符"); list = [p]; }
      let last = null;
      list.forEach(p => {
        const np = normalizeProject(p);
        if (projects.some(x => x.id === np.id)) np.id = uid("proj");
        projects.push(np); last = np;
      });
      curProjectId = last.id; currentPageId = last.pages[0] ? last.pages[0].id : null;
      persist(true); renderAll();
      alert(`导入成功：${list.length} 个项目`);
    } catch (err) { alert("导入失败：" + err.message); }
  };
  reader.readAsText(file);
  e.target.value = "";
};
function normalizeProject(p) {
  p.id = p.id || uid("proj");
  p.name = p.name || "未命名项目"; p.note = p.note || "";
  p.createdAt = p.createdAt || new Date().toISOString(); p.updatedAt = p.updatedAt || "";
  p.threats = (p.threats || []).map(t => ({ id: t.id, note: t.note || "", status: t.status || "open" }));
  p.pages = (p.pages || []).map(pg => ({
    id: pg.id || uid("page"), name: pg.name || "未命名页面", note: pg.note || "",
    funcs: (pg.funcs || []).map(f => ({
      id: f.id || uid("func"), name: f.name || "未命名功能", note: f.note || "",
      threats: (f.threats || []).map(t => ({ id: t.id, note: t.note || "", status: t.status || "open" })),
      flows: (f.flows || []).map(x => ({ id: x.id || uid("flow"), targetFuncId: x.targetFuncId, direction: x.direction || "downstream", dataDesc: x.dataDesc || "", protocol: x.protocol || "", threats: (x.threats || []).map(t => ({ id: t.id, note: t.note || "", status: t.status || "open" })) })),
      rels: (f.rels || []).map(x => ({ id: x.id || uid("rel"), targetFuncId: x.targetFuncId, direction: x.direction || "downstream" })),
    })),
  }));
  return p;
}

/* ============ 导出百度脑图 .km（紧凑美化版） ============ */
$("btnExportKm").onclick = () => {
  const pr = curProject(); if (!pr) { alert("无项目可导出"); return; }
  const PRIO = { High: 1, Medium: 2, Low: 3 };
  const node = (text, extra, children) => Object.assign({ data: Object.assign({ text }, extra || {}) }, children && children.length ? { children } : {});
  const threatNodes = (list) => list.map(t => {
    const info = threatInfo(t.id);
    const st = {open:"未处理",mitigated:"已缓解",na:"不适用"}[t.status||"open"];
    const detail = [];
    if (t.status !== "open" || t.note) detail.push(node(`状态：${st}${t.note ? " / " + t.note : ""}`));
    if (info.ref) detail.push(node(`映射：${info.ref}`));
    if (info.desc) detail.push(node(`场景：${info.desc}`));
    if (info.mitig) detail.push(node(`缓解：${info.mitig}`));
    return node(`${info.id} ${info.title}`, {
      priority: PRIO[info.sev] || 2,
      resource: [st],
      expandState: detail.length ? "collapsed" : undefined,
    }, detail);
  });
  const projThreatNodes = threatNodes(pr.threats || []);
  const pageNodes = pr.pages.map(pg => {
    const funcNodes = (pg.funcs || []).map(f => {
      const kids = [];
      threatNodes(f.threats).forEach(n => kids.push(n));
      f.flows.forEach(fl => {
        const arrow = fl.direction === "downstream" ? "数据 ->" : "数据 ←";
        const tail = `${fl.dataDesc ? "（" + fl.dataDesc + "）" : ""}${fl.protocol ? " [" + fl.protocol + "]" : ""}`;
        const flowThreats = threatNodes(fl.threats || []);
        kids.push(node(`${arrow} ${funcLabel(fl.targetFuncId)}${tail}`, { expandState: flowThreats.length ? "collapsed" : undefined }, flowThreats));
      });
      f.rels.forEach(r => {
        kids.push(node(`${r.direction === "downstream" ? "依赖 ->" : "上游 ←"} ${funcLabel(r.targetFuncId)}`));
      });
      return node(f.name + (f.note ? "（" + f.note + "）" : ""), { expandState: "collapsed" }, kids);
    });
    return node(pg.name + (pg.note ? "（" + pg.note + "）" : ""), null, funcNodes);
  });
  const rootChildren = [];
  if (projThreatNodes.length) rootChildren.push(node(`项目级风险（${projThreatNodes.length}）`, { expandState: "collapsed" }, projThreatNodes));
  rootChildren.push(...pageNodes);
  const root = {
    root: node(pr.name, { note: pr.note || undefined }, rootChildren),
    template: "file-catalog",
    theme: "fresh-blue",
    version: "1.4.43",
  };
  downloadFile(pr.name + "-mindmap.km", JSON.stringify(root, null, 2), "application/json");
};

function downloadFile(name, content, type) {
  const a = document.createElement("a");
  const blob = new Blob([content], { type: type + ";charset=utf-8" });
  a.href = URL.createObjectURL(blob);
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}

/* ============ 示例项目（作为独立项目加入） ============ */
$("btnLoadDemo").onclick = () => {
  const existing = projects.find(p => p.name === "云上商城（示例）");
  if (existing && !confirm("已存在示例项目，重新载入将替换它，继续？")) return;
  if (existing) projects = projects.filter(p => p !== existing);
  const mk = (pid, name, note, funcs) => ({ id: pid, name, note, funcs });
  const F = (id, name, note, threats, flows, rels) => ({ id, name, note, threats: threats.map(t => ({ id: t, note: "", status: "open" })), flows, rels });
  const demo = normalizeProject({
    id: uid("proj"), name: "云上商城（示例）", note: "小型电商威胁建模示例",
    createdAt: new Date().toISOString(), updatedAt: "",
    threats: [
      { id: "G-01", note: "用户手机号/地址需标记为敏感数据", status: "open" },
      { id: "G-03", note: "支付密钥统一放 KMS", status: "open" },
      { id: "G-04", note: "npm 依赖需锁定版本+审计", status: "open" },
    ],
    pages: [
      mk("demo-page-login", "/login 登录页", "账号密码 + 短信验证码", [
        F("demo-f-pwd-login", "账号密码登录", "主登录入口", ["EE-S01","PR-S03","PR-S04","EE-S02","PR-R01"],
          [{ id:"demo-fl-1", targetFuncId:"demo-f-session", direction:"downstream", dataDesc:"凭证校验结果", protocol:"内部RPC", threats:[{id:"DF-I01",note:"",status:"open"}] }],
          [{ id:"demo-rl-1", targetFuncId:"demo-f-session", direction:"downstream" }]),
        F("demo-f-sms-code", "短信验证码下发", "注册与找回共用", ["PR-D02","EE-D01"],
          [{ id:"demo-fl-2", targetFuncId:"demo-f-sms-provider", direction:"downstream", dataDesc:"手机号+模板", protocol:"HTTPS", threats:[{id:"DF-I02",note:"手机号在URL中泄露",status:"open"},{id:"DF-S02",note:"",status:"open"}] }],
          [{ id:"demo-rl-2", targetFuncId:"demo-f-sms-provider", direction:"downstream" }]),
      ]),
      mk("demo-page-product", "/product 商品详情页", "展示与评价", [
        F("demo-f-detail", "商品信息展示", "含富文本描述", ["PR-E01","PR-I02","EE-T01"], [], []),
        F("demo-f-review", "评价提交", "文本评价", ["EE-T01","PR-D01","PR-E04"], [], []),
        F("demo-f-favorite", "收藏/加购", "", ["PR-E04"], [], []),
      ]),
      mk("demo-page-pay", "/pay 收银台页", "下单支付", [
        F("demo-f-checkout", "订单提交", "金额计算", ["PR-E04","PR-E01","DF-T02"],
          [{ id:"demo-fl-3", targetFuncId:"demo-f-order-db", direction:"downstream", dataDesc:"订单数据", protocol:"SQL/TLS" }],
          [{ id:"demo-rl-3", targetFuncId:"demo-f-favorite", direction:"upstream" }]),
        F("demo-f-pay-callback", "支付回调处理", "支付宝/微信异步通知", ["EE-T03","DF-T01","DF-S02"],
          [{ id:"demo-fl-4", targetFuncId:"demo-f-pay-provider", direction:"downstream", dataDesc:"支付单创建/验签", protocol:"HTTPS", threats:[{id:"DF-S01",note:"回调必须验签+防重放",status:"open"},{id:"DF-T01",note:"",status:"open"}] }],
          [{ id:"demo-rl-4", targetFuncId:"demo-f-order-db", direction:"downstream" }]),
      ]),
      mk("demo-page-admin", "admin 订单管理", "后台子域", [
        F("demo-f-refund", "退款操作", "高权限操作", ["EE-E02","PR-E02","DS-R01"], [],
          [{ id:"demo-rl-5", targetFuncId:"demo-f-order-db", direction:"upstream" }]),
        F("demo-f-export", "订单导出", "含用户PII", ["PR-R02","DS-I02","DS-I03","PR-D02"], [], []),
      ]),
    ],
  });
  const infra = mk("demo-page-infra", "（基础设施）", "承载内部功能", [
    F("demo-f-session", "会话服务", "内部功能", ["PR-S02"], [], []),
    F("demo-f-sms-provider", "短信网关对接", "内部功能", ["DF-S02"], [], []),
    F("demo-f-order-db", "订单库访问", "内部功能", ["DS-E01","DS-I01"], [], []),
    F("demo-f-pay-provider", "支付渠道对接", "内部功能", ["EE-D01"], [], []),
  ]);
  demo.pages.push(infra);
  projects.push(demo);
  curProjectId = demo.id; currentPageId = demo.pages[0].id;
  persist(true); renderAll();
};

/* ============ 启动 ============ */
window.openFuncModal = openFuncModal;
load();
renderAll();
