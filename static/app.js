/* JS API Hunter — 前端逻辑
 *
 * 结构：上半部分输入（左：目标网址 / 右：扫描选项），下半部分输出。
 * 目标网址支持多行 —— 逐个目标顺序扫描，每个目标一个后端任务；
 * 结果可以按目标切换，也可以合并成一份看/导出。
 */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, txt) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (txt != null) n.textContent = txt;
    return n;
  };

  const PAGE_SIZES = [20, 50, 100, 200];

  const state = {
    targets: [],       // [{ url, tid, status, data, error }]
    active: "",        // "" = 全部合并；否则是某个 target.url
    viewIds: [],       // 当前视图对应的 task_id 列表（导出用）
    taskId: null,      // 正在跑的任务（停止用）
    scanOne: null,
    cancelled: false,
    scanning: false,
    data: null,
    rows: [],
    method: "",
    source: "",
    ctx: "",
    text: "",
    hideThird: true,
    hidePages: true,
    onlyParams: false,
    onlyHigh: false,
    onlyRuntime: false,
    sort: { key: "confidence", dir: "desc" },
    page: 1,
    pageSize: 50,
    openRow: null,
    stopTimer: null,
  };

  /* ---------------- 工具 ---------------- */

  function toast(msg) {
    let t = document.querySelector(".toast");
    if (!t) {
      t = el("div", "toast");
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(t._tm);
    t._tm = setTimeout(() => t.classList.remove("show"), 1800);
  }

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      const ta = el("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch {}
      ta.remove();
      return true;
    }
  }

  const fmtSize = (b) => {
    if (!b) return "—";
    if (b < 1024) return b + " B";
    if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
    return (b / 1048576).toFixed(2) + " MB";
  };
  const shortSrc = (s) => {
    if (!s) return "—";
    const clean = s.split("?")[0];
    const parts = clean.split("/");
    const tail = parts.slice(-2).join("/");
    return tail || clean;
  };
  const hostOf = (u) => {
    if (!u) return "";
    try {
      const x = new URL(/^https?:\/\//i.test(u) ? u : "https://" + u);
      return x.host;
    } catch {
      return String(u).split("//").pop().split("/")[0];
    }
  };
  const methodCls = (m) =>
    ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(m) ? "m-" + m : "m-OTHER";

  // 结果里的接口大多是相对路径（/api/user/list），要「跳转」就得拼成绝对地址。
  // 合并视图下每个接口自带 target（它是哪个站点扫出来的），优先用它 ——
  // 否则拿 data.target 会拼成 "url1 , url2/xxx" 这种废地址。
  function absoluteUrl(r) {
    const u = r.url || "";
    if (/^https?:\/\//i.test(u)) return u;
    if (u.startsWith("//")) return "https:" + u;
    const origin = r.target || (state.data && state.data.target) || "";
    if (!origin) return u;
    return String(origin).replace(/\/+$/, "") + (u.startsWith("/") ? u : "/" + u);
  }

  const JUMP_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
    'stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>' +
    '<path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg>';

  function openEndpoint(url) {
    window.open(url, "_blank", "noopener,noreferrer");
  }

  function highlight(text, needle) {
    const frag = document.createDocumentFragment();
    if (!needle) { frag.appendChild(document.createTextNode(text)); return frag; }
    const low = text.toLowerCase(), n = needle.toLowerCase();
    let i = 0;
    while (true) {
      const p = low.indexOf(n, i);
      if (p < 0) { frag.appendChild(document.createTextNode(text.slice(i))); break; }
      frag.appendChild(document.createTextNode(text.slice(i, p)));
      frag.appendChild(el("mark", null, text.slice(p, p + needle.length)));
      i = p + needle.length;
    }
    return frag;
  }

  /* ---------------- 目标网址解析 ---------------- */

  const URL_RE = /^https?:\/\/[^\s/?#.]+(?:[^\s]*)$/i;

  function normalizeUrl(line) {
    const s = line.trim().replace(/\s+/g, "");
    if (!s) return "";
    if (/^https?:\/\//i.test(s)) return s;
    if (/^\/\//.test(s)) return "https:" + s;
    return "https://" + s;
  }

  function parseUrls(raw) {
    const lines = String(raw || "")
      .split(/[\r\n]+/)
      .map((x) => x.trim())
      .filter((x) => x && !x.startsWith("#"));
    const fixed = [];
    const out = [];
    const bad = [];
    lines.forEach((line) => {
      const noScheme = !/^https?:\/\//i.test(line);
      const u = normalizeUrl(line);
      if (!URL_RE.test(u) || !hostOf(u)) { bad.push(line); return; }
      if (noScheme) fixed.push(u);
      if (!out.includes(u)) out.push(u);
    });
    return { urls: out, fixed, bad };
  }

  function refreshUrlMeta() {
    const { urls, fixed, bad } = parseUrls($("urlInput").value);
    const shell = $("urlShell");
    $("urlCount").textContent = urls.length + " 个目标";
    shell.classList.toggle("ok", urls.length > 0 && bad.length === 0);
    shell.classList.toggle("bad", bad.length > 0);
    const bits = [];
    if (bad.length) bits.push(`${bad.length} 行不是有效地址，会被跳过`);
    else if (fixed.length) bits.push(`${fixed.length} 行缺协议，按 https:// 处理`);
    const w = $("urlWarn");
    w.textContent = bits.join(" · ");
    w.classList.toggle("hidden", !bits.length);
    refreshMini();          // 摘要条跟网址走（真实输入事件会冒泡到 inputCard，这里兜一手）
    return urls;
  }

  /* ---------------- 选项 ---------------- */

  const OPT_IDS = [
    "optCrawl", "optMaxFiles", "optConcurrency", "optMinScore", "optTimeout",
    "optRuntimeSettle", "optRuntimeFollow", "optRuntimeJsBudget",
    "optCookies", "optHeaders", "optProxy",
    "optRuntime", "optRuntimeShow", "optRuntimeJs", "optOpenapi",
    "optSourcemap", "optChunks", "optJsFuzz", "optVerifySsl",
  ];
  const DEFAULTS = {};

  function snapshotDefaults() {
    OPT_IDS.forEach((id) => {
      const n = $(id);
      DEFAULTS[id] = n.type === "checkbox" ? n.checked : n.value;
    });
  }

  function resetOptions() {
    OPT_IDS.forEach((id) => {
      const n = $(id);
      if (n.type === "checkbox") n.checked = DEFAULTS[id];
      else n.value = DEFAULTS[id];
    });
    toast("选项已重置为默认值");
  }

  function gatherOptions() {
    return {
      concurrency: +$("optConcurrency").value,
      timeout: +$("optTimeout").value,
      max_files: +$("optMaxFiles").value,
      min_score: +$("optMinScore").value,
      crawl: +$("optCrawl").value,
      sourcemap: $("optSourcemap").checked,
      chunks: $("optChunks").checked,
      openapi: $("optOpenapi").checked,
      js_fuzz: $("optJsFuzz").checked,
      verify_ssl: $("optVerifySsl").checked,
      runtime: $("optRuntime").checked,
      runtime_headless: !$("optRuntimeShow").checked,
      runtime_js: $("optRuntimeJs").checked,
      runtime_settle: +$("optRuntimeSettle").value,
      runtime_follow: +$("optRuntimeFollow").value,
      runtime_js_budget: +$("optRuntimeJsBudget").value,
      cookies: $("optCookies").value,
      headers: $("optHeaders").value,
      proxy: $("optProxy").value.trim(),
    };
  }

  /* ---------------- 状态与日志 ---------------- */

  function setStatus(kind, text) {
    const p = $("statusPill");
    p.dataset.state = kind;
    p.querySelector("span").textContent = text;
  }

  function addLog(msg) {
    const box = $("log");
    const d = el("div");
    d.appendChild(el("time", null, new Date().toLocaleTimeString("zh-CN", { hour12: false })));
    d.appendChild(el("span", null, msg));
    box.appendChild(d);
    box.scrollTop = box.scrollHeight;
    while (box.children.length > 400) box.removeChild(box.firstChild);
  }

  /* ---------------- 输入区折叠 + 摘要条 ---------------- */

  let hintClosed = false;   // 蓝色提示框一旦关掉就不再弹（它占两行）

  function setInputCollapsed(c) {
    $("inputCard").classList.toggle("collapsed", c);
    $("collapseBtn").textContent = c ? "展开 ▾" : "收起 ▴";
    $("collapseBtn").title = c ? "展开输入区（改网址 / 选项）" : "收起输入区，把高度让给结果";
  }

  // 摘要条上的「选项」一栏：只列出和默认值不一样的，一眼看出这次改了什么
  function miniOptsText() {
    const diff = [];
    OPT_IDS.forEach((id) => {
      const n = $(id);
      const cur = n.type === "checkbox" ? n.checked : n.value;
      if (String(cur) === String(DEFAULTS[id])) return;
      const label = (n.previousElementSibling && n.previousElementSibling.textContent)
        || (n.closest("label") && n.closest("label").querySelector("span")
            ? n.closest("label").querySelector("span").textContent : id)
        || id;
      const short = label.replace(/[^A-Za-z\u4e00-\u9fa5]/g, "").slice(0, 6) || id;
      diff.push(n.type === "checkbox" ? `${short}${cur ? "开" : "关"}` : `${short} ${cur}`);
    });
    return diff.length ? diff.join(" · ") : "默认";
  }

  function refreshMini() {
    const { urls } = parseUrls($("urlInput").value);
    const mt = $("miniTarget");
    mt.textContent = urls.length === 0
      ? "未填写"
      : urls.length === 1
        ? urls[0].replace(/^https?:\/\//, "")
        : `${urls.length} 个目标 · ${urls.map(hostOf).join("、")}`;
    mt.title = urls.join("\n");
    $("miniOpts").textContent = miniOptsText();
  }

  /* ---------------- 扫描 ---------------- */

  async function startScan() {
    if (state.scanning) return;
    const urls = refreshUrlMeta();
    if (!urls.length) { toast("请先填入至少一个有效网址"); $("urlInput").focus(); return; }

    const opts = gatherOptions();
    resetResults();

    // 开扫就把输入区收起来 —— 上面那一大块只在改配置时才需要
    setInputCollapsed(true);

    state.cancelled = false;
    state.scanning = true;
    state.targets = urls.map((u) => ({ url: u, tid: null, status: "pending", data: null, error: "" }));
    state.active = "";
    renderTargetChips();

    setStatus("run", "分析中");
    $("scanBtn").disabled = true;
    $("cancelBtn").classList.remove("hidden");
    $("progressCard").classList.remove("hidden");
    $("tips").classList.add("hidden");
    addLog(`共提交 ${urls.length} 个目标，顺序执行`);

    for (let i = 0; i < state.targets.length; i++) {
      if (state.cancelled) break;
      const t = state.targets[i];
      t.status = "running";
      renderTargetChips();
      setStatus("run", `分析中 ${i + 1}/${state.targets.length}`);
      $("progLabel").textContent = `正在分析 ${hostOf(t.url)}（${i + 1}/${state.targets.length}）`;
      addLog(`[${i + 1}/${state.targets.length}] ${t.url}`);

      const res = await runOne(t.url, opts);
      t.tid = res.tid || null;
      t.status = res.status;
      t.data = res.data || null;
      t.error = res.error || "";
      renderTargetChips();

      if (t.status === "error") addLog(`× ${hostOf(t.url)} 失败：${t.error}`);
      else if (t.status === "cancelled") addLog(`× ${hostOf(t.url)} 已中止（保留部分结果）`);

      // 每完成一个目标就刷一次 —— 多目标时不用等到全部跑完才看到东西
      renderAll(buildView());
      if (state.cancelled) break;
    }

    finalize();
  }

  function resetResults() {
    if (state.stopTimer) { clearTimeout(state.stopTimer); state.stopTimer = null; }
    state.data = null;
    state.rows = [];
    state.method = "";
    state.source = "";
    state.ctx = "";
    state.text = "";
    state.hideThird = true;
    state.hidePages = true;
    state.onlyParams = false;
    state.onlyHigh = false;
    state.onlyRuntime = false;
    state.page = 1;
    state.openRow = null;
    state.viewIds = [];
    $("results").classList.add("hidden");
    $("log").innerHTML = "";
    $("barFill").style.width = "0";
    $("progSpinner").style.display = "";
    $("progLabel").textContent = "正在分析…";
    $("progMeta").textContent = "0 个接口 · 0 个文件 · 0.0s";
    $("filterText").value = "";
    $("onlyWithParams").checked = false;
    $("onlyHighConf").checked = false;
    $("onlyRuntime").checked = false;
    $("hideThird").checked = true;
    $("hidePages").checked = true;
  }

  function finalize() {
    state.scanning = false;
    const stopped = state.cancelled;
    $("cancelBtn").classList.add("hidden");
    $("scanBtn").disabled = false;
    $("progSpinner").style.display = "none";
    $("progLabel").textContent = stopped ? "已停止" : "全部完成";
    $("barFill").style.width = "100%";

    const ok = state.targets.filter((t) => t.data).length;
    const total = state.targets.reduce((a, t) => a + ((t.data && t.data.stats.endpoints) || 0), 0);
    if (stopped) {
      setStatus("idle", `已停止 · ${ok} 个目标有结果`);
      addLog(`已停止 —— 保留 ${ok} 个目标、${total} 个接口`);
    } else {
      const bad = state.targets.filter((t) => t.status === "error").length;
      setStatus(bad ? "err" : "ok", `${bad ? bad + " 个失败 · " : ""}完成 · ${total} 个接口`);
      addLog(`全部完成：${ok} 个目标，共 ${total} 个接口`);
    }
    setTimeout(() => $("progressCard").classList.add("hidden"), 1400);
  }

  /**
   * 跑一个目标，返回 { status, data, error, tid }。
   * 关键点与服务端约定一致：
   *  - 只有收到 `end` 事件才认为结束，避免 SSE 抖动被当成「跑完了」；
   *  - EventSource 自己会重连，先让 it 退避几次，真 CLOSED 或重试超限才兜底；
   *  - 取消走同一个 end 通道，中止前的结果照样拿得到。
   */
  function runOne(url, opts) {
    return new Promise((resolve) => {
      let settled = false;
      const done = (payload) => {
        if (settled) return;
        settled = true;
        state.runOne = null;
        resolve(payload);
      };
      state.runOne = () => done({ status: "cancelled", error: "停止信号已发出但未等到服务端收尾", tid: state.taskId });

      const pull = (tid, status, fallbackErr) => {
        fetch(`/api/scan/${tid}/result`)
          .then((x) => x.json())
          .then((rr) => {
            if (rr.status === "error") done({ status: "error", error: rr.error, tid });
            else if (rr.data) done({ status, data: rr.data, tid });
            else done({ status: "error", error: fallbackErr || "无结果", tid });
          })
          .catch((e) => done({ status: "error", error: fallbackErr || e.message, tid }));
      };

      (async () => {
        let tid;
        try {
          const r = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...opts, url }),
          });
          if (!r.ok) throw new Error("HTTP " + r.status);
          tid = (await r.json()).task_id;
        } catch (e) {
          done({ status: "error", error: "启动失败：" + e.message });
          return;
        }
        state.taskId = tid;

        const es = new EventSource(`/api/scan/${tid}/events`);
        let retries = 0;

        es.onmessage = (ev) => {
          let m;
          try { m = JSON.parse(ev.data); } catch { return; }
          if (m.event === "open") return;

          if (m.event === "end") {
            es.close();
            pull(tid, m.status || "done");
            return;
          }
          if (m.message) addLog(m.message);
          if (typeof m.progress === "number") {
            $("barFill").style.width = Math.round(m.progress * 100) + "%";
          }
          $("progMeta").textContent =
            `${m.endpoints || 0} 个接口 · ${m.files || 0} 个文件 · ${(m.time || 0).toFixed(1)}s`;
        };

        es.onerror = () => {
          if (settled) return;
          retries += 1;
          if (es.readyState === EventSource.CLOSED || retries > 6) {
            es.close();
            pull(tid, "done", "连接中断且没有结果");
          }
        };
      })();
    });
  }

  /* ---------------- 视图拼装（单目标 / 合并）---------------- */

  function buildView() {
    const ready = state.targets.filter((t) => t.data);
    const picked = state.active ? ready.filter((t) => t.url === state.active) : ready;
    state.viewIds = picked.map((t) => t.tid).filter(Boolean);
    if (!picked.length) return null;
    if (picked.length === 1) return { ...picked[0].data, _merged: false, _picked: picked };

    const EPS = new Map(), HOSTS = new Map(), BASE = new Map(), FIND = new Map(), RES = new Map();
    const stats = {};
    let elapsed = 0;

    picked.forEach((t) => {
      const d = t.data;
      elapsed += Number(d.elapsed) || 0;
      Object.entries(d.stats || {}).forEach(([k, v]) => {
        if (typeof v === "number") stats[k] = (stats[k] || 0) + v;
      });
      (d.endpoints || []).forEach((e) => {
        const key = e.method + " " + e.url;
        const cur = EPS.get(key);
        if (!cur) { EPS.set(key, { ...e, target: t.url }); return; }
        const have = new Set((cur.params || []).map((p) => p.name));
        (e.params || []).forEach((p) => { if (!have.has(p.name)) { cur.params.push(p); have.add(p.name); } });
        cur.confidence = Math.max(cur.confidence || 0, e.confidence || 0);
        if (e.runtime_hit) cur.runtime_hit = true;
      });
      (d.hosts || []).forEach((h) => {
        const cur = HOSTS.get(h.host);
        if (cur) cur.count = (cur.count || 0) + (h.count || 0);
        else HOSTS.set(h.host, { ...h });
      });
      (d.base_urls || []).forEach((b) => BASE.set(b.key + "\u0000" + b.value, { ...b }));
      (d.findings || []).forEach((f) => FIND.set(f.kind + "\u0000" + f.key + "\u0000" + f.value, { ...f }));
      (d.resources || []).forEach((r) => RES.set(r.url, { ...r }));
    });

    const endpoints = [...EPS.values()].sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
    stats.endpoints = endpoints.length;
    stats.params = endpoints.reduce((a, e) => a + (e.params || []).length, 0);
    stats.hosts = HOSTS.size;
    stats.findings = FIND.size;
    delete stats.elapsed;

    const by = (k) => endpoints.reduce((m, e) => (m[e[k] || ""] = (m[e[k] || ""] || 0) + 1, m), {});

    return {
      target: picked.map((t) => t.url).join(" , "),
      elapsed: Math.round(elapsed * 10) / 10,
      endpoints,
      hosts: [...HOSTS.values()].sort((a, b) => (b.count || 0) - (a.count || 0)),
      base_urls: [...BASE.values()],
      findings: [...FIND.values()],
      resources: [...RES.values()],
      stats,
      notes: picked.flatMap((t) => t.data.notes || []),
      errors: picked.flatMap((t) => t.data.errors || []),
      by_method: by("method"),
      by_ctx: by("ctx_type"),
      runtime_channel: picked.map((t) => t.data.runtime_channel).find(Boolean) || "",
      base_prefix: picked.map((t) => t.data.base_prefix).find(Boolean) || "",
      routes: picked.reduce((a, t) => a + ((t.data.routes || []).length), 0),
      vue_version: picked.map((t) => t.data.vue_version).find(Boolean) || "",
      _merged: true,
      _picked: picked,
    };
  }

  function switchTarget(url) {
    state.active = state.active === url ? "" : url;
    state.page = 1;
    renderTargetChips();
    renderAll(buildView());
  }

  function renderTargetChips() {
    const box = $("targetChips");
    box.innerHTML = "";
    const ready = state.targets.filter((t) => t.data);
    if (ready.length < 2) { box.classList.add("hidden"); return; }
    box.classList.remove("hidden");

    const all = el("button", "tchip" + (state.active === "" ? " on" : ""));
    all.appendChild(el("i"));
    all.appendChild(el("span", null, `全部 ${ready.length}`));
    all.title = "合并查看所有目标（同一接口只算一条）";
    all.onclick = () => { state.active = ""; state.page = 1; renderTargetChips(); renderAll(buildView()); };
    box.appendChild(all);

    state.targets.forEach((t) => {
      if (!t.data && t.status !== "error") return;
      const b = el("button", "tchip" + (state.active === t.url ? " on" : ""));
      b.dataset.st = t.status;
      b.appendChild(el("i"));
      b.appendChild(el("span", null, hostOf(t.url)));
      b.title = t.url + (t.error ? "\n错误：" + t.error : "");
      b.onclick = () => { state.active = t.url; state.page = 1; renderTargetChips(); renderAll(buildView()); };
      box.appendChild(b);
    });
  }

  /* ---------------- 渲染 ---------------- */

  function renderAll(d) {
    if (!d) return;
    state.data = d;

    const s = d.stats || {};
    const rtConfirmed = s.runtime_confirmed || 0;
    const cards = [
      ["接口总数", s.endpoints || 0, true],
      ["运行时确认", rtConfirmed, rtConfirmed > 0],
      ["实载 JS 补抓", s.runtime_js_added || 0, (s.runtime_js_added || 0) > 0],
      ["参数总数", s.params || 0],
      ["JS 文件", s.js_files || 0],
      ["接口文档", s.openapi || 0, (s.openapi || 0) > 0],
      ["sourcemap", s.sourcemaps || 0],
      ["域名", s.hosts || 0],
      ["凭证/鉴权字段", s.findings || 0],
      ["耗时(秒)", d.elapsed || 0],
    ];
    const box = $("stats");
    box.innerHTML = "";
    cards.forEach(([l, n, hi]) => {
      const c = el("div", "stat" + (hi ? " hi" : ""));
      c.appendChild(el("div", "n", String(n ?? 0)));
      c.appendChild(el("div", "l", l));
      box.appendChild(c);
    });

    const bh = $("baseHint");
    const bits = [];
    if (d.base_prefix) {
      const n = (d.endpoints || []).filter((r) => r.url.startsWith(d.base_prefix + "/")).length;
      bits.push(
        `检测到运行时 API 前缀 <b>${d.base_prefix}</b> —— 源码里写 <code>url: "xxx/yyy"</code>，` +
        `实际请求是 <code>${d.base_prefix}/xxx/yyy</code>。已为 <b>${n}</b> 个接口补上该前缀。`
      );
    }
    if (s.runtime_hits) {
      const only = s.runtime_only || 0;
      bits.push(
        `运行时采集用 <b>${d.runtime_channel || "浏览器"}</b> 打开了页面，` +
        `捕获 <b>${s.runtime_hits}</b> 个真实请求，` +
        `<b>${rtConfirmed}</b> 个接口得到真实地址确认` +
        (only ? `（其中 <b>${only}</b> 个是静态分析完全没找到的）` : "") + `。`
      );
    }
    if (s.runtime_js_added) {
      bits.push(
        `浏览器实际加载了 <b>${s.runtime_scripts || 0}</b> 个脚本，其中 <b>${s.runtime_js_added}</b> 个` +
        `是静态分析没抓到的（懒加载 chunk），已用独立配额回灌补抓。`
      );
    }
    if (s.routes) {
      const pg = (d.endpoints || []).filter((r) => r.page && r.page_src === "route").length;
      bits.push(
        `从前端路由表读到 <b>${s.routes}</b> 条路由` +
        (d.vue_version ? `（Vue ${d.vue_version}）` : "") +
        `，据此确认 <b>${pg}</b> 个条目其实是页面路由而非接口。`
      );
    }
    if (bits.length && !hintClosed) {
      bh.innerHTML = "";
      const body = el("div", "hint-body");
      bits.forEach((x) => {
        const d = el("div");
        d.innerHTML = x;
        body.appendChild(d);
      });
      const x = el("button", "hint-x", "×");
      x.title = "关闭这条提示";
      x.onclick = () => { hintClosed = true; bh.classList.add("hidden"); };
      bh.appendChild(body);
      bh.appendChild(x);
      bh.classList.remove("hidden");
    } else {
      bh.classList.add("hidden");
    }

    $("tabCountEp").textContent = s.endpoints || 0;
    $("tabCountHost").textContent = (d.hosts || []).length;
    $("tabCountBase").textContent = (d.base_urls || []).length;
    $("tabCountFind").textContent = (d.findings || []).length;
    $("tabCountRes").textContent = (d.resources || []).length;

    state.rows = d.endpoints || [];
    buildMethodChips(d.by_method || {});
    buildCtxFilter(d.by_ctx || {});
    buildSourceFilter(state.rows);
    renderEndpoints();
    renderHosts(d.hosts || []);
    renderBase(d.base_urls || []);
    renderFindings(d.findings || []);
    renderResources(d.resources || []);

    const scope = state.active
      ? hostOf(state.active)
      : (d._picked && d._picked.length > 1 ? `全部 ${d._picked.length} 个目标` : hostOf(d.target));
    $("exportScope").textContent = "导出范围：" + scope;

    $("results").classList.remove("hidden");
  }

  function buildMethodChips(by) {
    const box = $("methodChips");
    box.innerHTML = "";
    const all = [["", state.rows.length], ...Object.entries(by).sort((a, b) => b[1] - a[1])];
    all.forEach(([m, c]) => {
      const b = el("button", "chip" + (state.method === m ? " on" : ""), m || "全部");
      b.title = c + " 个";
      b.onclick = () => {
        state.method = m;
        state.page = 1;
        [...box.children].forEach((x) => x.classList.remove("on"));
        b.classList.add("on");
        renderEndpoints();
        resetTableScroll();
      };
      box.appendChild(b);
    });
  }

  const CTX_LABEL = {
    axios: "axios/实例方法", http: "实例方法", fetch: "fetch", xhr: "XMLHttpRequest",
    jquery: "jQuery", call: "封装函数", assign: "配置字段", location: "location",
    ws: "WebSocket", websocket: "WebSocket", beacon: "sendBeacon",
    eventsource: "EventSource", openapi: "接口文档", runtime: "运行时", literal: "裸字符串",
  };

  function buildCtxFilter(by) {
    const sel = $("filterCtx");
    sel.innerHTML = "";
    sel.appendChild(new Option("全部触发方式", ""));
    Object.entries(by)
      .sort((a, b) => b[1] - a[1])
      .forEach(([k, c]) => sel.appendChild(new Option(`${CTX_LABEL[k] || k}（${c}）`, k)));
    sel.value = state.ctx || "";
    sel.onchange = () => { state.ctx = sel.value; state.page = 1; renderEndpoints(); resetTableScroll(); };
  }

  function buildSourceFilter(rows) {
    const sel = $("filterSource");
    const counts = new Map();
    rows.forEach((r) => counts.set(r.source, (counts.get(r.source) || 0) + 1));
    const list = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    sel.innerHTML = "";
    sel.appendChild(new Option("全部来源（" + rows.length + "）", ""));
    list.forEach(([s, c]) => sel.appendChild(new Option(shortSrc(s) + "（" + c + "）", s)));
    sel.value = state.source || "";
    sel.onchange = () => { state.source = sel.value; state.page = 1; renderEndpoints(); resetTableScroll(); };
  }

  function filtered() {
    const q = state.text.toLowerCase();
    const rows = state.rows.filter((r) => {
      if (state.method && r.method !== state.method) return false;
      if (state.source && r.source !== state.source) return false;
      if (state.ctx && r.ctx_type !== state.ctx) return false;
      if (state.hideThird && r.third_party) return false;
      if (state.hidePages && r.page) return false;
      if (state.onlyRuntime && !r.runtime_hit) return false;
      if (state.onlyParams && !(r.params || []).length) return false;
      if (state.onlyHigh && r.confidence < 70) return false;
      if (!q) return true;
      if (r.url.toLowerCase().includes(q)) return true;
      if ((r.params || []).some((p) => p.name.toLowerCase().includes(q))) return true;
      if ((r.source || "").toLowerCase().includes(q)) return true;
      if ((r.target || "").toLowerCase().includes(q)) return true;
      return false;
    });
    const { key, dir } = state.sort;
    const mul = dir === "asc" ? 1 : -1;
    rows.sort((a, b) => {
      const va = a[key], vb = b[key];
      if (typeof va === "number") return (va - vb) * mul;
      return String(va ?? "").localeCompare(String(vb ?? "")) * mul;
    });
    return rows;
  }

  function renderEndpoints() {
    const rows = filtered();
    const body = $("epBody");
    body.innerHTML = "";
    $("epEmpty").classList.toggle("hidden", rows.length > 0);

    const pages = Math.max(1, Math.ceil(rows.length / state.pageSize));
    if (state.page > pages) state.page = pages;
    if (state.page < 1) state.page = 1;
    const start = (state.page - 1) * state.pageSize;
    const slice = rows.slice(start, start + state.pageSize);

    slice.forEach((r) => {
      const { row, detail } = rowEl(r);
      body.appendChild(row);
      body.appendChild(detail); // 详情必须是 tbody 的直接子节点，不能嵌在 <tr> 里
    });

    const hidden3 = state.hideThird ? state.rows.filter((r) => r.third_party).length : 0;
    const hiddenP = state.hidePages ? state.rows.filter((r) => r.page).length : 0;
    const extra = [];
    if (hidden3) extra.push(`已隐藏 ${hidden3} 个统计/第三方接口`);
    if (hiddenP) extra.push(`已隐藏 ${hiddenP} 个页面路由`);

    renderPager(rows.length, pages);
    renderStatusBar(rows, start, slice.length, extra);

    const foot = $("epFoot");
    foot.classList.toggle("hidden", rows.length === 0);
    $("pageInfo").textContent = rows.length
      ? `第 ${start + 1}-${start + slice.length} 条 / 共 ${rows.length} 条`
      : "";
  }

  // 换页 / 换每页条数 / 改筛选之后，表格内部要回到顶部 ——
  // 不然滚到第 1 页底部再点第 2 页，看到的还是列表尾部，像「没反应」
  function resetTableScroll() {
    const ts = document.querySelector("#panel-endpoints .table-scroll");
    if (ts) ts.scrollTop = 0;
  }

  function renderPager(total, pages) {
    const box = $("pager");
    box.innerHTML = "";
    if (!total) return;

    const mk = (label, page, opts = {}) => {
      const b = el("button", "pgbtn" + (opts.on ? " on" : ""), label);
      if (opts.disabled) b.disabled = true;
      if (opts.title) b.title = opts.title;
      b.onclick = () => {
        state.page = page;
        renderEndpoints();
        resetTableScroll();
        $("results").scrollIntoView({ block: "nearest" });
      };
      return b;
    };

    const cur = state.page;
    box.appendChild(mk("‹", Math.max(1, cur - 1), { disabled: cur <= 1, title: "上一页" }));

    const nums = new Set([1, pages, cur, cur - 1, cur + 1]);
    if (cur <= 3) [2, 3, 4].forEach((n) => nums.add(n));
    if (cur >= pages - 2) [pages - 1, pages - 2, pages - 3].forEach((n) => nums.add(n));
    const list = [...nums].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b);

    let prev = 0;
    list.forEach((n) => {
      if (prev && n - prev > 1) box.appendChild(el("span", "pgdots", "…"));
      box.appendChild(mk(String(n), n, { on: n === cur }));
      prev = n;
    });

    box.appendChild(mk("›", Math.min(pages, cur + 1), { disabled: cur >= pages, title: "下一页" }));

    const sel = el("select", "pgsize");
    PAGE_SIZES.forEach((n) => sel.appendChild(new Option(n + " / 页", n)));
    if (!PAGE_SIZES.includes(state.pageSize)) sel.appendChild(new Option(state.pageSize + " / 页", state.pageSize));
    sel.value = state.pageSize;
    sel.onchange = () => { state.pageSize = +sel.value; state.page = 1; renderEndpoints(); resetTableScroll(); };
    box.appendChild(sel);
  }

  function renderStatusBar(rows, start, shown, extra) {
    const box = $("statusBar");
    box.innerHTML = "";
    const s = (state.data && state.data.stats) || {};
    const scope = state.active
      ? hostOf(state.active)
      : (state.data && state.data._merged ? `全部 ${state.viewIds.length} 个目标` : hostOf(state.data && state.data.target));
    const pairs = [
      ["接口", (s.endpoints || 0)],
      ["当前显示", rows.length],
      ["参数", (s.params || 0)],
      ["目标", state.viewIds.length || state.targets.length || 0],
      ["用时", ((state.data && state.data.elapsed) || 0) + "s"],
      ["视图", scope],
    ];
    if (rows.length && shown < rows.length) pairs.splice(2, 0, ["本页", `${start + 1}-${start + shown}`]);
    pairs.forEach(([k, v], i) => {
      if (i) box.appendChild(el("span", "sep", "·"));
      const sp = el("span");
      sp.appendChild(document.createTextNode(k + " "));
      sp.appendChild(el("b", null, String(v)));
      box.appendChild(sp);
    });
    (extra || []).forEach((x) => {
      box.appendChild(el("span", "sep", "·"));
      box.appendChild(el("span", null, x));
    });
  }

  function rowEl(r) {
    const tr = el("tr", "row");
    tr.dataset.key = r.method + " " + r.url;

    // 目标站
    const tdT = el("td");
    const tc = el("div", "target-cell");
    const host = hostOf(r.target || (state.data && state.data.target) || "");
    const hs = el("span");
    hs.title = r.target || "";
    // 在点号后插 <wbr>，让长域名只在点处换行
    host.split(".").forEach((part, i, arr) => {
      if (i) hs.appendChild(document.createTextNode("."));
      hs.appendChild(document.createTextNode(part));
      if (i < arr.length - 1) hs.appendChild(el("wbr"));
    });
    tc.appendChild(hs);
    tdT.appendChild(tc);
    tr.appendChild(tdT);

    const tdM = el("td");
    tdM.appendChild(el("span", "m-badge " + methodCls(r.method), r.method));
    tr.appendChild(tdM);

    const tdU = el("td");
    const pw = el("div", "path");
    const abs = absoluteUrl(r);

    // 跳转按钮：放在路径前面，点一下在新标签页打开这个接口
    const jp = el("button", "jump");
    jp.innerHTML = JUMP_SVG;
    jp.title = "在新标签页打开\n" + abs;
    jp.onclick = (e) => { e.stopPropagation(); openEndpoint(abs); };
    pw.appendChild(jp);

    const u = el("span", "u");
    u.appendChild(highlight(r.url, state.text.toLowerCase()));
    pw.appendChild(u);
    const cp = el("button", "copy");
    cp.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
    cp.onclick = async (e) => {
      e.stopPropagation();
      await copy(r.url);
      cp.classList.add("done");
      toast("已复制：" + r.url);
      setTimeout(() => cp.classList.remove("done"), 1200);
    };
    pw.appendChild(cp);
    if (r.runtime_hit) {
      const rtag = el("span", "ctx-tag rt", "实测");
      rtag.title =
        "运行时（真实浏览器）观测到这个请求真的发出去了" +
        (r.runtime_status ? "，响应 HTTP " + r.runtime_status : "");
      pw.appendChild(rtag);
    }
    if (r.third_party) {
      const t3 = el("span", "ctx-tag third", "第三方");
      t3.title = "统计 / 广告 / 监控类第三方接口，不是目标站点的 API";
      pw.appendChild(t3);
    }
    if (r.page) {
      const pt = el("span", "ctx-tag page", "页面");
      pt.title = r.page_src === "route"
        ? "已由 Vue Router 路由表确认：这是页面路由，不是接口"
        : "按命名启发式判断像页面路由（可能是接口，请自行确认）";
      pw.appendChild(pt);
    }
    if (r.ctx_type && r.ctx_type !== "literal") {
      const tag = el("span", "ctx-tag", CTX_LABEL[r.ctx_type] || r.ctx_type);
      tag.title = "触发方式" + (r.fn_name ? "：" + r.fn_name : "");
      pw.appendChild(tag);
    }
    tdU.appendChild(pw);
    tr.appendChild(tdU);

    const tdP = el("td");
    const pc = el("div", "pchips");
    const ps = r.params || [];
    ps.slice(0, 7).forEach((p) => {
      if (p.inferred) {
        const g = el("span", "pchip infer", (p.location === "query" ? "?" : "") + p.name);
        g.title = "推测：该接口的参数名由调用方决定，静态看不到；按本站分页惯例补上";
        pc.appendChild(g);
        return;
      }
      const c = el("span", "pchip " + (p.location === "query" ? "q" : p.location === "body" ? "b" : p.location === "path" ? "p" : ""),
        p.location === "query" ? "?" + p.name : p.location === "path" ? ":" + p.name : p.name);
      c.title = `${p.location} · ${p.type}${p.sample ? " · 示例 " + p.sample : ""}`;
      pc.appendChild(c);
    });
    if (ps.length > 7) pc.appendChild(el("span", "pchip more", "+" + (ps.length - 7)));
    if (!ps.length) pc.appendChild(el("span", "pchip more", "—"));
    tdP.appendChild(pc);
    tr.appendChild(tdP);

    const tdC = el("td");
    const cw = el("div", "conf");
    const cb = el("div", "cb");
    const cf = el("div", "cf");
    const pct = r.confidence;
    cf.style.width = pct + "%";
    cf.style.background = pct >= 75 ? "#12a366" : pct >= 50 ? "#e0a325" : "#c2c9d4";
    cb.appendChild(cf);
    cw.appendChild(cb);
    cw.appendChild(el("span", null, pct));
    tdC.appendChild(cw);
    tr.appendChild(tdC);

    const tdS = el("td");
    const sd = el("div", "src", shortSrc(r.source));
    sd.title = r.source;
    tdS.appendChild(sd);
    tr.appendChild(tdS);

    const det = detailEl(r);
    det.classList.add("hidden");

    tr.onclick = () => {
      const open = det.classList.toggle("hidden") === false;
      tr.classList.toggle("open", open);
      if (open) {
        if (state.openRow && state.openRow !== tr) {
          state.openRow.classList.remove("open");
          const d = state.openRow.nextElementSibling;
          if (d && d.classList.contains("detail")) d.classList.add("hidden");
        }
        state.openRow = tr;
      } else if (state.openRow === tr) {
        state.openRow = null;
      }
    };
    return { row: tr, detail: det };
  }

  function detailEl(r) {
    const tr = el("tr", "detail");
    const td = el("td");
    td.colSpan = 6;
    const wrap = el("div", "detail-inner");

    const b1 = el("div", "detail-block");
    b1.appendChild(el("h5", null, "基本信息"));
    const kv = el("dl", "kv");
    [
      ["所属目标", r.target || (state.data && state.data.target) || "—"],
      ["接口路径", r.url],
      ...(r.raw && r.raw !== r.url ? [["源码中写法", r.raw + "（已规范化）"]] : []),
      ...(r.runtime_hit
        ? [["运行时实测", "已在真实浏览器中观测到该请求"
            + (r.runtime_status ? "，响应 HTTP " + r.runtime_status : "")]]
        : []),
      ...(r.runtime_sample && r.runtime_sample !== r.url
        ? [["真实请求样例", r.runtime_sample]]
        : []),
      ["请求方法", r.method],
      ["触发方式", (CTX_LABEL[r.ctx_type] || r.ctx_type || "—") + (r.fn_name ? "  ← " + r.fn_name : "")],
      ["置信度", r.confidence + " / 100"],
      ...(r.third_party ? [["类型", "第三方（统计 / 广告 / 监控），通常不是目标站点接口"]] : []),
      ...(r.page
        ? [["类型", r.page_src === "route"
            ? "前端页面路由（由 Vue Router 路由表确认，不是接口）"
            : "疑似前端页面路由（按命名启发式判断，可能是接口，请自行确认）"]]
        : []),
      ["出现次数", (r.count || 1) + " 次"],
      ["来源文件", r.source],
      ...(r.prefix_var ? [["运行时代码前缀", "由变量 " + r.prefix_var + " 动态拼接，实际地址需补上它"]] : []),
    ].forEach(([k, v]) => {
      kv.appendChild(el("dt", null, k));
      kv.appendChild(el("dd", null, v));
    });
    b1.appendChild(kv);
    wrap.appendChild(b1);

    const b2 = el("div", "detail-block");
    b2.appendChild(el("h5", null, `参数（${(r.params || []).length}）`));
    if ((r.params || []).length) {
      const t = el("table", "mini");
      t.innerHTML = "<thead><tr><th>参数名</th><th>位置</th><th>类型</th><th>示例值</th></tr></thead>";
      const tb = el("tbody");
      r.params.forEach((p) => {
        const ttr = el("tr");
        const nm = p.inferred ? p.name + "（推测）" : p.name;
        [nm, p.location, p.type, String(p.sample || "").slice(0, 90) || "—"].forEach((v, i) => {
          const c = el("td", null, v);
          if (i === 0) c.style.fontWeight = "600";
          ttr.appendChild(c);
        });
        tb.appendChild(ttr);
      });
      t.appendChild(tb);
      b2.appendChild(t);
    } else {
      b2.appendChild(el("div", "src", "未从调用上下文中解析到参数（可能是纯拼接或运行时动态构造）"));
    }
    wrap.appendChild(b2);

    if (r.stack && r.stack.length) {
      const bs = el("div", "detail-block");
      bs.appendChild(el("h5", null, "触发它的调用栈"));
      const c = el("code", "ctx");
      c.textContent = r.stack.join("\n");
      bs.appendChild(c);
      wrap.appendChild(bs);
    }

    if (r.context) {
      const b3 = el("div", "detail-block");
      b3.appendChild(el("h5", null, "代码上下文"));
      const c = el("code", "ctx");
      c.appendChild(highlight(r.context, r.raw));
      b3.appendChild(c);
      wrap.appendChild(b3);
    }

    const b4 = el("div", "detail-block");
    const bar2 = el("div", "btn-row");
    const btn = el("button", "btn small ghost", "复制完整接口地址");
    btn.onclick = async (e) => {
      e.stopPropagation();
      await copy(r.url);
      toast("已复制");
    };
    bar2.appendChild(btn);
    const jbtn = el("button", "btn small primary", "在新标签页打开");
    jbtn.title = "打开 " + absoluteUrl(r);
    jbtn.onclick = (e) => { e.stopPropagation(); openEndpoint(absoluteUrl(r)); };
    bar2.appendChild(jbtn);
    b4.appendChild(bar2);
    wrap.appendChild(b4);

    td.appendChild(wrap);
    tr.appendChild(td);
    return tr;
  }

  function renderHosts(list) {
    const box = $("hostsBody");
    box.innerHTML = "";
    if (!list.length) { box.appendChild(el("div", "empty", "未发现有价值的域名")); return; }
    list.forEach((h) => {
      const r = el("div", "srow");
      r.appendChild(el("span", "tag", "host"));
      r.appendChild(el("span", "val", h.host));
      r.appendChild(el("span", "cnt", h.count + " 次"));
      const c = el("button", "copy");
      c.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
      c.style.opacity = "1";
      c.onclick = async () => { await copy(h.host); toast("已复制"); };
      r.appendChild(c);
      box.appendChild(r);
    });
  }

  function renderBase(list) {
    const box = $("baseBody");
    box.innerHTML = "";
    if (!list.length) { box.appendChild(el("div", "empty", "未发现 baseURL 配置")); return; }
    list.forEach((b) => {
      const r = el("div", "srow");
      r.appendChild(el("span", "tag", b.key));
      r.appendChild(el("span", "val", b.value));
      if (!b.is_literal) r.appendChild(el("span", "cnt", "变量"));
      const c = el("button", "copy");
      c.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
      c.style.opacity = "1";
      c.onclick = async () => { await copy(b.value); toast("已复制"); };
      r.appendChild(c);
      box.appendChild(r);
    });
  }

  function renderFindings(list) {
    const box = $("findingsBody");
    box.innerHTML = "";
    if (!list.length) {
      box.appendChild(el("div", "empty", "没在 JS 里发现硬编码的密钥或鉴权字段"));
      return;
    }

    const withVal = list.filter((f) => f.value).length;
    const hint = el("div", "find-hint");
    hint.textContent = withVal
      ? `${withVal} 条取到了密钥本身；其余只是发现字段名叫 token / appId 之类，值通常在运行时才填。`
      : `这 ${list.length} 条都只是「发现了字段名叫 token / appId 之类」，没取到硬编码的值。`;
    box.appendChild(hint);

    list.forEach((f) => {
      const r = el("div", "srow");
      r.title = f.context || "";
      r.appendChild(el("span", "tag" + (f.kind === "secret" ? " warn" : ""),
                       f.kind === "secret" ? "疑似密钥" : "鉴权字段"));
      r.appendChild(el("span", "val", f.key));

      if (f.value) {
        const v = el("span", "secret-val", String(f.value).slice(0, 64));
        v.title = f.value;
        r.appendChild(v);
        const c = el("button", "copy");
        c.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
        c.style.opacity = "1";
        c.onclick = async () => { await copy(f.value); toast("已复制：" + f.value); };
        r.appendChild(c);
      } else {
        r.appendChild(el("span", "note", (f.context || "").slice(0, 110)));
      }

      if (f.source) {
        const s = el("span", "cnt", shortSrc(f.source));
        s.title = f.source;
        r.appendChild(s);
      }
      box.appendChild(r);
    });
  }

  function renderResources(list) {
    const body = $("resBody");
    body.innerHTML = "";
    const KIND_LABEL = { sourcemap: "sourcemap", html: "页面", js: "JS", openapi: "接口文档" };
    list.forEach((r) => {
      const tr = el("tr");
      tr.appendChild(el("td", null, KIND_LABEL[r.kind] || r.kind));
      const td = el("td");
      const d = el("div", "src", r.url);
      d.style.fontSize = "12px";
      td.appendChild(d);
      tr.appendChild(td);
      tr.appendChild(el("td", null, fmtSize(r.size)));
      tr.appendChild(el("td", null, r.endpoints ? String(r.endpoints) : "—"));
      body.appendChild(tr);
    });
    if (!list.length) body.appendChild(el("tr")).appendChild(el("td"));
  }

  /* ---------------- 事件绑定 ---------------- */

  $("scanBtn").onclick = startScan;
  $("urlInput").addEventListener("input", refreshUrlMeta);
  $("urlInput").addEventListener("keydown", (e) => {
    // 多行输入框里 Enter 是换行，所以用 Ctrl/Cmd + Enter 开跑
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); startScan(); }
  });
  $("clearUrls").onclick = () => {
    $("urlInput").value = "";
    refreshUrlMeta();
    $("urlInput").focus();
  };

  $("resetBtn").onclick = resetOptions;

  $("collapseBtn").onclick = () =>
    setInputCollapsed(!$("inputCard").classList.contains("collapsed"));

  // 摘要条跟着网址 / 选项变（事件委托，不用一个个绑）
  $("inputCard").addEventListener("input", refreshMini);
  $("inputCard").addEventListener("change", refreshMini);

  $("cancelBtn").onclick = async () => {
    state.cancelled = true;
    const tid = state.taskId;
    if (tid) { try { await fetch(`/api/scan/${tid}/cancel`, { method: "POST" }); } catch {} }
    $("cancelBtn").classList.add("hidden");
    $("progLabel").textContent = "正在停止…";
    setStatus("run", "正在停止");
    addLog("已发送停止信号，等待服务端收尾…");

    // 不直接收尾：服务端真正停手后会带 status=cancelled 发来 end 事件，
    // 统一走 runOne 的 resolve，中止前收集到的接口也就一并渲染出来了。
    // 兜底：25 秒还没等到（服务端卡住 / 连接断了）就自己解开等待。
    if (state.stopTimer) clearTimeout(state.stopTimer);
    state.stopTimer = setTimeout(() => {
      if (!state.scanning) return;
      addLog("没等到服务端收尾，强制结束当前目标");
      if (state.runOne) state.runOne();
    }, 25000);
  };

  $("advToggle").onclick = () => {
    $("advPanel").classList.toggle("hidden");
    $("advToggle").classList.toggle("open");
  };

  $("helpBtn").onclick = () => $("tips").classList.toggle("hidden");

  $("filterText").oninput = (e) => { state.text = e.target.value.trim(); state.page = 1; renderEndpoints(); resetTableScroll(); };
  $("hideThird").onchange = (e) => { state.hideThird = e.target.checked; state.page = 1; renderEndpoints(); resetTableScroll(); };
  $("hidePages").onchange = (e) => { state.hidePages = e.target.checked; state.page = 1; renderEndpoints(); resetTableScroll(); };
  $("onlyRuntime").onchange = (e) => { state.onlyRuntime = e.target.checked; state.page = 1; renderEndpoints(); resetTableScroll(); };
  $("onlyWithParams").onchange = (e) => { state.onlyParams = e.target.checked; state.page = 1; renderEndpoints(); resetTableScroll(); };
  $("onlyHighConf").onchange = (e) => { state.onlyHigh = e.target.checked; state.page = 1; renderEndpoints(); resetTableScroll(); };

  document.querySelectorAll("th.sortable").forEach((th) => {
    th.onclick = () => {
      const key = th.dataset.sort;
      if (state.sort.key === key) state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
      else { state.sort.key = key; state.sort.dir = key === "confidence" ? "desc" : "asc"; }
      document.querySelectorAll("th.sortable").forEach((x) => x.classList.remove("asc", "desc"));
      th.classList.add(state.sort.dir);
      state.page = 1;
      renderEndpoints();
      resetTableScroll();
    };
  });

  $("tabs").onclick = (e) => {
    const b = e.target.closest(".tab");
    if (!b) return;
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    ["endpoints", "hosts", "base", "findings", "resources"].forEach((k) => {
      $("panel-" + k).classList.toggle("hidden", k !== b.dataset.tab);
    });
  };

  $("exportBtn").onclick = (e) => {
    e.stopPropagation();
    $("exportMenu").classList.toggle("hidden");
  };
  document.addEventListener("click", () => $("exportMenu").classList.add("hidden"));
  $("exportMenu").onclick = (e) => {
    const a = e.target.closest("a");
    e.stopPropagation();
    if (!a) return;
    if (!state.viewIds.length) { toast("当前视图还没有结果"); return; }
    $("exportMenu").classList.add("hidden");
    window.location.href = `/api/export?ids=${state.viewIds.join(",")}&fmt=${a.dataset.fmt}`;
    toast("正在导出…");
  };

  snapshotDefaults();
  refreshUrlMeta();
  refreshMini();
})();
