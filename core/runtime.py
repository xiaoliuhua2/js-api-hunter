"""
运行时采集：用真实浏览器把页面跑起来，从网络层记录它实际发出的请求。

静态分析的三个天花板，只有运行时能突破：

  1. **运行时拼接** —— `baseURL + "/api/x"` 里的 baseURL 来自环境配置，
     静态只能猜。运行时拿到的就是拼好的真实地址。
  2. **动态参数** —— 请求体是 `JSON.stringify(state)`，字段名只有跑起来才知道。
  3. **触发时机** —— 懒加载 chunk 里的接口，不点开对应路由永远不会请求。

实现要点：

  * 用 Playwright 驱动**系统已装的 Chrome**（channel="chrome"），不额外下载 Chromium。
  * 主数据源是 `page.on("request")` —— 监听发生在浏览器网络层，页面代码绕过不了，
    能拿到最终 URL、完整请求头、post_data、状态码。
  * 补充注入一段脚本到页面上下文（`add_init_script`，先于所有页面脚本执行），
    专门用来拿**调用栈** —— 告诉你每个接口是页面里哪段代码触发的。
  * 图片/字体/媒体直接 abort，省流量省时间。
  * **只监听，不篡改任何请求**（除了拦截静态资源）。
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

# 注入到页面里的脚本。必须在任何页面脚本之前执行，所以用 add_init_script。
# 它只做一件事：把「谁发起了请求」记录下来（调用栈），外加尽力而为的 body 快照。
INIT_JS = r"""
(() => {
  if (window.__jh_hooked) return;
  window.__jh_hooked = true;

  const MAX = 4000;
  const clip = (s, n) => { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n) : s; };
  const report = (rec) => { try { window.__jhReport(JSON.stringify(rec)); } catch (e) {} };

  const stack = () => {
    try {
      return new Error().stack.split("\n").slice(2, 8).map((s) => clip(s.trim(), 190));
    } catch (e) { return []; }
  };

  const bodyOf = (b) => {
    try {
      if (b == null) return "";
      if (typeof b === "string") return clip(b, MAX);
      if (typeof URLSearchParams !== "undefined" && b instanceof URLSearchParams) return clip(b.toString(), MAX);
      if (typeof FormData !== "undefined" && b instanceof FormData) {
        const o = {};
        b.forEach((v, k) => { o[k] = (typeof v === "string") ? clip(v, 300) : "[file]"; });
        return clip(JSON.stringify(o), MAX);
      }
      if (typeof Blob !== "undefined" && b instanceof Blob) return "[Blob " + b.size + "]";
      if (typeof ArrayBuffer !== "undefined" && b instanceof ArrayBuffer) return "[ArrayBuffer " + b.byteLength + "]";
      return clip(JSON.stringify(b), MAX);
    } catch (e) { return ""; }
  };

  // 关键：页面代码里写的常常是 "//api.x.com/y" 或 "x/y" 这种相对地址，
  // 必须以页面地址为基准解析成绝对 URL，否则和网络层事件对不上、没法去重
  const urlOf = (i) => {
    try {
      let u = "";
      if (typeof i === "string") u = i;
      else if (i && typeof i.url === "string") u = i.url;
      else if (i && typeof i.href === "string") u = i.href;
      if (!u) return "";
      return new URL(u, location.href).href;
    } catch (e) { return ""; }
  };

  // ---- fetch ----
  const _fetch = window.fetch;
  if (typeof _fetch === "function") {
    window.fetch = function (input, init) {
      try {
        init = init || {};
        report({
          kind: "fetch",
          url: urlOf(input),
          method: clip(init.method || (input && input.method) || "GET", 12).toUpperCase(),
          body: bodyOf(init.body),
          stack: stack(),
        });
      } catch (e) {}
      return _fetch.apply(this, arguments);
    };
  }

  // ---- XMLHttpRequest（axios / jQuery / 各种 request 封装的底层）----
  const XP = XMLHttpRequest.prototype;
  const _open = XP.open, _send = XP.send;
  XP.open = function (m, u) {
    try { this.__jh = { m: clip(m, 12).toUpperCase(), u: urlOf(u) }; } catch (e) {}
    return _open.apply(this, arguments);
  };
  XP.send = function (body) {
    try {
      const h = this.__jh || {};
      report({ kind: "xhr", url: h.u || "", method: h.m || "GET", body: bodyOf(body), stack: stack() });
    } catch (e) {}
    return _send.apply(this, arguments);
  };

  // ---- WebSocket ----
  const _WS = window.WebSocket;
  if (typeof _WS === "function") {
    const W = function (url, protocols) {
      try { report({ kind: "websocket", url: urlOf(url), method: "WS", body: "", stack: stack() }); } catch (e) {}
      return protocols === undefined ? new _WS(url) : new _WS(url, protocols);
    };
    W.prototype = _WS.prototype;
    try { Object.defineProperty(W, "name", { value: "WebSocket" }); } catch (e) {}
    window.WebSocket = W;
  }

  // ---- navigator.sendBeacon（埋点/上报常用）----
  try {
    const _beacon = navigator.sendBeacon && navigator.sendBeacon.bind(navigator);
    if (_beacon) {
      navigator.sendBeacon = function (url, data) {
        try { report({ kind: "beacon", url: urlOf(url), method: "POST", body: bodyOf(data), stack: stack() }); } catch (e) {}
        return _beacon(url, data);
      };
    }
  } catch (e) {}

  // ---- EventSource（SSE）----
  const _ES = window.EventSource;
  if (typeof _ES === "function") {
    const S = function (url, cfg) {
      try { report({ kind: "eventsource", url: urlOf(url), method: "GET", body: "", stack: stack() }); } catch (e) {}
      return cfg === undefined ? new _ES(url) : new _ES(url, cfg);
    };
    S.prototype = _ES.prototype;
    window.EventSource = S;
  }
})();
"""

# 读前端路由表。和雪瞳的注入脚本同一个思路，但只读不写 ——
# 不碰 beforeHooks（那是页面自己的路由守卫，改了会改变站点行为）。
ROUTE_JS = r"""
() => {
  const out = { version: "", routes: [] };
  const seen = new Set();
  const push = (p) => {
    try {
      if (typeof p !== "string") return;
      p = p.trim();
      if (!p || p.length > 200 || p[0] !== "/") return;
      if (seen.has(p)) return;
      seen.add(p);
      out.routes.push(p);
    } catch (e) {}
  };
  const walk = (arr, base) => {
    if (!Array.isArray(arr)) return;
    for (const r of arr) {
      if (!r || typeof r !== "object") continue;
      let p = String(r.path || "");
      if (p && p[0] !== "/") {
        const b = String(base || "/").replace(/\/+$/, "");
        p = b + "/" + p.replace(/^\/+/, "");
      }
      if (p) push(p);
      if (Array.isArray(r.alias)) r.alias.forEach(push);
      if (Array.isArray(r.children) && r.children.length) walk(r.children, p);
    }
  };
  const findHost = (node, depth) => {
    if (!node || depth > 12) return null;
    if (node.__vue_app__ || node.__vue__) return node;
    const kids = node.children || [];
    for (let i = 0; i < kids.length; i++) {
      const r = findHost(kids[i], depth + 1);
      if (r) return r;
    }
    return null;
  };
  try {
    const root = document.getElementById("app") || document.getElementById("root") || document.body;
    const host = findHost(root, 0);
    if (host && host.__vue_app__) {
      const app = host.__vue_app__;
      out.version = String(app.version || "");
      const gp = app.config && app.config.globalProperties;
      const r = gp && gp.$router;
      if (r && typeof r.getRoutes === "function") {
        r.getRoutes().forEach((x) => {
          if (!x) return;
          push(x.path);
          if (Array.isArray(x.alias)) x.alias.forEach(push);
        });
      } else if (r && r.options && Array.isArray(r.options.routes)) {
        walk(r.options.routes, "");
      }
    } else if (host && host.__vue__) {
      const vm = host.__vue__;
      const base = vm.$root && vm.$root.$options && vm.$root.$options._base;
      out.version = String((base && base.version) || "2.x");
      const r = vm.$root && vm.$root.$options && vm.$root.$options.router;
      if (r) {
        if (typeof r.getRoutes === "function") {
          r.getRoutes().forEach((x) => x && push(x.path));
        } else if (r.options && Array.isArray(r.options.routes)) {
          walk(r.options.routes, "");
        }
      }
    }
  } catch (e) {}
  return out;
}
"""

# 我们关心的请求类型（Playwright 的 resource_type）
NET_TYPES = {"xhr", "fetch", "websocket", "eventsource", "ping"}

# 这些资源类型直接掐掉，能把加载时间压掉一大半
BLOCK_TYPES = {"image", "font", "media"}

# 脚本扩展名 —— 用来从请求里认出「这是个 JS 文件」
SCRIPT_URL_RE = re.compile(r"\.(?:js|mjs|cjs)(?:\?|$)", re.I)

# 请求头里值得留下的（其余是指纹类噪音，对理解接口没帮助）
KEEP_HEADERS = re.compile(
    r"^(authorization|cookie|token|x-.*token|x-auth.*|.*-token|auth.*|"
    r"content-type|x-requested-with|x-csrf.*|x-xsrf.*|referer|origin|"
    r"x-api-key|api-key|appid|app-id|sign|signature|timestamp|nonce|"
    r"x-tenant.*|tenant.*|lang.*|x-lang.*)$",
    re.I,
)

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@dataclass
class RuntimeHit:
    """一次被观测到的真实请求。"""

    url: str
    method: str = "GET"
    kind: str = "xhr"          # fetch | xhr | websocket | eventsource | beacon
    status: int = 0
    post_data: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    stack: list[str] = field(default_factory=list)
    count: int = 1
    first_seen: float = 0.0


class RuntimeCollector:
    """驱动浏览器跑一遍页面，收集真实请求。"""

    def __init__(self, opts, emit: Callable[[dict], None], cancel=None):
        self.o = opts
        self.emit = emit
        # 取消信号（与 Scanner 共用同一个 asyncio.Event）。运行时阶段是整次扫描里
        # 最慢的一段，用户点了停止之后不该还让一个无头浏览器自己跑几十秒。
        self._cancel = cancel
        self.notes: list[str] = []
        self.errors: list[str] = []
        self.visits: list[str] = []

        self._hits: dict[tuple[str, str], RuntimeHit] = {}
        self._by_url: dict[str, RuntimeHit] = {}
        self._net_seen: set[tuple[str, str]] = set()
        self._stacks: dict[str, list[str]] = {}
        self._hook_seen = 0
        self._channel_used = ""

        # 浏览器实际加载过的脚本 —— 这是「当前环境真正在用哪些 chunk」的真值。
        # 静态分析靠递归解析引用，会因配额截断、路径拼接错误、模板还原失败而漏；
        # 而浏览器加载过的一定存在。按发现顺序存，补抓优先级才稳定。
        self.scripts: dict[str, int] = {}
        self.routes: list[str] = []      # 前端路由表（Vue Router）
        self.vue_version = ""

    # ---- 取消 ---------------------------------------------------------

    def _stopped(self) -> bool:
        return bool(self._cancel is not None and self._cancel.is_set())

    async def _pause(self, seconds: float) -> bool:
        """可被「停止」打断的等待。返回 False 表示等待期间用户点了停止。"""
        if self._stopped():
            return False
        if self._cancel is None:
            await asyncio.sleep(seconds)
            return True
        try:
            await asyncio.wait_for(self._cancel.wait(), timeout=max(0.0, seconds))
            return False
        except asyncio.TimeoutError:
            return True

    # ---- 对外 ---------------------------------------------------------

    async def run(self) -> list[RuntimeHit]:
        budget = float(getattr(self.o, "runtime_budget", 120) or 120)
        try:
            return await asyncio.wait_for(self._run(), timeout=budget)
        except asyncio.TimeoutError:
            self.notes.append(f"运行时采集超过 {budget:.0f} 秒预算，已提前收工")
            return self._result()
        except Exception as e:  # 任何意外都不该拖垮整次扫描
            self.errors.append(f"运行时采集异常：{type(e).__name__}: {str(e)[:150]}")
            return self._result()

    # ---- 主流程 -------------------------------------------------------

    async def _run(self) -> list[RuntimeHit]:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.errors.append(
                "未安装 playwright，已跳过运行时采集"
                "（安装：pip install playwright，无需 playwright install）"
            )
            return []

        target = self.o.url
        if not re.match(r"^https?://", target, re.I):
            target = "http://" + target

        self._log("正在启动浏览器做运行时采集…")

        started = time.time()
        async with async_playwright() as pw:
            browser = await self._launch(pw)
            if browser is None:
                return self._result()
            try:
                await self._drive(browser, target)
            finally:
                try:
                    await browser.close()
                except Exception:
                    pass

        self.notes.append(
            f"运行时采集完成：观测到 {len(self._hits)} 个真实请求，"
            f"其中 {self._hook_seen} 个带调用栈（用时 {time.time() - started:.1f}s，浏览器 {self._channel_used}）"
        )
        return self._result()

    async def _launch(self, pw):
        """优先复用系统已装的 Chrome / Edge —— 不额外下载 Chromium。"""
        headless = bool(getattr(self.o, "runtime_headless", True))
        args = [
            "--disable-blink-features=AutomationControlled",
            "--ignore-certificate-errors",   # 目标站证书过期是常态
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-popup-blocking",
        ]
        proxy = None
        if getattr(self.o, "proxy", ""):
            proxy = {"server": self.o.proxy}

        wanted = getattr(self.o, "runtime_channel", "") or ""
        channels = [wanted] if wanted else ["chrome", "msedge"]
        last = ""
        for ch in channels:
            try:
                b = await pw.chromium.launch(channel=ch, headless=headless, args=args, proxy=proxy)
                self._channel_used = ch
                return b
            except Exception as e:
                last = str(e)[:160]
                continue

        # 系统浏览器都没有时，退回 Playwright 自带的 chromium（若已下载）
        try:
            b = await pw.chromium.launch(headless=headless, args=args, proxy=proxy)
            self._channel_used = "chromium"
            return b
        except Exception as e:
            self.errors.append(
                "无法启动浏览器，运行时采集已跳过。可用 channel=chrome/msedge 指定系统浏览器。"
                f"原始错误：{(last or str(e))[:150]}"
            )
            return None

    async def _drive(self, browser, target: str) -> None:
        ctx_kwargs: dict[str, Any] = {
            "ignore_https_errors": True,
            "viewport": {"width": 1440, "height": 900},
            "user_agent": UA,
            "locale": "zh-CN",
        }
        extra = self._extra_headers()
        if extra:
            ctx_kwargs["extra_http_headers"] = extra
        context = await browser.new_context(**ctx_kwargs)

        # Cookie（登录态）
        await self._inject_cookies(context, target)

        # hook 回传通道
        try:
            await context.expose_binding("__jhReport", self._on_hook)
        except Exception as e:
            self.notes.append(f"注入调用栈探测器失败（不影响主流程）：{str(e)[:80]}")

        # 静态资源阻断
        try:
            await context.route("**/*", self._route)
        except Exception:
            pass

        try:
            await context.add_init_script(INIT_JS)
        except Exception as e:
            self.notes.append(f"注入 hook 脚本失败：{str(e)[:80]}")

        try:
            pages = await self._open(context, target)
            if not await self._pause(float(getattr(self.o, "runtime_settle", 3.0) or 3.0)):
                return
            for p in pages:
                if self._stopped():
                    return
                await self._autoscroll(p)
            # 让滚动后触发的异步请求有机会跑完
            if not await self._pause(1.5):
                return

            # 前端路由表：① 精确区分「页面路由」和「接口」
            # ② SPA 的侧边栏菜单常常是 JS 点击事件而非 <a>，
            #    有路由表才知道还有哪些页面没走过
            for p in pages:
                await self._harvest_routes(p)

            follow = int(getattr(self.o, "runtime_follow", 0) or 0)
            if follow > 0:
                for p in pages:
                    if self._stopped():
                        return
                    await self._follow_links(p, follow, self.routes)
                    await self._harvest_routes(p)

            for p in pages:
                try:
                    if p.url not in self.visits:
                        self.visits.append(p.url)
                except Exception:
                    pass
        finally:
            try:
                await context.close()
            except Exception:
                pass

    async def _open(self, context, target: str):
        page = await context.new_page()
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("pageerror", lambda e: None)
        try:
            await page.goto(target, wait_until="domcontentloaded",
                            timeout=int(max(20, self.o.timeout * 3) * 1000))
        except Exception as e:
            self.errors.append(f"打开页面失败：{type(e).__name__}: {str(e)[:120]}")
            return [page]

        # SPA 会有持续的长轮询/心跳，networkidle 经常等不到，给个上限就放过
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass

        await self._dismiss_consent(page)
        return [page]

    async def _dismiss_consent(self, page) -> None:
        """顺手点掉 cookie 同意 / 弹窗，否则会挡住后续交互。"""
        for sel in (
            "button:has-text('同意')", "button:has-text('接受')", "button:has-text('我知道了')",
            "button:has-text('Accept')", "button:has-text('Allow')", "button:has-text('Got it')",
            ".el-dialog__headerbtn", ".ant-modal-close", "[aria-label='Close']",
        ):
            try:
                loc = page.locator(sel).first
                if await loc.is_visible(timeout=250):
                    await loc.click(timeout=800)
                    await asyncio.sleep(0.25)
            except Exception:
                continue

    async def _autoscroll(self, page, rounds: int = 6) -> None:
        """滚到底再滚回来，触发懒加载 / IntersectionObserver。"""
        try:
            for _ in range(rounds):
                if self._stopped():
                    return
                await page.evaluate(
                    "(r) => { const h = Math.max(document.body.scrollHeight,"
                    " document.documentElement.scrollHeight); window.scrollBy(0, h / r); }",
                    rounds,
                )
                if not await self._pause(0.5):
                    return
            await page.evaluate("() => window.scrollTo(0, 0)")
            await self._pause(0.3)
        except Exception:
            pass

    async def _follow_links(self, page, limit: int, routes: list[str] | None = None) -> None:
        """
        跟着页面上的同源链接走几个。

        作用很实在：SPA 的路由是懒加载的，不切到那个路由，它对应的 chunk
        根本不会下载、里面的接口也不会被请求。静态分析能靠 chunk 模板还原，
        运行时要靠真的走过去。

        除了 ``<a href>``，还会用**前端路由表**补齐 —— SPA 的侧边栏菜单常常是
        JS 点击事件而不是链接，只跟着 <a> 走会漏掉一大半页面。

        严格限制：只走同源、跳过登出/删除这类敏感词、跳过静态资源和带参路由，
        最多 limit 个。
        """
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href).filter(Boolean)"
            )
        except Exception:
            return

        try:
            cur = urlparse(page.url)
            root = f"{cur.scheme}://{cur.netloc}"
        except Exception:
            return

        skip = re.compile(
            r"(logout|signout|sign-out|exit|delete|remove|unbind|revoke|cancel|"
            r"login|pay|order/create)",
            re.I,
        )
        static_tail = re.compile(
            r"\.(?:png|jpe?g|gif|svg|css|js|pdf|zip|mp4|mp3|woff2?|xlsx?|docx?)$", re.I
        )

        targets: list[str] = []
        seen: set[str] = set()

        def take(u: str) -> bool:
            u = str(u or "").split("#")[0]
            if not u.startswith(root) or u in seen:
                return False
            if u.rstrip("/") == page.url.rstrip("/"):
                return False
            if skip.search(u) or static_tail.search(u):
                return False
            seen.add(u)
            targets.append(u)
            return True

        for h in hrefs:
            take(h)
            if len(targets) >= limit:
                break

        # <a> 走完还有余量，就用路由表补上菜单对应的页面
        if routes and len(targets) < limit:
            for r in routes[: limit * 4]:
                if ":" in r or "*" in r:
                    continue          # 带参 / 通配路由不盲跳，容易打到脏数据
                take(root + r)
                if len(targets) >= limit:
                    break

        targets = targets[:limit]
        if not targets:
            return
        self._log(f"运行时跟随 {len(targets)} 个同源页面")

        for u in targets:
            if self._stopped():
                return
            try:
                await page.goto(
                    u, wait_until="domcontentloaded",
                    timeout=int(max(15, self.o.timeout * 2) * 1000),
                )
                if not await self._pause(
                    min(4.0, float(getattr(self.o, "runtime_settle", 3) or 3))
                ):
                    return
                await self._autoscroll(page, rounds=2)
                if not await self._pause(0.8):
                    return
                if u not in self.visits:
                    self.visits.append(u)
            except Exception:
                continue

    async def _harvest_routes(self, page, tries: int = 3) -> None:
        """
        读 Vue Router 的路由表。

        SPA 挂载可能晚于 domcontentloaded，所以空结果要重试几次；拿到就收工。
        只读，不修改页面任何东西。
        """
        for i in range(max(1, tries)):
            if self._stopped():
                return
            try:
                data = await page.evaluate(ROUTE_JS)
            except Exception:
                return
            if isinstance(data, dict):
                ver = str(data.get("version") or "")
                if ver and not self.vue_version:
                    self.vue_version = ver
                for r in (data.get("routes") or []):
                    r = str(r or "").strip()
                    if r.startswith("/") and len(r) <= 200 and r not in self.routes:
                        self.routes.append(r)
                if self.routes:
                    return
            if i < tries - 1:
                if not await self._pause(1.0):
                    return

    # ---- 事件回调 -----------------------------------------------------

    async def _route(self, route) -> None:
        try:
            if route.request.resource_type in BLOCK_TYPES:
                await route.abort()
            else:
                await route.continue_()
        except Exception:
            try:
                await route.continue_()
            except Exception:
                pass

    def _on_request(self, request) -> None:
        try:
            rtype = request.resource_type
            url = request.url
            # 顺手记下脚本清单。它不参与接口判定，但静态分析结束后要拿它兜底：
            # 凡是浏览器加载过、而静态递归没抓到的 JS，都值得再分析一遍。
            # 只看扩展名，不看 resource_type —— jsonp/loader 这类无扩展名请求
            # 浏览器也报成 script，抓回来只会白占配额（实测这个站有 37 个）。
            if SCRIPT_URL_RE.search(url.split("?")[0]):
                if url not in self.scripts:
                    self.scripts[url] = len(self.scripts)
            if rtype not in NET_TYPES:
                return
            key = (request.method.upper(), url)
            hit = self._hits.get(key)
            if hit is None:
                hit = RuntimeHit(
                    url=url,
                    method=request.method.upper(),
                    kind=request.resource_type,
                    post_data=self._clip(request.post_data or "", 4000),
                    headers=self._pick_headers(request.headers),
                    first_seen=time.time(),
                    count=1,
                )
                self._hits[key] = hit
            elif key in self._net_seen:
                hit.count += 1          # 网络层再次看到同一请求 ＝ 真的又请求了一次
            # 请求头以后到的为准：网络层的比 hook 可靠
            hdrs = self._pick_headers(request.headers)
            if hdrs:
                hit.headers = hdrs
            if not hit.post_data and request.post_data:
                hit.post_data = self._clip(request.post_data, 4000)
            self._net_seen.add(key)
            self._by_url[url] = hit
        except Exception:
            pass

    def _on_response(self, response) -> None:
        try:
            url = response.url
            hit = self._by_url.get(url)
            if hit is None:
                try:
                    hit = self._by_url.get(response.request.url)
                except Exception:
                    hit = None
            if hit is None:
                return
            hit.status = response.status
            ctype = (response.headers or {}).get("content-type", "")
            hit.content_type = ctype.split(";")[0].strip()[:60]
        except Exception:
            pass

    def _on_hook(self, source, payload: str) -> None:
        """
        注入脚本回传 —— **只用来提供调用栈**。

        请求本身一律以网络层事件为准（那里有最终 URL、完整请求头、真实 post_data、
        状态码）。如果让 hook 也建记录，同一请求会变成两条数据（一条 `//api.x.com/a`，
        一条 `https://api.x.com/a`），所以它只往 _stacks 里塞。
        """
        try:
            rec = json.loads(payload)
        except Exception:
            return
        self._hook_seen += 1
        url = (rec.get("url") or "").strip()
        if not url:
            return
        st = rec.get("stack") or []
        if st:
            self._stacks.setdefault(url, [str(s)[:190] for s in st[:6]])

    # ---- 小工具 -------------------------------------------------------

    def _result(self) -> list[RuntimeHit]:
        out = list(self._hits.values())
        miss = [h for h in out if not h.stack]
        by_path: dict[str, list[str]] = {}
        if miss:
            # hook 的 URL 和网络层的偶尔会有细微差别（尾斜杠、query 顺序），
            # 精确匹配不上就按路径兜底
            for k, v in self._stacks.items():
                by_path.setdefault(k.split("?")[0].rstrip("/"), v)
        for h in out:
            if h.stack:
                continue
            h.stack = (
                self._stacks.get(h.url)
                or by_path.get(h.url.split("?")[0].rstrip("/"))
                or []
            )
        out.sort(key=lambda h: (-h.count, h.url))
        return out

    def _log(self, message: str) -> None:
        try:
            self.emit({"event": "progress", "message": message})
        except Exception:
            pass

    @staticmethod
    def _clip(s: str, n: int) -> str:
        s = str(s or "")
        return s if len(s) <= n else s[:n]

    @staticmethod
    def _pick_headers(headers: dict[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in (headers or {}).items():
            if KEEP_HEADERS.match(k):
                out[k] = RuntimeCollector._clip(v, 300)
            if len(out) >= 12:
                break
        return out

    def _extra_headers(self) -> dict[str, str]:
        h: dict[str, str] = {}
        for line in re.split(r"[\n;]+", getattr(self.o, "headers", "") or ""):
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            if k.strip():
                h[k.strip()] = v.strip()
        return h

    async def _inject_cookies(self, context, target: str) -> None:
        raw = (getattr(self.o, "cookies", "") or "").strip()
        if not raw:
            return
        try:
            host = urlparse(target).hostname or ""
            cookies = []
            for part in re.split(r"[;\n]+", raw):
                part = part.strip()
                if "=" not in part:
                    continue
                k, v = part.split("=", 1)
                k, v = k.strip(), v.strip()
                if not k:
                    continue
                cookies.append({"name": k, "value": v, "domain": host, "path": "/"})
            if cookies:
                await context.add_cookies(cookies)
                self.notes.append(f"已把 {len(cookies)} 个 Cookie 注入浏览器上下文")
        except Exception as e:
            self.notes.append(f"Cookie 注入失败：{str(e)[:80]}")
