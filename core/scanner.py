"""
扫描调度器。

流程：
  1. 抓入口页 HTML，发现 <script src> / 内联脚本 / 同源链接
  2. 探测 Swagger / OpenAPI 文档（有的话能直接拿到全量接口）
  3. 并发下载 JS；从 JS 里继续发现 webpack chunk、sourcemap、jsFuzz 候选
  4. 对每份源码跑提取引擎，全局常量表跨文件累积（前一个文件定义的
     ``const API_BASE = "/api"`` 能帮后一个文件解析路径）
  5. 汇总去重，按置信度排序
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from typing import Any, Callable
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs

import httpx

from .expr import ConstTable
from .extractor import (
    JSExtractor,
    find_script_urls,
    find_inline_scripts,
    find_links,
    find_sourcemap_url,
    find_js_refs,
    find_webpack_chunks,
    find_js_fuzz_targets,
    is_library_js,
    collapse_dup_dirs,
    origin_of,
    guess_type,
    _is_third_party,
)
from .openapi import (
    SPEC_PATHS,
    SPEC_HINT_RE,
    SPEC_HINT_KEYWORDS,
    looks_like_spec,
    parse_spec,
)
from .models import Endpoint, Finding, Param, Resource

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# 提取是 CPU 密集的纯 Python，跑在多个线程里会互相抢 GIL。
# 把切换间隔调小，主线程（负责响应 HTTP 请求、推进度）才不会被饿死。
sys.setswitchinterval(0.002)

# 同时做分析的文件数。比 HTTP 并发少很多：开太多线程只会互相拖慢，
# 还会让事件循环卡顿（表现为界面/接口无响应）。
CPU_WORKERS = max(2, min(6, (os.cpu_count() or 4) // 2))

# ---- 运行时采集的噪声判定 ------------------------------------------------
# 静态分析天然看不到埋点上报，运行时却会把它们全抓回来（B 站首页就有几十个）。
# 这里把它们标成第三方而不是直接丢掉 —— 用户取消勾选「隐藏统计/第三方」还能看到。

# 埋点 / 上报 / 监控类的路径段
RUNTIME_NOISE_RE = re.compile(
    r"(?:^|/)(?:log|logs|report|reporting|collect|collector|track|tracking|"
    r"stat|stats|statistics|metrics|monitor|beacon|analytics|rum|sentry)(?:/|\?|$)",
    re.I,
)
# 静态目录下的静态文件（含 .json —— CDN 上大量放图标/文案数据）
RUNTIME_STATIC_RE = re.compile(
    r"/(?:bfs|static|assets?|dist|build|public|img|images?|icons?|fonts?|media|"
    r"css|libs?|vendor|_next|__webpack)[^?]*"
    r"\.(?:json|png|jpe?g|gif|webp|svg|ico|css|js|woff2?|ttf|mp4|webm|map)$",
    re.I,
)
# 纯资源，不可能承载接口 —— 直接丢
RUNTIME_RESOURCE_RE = re.compile(
    r"\.(?:png|jpe?g|gif|webp|avif|bmp|svg|ico|css|woff2?|ttf|eot|otf|mp4|webm|"
    r"mp3|ogg|wav|map|wasm|zip|pdf|apk|dmg|exe)$",
    re.I,
)


def runtime_drop(path: str) -> bool:
    """纯静态资源（图片/字体/媒体），不可能承载接口 —— 直接丢弃。"""
    return bool(RUNTIME_RESOURCE_RE.search((path or "").split("?")[0]))


# 补分页参数时，排除掉明确不分页的接口。
# 用「反向排除」而不是「正向白名单」：白名单会漏掉优惠券、订单这类
# 名字里没有 page/list 的列表接口（实测漏了 4 个真参数），
# 而反向排除只挡掉登录、鉴权、字典这些确实没有分页语义的。
NON_PAGINATION_RE = re.compile(
    r"(login|logout|signin|signout|oauth|token|register|password|pwd|"
    r"sms|email|phone|captcha|nocaptcha|verify|checkcode|"
    r"upload|download|export|import|"
    r"dict|dictionary|menu|permission|role|dept|"
    r"tree|statistic|config|setting|detail|info$)",
    re.I,
)


# 回灌阶段只认真正的 JS 文件（`.jsonp` 这类会被浏览器报成 script，但没价值）
RT_SCRIPT_RE = re.compile(r"\.(?:js|mjs|cjs)$", re.I)

# 第三方风控 / 统计 / 广告域名 —— 回灌时排到最后。
# 注意**不能**笼统地拉黑 CDN（alicdn / bcebos 上也可能是目标站自己的业务代码，
# 实测就有站点把业务 JS 放在 bcebos 上），所以这里只列确定与业务无关的。
RT_THIRD_HOST_RE = re.compile(
    r"(?:^|\.)("
    r"google-analytics\.com|googletagmanager\.com|googlesyndication\.com|"
    r"doubleclick\.net|hm\.baidu\.com|bdstatic\.com|"
    r"cloudflareinsights\.com|sentry-cdn\.com|sentry\.io|"
    r"hotjar\.com|clarity\.ms|umeng\.com|umengcloud\.com|"
    r"cf\.aliyun\.com|ynuf\.aliapp\.org|tdum\.alibaba\.com"
    r")$",
    re.I,
)


# baseURL 列表只留「像 API 基地址」的键：别的（bgUrl / buyUrl / 图片地址）
# 混进来会让这个面板失去意义。
BASE_KEY_HINT = re.compile(
    r"(base|api|host|origin|domain|prefix|gateway|server|target)", re.I
)


def url_key(url: str) -> str:
    """
    合并去重用的归一化键。

    静态分析常拿到协议相对写法（`//api.example.com/x`，源码里就这么写的），
    运行时拿到的是完整地址（`https://api.example.com/x`）。不归一化的话，
    同一个接口会变成两条。
    """
    u = (url or "").strip()
    if u.startswith("//"):
        return "https:" + u
    return u


def runtime_noise(path: str) -> bool:
    """埋点上报 / 监控 / CDN 数据文件 —— 标记为第三方，可被一键隐藏。"""
    p = (path or "").split("?")[0]
    return bool(RUNTIME_NOISE_RE.search(p) or RUNTIME_STATIC_RE.search(p))


def _clamp(v, lo, hi):
    return max(lo, min(hi, v))


class ScanOptions:
    def __init__(self, data: dict[str, Any] | None = None):
        d = data or {}
        self.url: str = str(d.get("url", "")).strip()
        self.cookies: str = str(d.get("cookies", "") or "")
        self.headers: str = str(d.get("headers", "") or "")
        self.proxy: str = str(d.get("proxy", "") or "")
        self.concurrency: int = _clamp(int(d.get("concurrency", 8) or 8), 1, 32)
        self.timeout: float = _clamp(float(d.get("timeout", 15) or 15), 3, 120)
        # 默认给得比较宽：大型 SPA 的 vite/webpack 产物动辄三四百个 chunk，
        # 配额小了会在抓完之前就被截断，而漏掉的往往是按产品线懒加载的
        # 业务 chunk（也就是最有价值的那批接口）。
        self.max_files: int = _clamp(int(d.get("max_files", 400) or 400), 1, 3000)
        self.max_size: int = int(d.get("max_size", 6 * 1024 * 1024) or 6 * 1024 * 1024)
        self.crawl: int = _clamp(int(d.get("crawl", 0) or 0), 0, 3)
        self.use_sourcemap: bool = bool(d.get("sourcemap", True))
        self.discover_chunks: bool = bool(d.get("chunks", True))
        self.openapi: bool = bool(d.get("openapi", True))
        self.js_fuzz: bool = bool(d.get("js_fuzz", True))
        self.min_score: int = _clamp(int(d.get("min_score", 30) or 30), 0, 100)
        self.verify_ssl: bool = bool(d.get("verify_ssl", False))
        # --- 运行时采集 ---
        self.runtime: bool = bool(d.get("runtime", False))
        self.runtime_headless: bool = bool(d.get("runtime_headless", True))
        self.runtime_channel: str = str(d.get("runtime_channel", "") or "")
        self.runtime_settle: float = _clamp(float(d.get("runtime_settle", 3) or 3), 0.5, 30)
        self.runtime_budget: float = _clamp(float(d.get("runtime_budget", 120) or 120), 20, 600)
        # 跟随几个页面走一遍（SPA 路由懒加载，不走过去它对应的 chunk 就不会加载）。
        # 页面上的 <a> 不够用 —— 侧边栏菜单常常是 JS 点击事件，所以会用前端路由表补齐。
        # 默认给到 10：实测这一项直接决定浏览器能加载到多少业务 chunk。
        _rf = d.get("runtime_follow", 10)
        self.runtime_follow: int = _clamp(int(10 if _rf is None else _rf), 0, 30)
        # 浏览器加载过的 JS 清单回灌：静态递归会受配额截断、路径拼接错误影响，
        # 而「浏览器真的加载了哪些 chunk」是当前环境的真值
        self.runtime_js: bool = bool(d.get("runtime_js", True))
        self.runtime_js_max: int = _clamp(int(d.get("runtime_js_max", 300) or 300), 0, 1500)
        # 回灌阶段的**时间**预算。runtime_js_max 只管「抓多少个」，可站点 CDN 慢的时候
        # 单个请求能拖到二十几秒（httpx 的分阶段超时兜不住，见 _fetch_text），
        # 300 个文件叠起来就是十几分钟 —— 用户看到的现象就是「一直在查询」。
        # 0 = 不限（想要「一定要抓完」就设 0）。
        _jb = d.get("runtime_js_budget", 60)
        self.runtime_js_budget: float = _clamp(float(60 if _jb is None else _jb), 0, 600)
        # 用前端路由表精确区分「页面路由」和「接口」（比命名启发式准）
        self.runtime_routes: bool = bool(d.get("runtime_routes", True))

    def merged_headers(self) -> dict[str, str]:
        h = {
            "User-Agent": UA,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
        for line in re.split(r"[\n;]+", self.headers):
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            if k.strip():
                h[k.strip()] = v.strip()
        if self.cookies.strip():
            h["Cookie"] = self.cookies.strip()
        return h


class ScanResult:
    def __init__(self, target: str):
        self.target = target
        self.started = time.time()
        self.finished = 0.0
        self.endpoints: list[Endpoint] = []
        self.findings: list[Finding] = []
        self.resources: list[Resource] = []
        self.base_urls: list[dict] = []
        self.hosts: dict[str, int] = {}
        self.errors: list[str] = []
        self.notes: list[str] = []
        self.pages: list[str] = []
        self.openapi_specs: list[str] = []
        self.base_prefix = ""
        self.missing_maps = 0
        self.runtime_hits = 0        # 运行时观测到的真实请求数
        self.runtime_channel = ""    # 用的哪个浏览器
        self.runtime_visits: list[str] = []
        self.routes: list[str] = []  # 前端路由表（Vue Router）
        self.vue_version = ""
        self.runtime_scripts = 0     # 浏览器实际加载的脚本数
        self.runtime_js_added = 0    # 靠这份清单补抓的 JS 数

    def to_dict(self) -> dict[str, Any]:
        by_method: dict[str, int] = defaultdict(int)
        by_ctx: dict[str, int] = defaultdict(int)
        for e in self.endpoints:
            by_method[e.method] += 1
            by_ctx[e.ctx_type] += 1

        real_errors: list[str] = []
        seen: set[str] = set()
        for msg in self.errors:
            if " → HTTP 404" in msg and ".map" in msg:
                self.missing_maps += 1
                continue
            if msg in seen:
                continue
            seen.add(msg)
            real_errors.append(msg)

        return {
            "target": self.target,
            "elapsed": round(self.finished - self.started, 2) if self.finished else 0,
            "stats": {
                "endpoints": len(self.endpoints),
                "params": sum(len(e.params) for e in self.endpoints),
                "resources": len(self.resources),
                "js_files": sum(1 for r in self.resources if r.kind == "js"),
                "sourcemaps": sum(1 for r in self.resources if r.kind == "sourcemap"),
                "hosts": len(self.hosts),
                "findings": len(self.findings),
                "pages": len(self.pages),
                "openapi": len(self.openapi_specs),
                "missing_maps": self.missing_maps,
                "runtime_hits": self.runtime_hits,
                "runtime_confirmed": sum(1 for e in self.endpoints if e.runtime_hit),
                "runtime_only": sum(
                    1 for e in self.endpoints if e.runtime_hit and e.source_kind == "runtime"
                ),
                "routes": len(self.routes),
                "runtime_scripts": self.runtime_scripts,
                "runtime_js_added": self.runtime_js_added,
            },
            "by_method": dict(by_method),
            "by_ctx": dict(by_ctx),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "findings": [f.to_dict() for f in self.findings],
            "resources": [r.to_dict() for r in self.resources],
            "base_urls": self.base_urls,
            "hosts": sorted(
                ({"host": k, "count": v} for k, v in self.hosts.items()),
                key=lambda x: -x["count"],
            ),
            "openapi_specs": self.openapi_specs,
            "base_prefix": self.base_prefix,
            "runtime_channel": self.runtime_channel,
            "runtime_visits": self.runtime_visits[:20],
            "vue_version": self.vue_version,
            "routes": self.routes[:300],
            "notes": self.notes[:40],
            "errors": real_errors[:50],
            "pages": self.pages,
        }


class Scanner:
    def __init__(
        self,
        opts: ScanOptions,
        emit: Callable[[dict], None],
        cancel: asyncio.Event | None = None,
    ):
        self.o = opts
        self.emit = emit
        # 取消信号：由 server 层 set，引擎在每个可中断的 await 点检查它。
        # 不传就自建一个（永不触发），这样脚本里直接 new Scanner(opts, emit)
        # 的行为和以前完全一样。
        self._cancel: asyncio.Event = cancel or asyncio.Event()
        self.result = ScanResult(opts.url)
        self.consts = ConstTable()
        self.api_fns: dict[str, tuple[str, str]] = {}   # 汇总所有文件的「封装函数名 → URL」
        self.fn_calls: list[tuple[str, list[str]]] = []  # 汇总所有「调用点的参数键」
        self.unresolved_params: set[tuple[str, str]] = set()  # (method, url) 有参数但解析不出名字
        self.base_prefix = ""   # 运行时 API 前缀，发现后套用到后续文件
        self._scheme = "https"
        self._visited: set[str] = set()
        self._queue: list[str] = []       # 业务 JS / 页面，优先抓
        self._queue_lib: list[str] = []   # 第三方库 JS，配额有剩再抓
        self._lib_count = 0
        self._done = 0
        self._fails = 0          # 抓取失败计数（不占配额，但要防无限尝试）
        self._total = 1
        self._fuzzed = False
        self._cpu_sem = asyncio.Semaphore(CPU_WORKERS)
        self._rt_left = 0        # 运行时回灌阶段的独立配额
        self._base_seen: set[tuple] = set()   # baseURL 去重（每个文件都会重复上报）
        self._spec_hints: set[str] = set()
        self._spec_probed: set[str] = set()

    # ---- 取消 ---------------------------------------------------------

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def _finish_cancelled(self) -> ScanResult:
        """
        用户点了停止：保留中止前已经拿到的部分结果，而不是整个丢掉。

        静态阶段扫过的每个文件都是有效成果，直接扔掉等于白跑一遍；
        这里只补上收尾信息，不改变任何已提取的数据。
        """
        self.result.finished = time.time()
        self.result.hosts.update(self._collect_hosts(self.result.endpoints))
        self.result.notes.append("扫描被用户中止，结果是中止前已完成的部分")
        self._emit(
            "progress",
            f"已停止 —— 中止前收集到 {len(self.result.endpoints)} 个接口 / "
            f"{len(self.result.resources)} 个资源",
            progress=1.0,
        )
        return self.result

    # ---- 对外入口 -----------------------------------------------------

    def _httpx_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(self.o.timeout),
            "follow_redirects": True,
            "verify": self.o.verify_ssl,
            "headers": self.o.merged_headers(),
            "limits": httpx.Limits(max_connections=self.o.concurrency * 2),
        }
        if self.o.proxy:
            kwargs["proxy"] = self.o.proxy
        else:
            kwargs["trust_env"] = True
        return kwargs

    async def run(self) -> ScanResult:
        target = self.o.url
        if not re.match(r"^https?://", target, re.I):
            target = "http://" + target
        self.result = ScanResult(target)

        kwargs = self._httpx_kwargs()

        self._emit("start", f"开始扫描 {target}")

        async with httpx.AsyncClient(**kwargs) as client:
            text, final_url = await self._fetch_text(client, target, "html")
            if text is None:
                self._emit("error", f"无法获取首页：{target}")
                self.result.finished = time.time()
                return self.result

            origin = origin_of(final_url)
            self._scheme = urlparse(final_url).scheme or "https"
            self._add_resource(final_url, "html", len(text), 200, 0)
            self.result.pages.append(final_url)
            self._visited.add(final_url)

            await self._analyze(text, final_url, "html")

            js_urls = find_script_urls(text, final_url)
            inline = find_inline_scripts(text)
            self._emit("progress", f"首页发现 {len(js_urls)} 个脚本 / {len(inline)} 段内联代码")

            for i, code in enumerate(inline):
                await self._analyze(code, f"{final_url} (内联#{i + 1})", "html")

            if self.o.crawl > 0:
                pages = [urldefrag(p)[0] for p in find_links(text, final_url, origin)]
                pages = [p for p in dict.fromkeys(pages) if p not in self._visited]
                self._queue.extend(pages[: self.o.crawl * 10])
                self._emit("progress", f"待爬取同源页面 {len(self._queue)} 个")

            for u in js_urls:
                self._enqueue(u)
            self._total = max(1, len(self._visited) + len(self._queue))

            if self.o.openapi:
                self._harvest_spec_hints(text, final_url)
                await self._probe_openapi(client, origin)

            await self._drain(client)
            if self.cancelled:
                return self._finish_cancelled()

            # JS 里发现的新文档地址，再补一轮探测
            if self.o.openapi and not self.cancelled:
                extra = [u for u in self._spec_hints if u not in self._spec_probed]
                if extra:
                    self._emit("progress", f"从代码里又发现 {len(extra)} 个接口文档地址")
                    await self._probe_openapi(client, origin, extra)

            # 兜底：接口数不多时，爆一波常见 JS 入口文件名
            if self.o.js_fuzz and len(self.result.endpoints) < 500 and not self.cancelled:
                await self._js_fuzz(client, origin)
                await self._drain(client)

        if self.cancelled:
            return self._finish_cancelled()

        # 静态分析跑完，最后做一次跨文件参数回填
        filled = self._backfill_params()
        if filled:
            self._emit("progress", f"从调用点回填了 {filled} 个参数", progress=0.85)
        guessed = self._backfill_pagination()
        if guessed:
            self._emit("progress", f"按本站惯例补了 {guessed} 个推测参数", progress=0.86)

        # 配额不够时明确告诉用户 —— 否则「漏接口」会表现成静默的假象
        left = len(self._queue) + len(self._queue_lib)
        if left:
            self.result.notes.append(
                f"还有 {left} 个已发现的 JS 没抓（受「最多分析文件数」{self.o.max_files} 限制）。"
                f"调大这个值可以覆盖更多懒加载 chunk。"
            )

        # 运行时采集：静态跑完再上浏览器。它慢，但能拿到静态永远拿不到的东西
        # ——拼好的真实 URL、真实请求体字段、真实鉴权头。
        if self.o.runtime and not self.cancelled:
            await self._runtime_pass(target)
        if self.cancelled:
            return self._finish_cancelled()

        # 前缀回填放在最后：此时所有文件（含运行时回灌那批）都分析完了，
        # self.base_prefix 已经是最终值，一次补齐；顺带消化掉「静态裸路径」
        # 与「运行时带前缀路径」指向同一接口而产生的重复条目。
        prefixed = self._backfill_prefix()
        if prefixed:
            self._emit(
                "progress",
                f"按运行时前缀 {self.base_prefix} 回填了 {prefixed} 个接口路径"
                f"（这些文件比前缀所在的 chunk 先被分析）",
                progress=0.997,
            )

        dropped = self._strip_page_params()
        if dropped:
            self._emit(
                "progress",
                f"清掉页面路由上的 {dropped} 个无效「参数」（实为组件属性）",
                progress=0.995,
            )

        self.result.finished = time.time()
        self.result.hosts.update(self._collect_hosts(self.result.endpoints))
        self._emit(
            "done",
            f"完成：{len(self.result.endpoints)} 个接口 / "
            f"{len(self.result.resources)} 个资源",
        )
        return self.result

    # ---- OpenAPI 探测 -------------------------------------------------

    def _harvest_spec_hints(self, text: str, base: str) -> None:
        """从页面 / JS 里找 Swagger 文档地址线索（swagger-ui 会把 spec 地址写在代码里）。"""
        if not text or len(text) > 8 * 1024 * 1024:
            return
        low = text.lower()
        if not any(k in low for k in SPEC_HINT_KEYWORDS):
            return
        for m in SPEC_HINT_RE.finditer(text):
            u = m.group("u").strip()
            if not u or u.startswith("data:") or len(u) > 300:
                continue
            self._spec_hints.add(urljoin(base, u))

    async def _probe_openapi(
        self, client: httpx.AsyncClient, origin: str, extra_targets: list[str] | None = None
    ) -> None:
        sem = asyncio.Semaphore(6)
        targets = [urljoin(origin + "/", p.lstrip("/")) for p in SPEC_PATHS]
        if extra_targets:
            targets.extend(extra_targets)
        targets = [u for u in dict.fromkeys(targets) if u not in self._spec_probed]
        self._spec_probed.update(targets)
        extra: list[str] = []

        async def probe(url: str) -> None:
            async with sem:
                try:
                    r = await client.get(url, headers={"Accept": "application/json,*/*"})
                except Exception:
                    return
                if r.status_code >= 400:
                    return
                body = r.text
                if not body or len(body) > 12 * 1024 * 1024:
                    return
                if body.lstrip()[:1] not in ("{", "["):
                    return
                try:
                    data = json.loads(body)
                except Exception:
                    return

                # swagger-config / swagger-resources：里面还挂着真正的文档地址
                if isinstance(data, dict) and isinstance(data.get("urls"), list):
                    for item in data["urls"][:8]:
                        u = (item or {}).get("url") if isinstance(item, dict) else None
                        if u:
                            extra.append(urljoin(str(r.url), str(u)))
                    return
                if isinstance(data, list) and data and isinstance(data[0], dict) and "url" in data[0]:
                    for item in data[:8]:
                        extra.append(urljoin(str(r.url), str(item.get("url"))))
                    return

                if not looks_like_spec(data):
                    return
                eps = parse_spec(data, str(r.url))
                if not eps:
                    return
                self._add_resource(str(r.url), "openapi", len(body), r.status_code, len(eps))
                self.result.openapi_specs.append(str(r.url))
                for e in eps:
                    e.source = str(r.url)
                    e.source_kind = "openapi"
                self._merge(eps)
                self._emit(
                    "progress",
                    f"发现接口文档 {r.url} → 新增 {len(eps)} 个接口",
                    progress=min(0.7, len(self.result.endpoints) / max(1, self._total * 8)),
                )

        await asyncio.gather(*(probe(u) for u in targets))
        if extra:
            self._emit("progress", f"接口文档里还指向 {len(extra)} 个子文档，继续探测")
            await asyncio.gather(*(probe(u) for u in dict.fromkeys(extra)[:10]))

    # ---- jsFuzz -------------------------------------------------------

    async def _js_fuzz(self, client: httpx.AsyncClient, origin: str) -> None:
        if self._fuzzed:
            return
        self._fuzzed = True
        js_urls = [u for u in self._visited if re.search(r"\.(js|mjs)(\?|$)", u, re.I)]
        candidates = find_js_fuzz_targets(js_urls, origin)
        pending = [u for u in candidates if u not in self._visited][:100]
        if not pending:
            return
        self._emit("progress", f"猜测 {len(pending)} 个常见 JS 入口文件")
        for u in pending:
            self._enqueue(u)
        self._total = max(self._total, self._done + len(pending))

    # ---- 队列调度 -----------------------------------------------------

    def _enqueue(self, url: str) -> None:
        url = urldefrag(url)[0]
        # 兜底：协议相对 URL（//host/x.js）没有 scheme，httpx 处理不了
        if url.startswith("//"):
            url = self._scheme + ":" + url
        if not url.startswith(("http://", "https://")):
            return
        if url in self._visited or len(self._visited) > self.o.max_files * 4:
            return
        self._visited.add(url)
        # 第三方库文件排到最后：它们体积大、几乎不含业务接口，
        # 先抓业务 chunk 能显著提高有限配额下的收获
        if is_library_js(url):
            self._queue_lib.append(url)
            self._lib_count += 1
        else:
            self._queue.append(url)

    async def _drain(self, client: httpx.AsyncClient) -> None:
        sem = asyncio.Semaphore(self.o.concurrency)
        # 业务队列优先；处理过程中发现的新业务 chunk 会插回 _queue，
        # 于是下一轮又优先于剩下的库文件
        while (self._queue or self._queue_lib) and not self.cancelled:
            q = self._queue if self._queue else self._queue_lib
            batch = q[: self.o.max_files]
            del q[: len(batch)]
            if not batch:
                break
            await asyncio.gather(*(self._work(client, u, sem) for u in batch))

    async def _work(
        self, client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore, rt: bool = False
    ) -> None:
        async with sem:
            # 点了停止后立刻退出：一整批 gather 里排队等信号量的那几百个任务
            # 会在这里瞬间返回，只有已经在飞的那 concurrency 个请求会跑完
            # （上限 = 单次请求超时），所以「停止」的响应是秒级的。
            if self.cancelled:
                return
            if url in self.result.pages:
                return
            if rt:
                # 运行时回灌阶段有独立配额：这批是「浏览器认证过」的真值，
                # 不该被静态那一轮已经用满的 max_files 挡在门外
                if self._rt_left <= 0:
                    return
                self._rt_left -= 1
            else:
                if self._done >= self.o.max_files:
                    return
                if self._fails >= self.o.max_files * 3:
                    return
                self._done += 1
            is_page = not re.search(r"\.(js|mjs)(\?|$)", url, re.I)
            kind = "html" if is_page else "js"
            text, final = await self._fetch_text(client, url, kind)
            if text is None:
                if not rt:
                    self._done -= 1          # 退还配额
                self._fails += 1
            if text is None and kind == "js":
                # 兜底：如果地址里有相邻重复目录（/assets/assets/x.js），
                # 折叠后再试一次。某些打包器会写出这种相对引用。
                alt = collapse_dup_dirs(url)
                if alt != url and alt not in self._visited:
                    self._visited.add(alt)
                    text, final = await self._fetch_text(client, alt, kind)
            if text is None:
                return
            self._add_resource(final, kind, len(text), 200, 0)

            before = len(self.result.endpoints)
            await self._analyze(text, final, kind)
            got = len(self.result.endpoints) - before

            if self.result.resources:
                self.result.resources[-1].endpoints = got

            if self.o.openapi:
                self._harvest_spec_hints(text, final)

            if is_page:
                self.result.pages.append(final)
                for u in find_script_urls(text, final):
                    self._enqueue(u)
                for i, code in enumerate(find_inline_scripts(text)):
                    await self._analyze(code, f"{final} (内联#{i + 1})", "html")
                if self.o.crawl > 0 and len(self.result.pages) < self.o.crawl * 12:
                    page_origin = origin_of(final)
                    for u in find_links(text, final, page_origin)[:40]:
                        self._enqueue(u)
            else:
                if self.o.discover_chunks:
                    for u in find_webpack_chunks(text, final):
                        self._enqueue(u)
                    for u in find_js_refs(text, final):
                        self._enqueue(u)
                if self.o.use_sourcemap:
                    sm = find_sourcemap_url(text, final)
                    if sm and sm not in self._visited:
                        self._visited.add(sm)
                        await self._load_sourcemap(client, sm, final, sem)

            self._emit(
                "file",
                f"{final.split('/')[-1][:58]} → 新增 {got} 个接口",
                progress=self._progress(),
                file=final,
                got=got,
            )

    def _progress(self) -> float:
        total = max(self._total, self._done)
        return round(min(0.98, self._done / max(1, total)), 3)

    async def _load_sourcemap(
        self, client: httpx.AsyncClient, sm_url: str, ref: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            text, final = await self._fetch_text(client, sm_url, "sourcemap")
            if text is None:
                return
            try:
                data = json.loads(text)
            except Exception:
                self._add_resource(final, "sourcemap", len(text), 200, 0)
                return
            sources = data.get("sourcesContent") or []
            names = data.get("sources") or []
            self._add_resource(final, "sourcemap", len(text), 200, len(sources))
            if not sources:
                self.result.notes.append(f"{final} 无 sourcesContent，无法还原源码")
                return
            self._emit("progress", f"解析 sourcemap：还原 {len(sources)} 个源文件")
            for i, code in enumerate(sources):
                if not isinstance(code, str) or len(code) < 20:
                    continue
                label = names[i] if i < len(names) else f"source#{i}"
                await self._analyze(code, f"{ref} ← {label}", "sourcemap")

    # ---- 抓取 ---------------------------------------------------------

    async def _fetch_text(
        self, client: httpx.AsyncClient, url: str, kind: str
    ) -> tuple[str | None, str]:
        try:
            # 必须再套一层总时长上限：httpx 的 Timeout 是 connect/read/write **各自**的
            # 间隔上限，不是整个请求的上限。CDN 慢速滴流时每次 read 都不超时，
            # 整个请求却能拖很久 —— 实测 bilibili 的 s1.hdslb.com 设 15s 却跑了 22s，
            # 这类请求几十个叠起来就是「一直在查询」。
            r = await asyncio.wait_for(client.get(url), timeout=self.o.timeout)
        except asyncio.TimeoutError:
            self.result.errors.append(
                f"{url} → 超过 {self.o.timeout:g}s 总时长上限，已放弃"
            )
            return None, url
        except Exception as e:
            self.result.errors.append(f"{url} → {type(e).__name__}: {str(e)[:110]}")
            return None, url
        if r.status_code >= 400:
            if not (".map" in url and r.status_code == 404):
                self.result.errors.append(f"{url} → HTTP {r.status_code}")
            return None, str(r.url)
        ctype = r.headers.get("content-type", "").lower()
        if kind == "js":
            if "image/" in ctype or "font/" in ctype or "text/css" in ctype:
                return None, str(r.url)
            # SPA 回退：路径不存在时服务器会返回 index.html。当成 JS 解析
            # 不但浪费时间，还会从 HTML 里再派生出 `assets/assets/xxx.js`
            # 这种重复路径，所以直接判为未命中
            if "text/html" in ctype:
                self.result.notes.append(f"{url} 返回的是 HTML（资源不存在，已跳过）")
                return None, str(r.url)
        if r.content and len(r.content) > self.o.max_size:
            self.result.errors.append(f"{url} → 文件过大已跳过（{len(r.content)} 字节）")
            return None, str(r.url)
        try:
            return r.text, str(r.url)
        except Exception:
            return r.content.decode("utf-8", "ignore"), str(r.url)

    # ---- 分析 ---------------------------------------------------------

    async def _analyze(self, code: str, source: str, kind: str) -> None:
        if not code or len(code) < 20:
            return

        def work():
            ex = JSExtractor(
                code,
                min_score=self.o.min_score,
                consts=self.consts,
                base_prefix=self.base_prefix,
            )
            return ex, ex.run()

        # 提取是纯 CPU 活儿；直接跑会把事件循环堵死（进度推送、结果接口
        # 全部超时），所以丢到线程池里跑，同时限制并发线程数
        async with self._cpu_sem:
            ex, eps = await asyncio.to_thread(work)
        if ex.base_prefix and not self.base_prefix:
            self.base_prefix = ex.base_prefix
            self.result.base_prefix = ex.base_prefix
            self._emit("progress", f"发现运行时 API 前缀：{ex.base_prefix}（已套用到接口路径）")
        for e in eps:
            e.source = source
            e.source_kind = kind
        self._merge(eps)
        # 本文件里发现的地址常量沉淀到全局，供后续文件解析
        self.consts.merge(ex.consts)
        for fn, info in ex.api_fns.items():
            self.api_fns.setdefault(fn, info)
        if ex.fn_calls:
            self.fn_calls.extend(ex.fn_calls)
        if ex.unresolved:
            self.unresolved_params |= ex.unresolved
        self._merge_findings(ex.findings, source)
        if ex.base_urls:
            # 每个 JS 文件里都写着同一份环境变量，不去重的话 baseURL 列表会
            # 膨胀到几千条（实测 348 个文件 × 若干 = 2624 条，去重后只有 19 条）。
            # 同时过滤掉 bgUrl / buyUrl / 图片地址这类跟 API 无关的配置。
            for b in ex.base_urls:
                key = str(b.get("key") or "")
                if not BASE_KEY_HINT.search(key):
                    continue
                k = (key, b.get("value"))
                if k in self._base_seen:
                    continue
                self._base_seen.add(k)
                self.result.base_urls.append(b)
        for h, c in ex.hosts.items():
            self.result.hosts[h] = self.result.hosts.get(h, 0) + c

    def _backfill_params(self) -> int:
        """
        跨文件回填参数。

        `getMessageList(e){return api.get({url:"...", params:e})}` 这种封装，
        参数名只有调用处才知道：`getMessageList({current:1, size:10})`。
        定义在主 bundle、调用在页面 chunk，所以要等所有文件都分析完再统一合并。

        保守起见：函数名必须**唯一**对应一个 URL 才回填 —— 压缩代码里重名很常见，
        猜错不如不填。
        """
        if not self.fn_calls or not self.api_fns:
            return 0

        by_fn: dict[str, set[tuple[str, str]]] = {}
        for fn, info in self.api_fns.items():
            by_fn.setdefault(fn, set()).add(info)

        index = {(e.method, url_key(e.url)): e for e in self.result.endpoints}
        added = 0
        for fn, keys in self.fn_calls:
            mapps = by_fn.get(fn)
            if not mapps or len(mapps) != 1:
                continue
            method, url = next(iter(mapps))
            ep = index.get((method, url_key(url)))
            if ep is None:
                continue
            # GET 的参数走 query，写操作走 body —— 和主流前后端约定一致
            loc = "query" if method in ("GET", "HEAD") else "body"
            have = {(p.name, p.location) for p in ep.params}
            for k in keys:
                k = str(k).strip()
                if not k or len(k) > 60 or (k, loc) in have:
                    continue
                ep.params.append(Param(name=k, location=loc))
                have.add((k, loc))
                added += 1
        return added

    def _backfill_pagination(self) -> int:
        """
        给「有参数、但静态看不到名字」的接口补通用分页参数。

        `getUserStoredCardList(e){ ...params:e }` 这类封装，字段名由调用方决定，
        静态分析拿不到。但这类列表查询接口的分页参数是框架固定的。

        这里**不硬编码**任何框架：先从本站已经确证的参数里统计出最常用的那一对
        分页字段（比如 current/size 还是 page/pageSize），再补到这些接口上，
        并标记 inferred=True —— 界面上和确证参数区分显示，用户自己判断。
        """
        if not self.unresolved_params:
            return 0

        PAGE = {"current", "page", "pageNo", "pageNum", "pageIndex", "pageIndex",
                "offset", "start", "begin"}
        SIZE = {"size", "pageSize", "limit", "rows", "perPage", "count"}
        pages: Counter = Counter()
        sizes: Counter = Counter()
        for e in self.result.endpoints:
            for p in e.params:
                if p.inferred:
                    continue
                if p.name in PAGE:
                    pages[p.name] += 1
                elif p.name in SIZE:
                    sizes[p.name] += 1
        if not pages or not sizes:
            return 0          # 站内找不到证据就不猜
        page_key = pages.most_common(1)[0][0]
        size_key = sizes.most_common(1)[0][0]

        index = {(e.method, url_key(e.url)): e for e in self.result.endpoints}
        added = 0
        for method, u in self.unresolved_params:
            ep = index.get((method, url_key(u)))
            if ep is None:
                continue
            # 已经有**确证的分页参数**才跳过 —— 有别的确证参数（比如 productType）
            # 不代表分页字段也解析到了
            if any(
                p.location in ("query", "body") and not p.inferred
                and (p.name in PAGE or p.name in SIZE)
                for p in ep.params
            ):
                continue
            # 登录/鉴权/字典这类接口不分页，塞 current/size 是纯噪声
            if NON_PAGINATION_RE.search(u.split("?")[0]):
                continue
            loc = "query" if method in ("GET", "HEAD") else "body"
            have = {(p.name, p.location) for p in ep.params}
            for name in (page_key, size_key):
                if (name, loc) in have:
                    continue
                ep.params.append(Param(name=name, location=loc, inferred=True))
                have.add((name, loc))
                added += 1
        if added:
            self.result.notes.append(
                f"有 {len(self.unresolved_params)} 个接口的参数名在调用方手里（静态看不到），"
                f"已按本站惯例补上推测的分页参数 {page_key}/{size_key} —— 界面上标注为「推测」"
            )
        return added

    def _merge(self, eps: list[Endpoint]) -> None:
        if not eps:
            return
        index = {(e.method, url_key(e.url)): e for e in self.result.endpoints}
        for e in eps:
            k = (e.method, url_key(e.url))
            old = index.get(k)
            if old is None:
                index[k] = e
                self.result.endpoints.append(e)
                continue
            old.count += 1
            old.confidence = max(old.confidence, e.confidence)
            # 运行时看到的是协议完整的真实地址，比静态的协议相对写法更准确
            if e.runtime_hit and old.url != e.url:
                old.url = e.url
            if old.ctx_type == "literal" and e.ctx_type != "literal":
                old.ctx_type = e.ctx_type
                old.fn_name = e.fn_name or old.fn_name
            if not old.prefix_var or e.runtime_hit:
                # 运行时确认过，前缀就不再是"未知变量"了
                old.prefix_var = "" if e.runtime_hit else e.prefix_var
            if e.page:
                old.page = True
            if e.runtime_hit:
                old.runtime_hit = True
                old.runtime_sample = old.runtime_sample or e.runtime_sample
                old.runtime_status = old.runtime_status or e.runtime_status
                if e.stack and not old.stack:
                    old.stack = e.stack
            have = {(p.name, p.location) for p in old.params}
            for p in e.params:
                if (p.name, p.location) not in have:
                    old.params.append(p)
                    have.add((p.name, p.location))
            if not old.context:
                old.context = e.context

    def _backfill_prefix(self) -> int:
        """
        收尾时按最终确定的前缀回填。

        运行时前缀（``/api`` 之类）写在某一个 chunk 里，而 chunk 的分析顺序是
        队列决定的 —— 比那个文件先被分析的文件，当时 ``self.base_prefix`` 还是空的，
        ``_finalize_url`` 只能原样输出裸路径。结果是**同一个服务的接口出现两种写法**：
        ``/api/blade-oss/x`` 和 ``/blade-oss/y`` 并存，后者在界面上按完整路径搜不到。

        这里在全部文件分析完之后统一补一次。只补**当时确实因为前缀未探到**而漏掉的
        条目（``_finalize_url`` 打的标记）：
          * 页面路由 —— 连标记都不会有（大写段判定在补前缀之前就 return 了）
          * 自带请求级 baseURL 的（``{url:"x", baseURL:"/AliYun/"}``）—— b 非空，同样不会标记
        """
        b = (self.base_prefix or "").rstrip("/")
        if not b:
            return 0

        pending = [e for e in self.result.endpoints if e.prefix_missing]
        if not pending:
            return 0

        keep = [e for e in self.result.endpoints if not e.prefix_missing]
        self.result.endpoints = keep

        changed: list[Endpoint] = []
        for e in pending:
            e.prefix_missing = False
            url = e.url
            if (
                not url.startswith("/")
                or url.startswith("//")
                or e.prefix_var                  # 前缀是未知变量，交给 _reconcile_prefix 处理
                or url == b
                or url.startswith(b + "/")
                or f"{b}/" in url                # 路径里已经有这个前缀段，别再叠一层
            ):
                keep.append(e)                   # 不需要补，原样放回
                continue
            e.url = b + url
            changed.append(e)

        if changed:
            # 回填后可能和另一条「本来就带前缀」的重复，走统一的合并逻辑消化掉
            self._merge(changed)
        return len(changed)

    def _merge_findings(self, findings: list[Finding], source: str) -> None:
        seen = {(f.kind, f.key.lower(), (f.value or "")[:64]) for f in self.result.findings}
        for f in findings:
            # 「只报键名」这一类价值低，而库文件里全是这种（pdf.js 的 signature /
            # nonce、各家 SDK 的 appid）—— 直接挡掉，别让它混进结果。
            # 带值的（secret）不在这里过滤：真密钥即使出现在库里也值得看一眼。
            if f.kind == "auth" and not f.value and is_library_js(source):
                continue
            k = (f.kind, f.key.lower(), (f.value or "")[:64])
            if k in seen or len(self.result.findings) >= 200:
                continue
            seen.add(k)
            f.source = source
            self.result.findings.append(f)

    def _add_resource(self, url: str, kind: str, size: int, status: int, eps: int) -> None:
        self.result.resources.append(
            Resource(url=url, kind=kind, size=size, status=status, endpoints=eps)
        )

    @staticmethod
    def _collect_hosts(eps: list[Endpoint]) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in eps:
            if e.kind == "absolute":
                try:
                    h = urlparse(e.raw if "://" in e.raw else "http:" + e.raw).hostname
                except Exception:
                    continue
                if h:
                    out[h] = out.get(h, 0) + 1
        return out

    # ---- 运行时采集 ---------------------------------------------------

    async def _runtime_pass(self, target: str) -> None:
        """用真实浏览器跑一遍页面，把观测到的请求并进结果。"""
        from .runtime import RuntimeCollector

        if self.cancelled:
            return
        self._emit("progress", "静态分析已完成，启动浏览器做运行时采集…", progress=0.9)
        col = RuntimeCollector(self.o, self.emit, cancel=self._cancel)
        hits = await col.run()

        self.result.notes.extend(col.notes)
        self.result.errors.extend(col.errors)
        self.result.runtime_channel = col._channel_used
        self.result.runtime_visits = col.visits
        self.result.runtime_hits = len(hits)
        self.result.runtime_scripts = len(col.scripts)

        # ---- ① 浏览器实载的 JS 清单回灌 ----
        if self.o.runtime_js and col.scripts:
            # 加一层时间预算：这一批可能有几百个文件，而站点 CDN 慢的时候单个请求
            # 能拖二十几秒，没有上限就是「一直在查询」。超时就收工，已抓到的都保留。
            budget = self.o.runtime_js_budget
            try:
                if budget > 0:
                    await asyncio.wait_for(
                        self._ingest_runtime_js(col.scripts), timeout=budget
                    )
                else:
                    await self._ingest_runtime_js(col.scripts)
            except asyncio.TimeoutError:
                self.result.notes.append(
                    f"JS 回灌超过 {budget:.0f} 秒预算已提前收工（已抓到的结果都保留）。"
                    f"想让它抓完，把「回灌时间上限」设为 0。"
                )
                self._emit(
                    "progress",
                    f"JS 回灌超过 {budget:.0f} 秒预算，已提前收工（结果保留）",
                    progress=0.92,
                )
            filled = self._backfill_params()
            guessed = self._backfill_pagination()
            if filled or guessed:
                self._emit(
                    "progress",
                    f"回灌的 JS 里又解析出 {filled + guessed} 个参数",
                    progress=0.92,
                )

        # ---- ② 前端路由表 ----
        # 必须放在回灌之后：回灌会带进来新的条目，它们同样要过一遍路由判定，
        # 否则会留下「按命名启发式猜的」残留标记
        if self.o.runtime_routes and col.routes:
            self.result.routes = list(col.routes)
            self.result.vue_version = col.vue_version
            marked, unmarked = self._apply_routes(col.routes)
            msg = f"从前端路由表读到 {len(col.routes)} 条路由"
            if marked:
                msg += f"，认定 {marked} 个条目其实是页面路由"
            if unmarked:
                msg += f"，并纠正了 {unmarked} 个被命名启发式误判的"
            self._emit("progress", msg, progress=0.96)

        if not hits:
            self._emit("progress", "运行时采集未捕获到任何请求")
            return

        # 合并阶段的任何意外都不该让静态分析的成果白跑
        try:
            eps = self._hits_to_endpoints(hits, target)
            before = len(self.result.endpoints)
            self._merge(eps)
            fixed = self._reconcile_prefix()
            hosted = self._attach_runtime_hosts()
        except Exception as e:
            self.result.errors.append(
                f"运行时结果合并失败：{type(e).__name__}: {str(e)[:130]}"
            )
            return

        self.result.hosts.update(self._collect_hosts(eps))
        added = len(self.result.endpoints) - before
        confirmed = sum(1 for e in self.result.endpoints if e.runtime_hit)
        msg = (
            f"运行时采集：捕获 {len(hits)} 个真实请求 → 新增 {added} 个接口，"
            f"{confirmed} 个接口得到真实地址确认"
        )
        if fixed or hosted:
            msg += f"，补全了 {fixed + hosted} 个接口的完整地址（前缀 / 域名）"
        self._emit("progress", msg, progress=0.99)

    # ---- 浏览器实载 JS 回灌 ---------------------------------------------

    async def _ingest_runtime_js(self, scripts) -> int:
        """
        把浏览器实际加载过的 JS 回灌进分析队列。

        这是「被动清单」的价值：静态分析靠递归解析 chunk 引用，会因配额截断、
        路径拼接错误、模板还原失败而漏；而浏览器加载过的脚本一定存在、
        一定是当前环境在用的那一份。用它兜底，漏报会明显下降。

        这批走独立配额（`runtime_js_max`），因为它们是浏览器认证过的真值，
        不该被静态那轮已经用满的 `max_files` 挡在门外。配额还有余时，
        会顺手把静态阶段没抓完的队列也一起清掉。
        """
        cap = self.o.runtime_js_max
        if cap <= 0:
            return 0

        fresh: list[str] = []
        seen: set[str] = set()
        for u in scripts:
            u = urldefrag(str(u or ""))[0]
            if u.startswith("//"):
                u = self._scheme + ":" + u
            if not u.startswith(("http://", "https://")):
                continue
            if not RT_SCRIPT_RE.search(urlparse(u).path):
                continue          # jsonp / loader 之类，浏览器也报 script，但没价值
            if u in self._visited or u in seen or u in self.result.pages:
                continue
            seen.add(u)
            fresh.append(u)

        # 第三方统计 / 风控脚本直接跳过：业务接口不可能挂在 analytics / 风控域名上，
        # 而它们数量不小（这个站 23 个），白占抓取时间
        skipped = 0
        biz: list[str] = []
        for u in fresh:
            if self._rt_rank(u) == 3:
                skipped += 1
                continue
            biz.append(u)
        fresh = biz
        if skipped:
            self.result.notes.append(f"回灌时跳过了 {skipped} 个第三方统计 / 风控脚本")

        pending = bool(self._queue or self._queue_lib)
        if not fresh and not pending:
            self._emit(
                "progress",
                f"浏览器加载的 {len(scripts)} 个脚本，静态分析已全部覆盖"
                + (f"（另跳过 {skipped} 个第三方脚本）" if skipped else ""),
                progress=0.94,
            )
            return 0

        # 分四层排优先级，保证有限配额先用在本站业务代码上：
        #   0 同源（一定和业务有关）
        #   1 跨域但文件名正常（可能是站点自己的 CDN，比如 B 站的 s1.hdslb.com）
        #   2 已知前端库（jquery/vue/echarts…）
        #   3 确定与业务无关的第三方（风控 / 统计 / 广告）
        batch = sorted(fresh, key=self._rt_rank)[:cap]
        if fresh:
            self._emit(
                "progress",
                f"浏览器实际加载了 {len(scripts)} 个脚本，其中 {len(fresh)} 个是静态没抓到的"
                f"（多为懒加载 chunk），补抓 {len(batch)} 个…",
                progress=0.94,
            )

        self._rt_left = cap
        budget0 = cap
        before = len(self.result.endpoints)
        sem = asyncio.Semaphore(self.o.concurrency)
        try:
            async with httpx.AsyncClient(**self._httpx_kwargs()) as client:
                await asyncio.gather(*(self._work(client, u, sem, rt=True) for u in batch))
                # 补抓的文件里又会暴露出新的 chunk，只要配额还有就继续用完
                while (
                    self._rt_left > 0
                    and (self._queue or self._queue_lib)
                    and not self.cancelled
                ):
                    q = self._queue if self._queue else self._queue_lib
                    nxt = q[: self._rt_left]
                    del q[: len(nxt)]
                    if not nxt:
                        break
                    await asyncio.gather(
                        *(self._work(client, u, sem, rt=True) for u in nxt)
                    )
        except Exception as e:
            self.result.errors.append(
                f"运行时 JS 回灌失败：{type(e).__name__}: {str(e)[:130]}"
            )
            return 0

        used = budget0 - self._rt_left
        added = len(self.result.endpoints) - before
        self.result.runtime_js_added = used
        if used:
            self.result.notes.append(
                f"浏览器实际加载了 {len(scripts)} 个脚本，其中 {len(fresh)} 个是静态分析没抓到的"
                f"（懒加载 chunk）；已用独立配额补抓 {used} 个 → 新增 {added} 个接口"
            )
            self._emit(
                "progress",
                f"补抓 {used} 个浏览器实载脚本 → 新增 {added} 个接口",
                progress=0.95,
            )
        return used

    def _rt_rank(self, url: str) -> int:
        """回灌优先级：同源 → 跨域正常 → 前端库 → 第三方统计/风控。"""
        try:
            host = (urlparse(url).hostname or "").lower()
            root = (urlparse(self.result.target).hostname or "").lower()
        except Exception:
            return 1
        if RT_THIRD_HOST_RE.search(host):
            return 3
        if is_library_js(url):
            return 2
        return 0 if host == root else 1

    def _strip_page_params(self) -> int:
        """
        页面路由不是接口，挂在它上面的「参数」全是组件 props 之类的东西。

        实测某条路由被解析出 67 个「参数」（enumerable / configurable / modelValue
        / label-width…），全是 Vue 组件的属性定义，混在参数统计里非常误导。
        既然已经能确认它是页面，就把这些一起清掉。
        """
        dropped = 0
        for e in self.result.endpoints:
            if e.page and e.params:
                dropped += len(e.params)
                e.params = []
        return dropped

    # ---- 前端路由表 -----------------------------------------------------

    @staticmethod
    def _route_key(path: str) -> str:
        """
        把路径归一化成可比对的键。

        `/User/:id/Detail` 和 `/user/{id}/detail` 说的是同一个页面，
        所以动态段一律折成 `*`，大小写、尾斜杠、query、hash 都抹平。
        """
        p = (path or "").strip()
        if not p:
            return ""
        p = p.split("?")[0].split("#")[0]
        if "://" in p:
            p = urlparse(p).path or ""
        segs: list[str] = []
        for seg in p.split("/"):
            if not seg or seg in (".", ".."):
                continue
            if seg.startswith(":") or (seg.startswith("{") and seg.endswith("}")) \
                    or seg in ("*", "**"):
                segs.append("*")
            else:
                segs.append(re.sub(r"\{[^/]{1,40}\}", "*", seg).lower())
        return "/".join(segs)

    def _route_candidates(self, url: str) -> list[str]:
        """
        一个接口地址可能的「路由写法」。

        静态提取时前缀会被套上去（`url:"Individual/Order/X"` → `/api/Individual/Order/X`），
        但路由表里存的是不带 API 前缀的 `/Individual/Order/X`。所以除了原样，
        还要试一下剥掉已识别的运行时前缀 —— 前缀是从 `VITE_BASE_URL` / `baseURL`
        真读出来的，不是猜的，所以这一步是安全的。
        """
        out: list[str] = []
        u = (url or "").strip()
        if not u:
            return out
        if u.startswith(("http://", "https://", "//")):
            try:
                u = urlparse(url_key(u)).path or "/"
            except Exception:
                return out
        out.append(u)
        bp = (self.base_prefix or "").rstrip("/")
        if bp and u.startswith(bp + "/"):
            out.append(u[len(bp):])
        return list(dict.fromkeys(out))

    def _apply_routes(self, routes: list[str]) -> tuple[int, int]:
        """
        用前端路由表精确标记「这不是接口，是页面」。

        以前只能靠「首段是大写驼峰」猜（`/Individual/Order/AliCloud`），
        会把 `/AliYun/order/index` 这类真接口误判成页面。路由表是权威答案。

        反过来，**路由表里没有的，就没理由是页面** —— 启发式标出来的 `guess`
        条目会被纠正回去。只在路由表足够可信（≥5 条）时才纠正，避免半截
        路由表把真页面放出来。
        """
        keys = {self._route_key(r) for r in routes}
        keys.discard("")
        if not keys:
            return 0, 0

        marked = 0
        for e in self.result.endpoints:
            if e.page:
                continue
            if self._route_hit(e.url, keys, strict=True):
                e.page = True
                e.page_src = "route"
                marked += 1

        unmarked = 0
        if len(keys) >= 5:
            for e in self.result.endpoints:
                if not e.page or e.page_src != "guess":
                    continue
                if self._route_hit(e.url, keys, strict=False):
                    e.page_src = "route"     # 启发式和路由表都说是页面
                    continue
                e.page = False
                e.page_src = ""
                unmarked += 1
        return marked, unmarked

    def _route_hit(self, url: str, keys: set[str], strict: bool) -> bool:
        """
        这个地址能不能对上路由表。

        `strict=True`（把接口判定成页面）时更保守：如果只有**剥掉 API 前缀**之后
        才命中，而且命中的是单段路由，就不认 —— 路由 `/goods`（页面）和真接口
        `/api/goods` 会互相撞车，这种时候宁可多留一个接口，也不能把它藏起来。

        `strict=False`（纠正启发式误判）方向相反：宁可认成页面，也别多冒一个假接口。
        """
        for i, c in enumerate(self._route_candidates(url)):
            k = self._route_key(c)
            if not k or k not in keys:
                continue
            if strict and i > 0 and "/" not in k:
                continue
            return True
        return False

    # ---- 运行时前缀补全 -------------------------------------------------

    def _reconcile_prefix(self) -> int:
        """
        运行时补全静态推断不出来的前缀。

        静态结果里 `url:"blade-system/x"` 会带着 prefix_var（前缀来自运行时变量），
        浏览器真实请求的却是 `/api/blade-system/x`。把两者对上，静态那条就升级成
        带完整前缀的真实地址 —— 这正是「按完整路径搜不到接口」的根因。
        """
        rt = [e for e in self.result.endpoints if e.runtime_hit and e.source_kind == "runtime"]
        if not rt:
            return 0

        index = {(e.method, url_key(e.url)): e for e in self.result.endpoints}
        drop: set[int] = set()
        fixed = 0

        for e in list(self.result.endpoints):
            if e.runtime_hit or not e.prefix_var or id(e) in drop:
                continue
            tail = "/" + e.url.lstrip("/")
            cand = [
                r for r in rt
                if r.url != e.url and r.url.endswith(tail) and len(r.url) > len(e.url)
            ]
            if len(cand) != 1:
                continue
            target = cand[0]
            occupied = index.get((e.method, url_key(target.url)))
            if occupied is not None and occupied is not target:
                # 目标地址已经有一条了：把参数并过去，丢掉这条残缺的
                have = {(p.name, p.location) for p in occupied.params}
                for p in e.params:
                    if (p.name, p.location) not in have:
                        occupied.params.append(p)
                        have.add((p.name, p.location))
                occupied.runtime_hit = True
                occupied.runtime_sample = occupied.runtime_sample or target.runtime_sample
                occupied.prefix_var = ""
                drop.add(id(e))
                fixed += 1
                continue

            index.pop((e.method, url_key(e.url)), None)
            e.url = target.url
            e.prefix_var = ""
            e.runtime_hit = True
            e.runtime_sample = target.runtime_sample or e.runtime_sample
            e.runtime_status = target.runtime_status
            e.confidence = 100
            e.method = target.method
            have = {(p.name, p.location) for p in e.params}
            for p in target.params:
                if (p.name, p.location) not in have:
                    e.params.append(p)
                    have.add((p.name, p.location))
            index[(e.method, url_key(e.url))] = e
            drop.add(id(target))          # 运行时新建的那条已并入，去掉重复
            fixed += 1

        if drop:
            self.result.endpoints = [
                e for e in self.result.endpoints if id(e) not in drop
            ]
        return fixed

    def _attach_runtime_hosts(self) -> int:
        """
        给静态分析里「只有路径、没有域名」的接口补上运行时观测到的域名。

        静态常提取到 `/x/web-interface/nav`（域名在别处拼进去），运行时看到的却是
        `https://api.bilibili.com/x/web-interface/nav`。不把两者对上，同一个接口会
        以两种形式各占一行 —— 用户看到的接口数虚高，还得自己脑补域名。
        """
        rt = [
            e for e in self.result.endpoints
            if e.runtime_hit and e.source_kind == "runtime" and e.kind == "absolute"
        ]
        if not rt:
            return 0

        by_path: dict[str, list[Endpoint]] = {}
        for r in rt:
            try:
                by_path.setdefault(urlparse(r.url).path.rstrip("/"), []).append(r)
            except Exception:
                continue

        drop: set[int] = set()
        merged = 0
        for e in list(self.result.endpoints):
            if e.runtime_hit or e.kind != "path" or id(e) in drop:
                continue
            # 太短的路径（/x、/list）不唯一，宁可不合
            if e.url.count("/") < 2 or len(e.url) < 8:
                continue
            cands = [c for c in by_path.get(e.url.rstrip("/"), []) if id(c) not in drop]
            if len(cands) != 1 or cands[0].method != e.method:
                continue
            t = cands[0]

            e.url = t.url
            e.kind = "absolute"
            e.runtime_hit = True
            e.runtime_status = t.runtime_status
            e.runtime_sample = t.runtime_sample or e.runtime_sample
            e.confidence = 100
            have = {(p.name, p.location) for p in e.params}
            for p in t.params:
                if (p.name, p.location) not in have:
                    e.params.append(p)
                    have.add((p.name, p.location))
            drop.add(id(t))
            merged += 1

        if drop:
            self.result.endpoints = [
                e for e in self.result.endpoints if id(e) not in drop
            ]
        return merged

    def _hits_to_endpoints(self, hits, target: str) -> list[Endpoint]:
        """把浏览器观测到的请求转成 Endpoint，以便与静态结果合并。"""
        base = urlparse(target)
        root = f"{base.scheme}://{base.netloc}"
        out: list[Endpoint] = []

        for h in hits:
            raw = (h.url or "").strip()
            if not raw.startswith(("http://", "https://")):
                continue
            p = urlparse(raw)
            if runtime_drop(p.path):
                continue          # 图片/字体/媒体，不可能是接口
            # 返回 HTML 的是页面导航 / SPA 局部页面（常见于预取用户主页链接），
            # 不是接口。真接口极少返回 text/html。
            if (h.content_type or "").startswith(("text/html", "image/", "font/", "text/css")):
                continue
            same_origin = f"{p.scheme}://{p.netloc}" == root
            path = self._templatize(p.path or "/")
            if not path.startswith("/"):
                path = "/" + path
            # 同源 → 统一的路径写法（和静态结果对齐）；跨域 → 完整 URL
            url = path if same_origin else f"{p.scheme}://{p.netloc}{path}"

            params: list[Param] = []
            seen: set[tuple[str, str]] = set()

            def add(name, loc, sample="", ptype="unknown"):
                name = str(name or "").strip()
                if not name or len(name) > 80 or (name, loc) in seen:
                    return
                sample = str(sample)[:120]
                # 运行时拿到的都是真实值；[Blob 123] 这种是 hook 的占位说明
                seen.add((name, loc))
                params.append(
                    Param(name=name, location=loc, sample=sample,
                          type=guess_type(sample) if not sample.startswith("[") else "binary",
                          required=True)   # 真实发出去的请求，参数就是必带的
                )

            for k, vs in parse_qs(p.query, keep_blank_values=True).items():
                add(k, "query", vs[0] if vs else "")

            body = (h.post_data or "").strip()
            if body and not body.startswith("["):
                if body[:1] in ("{", "["):
                    try:
                        data = json.loads(body)
                    except Exception:
                        data = None
                    if isinstance(data, dict):
                        for k, v in data.items():
                            add(k, "body", v if isinstance(v, (str, int, float, bool)) else json.dumps(v, ensure_ascii=False))
                else:
                    for part in body.split("&"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            add(k, "body", v)

            for k, v in (h.headers or {}).items():
                add(k, "header", v)

            fn_name = ""
            if h.stack:
                m = re.search(r"([\w.\-]+\.js[^)\s]*:\d+:\d+)", h.stack[0])
                fn_name = m.group(1)[:80] if m else h.stack[0][:80]

            out.append(
                Endpoint(
                    url=url,
                    raw=raw,
                    method=h.method or "GET",
                    kind="path" if same_origin else "absolute",
                    params=params,
                    confidence=100,           # 真实发出去了，不存在猜错
                    context=(h.stack[0] if h.stack else ""),
                    source="运行时采集（真实浏览器）",
                    source_kind="runtime",
                    ctx_type=h.kind or "fetch",
                    fn_name=fn_name,
                    third_party=_is_third_party(raw) or runtime_noise(p.path),
                    runtime_hit=True,
                    runtime_sample=raw,
                    runtime_status=h.status,
                    stack=h.stack[:5],
                    count=h.count,
                )
            )

        return out

    @staticmethod
    def _templatize(path: str) -> str:
        """
        把真实路径里的具体值还原成占位符，才能和静态分析结果对上：

            /blade-system/dict/12345678      → /blade-system/dict/{id}
            /user/7f3a...-uuid/detail        → /user/{uuid}/detail

        注意只动**整段都是**数字/UUID/长哈希的分段，`/api/v2/x` 这类不受影响。
        """
        segs: list[str] = []
        for seg in (path or "/").split("/"):
            if re.fullmatch(r"\d{2,}", seg):
                segs.append("{id}")
            elif re.fullmatch(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                seg,
            ):
                segs.append("{uuid}")
            elif re.fullmatch(r"[0-9a-fA-F]{16,}", seg):
                segs.append("{hash}")
            else:
                segs.append(seg)
        out = "/".join(segs)
        return out if out.startswith("/") else "/" + out

    # ---- 事件 ---------------------------------------------------------

    def _emit(self, event: str, message: str, **extra) -> None:
        payload = {
            "event": event,
            "message": message,
            "progress": extra.pop("progress", self._progress()),
            "endpoints": len(self.result.endpoints),
            "files": len(self.result.resources),
            "time": round(time.time() - self.result.started, 2),
        }
        payload.update(extra)
        try:
            self.emit(payload)
        except Exception:
            pass
