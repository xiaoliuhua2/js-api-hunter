"""
JS API Hunter —— 后端服务。

启动：  python server.py
然后浏览器打开 http://127.0.0.1:8765
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import ScanOptions, Scanner  # noqa: E402

BASE = Path(__file__).parent
PORT = int(os.environ.get("PORT", 8765))

app = FastAPI(title="JS API Hunter", version="1.0.0")

# --------------------------------------------------------------------------
# 任务存储
# --------------------------------------------------------------------------


class Task:
    def __init__(self, tid: str, opts: dict):
        self.id = tid
        self.opts = opts
        self.queue: asyncio.Queue = asyncio.Queue()
        self.result: dict | None = None
        self.status = "running"        # running | done | error | cancelled
        self.error = ""
        self.cancel_flag = False
        # 真正的取消信号：引擎在 await 点检查它。置位后扫描会尽快收手，
        # 而不是只把状态改成「已取消」、后台却继续跑到结束。
        self.cancel_event: asyncio.Event = asyncio.Event()
        self.created = time.time()
        self.scan_result = None

    def push(self, payload: dict) -> None:
        self.queue.put_nowait(payload)


TASKS: dict[str, Task] = {}
MAX_TASKS = 30


def _gc() -> None:
    if len(TASKS) <= MAX_TASKS:
        return
    for tid in sorted(TASKS, key=lambda k: TASKS[k].created)[: len(TASKS) - MAX_TASKS]:
        if TASKS[tid].status != "running":
            TASKS.pop(tid, None)


# --------------------------------------------------------------------------
# 路由
# --------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index():
    f = BASE / "static" / "index.html"
    return HTMLResponse(f.read_text(encoding="utf-8"))


@app.post("/api/scan")
async def start_scan(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    url = str(body.get("url", "")).strip()
    if not url:
        raise HTTPException(400, "缺少 url 参数")
    if not url.startswith("http"):
        body["url"] = "http://" + url

    tid = uuid.uuid4().hex[:12]
    task = Task(tid, body)
    TASKS[tid] = task
    _gc()
    asyncio.create_task(_run_scan(task))
    return {"task_id": tid}


async def _run_scan(task: Task) -> None:
    loop = asyncio.get_running_loop()

    def emit(payload: dict) -> None:
        loop.call_soon_threadsafe(task.push, payload)

    try:
        opts = ScanOptions(task.opts)
        scanner = Scanner(opts, emit, cancel=task.cancel_event)
        task.scan_result = scanner
        result = await scanner.run()
        if task.cancel_flag:
            task.status = "cancelled"
        task.result = result.to_dict()
        task.status = task.status if task.status == "cancelled" else "done"
    except Exception as e:
        task.status = "error"
        task.error = f"{type(e).__name__}: {e}"
        task.push({"event": "error", "message": task.error, "progress": 1.0})
    finally:
        task.push({"event": "__end__", "message": "", "progress": 1.0,
                   "status": task.status})


@app.get("/api/scan/{tid}/events")
async def scan_events(tid: str):
    task = TASKS.get(tid)
    if not task:
        raise HTTPException(404, "任务不存在")

    async def gen():
        yield _sse({"event": "open", "message": "已连接", "progress": 0,
                    "endpoints": 0, "files": 0, "time": 0})
        while True:
            try:
                payload = await asyncio.wait_for(task.queue.get(), timeout=25)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue
            if payload.get("event") == "__end__":
                yield _sse({**payload, "event": "end"})
                break
            yield _sse(payload)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Connection": "keep-alive"},
    )


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


@app.get("/api/scan/{tid}/result")
async def scan_result(tid: str):
    task = TASKS.get(tid)
    if not task:
        raise HTTPException(404, "任务不存在")
    if task.status == "running":
        return JSONResponse({"status": "running", "partial": _partial(task)})
    if task.status == "error":
        return JSONResponse({"status": "error", "error": task.error})
    return JSONResponse({"status": task.status, "data": task.result})


def _partial(task: Task) -> dict:
    s = task.scan_result
    if not s:
        return {"endpoints": [], "resources": [], "stats": {}}
    return {
        "endpoints": [e.to_dict() for e in s.result.endpoints[:500]],
        "resources": [r.to_dict() for r in s.result.resources],
        "stats": {"endpoints": len(s.result.endpoints)},
    }


@app.post("/api/scan/{tid}/cancel")
async def cancel_scan(tid: str):
    task = TASKS.get(tid)
    if not task:
        raise HTTPException(404, "任务不存在")
    task.cancel_flag = True
    task.status = "cancelled"
    task.cancel_event.set()      # 唤醒引擎里的 await 点，让它立刻收手
    return {"ok": True}


# --------------------------------------------------------------------------
# 导出
# --------------------------------------------------------------------------


@app.get("/api/scan/{tid}/export")
async def export(tid: str, fmt: str = "json"):
    task = TASKS.get(tid)
    if not task or not task.result:
        raise HTTPException(404, "结果不存在")
    return _render_export(task.result, fmt)


@app.get("/api/export")
async def export_multi(ids: str = "", fmt: str = "json"):
    """
    多目标合并导出。

    `ids` 是逗号分隔的 task_id（顺序即目标顺序）。前端做「全部目标」视图时用它，
    这样合并逻辑（去重、参数并集、统计汇总）只有一份实现，不用在 JS 里再抄一遍。
    """
    results = []
    for t in (x.strip() for x in ids.split(",")):
        task = TASKS.get(t)
        if t and task and task.result:
            results.append(task.result)
    if not results:
        raise HTTPException(404, "结果不存在")
    data = results[0] if len(results) == 1 else _merge_results(results)
    return _render_export(data, fmt)


def _render_export(data: dict, fmt: str):
    """把一份结果渲染成指定格式的下载响应。单目标与合并共用这一条路径。"""
    raw = (data.get("target") or "result").split(",")[0].strip()
    host = raw.split("//")[-1].split("/")[0].replace(":", "_") or "result"
    if data.get("_merged"):
        host = "merged-" + host
    stamp = time.strftime("%Y%m%d-%H%M")

    if fmt == "json":
        body = json.dumps(data, ensure_ascii=False, indent=2)
        return _dl(body, f"api-{host}-{stamp}.json", "application/json")
    if fmt == "csv":
        return _dl(_to_csv(data), f"api-{host}-{stamp}.csv", "text/csv")
    if fmt in ("md", "markdown"):
        return _dl(_to_md(data), f"api-{host}-{stamp}.md", "text/markdown")
    if fmt == "txt":
        lines = [e["method"] + " " + e["url"] for e in data.get("endpoints", [])]
        return _dl("\n".join(lines), f"api-{host}-{stamp}.txt", "text/plain")
    if fmt in ("http", "rest"):
        return _dl(_to_http(data), f"api-{host}-{stamp}.http", "text/plain")
    raise HTTPException(400, "不支持的格式")


def _origin(url: str) -> str:
    p = urlparse(url or "")
    return f"{p.scheme}://{p.netloc}" if (p.scheme and p.netloc) else ""


def _count_by(items: list[dict], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        k = str(it.get(key) or "")
        out[k] = out.get(k, 0) + 1
    return out


def _merge_results(results: list[dict]) -> dict:
    """
    把多个目标的扫描结果合成一份。

    去重口径与前端「全部目标」视图一致：`(方法, 路径)` 相同即视为同一个接口，
    参数取并集、置信度取高、任一目标实测过就标 runtime_hit。
    每个接口带上 `_origin`（它属于哪个站点），否则合并后的相对路径就没法还原成完整地址。
    """
    eps: dict[tuple, dict] = {}
    host_map: dict[str, dict] = {}
    base_map: dict[tuple, dict] = {}
    find_map: dict[tuple, dict] = {}
    res_map: dict[str, dict] = {}
    stats: dict[str, float] = {}
    elapsed = 0.0
    targets: list[str] = []

    for d in results:
        targets.append(d.get("target") or "")
        elapsed += float(d.get("elapsed") or 0)
        for k, v in (d.get("stats") or {}).items():
            if isinstance(v, (int, float)):
                stats[k] = stats.get(k, 0) + v
        origin = _origin(d.get("target") or "")

        for e in d.get("endpoints", []):
            key = (e.get("method"), e.get("url"))
            cur = eps.get(key)
            if cur is None:
                row = dict(e)
                row["_origin"] = origin
                eps[key] = row
                continue
            have = {p.get("name") for p in cur.get("params") or []}
            for p in e.get("params") or []:
                if p.get("name") not in have:
                    cur.setdefault("params", []).append(p)
                    have.add(p.get("name"))
            cur["confidence"] = max(cur.get("confidence") or 0, e.get("confidence") or 0)
            if e.get("runtime_hit"):
                cur["runtime_hit"] = True
                cur["runtime_status"] = cur.get("runtime_status") or e.get("runtime_status")

        for h in d.get("hosts", []):
            cur = host_map.get(h.get("host"))
            if cur:
                cur["count"] = (cur.get("count") or 0) + (h.get("count") or 0)
            else:
                host_map[h.get("host")] = dict(h)
        for b in d.get("base_urls", []):
            base_map.setdefault((b.get("key"), b.get("value")), dict(b))
        for f in d.get("findings", []):
            find_map.setdefault((f.get("kind"), f.get("key"), f.get("value")), dict(f))
        for r in d.get("resources", []):
            res_map.setdefault(r.get("url"), dict(r))

    endpoints = sorted(eps.values(), key=lambda e: -(e.get("confidence") or 0))
    stats["endpoints"] = len(endpoints)
    stats["params"] = sum(len(e.get("params") or []) for e in endpoints)
    stats["hosts"] = len(host_map)
    stats["findings"] = len(find_map)
    stats.pop("elapsed", None)

    return {
        "target": " , ".join(t for t in targets if t),
        "elapsed": round(elapsed, 1),
        "endpoints": endpoints,
        "hosts": sorted(host_map.values(), key=lambda h: -(h.get("count") or 0)),
        "base_urls": list(base_map.values()),
        "findings": list(find_map.values()),
        "resources": list(res_map.values()),
        "stats": stats,
        "notes": [n for d in results for n in (d.get("notes") or [])],
        "errors": [x for d in results for x in (d.get("errors") or [])],
        "by_method": _count_by(endpoints, "method"),
        "by_ctx": _count_by(endpoints, "ctx_type"),
        "runtime_channel": next((d.get("runtime_channel") for d in results if d.get("runtime_channel")), ""),
        "base_prefix": next((d.get("base_prefix") for d in results if d.get("base_prefix")), ""),
        "routes": sum(len(d.get("routes") or []) for d in results),
        "vue_version": next((d.get("vue_version") for d in results if d.get("vue_version")), ""),
        "_merged": True,
    }


def _dl(body: str, name: str, mime: str):
    return PlainTextResponse(
        body,
        media_type=mime + "; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"},
    )


def _to_csv(data: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["接口路径", "方法", "参数名", "参数位置", "参数类型", "示例值",
                "接口置信度", "来源文件", "完整原始串"])
    for e in data.get("endpoints", []):
        if not e.get("params"):
            w.writerow([e["url"], e["method"], "", "", "", "", e["confidence"],
                        e["source"], e["raw"]])
        for p in e["params"]:
            w.writerow([e["url"], e["method"], p["name"], p["location"], p["type"],
                        p.get("sample", ""), e["confidence"], e["source"], e["raw"]])
    return buf.getvalue()


def _to_http(data: dict) -> str:
    """
    导出 .http 请求模板（JetBrains HTTP Client / VS Code REST Client 格式）。

    可以直接被 IDE 的 HTTP Client 识别，也方便整段贴到 Burp Repeater / Postman 里。
    参数只填「名字」，值留空占位 —— 工具不会真的发这些请求。
    """
    target = data.get("target") or ""
    default_host = urlparse(target).netloc or target.split("//")[-1].split("/")[0]
    scheme = urlparse(target).scheme or "https"

    lines = [
        f"# 由 JS API Hunter 生成 — 目标 {target}",
        f"# 共 {len(data.get('endpoints', []))} 个接口，参数为占位符，请自行填写后再发送",
        "",
    ]

    for e in data.get("endpoints", []):
        url = e.get("url") or ""
        # 合并导出时每个接口自带 `_origin`（属于哪个站点）；单目标导出回落到 data.target
        origin = e.get("_origin") or target
        ep_host = urlparse(origin).netloc or origin.split("//")[-1].split("/")[0] or default_host
        ep_scheme = urlparse(origin).scheme or scheme
        if url.startswith("http"):
            full_url, req_host = url, urlparse(url).netloc
        elif url.startswith("//"):
            full_url, req_host = f"{ep_scheme}:{url}", url.split("/")[2] if len(url.split("/")) > 2 else ep_host
        else:
            full_url, req_host = f"{ep_scheme}://{ep_host}{url}", ep_host

        method = e.get("method") or "GET"
        params = e.get("params") or []
        qs = [p["name"] for p in params if p.get("location") == "query"]
        path = urlparse(full_url).path or "/"
        query = "&".join(f"{quote(str(n))}=" for n in qs)
        req_target = path + (("?" + query) if query else "")

        lines.append(f"### {method} {url}"
                     + (f"   [{e.get('fn_name')}]" if e.get("fn_name") else ""))
        lines.append(f"{method} {req_target} HTTP/1.1")
        lines.append(f"Host: {req_host}")
        lines.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        lines.append("Accept: application/json, text/plain, */*")

        for p in params:
            if p.get("location") == "header":
                lines.append(f"{p['name']}: ")

        body_params = [p for p in params if p.get("location") == "body"]
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE") and body_params:
            lines.append("Content-Type: application/json;charset=UTF-8")
            lines.append("")
            lines.append("{")
            lines.append(",\n".join(f'  "{p["name"]}": ""' for p in body_params))
            lines.append("}")
        lines.append("")
        lines.append("")

    return "\n".join(lines)


def _to_md(data: dict) -> str:
    st = data.get("stats", {})
    out = [
        f"# 接口清单 — {data.get('target')}",
        "",
        f"- 扫描时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 耗时：{data.get('elapsed')}s",
        f"- 接口 **{st.get('endpoints', 0)}** 个 / 参数 **{st.get('params', 0)}** 个 / "
        f"JS 文件 {st.get('js_files', 0)} 个 / 域名 {st.get('hosts', 0)} 个",
        "",
    ]
    eps = data.get("endpoints", [])
    groups: dict[str, list] = {}
    for e in eps:
        groups.setdefault(e["method"], []).append(e)
    for method in sorted(groups):
        out.append(f"## {method}（{len(groups[method])}）")
        out.append("")
        for e in groups[method]:
            out.append(f"### `{e['url']}`")
            out.append("")
            out.append(f"- 置信度：{e['confidence']}")
            out.append(f"- 来源：`{e['source']}`")
            if e.get("params"):
                out.append("")
                out.append("| 参数 | 位置 | 类型 | 示例 |")
                out.append("| --- | --- | --- | --- |")
                for p in e["params"]:
                    out.append(
                        f"| `{p['name']}` | {p['location']} | {p['type']} | "
                        f"`{str(p.get('sample', ''))[:60]}` |"
                    )
            out.append("")
    if data.get("base_urls"):
        out.append("## 发现的 baseURL / 环境变量")
        out.append("")
        out.append("| 键 | 值 |")
        out.append("| --- | --- |")
        for b in data["base_urls"][:80]:
            out.append(f"| `{b['key']}` | `{b['value']}` |")
        out.append("")
    if data.get("findings"):
        out.append("## 鉴权字段 / 疑似凭证")
        out.append("")
        out.append("| 类型 | 键 | 值 |")
        out.append("| --- | --- | --- |")
        for f in data["findings"]:
            out.append(f"| {f['kind']} | `{f['key']}` | `{str(f.get('value', ''))[:60]}` |")
        out.append("")
    return "\n".join(out)


@app.get("/api/health")
async def health():
    return {"ok": True, "time": time.time()}


app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


if __name__ == "__main__":
    import uvicorn

    print(f"\n  JS API Hunter  →  http://127.0.0.1:{PORT}\n")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
