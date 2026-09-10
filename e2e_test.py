"""端到端测试：走真实 HTTP API + SSE，跑一个线上站点。"""

import json
import sys
import threading
import time

import httpx

BASE = "http://127.0.0.1:8765"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://juejin.cn"
MAXFILES = int(sys.argv[2]) if len(sys.argv) > 2 else 40

payload = {
    "url": TARGET,
    "concurrency": 10,
    "timeout": 15,
    "max_files": MAXFILES,
    "crawl": 0,
    "sourcemap": True,
    "chunks": True,
    "min_score": 30,
}

r = httpx.post(f"{BASE}/api/scan", json=payload, timeout=30)
tid = r.json()["task_id"]
print("task:", tid, "target:", TARGET)

stop = threading.Event()


def reader():
    with httpx.stream("GET", f"{BASE}/api/scan/{tid}/events", timeout=900) as s:
        for line in s.iter_lines():
            if stop.is_set():
                break
            if not line.startswith("data: "):
                continue
            m = json.loads(line[6:])
            if m.get("event") in ("file", "progress", "start", "error"):
                print(f"  [{m.get('time', 0):>6.1f}s] {m.get('message', '')[:110]}")
            if m.get("event") == "end":
                print("  >>> 结束，状态:", m.get("status"))
                break


t = threading.Thread(target=reader, daemon=True)
t.start()
t.join(timeout=900)
stop.set()

res = httpx.get(f"{BASE}/api/scan/{tid}/result", timeout=60).json()
if res.get("status") != "done":
    print("扫描未正常完成:", res.get("status"), res.get("error"))
    sys.exit(1)

d = res["data"]
s = d["stats"]
print()
print("=" * 78)
print(f"目标 {d['target']}   耗时 {d['elapsed']}s")
print(f"接口 {s['endpoints']} / 参数 {s['params']} / JS {s['js_files']} / "
      f"sourcemap {s['sourcemaps']} / 域名 {s['hosts']} / 凭证 {s['findings']} / "
      f"接口文档 {s.get('openapi', 0)}")
print("按方法:", d["by_method"])
print("按触发方式:", d.get("by_ctx"))
if d.get("openapi_specs"):
    print("发现文档:", d["openapi_specs"])
print("=" * 78)

eps = sorted(d["endpoints"], key=lambda e: (-e["confidence"], e["url"]))
for e in eps[:35]:
    ps = ", ".join(
        f"{p['location'][0]}:{p['name']}" + (f"={str(p['sample'])[:14]}" if p["sample"] else "")
        for p in e["params"]
    ) or "—"
    print(f"[{e['confidence']:>3}] {e['method']:<6} {e['url'][:100]}")
    if ps != "—":
        print(f"      └ {ps[:150]}")

print()
print("域名 TOP:", [h["host"] for h in d["hosts"][:8]])
print()
print("baseURL 示例:")
for b in d["base_urls"][:10]:
    print(f"   {b['key']:<32} = {b['value'][:70]}")
print()
print("凭证/鉴权字段:", [(f["kind"], f["key"]) for f in d["findings"][:15]])
print()
print("错误:", d["errors"][:5])

for fmt in ("json", "csv", "md"):
    rr = httpx.get(f"{BASE}/api/scan/{tid}/export?fmt={fmt}", timeout=60)
    print(f"导出 {fmt}: HTTP {rr.status_code}, {len(rr.text)} 字节")
