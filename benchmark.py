"""
准确率基准 —— 用真实流量当标准答案，把「更准了没有」变成看得见的数字。

为什么需要它：改召回/准确相关的规则（前缀回填、页面判定、评分阈值）时，
光看「提取了多少接口」说明不了问题 —— 放宽阈值就能刷高，但全是噪声。
所以这里固定三件事来量：

  1. **召回**：标准答案是浏览器真实发出过的请求（`benchmarks/<slug>.json` 的 truth），
     拿静态分析的结果去对。对不上就是漏报，没有争议。
  2. **噪声**：命中已知库内部 / 命名空间 / 第三方特征的条目数。越少越好。
     这些模式是确定性匹配，不受分数阈值影响，所以能稳定反映回归。
  3. **规模**：接口 / 参数 / 页面路由条数。用来发现「接口数暴涨」这类副作用。

用法：
    python benchmark.py                 # 跑全部案例，和 baseline 对比
    python benchmark.py --save          # 把当前结果写进 baseline
    python benchmark.py sjzc            # 只跑名字里含 sjzc 的案例

退出码：召回下降或噪声上升 → 1；否则 0。适合挂进提交前检查。

注意：这是**联网**跑的，站点内容会变，指标有正常波动。
所以判断标准是「明显变差」而不是「数字必须一模一样」。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from core.scanner import ScanOptions, Scanner  # noqa: E402

BENCH_DIR = Path(__file__).parent / "benchmarks"

# 已知噪声特征：第三方库内部串、XML 命名空间、文档格式标识、MIME 类型、转义残留。
# 刻意只放**确定性**的特征 —— 不要把「置信度低」当噪声，那是循环论证。
#
# 注意：这是个固定清单，站点换了就可能有新的噪声类落在清单外，
# 那时 noise 会显示成 0 —— 那是**指标的盲区，不是真的没噪声**。
# 每扫一个新形态的站点，都要拿它的 404 条目回来补这里，
# 否则这个数字会骗人（fanyu 用例第一次跑就是这样）。
NOISE_RE = re.compile(
    r"w3\.org|adobe\.com|AcroPDF|ActiveXObject|MediaPlayer|\.PDF/|"
    r"mp4a\.|/[a-z]*codec|zencoding|"
    r"aliyun\.com|aliapp\.org|beian\.gov\.cn|qr\.95516\.com|"
    r"(?:^|/)text/css$|"                     # style.type = 'text/css'
    r"(?:/u[0-9a-f]{4}){2,}",                # 写坏了的 \uXXXX 转义（/u661f/u671f）
    re.I,
)

# 容忍度：超过这个幅度才算回归（站点内容本身会漂）
TOL_RECALL = 1        # 召回允许少 1 条
TOL_NOISE = 5         # 噪声允许 +5 条


def norm(p: str) -> str:
    p = (p or "").split("?")[0].rstrip("/")
    return p or "/"


def match_truth(ep_url: str, truth: list[str]) -> str | None:
    """端点地址和标准答案是否指向同一个接口。"""
    a = norm(ep_url)
    for t in truth:
        if a == t:
            return t
        # 静态侧可能只拿到路径后半段（前缀没解析出来），或多了前缀
        if a.endswith(t) or t.endswith(a):
            return t
    return None


async def run_case(case: dict) -> dict:
    opts = ScanOptions({**case.get("options", {}), "url": case["url"], "runtime": False})
    t0 = time.time()
    result = await Scanner(opts, lambda p: None).run()
    eps = result.endpoints
    truth = [norm(t) for t in case.get("truth", [])]

    found: dict[str, str] = {}
    for e in eps:
        t = match_truth(e.url, truth)
        if t and t not in found:
            found[t] = e.url
    missed = [t for t in truth if t not in found]

    noise = [e for e in eps if NOISE_RE.search(e.url)]
    # 「用户真的会看到的」噪声：界面默认隐藏页面路由和第三方接口，
    # 所以只有既不是页面、也没被标第三方的，才是真正碍眼的那批
    vis_noise = [e for e in noise if not e.page and not e.third_party]
    pages = [e for e in eps if e.page]

    return {
        "elapsed": round(time.time() - t0, 1),
        "endpoints": len(eps),
        "params": sum(len(e.params) for e in eps),
        "pages": len(pages),
        "noise": len(noise),
        "visible_noise": len(vis_noise),
        "truth_total": len(truth),
        "truth_found": len(found),
        "recall": round(len(found) / max(1, len(truth)), 3),
        "missed": missed,
        "noise_sample": [e.url for e in vis_noise][:6] or [e.url for e in noise][:6],
    }


def fmt_delta(cur, base, key):
    """显示当前值 + 变化量，**不判好坏**。

    接口数 / 参数数 / 页面数没有「越多越好」—— 放宽阈值就能刷高，那不代表变准。
    它们的作用只是让人一眼看到「数字暴涨」这类副作用；
    真正判好坏的只有上面的召回和下面的噪声。
    """
    v = cur.get(key)
    if base is None or base.get(key) is None:
        return str(v)
    d = v - base[key]
    return f"{v}" if d == 0 else f"{v}  ({'+' if d > 0 else ''}{d})"


def fmt_noise(cur, base):
    v = cur.get("noise", 0)
    if base is None or base.get("noise") is None:
        return str(v)
    d = v - base["noise"]
    if d == 0:
        return f"{v}   基线 {base['noise']}"
    # 幅度在容忍度内就只报数字、不判好坏 —— 站点内容本身就会漂，
    # 每次波动都盖个「变差」的章只会让这个指标失去可信度
    if abs(d) <= TOL_NOISE:
        return f"{v}   基线 {base['noise']}  ({'+' if d > 0 else ''}{d}，在容忍度内)"
    return (f"{v}   基线 {base['noise']}  ({'+' if d > 0 else ''}{d}) "
            f"{'变大（变差）' if d > 0 else '变少（变好）'}")


def main() -> int:
    ap = argparse.ArgumentParser(description="准确率基准")
    ap.add_argument("filter", nargs="?", default="", help="只跑名字含该串的案例")
    ap.add_argument("--save", action="store_true", help="把当前指标写入 baseline")
    args = ap.parse_args()

    files = sorted(BENCH_DIR.glob("*.json"))
    files = [f for f in files if not f.name.startswith("_") and args.filter in f.stem]
    if not files:
        print(f"没找到基准文件（{BENCH_DIR}/*.json）")
        return 1

    failed = False
    for fp in files:
        case = json.loads(fp.read_text(encoding="utf-8"))
        print("=" * 78)
        print(f"案例 {case.get('name', fp.stem)}   {case['url']}")
        print(f"标准答案 {len(case.get('truth', []))} 条（{case.get('truth_source', '')[:34]}…）")
        print("=" * 78)

        cur = asyncio.run(run_case(case))
        base = case.get("baseline")

        if args.save:
            case["baseline"] = {k: cur[k] for k in
                                ("endpoints", "params", "pages", "noise", "visible_noise",
                                 "truth_total", "truth_found", "recall", "elapsed")}
            fp.write_text(json.dumps(case, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
            print("  已写入 baseline")
        else:
            print(f"  召回      {cur['truth_found']}/{cur['truth_total']} = {cur['recall']:.0%}"
                  + (f"   基线 {base['truth_found']}/{base['truth_total']}"
                     if base else "   （还没有基线，用 --save 记录）"))
            print(f"  噪声      {fmt_noise(cur, base)}")
            if base and base.get("visible_noise") is not None:
                vd = cur["visible_noise"] - base["visible_noise"]
                print(f"  其中可见   {cur['visible_noise']}   基线 {base['visible_noise']}"
                      + (f"  ({'+' if vd > 0 else ''}{vd})" if vd else ""))
            else:
                print(f"  其中可见   {cur['visible_noise']}   (排除页面路由和第三方后，用户真正看到的)")
            print(f"  接口      {fmt_delta(cur, base, 'endpoints')}")
            print(f"  参数      {fmt_delta(cur, base, 'params')}")
            print(f"  页面路由  {fmt_delta(cur, base, 'pages')}")
            print(f"  耗时      {cur['elapsed']}s")
            if base:
                print("  （接口/参数/页面数只反映规模，站点内容有漂移，±几条属正常）")

            if base:
                if cur["truth_found"] < base["truth_found"] - TOL_RECALL:
                    print(f"  !! 召回下降：{base['truth_found']} → {cur['truth_found']}")
                    failed = True
                if cur["noise"] > base["noise"] + TOL_NOISE:
                    print(f"  !! 噪声上升：{base['noise']} → {cur['noise']}")
                    failed = True

        if cur["missed"]:
            print(f"  漏报 {len(cur['missed'])} 条：")
            for m in cur["missed"]:
                print(f"      {m}")
        if cur["noise_sample"]:
            print(f"  噪声样例：{cur['noise_sample']}")
        print()

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
