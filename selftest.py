"""引擎自测：用合成 JS 验证提取效果，不需要联网。

覆盖这几类容易漏的场景：
  * 字符串拼接 / 模板串 / 常量引用
  * 二次封装的请求函数（request / service.xxx）
  * 无前导斜杠的相对路径
  * XHR / sendBeacon / WebSocket / location 赋值
  * 静态资源与代码路径的噪声排除
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from core.extractor import (  # noqa: E402
    JSExtractor,
    find_webpack_chunks,
    find_script_urls,
    find_js_fuzz_targets,
    is_library_js,
    resolve_js_ref,
)
from core.expr import ConstTable  # noqa: E402

# 假密钥在源码里拆成两段拼接，避免被 GitHub 密钥扫描（secret scanning /
# push protection）误报成真实泄露；运行时拼回完整串交给检测器，断言不变。
K_AIza    = "AIza" + "SyD-1234567890abcdefghijklmnopqrst"
K_ghp     = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
K_xoxb    = "xoxb" + "-123456789012-abcdefghijklmnop"
K_sk_live = "sk_live_" + "51H8xYzAbCdEfGhIjKlMnOpQr"
K_sk      = "sk-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef"
K_pem     = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234"
K_npm     = "npm_" + "1234567890abcdefghijklmnopqrstuvwxyz"

SAMPLE = r"""
// ---------- 常量与 baseURL ----------
var baseURL = "https://api.example.com/v2";
const API_HOST = 'https://gateway.example.com';
const BASE = "/api/v1";
const SAME = BASE;
const ApiPrefix = "/gateway";
axios.defaults.baseURL = "https://api.example.com";

// ---------- 直接字面量 ----------
export function login(username, password) {
  return request({ url: "/api/user/login", method: "post",
    data: { username, password, captcha: code, rememberMe: true } });
}
export const getUser = (id) => axios.get(`/api/user/${id}/detail`);

// ---------- 拼接 / 模板 / 常量 ----------
export function listOrders(pageNum, pageSize, status) {
  return axios.get("/api/" + type + "/list", { params: { pageNum, pageSize, status } });
}
axios.get(BASE + "/user/info", { params: { uid } });
service.post(SAME + "/order/detail", { orderId: oid });
request(`${ApiPrefix}/pay/cashier/${orderId}`);

// ---------- 无前导斜杠的相对路径 ----------
service.del("api/user/remove", { data: { userId } });
http.post("interact_api/v1/digg/save", JSON.stringify({ itemId, itemType }));

// ---------- 二次封装函数（非 axios/fetch） ----------
function doQuery(kw) { return callApi("/search_api/v1/query", { keyword: kw }); }
wrapped("/content_api/v1/article/detail", { articleId: id });

// ---------- 对象字面量形式：HTTP 方法由外层函数名决定，没有 method 字段 ----------
service.get({ url: "obj_api/v1/user/detail", params: { userId } });
service.post({ url: "obj_api/v1/user/submit", data: form });
service.put({ url: "obj_api/v1/user/modify", data: form });
service.del({ url: "obj_api/v1/user/remove", params: { ids } });
api.request({ url: "obj_api/v1/raw/upload", method: "patch", data: blob });

// ---------- fetch / XHR / beacon / ws ----------
fetch("/api/v1/notice/read?noticeId=123&type=2", {
  method: "POST",
  headers: { Authorization: "Bearer " + token, "X-Trace-Id": uuid() },
  body: JSON.stringify({ ids: [], all: false })
});
const xhr = new XMLHttpRequest();
xhr.open("PUT", "/api/v2/profile/update");
xhr.send(JSON.stringify({ nickname: nn, avatar: av }));
navigator.sendBeacon("/collect_api/v1/track", JSON.stringify({ evt: e }));
new WebSocket("wss://ws.example.com/api/socket/connect");

// ---------- jQuery ----------
$.ajax({ url: "/admin/system/config/save", type: "POST", data: { configKey: "site" } });
$.post("/admin/system/config/list", { pageNum: 1 });

// ---------- location ----------
location.href = "/client/login/redirect";

// ---------- 调用点回填（URL 在常量里、参数在调用里）----------
const ORDER_URL = "/api/v3/order/page";
axios.get(ORDER_URL, { params: { pageNo: 1, pageSize: 20, status: 2 } });

// ---------- 首段是域名，应补成协议相对 ----------
const CDN = "api.example.com/pgc/player/web/v2/playurl";

// ---------- 噪声：静态资源 / 代码路径 / i18n / MIME / 模块相对路径 ----------
var img = "/static/logo.abc123.png";
var css = "/assets/index.4f2a1b.css";
var chunk = "/static/js/vendor.9a8b7c.js";
import Header from "./components/Header.vue";
const t = (k) => k; t("common.confirm");
console.log("/some/log/path");
require("./utils/format");
headers["Content-Type"] = "application/json";
var accept = "text/javascript";
var bogus = "./undefined";
var bogus2 = "application/x-www-form-urlencoded";
var pct = "https://www.%s/ads/ga-audiences";

// ---------- 第三方统计接口，应被标记而不是丢掉 ----------
gtag("config", "G-XXXX");
fetch("https://www.google-analytics.com/g/collect?v=2&tid=G-XXXX");
fetch("/g/collect?v=2&tid=G-XXXX");
"""

HTML = """
<html><head>
<link rel="modulepreload" href="/static/js/app.js">
</head><body>
<script src="/static/js/runtime.js"></script>
<script src="https://cdn.example.com/lib/vendor.min.js?v=3"></script>
<script>var x = fetch("/inner/api/ping", {method:"POST", body: JSON.stringify({ts: Date.now(), sig: s})});</script>
<a href="/client/settings">设置</a>
</body></html>
"""

WEBPACK = 'r.u=function(e){return "static/js/"+e+"."+{0:"a1b2c3",1:"d4e5f6",2:"0099ff"}[e]+".js"}'

# 运行时前缀：源码里 url 不带 /api，真实请求要补上
BASE_SAMPLE = r"""
const {VITE_BASE_URL} = {VITE_APP_MODE:"production", VITE_BASE_URL:"/api/"};
service.get({url: "blade-system/dict/list", method: "get", params: {current: 1}});
service.post({url: "blade-system/dict/submit", method: "post", data: row});
service.post({url: "blade-system/dict/remove", method: "post", params: {ids}});
service.get({url: "/blade-system/dict-biz/dictionary", params: {code}});
// 页面路由不该被加前缀
const routes = [{ path: "/Login", name: "login" }, { path: "/goods" }];
// 已经是完整路径的不重复加
service.get({url: "/api/blade-user/user/info"});
"""


def main():
    ok = True

    print("=" * 78)
    print("HTML 资源发现")
    print("=" * 78)
    for u in find_script_urls(HTML, "https://www.example.com/a/b"):
        print("  ", u)

    print()
    print("webpack chunk 还原")
    for u in find_webpack_chunks(WEBPACK, "https://www.example.com/static/js/app.js")[:5]:
        print("  ", u)

    print()
    print("jsFuzz 候选（前 6 个）")
    for u in find_js_fuzz_targets(["https://www.example.com/static/js/app.js"])[:6]:
        print("  ", u)

    print()
    print("=" * 78)
    print("接口提取")
    print("=" * 78)
    ex = JSExtractor(SAMPLE, min_score=30)
    eps = ex.run()
    eps.sort(key=lambda e: (-e.confidence, e.method, e.url))

    noisy = []
    for e in eps:
        ps = ", ".join(
            f"{p.location[0]}:{p.name}" + (f"={str(p.sample)[:14]}" if p.sample else "")
            for p in e.params
        ) or "—"
        print(f"  [{e.confidence:>3}] {e.method:<6} {e.url:<44} <{e.ctx_type}/{e.fn_name or '-'}>")
        if ps != "—":
            print(f"        └ {ps[:130]}")
        if any(x in e.url for x in (".png", ".css", ".vue", "components/", "utils/", "common.confirm")):
            noisy.append(e.url)

    print()
    print("baseURL / 地址常量：")
    for b in ex.base_urls[:12]:
        print(f"    {b['key']:<24} = {b['value']}")
    print("域名：", ex.hosts)
    print("凭证/鉴权：", [(f.kind, f.key) for f in ex.findings])
    print()
    print(f"合计 {len(eps)} 个接口")

    # ---- 断言 ----
    urls = {e.url for e in eps}

    def want(u, note=""):
        nonlocal ok
        if u not in urls:
            print(f"  ✗ 缺失预期接口: {u} {note}")
            ok = False

    def reject(sub, note=""):
        nonlocal ok
        hit = [u for u in urls if sub in u]
        if hit:
            print(f"  ✗ 噪声混入: {hit} {note}")
            ok = False

    print()
    print("=" * 78)
    print("断言")
    print("=" * 78)
    # 拼接 / 模板 / 常量
    want("/api/{type}/list", "字符串拼接")
    want("/api/v1/user/info", "常量拼接")
    want("/api/v1/order/detail", "常量别名链")
    want("/gateway/pay/cashier/{orderId}", "模板串+常量")
    want("/api/user/{id}/detail", "模板串")
    want("/api/v3/order/page", "调用点常量回填")
    # 相对路径：应被规范化成带前导斜杠的站点绝对路径
    want("/api/user/remove", "无前导斜杠 → 补 /")
    want("/interact_api/v1/digg/save", "无前导斜杠+JSON.stringify")
    # 首段是域名 → 协议相对
    want("//api.example.com/pgc/player/web/v2/playurl", "域名+路径")
    # 二次封装
    want("/search_api/v1/query", "callApi 封装")
    want("/content_api/v1/article/detail", "wrapped 封装")
    # 各种请求方式
    want("/api/v1/notice/read", "fetch")
    # 对象字面量形式的方法推断
    want("/obj_api/v1/user/detail", "service.get({url})")
    want("/obj_api/v1/user/submit", "service.post({url})")
    want("/obj_api/v1/user/modify", "service.put({url})")
    want("/obj_api/v1/user/remove", "service.del({url})")
    want("/api/v2/profile/update", "XHR")
    want("/collect_api/v1/track", "sendBeacon")
    want("/admin/system/config/save", "jQuery ajax")
    want("/client/login/redirect", "location.href")
    # 噪声
    reject(".png", "静态图")
    reject(".css", "样式")
    reject(".vue", "组件路径")
    reject("components/", "代码目录")
    reject("utils/", "工具目录")
    reject("application/", "MIME 类型")
    reject("text/javascript", "MIME 类型")
    reject("./", "模块相对路径")

    # 所有路径都必须有前导 / 或 //，不能出现裸相对路径
    bad = [e.url for e in eps if not e.url.startswith(("/", "http", "ws"))]
    if bad:
        print(f"  ✗ 存在没有前导斜杠的路径: {bad}")
        ok = False
    else:
        print("  ✓ 所有路径都带前导 /")

    # 非法百分号应被过滤
    reject("%", "非法百分号（模板残留）")

    # 第三方统计接口应被标记，且仍可查
    third = {e.url for e in eps if e.third_party}
    own = {e.url for e in eps if not e.third_party}
    if not third:
        print("  ✗ 没有识别出任何第三方统计接口")
        ok = False
    else:
        print(f"  ✓ 第三方接口已标记（{len(third)} 个）: {sorted(third)[:3]}")
    leaked = [u for u in third if u in own]
    if leaked:
        print(f"  ✗ 第三方标记不一致: {leaked}")
        ok = False

    # 参数校验
    def params_of(u):
        for e in eps:
            if e.url == u:
                return {p.name: p.location for p in e.params}
        return {}

    checks = [
        ("/api/user/login", {"username": "body", "password": "body", "rememberMe": "body"}),
        ("/api/{type}/list", {"pageNum": "query", "pageSize": "query", "status": "query"}),
        ("/api/v1/notice/read", {"noticeId": "query", "type": "query", "ids": "body"}),
        ("/api/v3/order/page", {"pageNo": "query", "pageSize": "query", "status": "query"}),
        ("/api/user/{id}/detail", {"id": "path"}),
    ]
    # 方法校验：对象字面量形式必须能推断出正确的 HTTP 方法
    method_by_url = {e.url: e.method for e in eps}
    method_checks = [
        ("/obj_api/v1/user/detail", "GET"),
        ("/obj_api/v1/user/submit", "POST"),
        ("/obj_api/v1/user/modify", "PUT"),
        ("/obj_api/v1/user/remove", "DELETE"),
        ("/obj_api/v1/raw/upload", "PATCH"),
        ("/api/user/login", "POST"),
        ("/api/v2/profile/update", "PUT"),
        ("/admin/system/config/save", "POST"),
    ]
    print()
    for u, exp in method_checks:
        got = method_by_url.get(u)
        if got != exp:
            print(f"  ✗ {u} 方法应为 {exp}，实际 {got}")
            ok = False
        else:
            print(f"  ✓ {u} 方法={got}")

    print()
    for u, expect in checks:
        got = params_of(u)
        missing = {k: v for k, v in expect.items() if got.get(k) != v}
        if missing:
            print(f"  ✗ {u} 参数不符，缺/错: {missing}（实际 {got}）")
            ok = False
        else:
            print(f"  ✓ {u} 参数正确 {list(expect)}")

    # ---- 运行时前缀（VITE_BASE_URL）----
    print()
    print("=" * 78)
    print("运行时 API 前缀")
    print("=" * 78)
    exb = JSExtractor(BASE_SAMPLE, min_score=30)
    base_eps = exb.run()
    print(f"  探测到前缀: {exb.base_prefix!r}")
    got = {e.url for e in base_eps}
    for u in sorted(got):
        print(f"    {u}")
    print()
    if exb.base_prefix != "/api":
        print(f"  ✗ 前缀探测错误，期望 /api，实际 {exb.base_prefix!r}")
        ok = False
    else:
        print("  ✓ 前缀探测正确（/api）")
    for u, note in [
        ("/api/blade-system/dict/list", "无斜杠 url → 补前缀"),
        ("/api/blade-system/dict/submit", "submit"),
        ("/api/blade-system/dict/remove", "remove"),
        ("/api/blade-system/dict-biz/dictionary", "本身带 /"),
        ("/api/blade-user/user/info", "已含前缀不重复"),
    ]:
        if u not in got:
            print(f"  ✗ 缺失: {u}（{note}）")
            ok = False
    # 页面路由可以被提取出来，但绝不能被加上 API 前缀
    bad_prefix = [u for u in got if u.startswith(exb.base_prefix + "/Login")
                  or u.startswith(exb.base_prefix + "/goods")
                  or u.startswith(exb.base_prefix + exb.base_prefix)]
    if bad_prefix:
        print(f"  ✗ 前缀被错误套用: {bad_prefix}")
        ok = False
    else:
        print("  ✓ 页面路由未被误加前缀，已含前缀的也没重复")

    # 参数仍要正确
    for e in base_eps:
        if e.url == "/api/blade-system/dict/list":
            names = {p.name for p in e.params}
            if "current" not in names:
                print(f"  ✗ dict/list 参数缺失: {names}")
                ok = False
            else:
                print(f"  ✓ dict/list 参数正确 {sorted(names)}")

    # ---- JS 引用解析 & 库文件识别 ----
    print()
    print("=" * 78)
    print("JS 引用解析 / 库文件识别")
    print("=" * 78)
    ref_cases = [
        # Vite 的 __vite__mapDeps 用 `./assets/x.js` 表示「相对文档根」
        ("./assets/Purchase-a1.js", "https://h/assets/index-9f.js",
         "https://h/assets/Purchase-a1.js", "文档根相对"),
        # 同一个依赖表里还有**不带 ./ 前缀**的写法，一样相对文档根。
        # 漏判会把 /assets/a.js 拼成 /assets/assets/a.js（实测该站漏了 240 个 chunk）
        ("assets/Purchase-a1.js", "https://h/assets/index-9f.js",
         "https://h/assets/Purchase-a1.js", "文档根相对（无 ./ 前缀）"),
        ("./Purchase-a1.js", "https://h/assets/index-9f.js",
         "https://h/assets/Purchase-a1.js", "chunk 相对"),
        ("./js/chunk.js", "https://h/static/js/app.js",
         "https://h/static/js/js/chunk.js", "深目录不误判"),
        ("../lib/x.js", "https://h/assets/sub/app.js",
         "https://h/assets/lib/x.js", "上级目录"),
        # 协议相对：必须补上 scheme，否则 httpx 直接报 unknown url type
        ("//cdn.other.com/x.js", "https://h/assets/app.js",
         "https://cdn.other.com/x.js", "协议相对"),
        ("/abs/x.js", "https://h/assets/app.js",
         "https://h/abs/x.js", "根绝对路径"),
    ]
    for ref, base, exp, note in ref_cases:
        got = resolve_js_ref(ref, base)
        if got != exp:
            print(f"  ✗ {ref} @ {base} → {got}，期望 {exp}（{note}）")
            ok = False
        else:
            print(f"  ✓ {note}: {ref} → {got}")

    lib_cases = [
        ("https://g.alicdn.com/AWSC/AWSC/AWSC-br/fireyejs/1.227.0/fireyejs.js", True),
        ("https://cloud.sjzc.edu.cn/assets/pdfjs-dist-6651c146.js", True),
        ("https://cloud.sjzc.edu.cn/assets/element-plus-030566bc.js", True),
        ("https://cloud.sjzc.edu.cn/assets/index-05c393a7.js", False),
        # 站点自己的 CDN 不能被判成第三方，业务 chunk 就在上面
        ("https://s1.hdslb.com/bfs/static/shanks/laputa-home/assets/index-37875958.js", False),
    ]
    for u, exp in lib_cases:
        got = is_library_js(u)
        if got != exp:
            print(f"  ✗ 库文件判定错误 {u} → {got}，期望 {exp}")
            ok = False
    if all(is_library_js(u) == e for u, e in lib_cases):
        print(f"  ✓ 库文件识别 {len(lib_cases)} 项全部正确")

    # ---- 请求级 baseURL 不能当成全局前缀 ----
    print()
    print("=" * 78)
    print("请求级 baseURL（同一文件里多种前缀并存）")
    print("=" * 78)
    multi = r"""
var baseURL = "/api";
VITE_BASE_URL = "/api";
const api = {
  getList:   (e) => r.get({url:"blade-vstec/dtorder/getList", params:e}),
  aliOrder:  (e) => r.post({url:"order/index", timeout:60000, baseURL:"/AliYun/"}),
  aliStatus: (e) => r.get({url:"order/orderStatus", params:e, baseURL:"/AliYun/"}),
};
"""
    exm = JSExtractor(multi, min_score=0)
    got = {e.url for e in exm.run()}
    if exm.base_prefix == "/api":
        print("  ✓ 全局前缀没被请求级 baseURL 污染")
    else:
        print(f"  ✗ 全局前缀应推断为 /api，实际 {exm.base_prefix!r}")
        ok = False
    for want in ("/api/blade-vstec/dtorder/getList",
                 "/AliYun/order/index",
                 "/AliYun/order/orderStatus"):
        if want in got:
            print(f"  ✓ {want}")
        else:
            print(f"  ✗ 缺少 {want}")
            ok = False

    # ---- API 封装识别（跨文件参数回填的基础）----
    print()
    print("=" * 78)
    print("API 封装识别 / 未解析参数标记")
    print("=" * 78)
    wrap = r"""
const api = {
  getMessageList(e){ return client.get({url:"blade-vstec/tnoticevo/page", params:e}) },
  getSiteConfig(e){ return client.get({url:"blade-vstec/exhomeconfig/getByTenantId",
                                       params:{page:1, size:100, tenantId:e}}) },
  getAliSignIn(e){ return client.get({url:"blade-vstec/alishopcontroller/aliSignIn", params:e}) },
};
api.getMessageList({current:1, size:10});
"""
    exw = JSExtractor(wrap, min_score=0, base_prefix="/api")
    exw.run()
    fns = {k: v[1] for k, v in exw.api_fns.items()}
    for want_fn, want_url in (("getMessageList", "/api/blade-vstec/tnoticevo/page"),
                              ("getSiteConfig", "/api/blade-vstec/exhomeconfig/getByTenantId")):
        if fns.get(want_fn) == want_url:
            print(f"  ✓ 封装识别 {want_fn} → {want_url}")
        else:
            print(f"  ✗ {want_fn} 期望 {want_url}，实际 {fns.get(want_fn)}")
            ok = False
    # `params:e`（变量）→ 参数名看不到，要标记；`params:{...}` → 能解析，不标
    if ("GET", "/api/blade-vstec/tnoticevo/page") in exw.unresolved:
        print("  ✓ params:变量 被标记为「看不到参数名」")
    else:
        print(f"  ✗ 未标记 unresolved：{exw.unresolved}")
        ok = False
    if ("GET", "/api/blade-vstec/exhomeconfig/getByTenantId") not in exw.unresolved:
        print("  ✓ 字面量 params 不会被误标")
    else:
        print("  ✗ 字面量 params 被误标")
        ok = False
    # 调用点的参数对象要被收集，供 scanner 跨文件回填
    keys = [k for _fn, k in exw.fn_calls if _fn == "getMessageList"]
    if keys and "current" in keys[0] and "size" in keys[0]:
        print(f"  ✓ 调用点参数被收集：{keys[0]}")
    else:
        print(f"  ✗ 调用点参数未收集：{exw.fn_calls}")
        ok = False

    # ---- 前端路由表：精确区分「页面路由」和「接口」----
    print()
    print("=" * 78)
    print("前端路由表（Vue Router）→ 页面路由判定")
    print("=" * 78)
    from core.scanner import ScanOptions, Scanner
    from core.models import Endpoint

    # 路径归一化
    key_cases = [
        ("/Individual/Order/AliCloud", "individual/order/alicloud"),
        ("/user/:id/detail", "user/*/detail"),
        ("/user/{id}/detail", "user/*/detail"),
        ("/a/:pathMatch(.*)*/b", "a/*/b"),
        ("/Login/", "login"),
    ]
    for src, want in key_cases:
        got = Scanner._route_key(src)
        if got == want:
            print(f"  ✓ {src:<28} → {got}")
        else:
            print(f"  ✗ {src:<28} → {got}（期望 {want}）")
            ok = False

    sc = Scanner(ScanOptions({"url": "https://x.com"}), lambda p: None)
    sc.base_prefix = "/api"
    sc.result.base_prefix = "/api"
    sc.result.endpoints = [
        # 启发式误判成页面，但路由表里没有 → 应该被纠正回接口
        Endpoint(url="/api/AliYun/order/index", method="POST", confidence=90,
                 page=True, page_src="guess"),
        # 路由表命中（剥掉 /api 前缀后）→ 页面
        Endpoint(url="/api/Individual/Order/AliCloud", method="GET", confidence=60),
        # 动态段归一化后命中 → 页面
        Endpoint(url="/api/user/{id}/detail", method="GET", confidence=80),
        # 路由表里完全没有 → 保持接口
        Endpoint(url="/api/blade-vstec/dtorder/getList", method="GET", confidence=95),
        # 剥前缀后只命中单段路由 → 保守起见不认（真接口 /api/goods vs 页面 /goods）
        Endpoint(url="/api/goods", method="GET", confidence=94),
    ]
    routes = [
        "/Individual/Order/AliCloud", "/user/:id/detail", "/Console/MAAS/List",
        "/login", "/Register", "/goods",
    ]
    marked, unmarked = sc._apply_routes(routes)
    eps = {e.url: e for e in sc.result.endpoints}
    want = [
        ("/api/AliYun/order/index", False, "", "不在路由表里 → 纠正回接口"),
        ("/api/Individual/Order/AliCloud", True, "route", "剥掉 /api 前缀后命中路由表"),
        ("/api/user/{id}/detail", True, "route", "动态段归一化后命中"),
        ("/api/blade-vstec/dtorder/getList", False, "", "真实接口不受影响"),
        ("/api/goods", False, "", "剥前缀后只命中单段路由 → 不认（避免藏掉接口）"),
    ]
    for url, w_page, w_src, label in want:
        e = eps.get(url)
        got = (e.page, e.page_src) if e else (None, None)
        if got == (w_page, w_src):
            print(f"  ✓ {label}")
        else:
            print(f"  ✗ {label}  期望 {(w_page, w_src)}，实际 {got}")
            ok = False
    if marked == 2 and unmarked == 1:
        print(f"  ✓ 统计正确（认定 {marked} 个 / 纠正 {unmarked} 个）")
    else:
        print(f"  ✗ 统计不符：marked={marked} unmarked={unmarked}（期望 2 / 1）")
        ok = False

    # ---- 实载 JS 清单的过滤与配额 ----
    print()
    print("=" * 78)
    print("浏览器实载 JS 清单 → 回灌过滤")
    print("=" * 78)
    sc2 = Scanner(ScanOptions({"url": "https://x.com", "runtime_js_max": 10}), lambda p: None)
    sc2._visited.add("https://x.com/assets/seen.js")
    sc2.result.pages.append("https://x.com/")
    import asyncio as _aio

    async def _noop(*a, **k):
        return None

    sc2._work = _noop  # 不真的发请求，只看它挑出了哪些
    picked = []
    _orig = sc2._httpx_kwargs

    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    import core.scanner as _sc

    _real_client = _sc.httpx.AsyncClient
    _sc.httpx.AsyncClient = lambda **k: _FakeClient()

    async def _spy(client, url, sem, rt=False):
        picked.append(url)
        if rt:
            sc2._rt_left -= 1          # 和真实的 _work 一样消耗配额

    sc2._work = _spy
    try:
        used = _aio.run(sc2._ingest_runtime_js([
            "https://x.com/assets/seen.js",           # 已抓过 → 排除
            "https://x.com/",                          # 是页面 → 排除
            "//cdn.x.com/a.js",                        # 协议相对 → 补 scheme 后保留
            "ftp://x.com/b.js",                        # 非 http → 排除
            "https://x.com/assets/new1.js",
            "https://x.com/assets/jquery.min.js",      # 库文件 → 次后
            "https://cf.aliyun.com/nvc/nvc_1.js",      # 第三方风控 → 最后
            "https://cf.aliyun.com/nvc/prepare.jsonp",  # 非 JS → 排除
        ]))
    finally:
        _sc.httpx.AsyncClient = _real_client

    keep = [u for u in picked]
    if "https://x.com/assets/seen.js" not in keep:
        print("  ✓ 已抓过的排除")
    else:
        print("  ✗ 已抓过的没排除")
        ok = False
    if "https://x.com/" not in keep:
        print("  ✓ 页面排除")
    else:
        print("  ✗ 页面没排除")
        ok = False
    if "https://cdn.x.com/a.js" in keep:
        print("  ✓ 协议相对 URL 补齐 scheme")
    else:
        print(f"  ✗ 协议相对 URL 丢失：{keep}")
        ok = False
    if not any(u.startswith("ftp") for u in keep):
        print("  ✓ 非 http 协议排除")
    else:
        print("  ✗ 非 http 协议没排除")
        ok = False
    order = [u.rsplit("/", 1)[-1] for u in keep]
    if order == ["new1.js", "a.js", "jquery.min.js"]:
        print(f"  ✓ 分层次序正确：{order}")
    else:
        print(f"  ✗ 分层次序不对：{order}（期望 new1.js/a.js/jquery.min.js）")
        ok = False
    if not any("cf.aliyun.com" in u for u in keep):
        print("  ✓ 第三方统计/风控脚本被跳过")
    else:
        print(f"  ✗ 第三方脚本没被跳过：{keep}")
        ok = False
    if not any("jsonp" in u for u in keep):
        print("  ✓ 非 JS（.jsonp）被排除")
    else:
        print(f"  ✗ .jsonp 没被排除：{keep}")
        ok = False
    if used == len(keep) == 3:
        print(f"  ✓ 配额计数正确（used={used}）")
    else:
        print(f"  ✗ 配额计数：used={used} picked={len(keep)}")
        ok = False

    print()
    print("=" * 78)
    print("运行时前缀回填（结果不应依赖文件分析顺序）")
    print("=" * 78)
    import asyncio
    from core.scanner import ScanOptions, Scanner

    # 一个文件里是接口（不带前缀），另一个文件里才写着 VITE_BASE_URL
    ORDER_JS = ('axios.get("/order/detail", {params:{id:1}});'
                'axios.get("/blade-user/user/list");'
                'axios.post({url:"order/index", baseURL:"/AliYun/"});'
                'axios.get("/Login");')
    PREFIX_JS = 'const c={VITE_BASE_URL:"/api/"};'

    def build(seq):
        async def go():
            sc = Scanner(ScanOptions({"url": "https://x.example/"}), lambda p: None)
            for i, code in enumerate(seq):
                await sc._analyze(code, f"f{i}.js", "js")
            sc._backfill_prefix()
            return sorted(e.url for e in sc.result.endpoints)
        return asyncio.run(go())

    r_prefix_first = build([PREFIX_JS, ORDER_JS])
    r_prefix_last = build([ORDER_JS, PREFIX_JS])

    if r_prefix_first == r_prefix_last:
        print("  ✓ 两种分析顺序结果一致（顺序依赖已消除）")
    else:
        print(f"  ✗ 顺序不同结果不同：{r_prefix_first} vs {r_prefix_last}")
        ok = False
    if "/api/order/detail" in r_prefix_last:
        print("  ✓ 裸相对路径补上了前缀：/api/order/detail")
    else:
        print(f"  ✗ /order/detail 没补上前缀：{r_prefix_last}")
        ok = False
    if "/api/blade-user/user/list" in r_prefix_last:
        print("  ✓ 无前导斜杠的写法也补上：/api/blade-user/user/list")
    else:
        print(f"  ✗ /blade-user/user/list 没补上前缀：{r_prefix_last}")
        ok = False
    if "/Login" in r_prefix_last and "/api/Login" not in r_prefix_last:
        print("  ✓ 页面路由不被补前缀")
    else:
        print(f"  ✗ 页面路由被补了前缀：{r_prefix_last}")
        ok = False
    if "/AliYun/order/index" in r_prefix_last:
        print("  ✓ 自带请求级 baseURL 的不被全局前缀覆盖")
    else:
        print(f"  ✗ 请求级 baseURL 被覆盖：{r_prefix_last}")
        ok = False
    if not any(u.startswith("/api/api") for u in r_prefix_last):
        print("  ✓ 已带前缀的不会叠成 /api/api/…")
    else:
        print(f"  ✗ 出现重复前缀：{r_prefix_last}")
        ok = False

    # 页面判定的判据是「首段」，不是「任意一段」——
    # 末段 camelCase 的真接口曾被误伤（/blade-xxx/order/QueryOrderDetail）
    SEG_JS = ('axios.get("blade-aliyun-shop/order/QueryOrderDetail");'
              'axios.get("/Individual/Order/AliCloud/List");')
    r_seg = build([PREFIX_JS, SEG_JS])
    if "/api/blade-aliyun-shop/order/QueryOrderDetail" in r_seg:
        print("  ✓ 末段 camelCase 的接口照常补前缀（判据只看首段）")
    else:
        print(f"  ✗ 末段 camelCase 的接口被误判成页面：{r_seg}")
        ok = False
    if "/Individual/Order/AliCloud/List" in r_seg:
        print("  ✓ 首段 PascalCase 的页面路由不吃前缀")
    else:
        print(f"  ✗ 页面路由被补了前缀：{r_seg}")
        ok = False

    print()
    print("=" * 78)
    print("主机名是变量拼的（'http://'+serverip+':'+serverport+'/x'）")
    print("=" * 78)
    VAR_HOST_JS = ('var serverip =""; var serverport ="80";'
                   'function go(){var u=\'http://\'+serverip+\':\'+serverport'
                   '+\'/hzcms/wcm/member/loginverify.jsp\';window.open(u);}')
    vh = JSExtractor(VAR_HOST_JS, min_score=0, base_prefix="").run()
    urls = [e.url for e in vh]
    if "/hzcms/wcm/member/loginverify.jsp" in urls:
        print("  ✓ 主机不可用时剥掉 scheme+authority，只留路径")
    else:
        print(f"  ✗ 没被剥成路径：{urls}")
        ok = False
    names = [p.name for e in vh for p in e.params]
    if "serverip" not in names and "serverport" not in names:
        print("  ✓ 主机/端口变量不会被当成 HTTP 参数")
    else:
        print(f"  ✗ 混进了假参数：{names}")
        ok = False
    real = JSExtractor('axios.get("/api/user/{id}/detail", {params:{withOrg:1}});',
                       min_score=0).run()
    rnames = sorted(p.name for p in real[0].params) if real else []
    if rnames == ["id", "withOrg"]:
        print("  ✓ 真正的路径参数没被误伤（{id} + withOrg 都在）")
    else:
        print(f"  ✗ 路径参数被误伤：{rnames}")
        ok = False

    # ------------------------------------------------------------------
    # 泄露的凭据：36 例矩阵 + 厂商格式 + 反向用例
    #
    # 这一块的价值在于**防回归**：以前只看键名、且键名必须带引号，
    # 36 例里只能取到 8% 的值、厂商格式 0/12。改规则很容易又把它改回去，
    # 所以这里把「值取到了没」当成硬断言。
    # ------------------------------------------------------------------
    print("=" * 78)
    print("泄露的凭据（密钥 / 令牌）")
    print("=" * 78)

    V = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    M = [
        ("appSecret", "appSecret", V),
        ("apiKey", "apiKey", K_AIza),
        ("clientSecret", "clientSecret", "S3cr3tV4lue1234567890"),
        ("aesKey", "aesKey", "0123456789abcdef"),
        ("password", "password", "P@ssw0rd123!"),
        ("accessKeyId", "accessKeyId", "AKIAIOSFODNN7EXAMPLE"),
        ("sdkSecret", "sdkSecret", "Zx8Kq2WmP7nR4tY6uI0oA3sD5fG8hJ2k"),
        ("privateKey", "privateKey", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAg"),
        ("token(JWT)", "token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5NXgL0n3I9PlFUP0THsR8U"),
        ("signKey", "signKey", "9f8e7d6c5b4a39281706f5e4d3c2b1a0"),
        ("amapKey", "amapKey", "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"),
        ("AK(阿里云)", "AK", "LTAI5tH8kPq2WmN7vR4tY6uI"),
    ]
    FORMS = [
        ("const X =", lambda k, v: f'const {k} = "{v}";'),
        ("{ X:", lambda k, v: f"const o = {{{k}: \"{v}\"}};"),
        ('{"X":', lambda k, v: f'const o = {{"{k}": "{v}"}};'),
    ]

    def vals(src):
        fx = JSExtractor(src, min_score=0)
        fx.run()
        return [(f.kind, f.key, f.value) for f in fx.findings]

    got = miss = 0
    for label, k, v in M:
        for _, fn in FORMS:
            if any(x[2] for x in vals(fn(k, v))):
                got += 1
            else:
                miss += 1
                print(f"  ✗ {label} 没取到值（{fn(k, v)[:40]}）")
    if miss == 0:
        print(f"  ✓ {len(M)} 种密钥 × {len(FORMS)} 种写法 = {got} 例，全部取到了密钥本身")
    else:
        print(f"  ✗ {miss}/{got + miss} 例没取到值")
        ok = False

    VENDOR = [
        ("JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5NXgL0n3I9PlFUP0THsR8U"),
        ("阿里云 AK", "LTAI5tH8kPq2WmN7vR4tY6uI"),
        ("Google API", K_AIza),
        ("GitHub PAT", K_ghp),
        ("Slack", K_xoxb),
        ("Stripe", K_sk_live),
        ("OpenAI", K_sk),
        ("PEM 私钥", K_pem),
        ("微信 AppID", "wxd2b40313baa34cbf"),
        ("npm Token", K_npm),
        ("AWS AKID", "AKIAIOSFODNN7EXAMPLE"),
    ]
    vmiss = [n for n, v in VENDOR if not any(x[2] for x in vals(f'const x = "{v}";'))]
    if not vmiss:
        print(f"  ✓ {len(VENDOR)} 种厂商格式，键名叫 x 也认（含 ghp_/AbCd/EXAMPLE 这类"
              f"值里带占位词子串的）")
    else:
        print(f"  ✗ 厂商格式漏了：{vmiss}")
        ok = False

    NEG = [
        ("普通配置值", 'const secretKey = "someLongConfigValue";'),
        ("占位符", 'const apiKey = "your_api_key_here";'),
        ("纯 x 填充", 'const appSecret = "xxxxxxxxxxxxxxxxxxxx";'),
        ("URL 值", 'const apiKey = "https://api.example.com/v1";'),
        ("路径值", 'const token = "/static/js/app.js";'),
        ("太短", 'const secret = "abc";'),
        ("中文提示", 'const password = "请输入您的登录密码";'),
        ("普通变量", 'const username = "zhangsan12345678";'),
        ("模板串", 'const secretKey = "${config.apiKey}";'),
        ("SDK 默认值", 'const umidToken = "defaultToken1_um_not_loaded@@1.2.3";'),
    ]
    nbad = [n for n, s in NEG if any(x[2] for x in vals(s))]
    if not nbad:
        print(f"  ✓ {len(NEG)} 类反向用例全部正确放过（占位符 / URL / 模板串 / SDK 默认值）")
    else:
        print(f"  ✗ 误报：{nbad}")
        ok = False

    print()
    print("★ 全部通过" if ok else "★ 有失败项")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
