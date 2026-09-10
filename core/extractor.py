"""
接口提取引擎 v2。

相比 v1 的改进（对照 jsluice / URLFinder / LinkFinder 的做法）：

1. **表达式折叠**：`"/api/" + t + "/list"`、`BASE + "/user"`、`` `${P}/x/${id}` ``
   都会被还原成一条完整路径（见 ``expr.py``），而不是只捞到半截。
2. **常量表**：`const BASE = "/api/v1"` 甚至 `const U = BASE` 都能解析。
3. **泛化调用识别**：不再只认 `axios.get`，任何 `xxx("看起来像路径的串")`
   都会被考虑，再按函数名好坏加减分 —— 这样 `request()`、`service.del()`
   这类二次封装不会被漏掉。
4. **无前导斜杠的相对路径**：`"api/user/list"` 也能提取。
5. **更全的请求方式**：XHR `.open/.send`、`sendBeacon`、`WebSocket`、
   `EventSource`、`$http`、`$.ajax`、`location.href` 赋值。
6. **调用点回填**：`const u = "/api/x"; axios.get(u, {params})` 这种
   「URL 在常量里、参数在调用里」的情况，会把参数补回对应接口。
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urljoin, urlunparse

from .expr import ConstTable, collapse, unescape
from .jsparse import (
    iter_strings,
    match_bracket,
    enclosing_scope,
    depth_map,
    find_object_literals,
    object_keys,
    guess_type,
    looks_like_object,
    IDENT_RE,
)
from .models import Endpoint, Param, Finding

# ==========================================================================
# 基础常量
# ==========================================================================

STATIC_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".svg", ".ico",
    ".css", ".scss", ".less", ".sass", ".styl", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".mp4", ".mp3", ".webm", ".ogg", ".wav", ".avi", ".mov",
    ".zip", ".rar", ".7z", ".gz", ".tar", ".exe", ".dmg", ".apk", ".ipa",
    ".map", ".wasm", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".yaml", ".yml", ".toml", ".ini", ".lock",
}
CODE_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".css",
            ".scss", ".less", ".sass", ".html", ".htm", ".md"}

SCHEME_RE = re.compile(
    r"^(data|blob|javascript|mailto|tel|about|chrome|chrome-extension|file|ftp):",
    re.I,
)
ANY_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.\-]*)://", re.I)

# 出现在接口路径里的业务关键词 —— 命中加分
API_HINT_RE = re.compile(
    r"(^|/)(api|apis|rest|restful|graphql|gql|rpc|svc|service|services|"
    r"admin|manage|management|auth|oauth|sso|login|logout|signin|signup|"
    r"register|user|users|account|accounts|member|members|profile|"
    r"v\d+(\.\d+)?|open|openapi|internal|gateway|proxy|passport|"
    r"collect|report|reports|query|list|page|detail|info|data|search|"
    r"upload|download|file|files|order|orders|pay|payment|cart|goods|"
    r"product|products|msg|message|messages|notice|notify|config|setting|"
    r"settings|system|sys|dashboard|stat|stats|statistics|export|import|"
    r"sync|notify|comment|article|content|feed|rank|recommend)(/|$)",
    re.I,
)

# 代码目录 —— 相对路径命中这些基本不是接口
CODE_DIR_RE = re.compile(
    r"^(?:\.{1,2}/)*(?:src|lib|libs|components?|pages?|views?|layouts?|router|"
    r"routes?|store|stores|redux|hooks?|utils?|helpers?|assets?|static|public|"
    r"styles?|themes?|icons?|fonts?|images?|img|node_modules|vendor|dist|"
    r"build|types?|interface|enum|constants?|locales?|i18n|lang|mock|mocks|"
    r"__tests__|__mocks__|tests?|spec)(/|$)",
    re.I,
)

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
METHOD_LABEL = {
    "get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH",
    "delete": "DELETE", "head": "HEAD", "options": "OPTIONS",
    "del": "DELETE", "remove": "DELETE", "add": "POST", "create": "POST",
    "save": "POST", "submit": "POST", "update": "PUT", "edit": "PUT",
    "query": "GET", "load": "GET", "fetch": "GET", "list": "GET",
}

# 名字里带这些词，说明这个函数大概率在做网络请求
STRONG_FN_RE = re.compile(
    r"(api|http|ajax|axios|request|req|fetch|service|server|backend|gateway|"
    r"proxy|client|query|load|save|submit|send|post|put|delete|patch|remove|"
    r"update|create|add|list|detail|info|upload|download|sync|connect|invoke|"
    r"call|rpc|rest|graphql|sso|login|logout|sign|auth|token|data|remote)",
    re.I,
)

# 第一个参数是字符串、但显然不是网络请求的函数 —— 直接排除
NON_NET_FN_RE = re.compile(
    r"^(?:"
    r"console|log|warn|error|info|debug|trace|table|dir|group|assert|"
    r"require|import|define|eval|"
    r"json|object|array|string|number|boolean|symbol|bigint|promise|regexp|"
    r"date|math|map|set|weakmap|weakset|error|typeerror|"
    r"parseint|parsefloat|isnan|isfinite|decodeuri|decodeuricomponent|"
    r"encodeuri|encodeuricomponent|escape|unescape|btoa|atob|"
    r"settimeout|setinterval|cleartimeout|clearinterval|requestanimationframe|"
    r"document|window|element|node|el|dom|alert|confirm|prompt|"
    r"push|pop|shift|unshift|slice|splice|concat|join|split|includes|"
    r"indexof|lastindexof|startswith|endswith|replace|replaceall|match|"
    r"matchall|search|test|exec|tolowercase|touppercase|trim|tostring|"
    r"valueof|charat|substring|substr|padstart|padend|repeat|localecompare|"
    r"addeventlistener|removeeventlistener|dispatchevent|queryselector|"
    r"queryselectorall|getelementbyid|setattribute|getattribute|"
    r"appendchild|removechild|insertbefore|createelement|focus|blur|click|"
    r"hasownproperty|defineproperty|create|assign|keys|values|entries|freeze|"
    r"from|of|is|all|race|resolve|reject|then|catch|finally|next|emit|on|once|"
    r"tostring|tofixed|tojson|sort|reverse|fill|flat|flatmap|find|findindex|"
    r"filter|foreach|reduce|reduceright|some|every|keys|values"
    r")(?:\.|$)",
    re.I,
)

# `xxx.open("POST", ` / `new WebSocket(` / `sendBeacon(` ...
SPECIAL_BEFORE_RE = re.compile(
    r"(?:"
    r"new\s+(?P<ws>WebSocket|EventSource|SharedWorker)\s*\(\s*$"
    r"|(?P<beacon>sendBeacon)\s*\(\s*$"
    r"|(?P<xhr>\bopen)\s*\(\s*(?:['\"`][A-Za-z]{3,7}['\"`]\s*,\s*)?$"
    r"|location\s*\.\s*(?:replace|assign)\s*\(\s*$"
    r"|location\s*\.\s*href\s*=\s*$"
    r"|window\s*\.\s*open\s*\(\s*$"
    r")",
    re.I,
)

# 任意 `name(` —— 用于泛化调用识别
CALL_BEFORE_RE = re.compile(r"(?P<fn>[A-Za-z_$][\w$.]*)\s*\(\s*$")
# 对象字面量形式的外层调用：`service.post({url:"..."` —— 方法由外层函数名决定，
# 很多项目（BladeX / 各类 request 封装）根本不写 method 字段
CALL_WRAP_RE = re.compile(r"(?P<fn>[A-Za-z_$][\w$.]*)\s*\(\s*\{[^{}]{0,400}$")
# `url:` / `url = ` —— 配置字段
KEY_BEFORE_RE = re.compile(
    r"(?P<key>url|uri|endpoint|path|action|href|src|baseURL|baseUrl|base_url|"
    r"api|apiUrl|target|requestUrl|serviceUrl|fullUrl)\s*[:=]\s*$",
    re.I,
)
METHOD_CFG_RE = re.compile(r"""\b(?:method|type)\s*:\s*["']([A-Za-z]{3,7})["']""")

# 调用点：`axios.get(url, {...})` 里第一个参数是标识符
CALL_SITE_RE = re.compile(
    r"(?P<fn>[A-Za-z_$][\w$.]*)\s*\(\s*(?P<arg>[A-Za-z_$][\w$]*)\s*(?P<tail>[,)])"
)

RELATIVE_PATH_RE = re.compile(r"^[\w\-.{}$@~]+(?:/[\w\-.{}$@~]+)+$")

# MIME 类型长得就像 a/b，必须排除（application/json、text/javascript …）
MIME_RE = re.compile(
    r"^(?:application|text|image|audio|video|font|multipart|message|model)"
    r"/[\w.+\-*]+$",
    re.I,
)
# 统计 / 广告 / 监控类第三方服务 —— 不是目标站点的接口，标记出来便于一键隐藏
THIRD_PARTY_HOST_RE = re.compile(
    r"(google-analytics\.com|googletagmanager\.com|doubleclick\.net|"
    r"google\.com|googlesyndication\.com|googleapis\.com|gstatic\.com|"
    r"facebook\.(com|net)|hotjar\.com|segment\.(io|com)|mixpanel\.com|"
    r"sentry(-cdn)?\.io|umeng\.com|umengcloud\.com|cnzz\.com|"
    r"talkingdata\.com|growingio\.com|matomo\.|piwik\.|clarity\.ms|"
    # 实测补进来的（原先全漏，ynuf.aliapp.org 甚至拿了 94 分）：
    # 阿里风控 / 阿里备案 / 银联二维码 —— 站点不会把自己的业务接口放在这些域名上
    r"aliyun\.com|aliapp\.org|alibaba\.com|beian\.gov\.cn|95516\.com|"
    r"^gtag$)",
    re.I,
)
# XML 命名空间 / 文档格式规范标识符：http://www.w3.org/1999/xlink、http://ns.adobe.com/xdp/pdf/。
# 这些是「格式的名字」，不是任何服务器上的资源 —— 拿到它们的 URL 去请求是没有意义的，
# 所以不当接口，也不当第三方接口，直接丢。实测 pdfjs / @vue 里会大量出现。
NAMESPACE_URI_RE = re.compile(
    # 直接按域名匹配。原先写成 `w3\.org/(?:19|20)\d\d/` 只覆盖了 w3.org/1999/…
    # 这种命名空间，漏了 DTD（w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd）
    # —— 实测在 www.cdcas.edu.cn 上就漏出去了。
    r"w3\.org/|ns\.adobe\.com|schema\.org/|"
    r"openxmlformats\.org|purl\.org/|xmlns\.com|oasis-open\.org|"
    r"apple\.com/DTDs",
    re.I,
)
# 浏览器插件探测串：浏览器能力探测代码里列出的插件标识符，不是路径。
# （和 NON_PATH_HEADS 挡 undefined / function 是同一类 —— JS 内建名不可能是路径段）
JS_BUILTIN_RE = re.compile(
    r"ActiveXObject|ShockwaveFlash|XMLHttpRequest|DivXBrowserPlugin|"
    r"Adobe\.SVGCtl|\bAcroPDF\b|MediaPlayer\.OCX|GetSVGViewerVersion",
    re.I,
)
# GA / GTM 在相对路径下的经典端点。这些没有 host，只能靠路径形状认：
#   /g/collect  /mc/collect  /ccm/s/collect  /d/ccm/form-data
#   /gtag/destination  /pagead/regclk  /ag/g/c  /as/p/c
THIRD_PARTY_PATH_RE = re.compile(
    r"/(?:ccm|gtag|rmkt|pagead|ga-?audiences|conversion)(?:/|$)"
    r"|^/(?!api(?:/|$))[a-z]{1,3}/(?:collect|g/c|pagead|j/collect)(?:/|$)",
    re.I,
)
HOST_IN_URL_RE = re.compile(r"^(?:https?:)?//([^/?#]+)", re.I)
# 非法百分号：% 后面不跟两位十六进制（说明是模板残留而不是 URL 编码）
BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _is_third_party(url: str) -> bool:
    m = HOST_IN_URL_RE.match(url)
    if m:
        return bool(THIRD_PARTY_HOST_RE.search(m.group(1)))
    # 用 search：GA 的路径可能带前缀目录，比如 /d/ccm/form-data
    return bool(THIRD_PARTY_PATH_RE.search(url.split("?")[0]))

# 相对路径的首段命中这些词，基本可以断定不是接口
NON_PATH_HEADS = {
    "application", "text", "image", "audio", "video", "font", "multipart",
    "undefined", "null", "true", "false", "function", "object", "string",
    "number", "boolean", "symbol", "regexp", "date", "array", "json",
}

# ---- 热路径上会反复用到的正则，统一预编译（避免每次查找正则缓存）----
BADCHAR_RE = re.compile(r"""[<>|"\\^`]""")
CJK_WS_RE = re.compile(r"[\u4e00-\u9fff\s]")
EXT_RE = re.compile(r"(\.[a-z0-9]{2,6})(?:$|[?#])")
NON_ALPHA_RE = re.compile(r"[^A-Za-z]")
PLACEHOLDER_RE = re.compile(r"\{\w+\}")
ONLY_PLACEHOLDER_RE = re.compile(r"^/?\{\w+\}/?$")
API_EXT_RE = re.compile(r"\.(do|action|json)$")
ASSET_DIR_RE = re.compile(r"^/(assets|static|dist|public|build|media|img|images|fonts?|cdn)/")
BUNDLE_NAME_RE = re.compile(r"/(index|main|app|vendor|runtime|polyfills|chunk)([.\-][\w]+)?$")
PARAMS_IN_SCOPE_RE = re.compile(r"\b(params|data|body|payload|query)\s*:", re.I)
FULL_URL_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)
HTTP_PATH_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://[^/]*", re.I)
PLACEHOLDER_TOKEN_RE = re.compile(r"\$\{\s*([^}]{1,80}?)\s*\}|\{\s*([A-Za-z_$][\w$]{0,50})\s*\}")
# URL 的主机名整个是模板占位符：http://{serverip}:80/x、//{host}/api/y。
# 这种是 `'http://'+serverip+':'+serverport+'/x'` 折叠出来的 —— 主机没法请求，
# 但后面的路径是真的。（要求占位符占满整个 authority，后面紧跟 : / 或结束，
# 免得把 http://{sub}.example.com/x 这种误判成「整段主机都是变量」。）
PLACEHOLDER_HOST_RE = re.compile(r"^(?:[a-z][a-z0-9+.\-]*:)?//\{[^{}/]{1,60}\}(?=[:/]|$)")
SAFE_NAME_RE = re.compile(r"^[\w$.\-\[\]]+$")
IDENT_HEAD_RE = re.compile(r"[A-Za-z_$][\w$]*(?:\.[\w$]+)*")
CALL_OPEN_RE = re.compile(r"\(\s*$")
XHR_SEND_RE = re.compile(r"\.\s*send\s*\(\s*")

# 赋值号左边那个名字（用于识别 baseURL / 环境变量常量）
ASSIGN_TARGET_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*[:=]\s*$")
# 名字命中这些后缀 → 它是基地址，直接不当作接口
HARD_BASE_SUFFIXES = (
    "baseurl", "base_url", "basepath", "base_path", "baseapi", "base_api",
    "apiurl", "api_url", "apibase", "api_base", "apihost", "api_host",
    "apiprefix", "api_prefix", "host", "hostname", "origin", "domain",
    "gateway", "prefix", "base", "target", "socket",
)
# `const NAME = ` —— 可以据此判断这个串是否只是个常量定义
CONST_DECL_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$")
# 名字里带这些词，说明这个常量大概率就是接口地址
URLISH_NAME_RE = re.compile(
    r"(url|uri|api|path|endpoint|href|action|link|host|domain|server|gateway|origin|cdn)",
    re.I,
)

# 常见的基地址式常量名后缀，用于从常量表里捞 baseURL
BASEVAR_SUFFIXES = (
    "url", "uri", "base", "baseurl", "base_url", "basepath", "base_path",
    "api", "apiurl", "api_url", "apibase", "api_base", "apihost", "api_host",
    "apiprefix", "api_prefix", "host", "hostname", "origin", "domain",
    "gateway", "server", "endpoint", "prefix",
)
BASEVAR_BLOCKLIST = {
    "url", "uri", "href", "src", "path", "action", "target", "api", "host",
    "base", "prefix", "endpoint", "domain", "server", "name", "value", "key",
}

# ==========================================================================
# 元信息相关
# ==========================================================================

BASEURL_RE = re.compile(
    r"""\b(?P<key>baseURL|baseUrl|base_url|BASE_URL|API_URL|apiUrl|apiBase|apiHost|
            VUE_APP_[A-Z_]*?(?:BASE|API|HOST|URL)[A-Z_]*|
            REACT_APP_[A-Z_]*?(?:BASE|API|HOST|URL)[A-Z_]*|
            NEXT_PUBLIC_[A-Z_]*?(?:BASE|API|HOST|URL)[A-Z_]*|
            VITE_[A-Z_]*?(?:BASE|API|HOST|URL)[A-Z_]*|
            apiPrefix|API_PREFIX|API_HOST|HOST)
        \s*[:=]\s*
        (?P<val>["'`][^"'`\n]{4,200}["'`]|[A-Za-z_$][\w$.]{2,80})""",
    re.X,
)

HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$",
    re.I,
)
HOST_BLOCKLIST = {
    "www.w3.org", "w3.org", "schema.org", "www.schema.org", "ns.adobe.com",
    "purl.org", "ogp.me", "opensource.org", "creativecommons.org",
    "www.unicode.org", "unicode.org", "example.com", "localhost",
}

LITERAL_VALUE_RE = re.compile(r"""^\s*(?:["'`]|-?\d|true\b|false\b|null\b|\[|\{)""")

SECRET_KEY_DENY = re.compile(
    r"(title|tip|tips|placeholder|label|text|name|desc|description|hint|"
    r"msg|message|error|btn|button|modal|dialog|form|page|screen|tab|"
    r"login|logout|reset|forgot|enter|retrieve|confirm|change|update|"
    r"verify|bind|create|edit|show|hide|prefix|suffix)",
    re.I,
)
CJK_RE = re.compile(r"[\u4e00-\u9fff]")
SECRET_VALUE_CHARS = re.compile(r"^[A-Za-z0-9+/=_\-.:!@#$%^&*~]{8,512}$")

# 键名里带这些词 → **它的值**值得取出来（真凭据）
SECRET_NAME_RE = re.compile(
    r"secret|passwd|password|pwd|api[-_]?key|access[-_]?key|private[-_]?key|"
    r"aes[-_]?key|rsa[-_]?key|encrypt[-_]?key|sign[-_]?key|credential|jwt|"
    r"token|authorization|bearer",
    re.I,
)
# 形如 amapKey / smsKey / paySecret —— 短前缀 + key|secret|token，靠值的形态兜底
SHORT_KEY_NAME_RE = re.compile(r"^[A-Za-z]{2,14}(?:key|secret|token)$", re.I)

# 鉴权字段：值常常是公开 id，或者运行时才填，所以只记键名、不取值
TOKEN_KEY_RE = re.compile(
    r"""(?:"|')?\b(?P<k>
        (?:x-)?(?:auth-?token|access-?token|refresh-?token|id-?token|token)
        |session-?id|authorization|api-?key|app-?key|appid|app-?secret
        |client-?id|client-?secret|secret|signature|nonce
        |aes-?key|rsa-?key|public-?key|private-?key|encrypt-?key)
        (?:"|')?\s*:""",
    re.I | re.X,
)

# 键值对。注意**键名允许不带引号**：真实 JS 几乎都写成
# `const appSecret = "..."` 或 `{appSecret: "..."}`，
# 原来只认 `{"appSecret": "..."}` 导致 36 例里只能取到 8% 的值。
SECRET_KV_RE = re.compile(
    r"""(?:["'](?P<k1>[A-Za-z_$][\w$]{1,63})["']|(?P<k2>[A-Za-z_$][\w$]{1,63}))"""
    r"""\s*[:=]\s*["'](?P<v>[^"'\n]{6,512})["']"""
)

# 只看**值的形态**、不看键名叫什么 —— 各家厂商的密钥都有固定前缀，
# 这是「键名不认识但值是真的」这一类唯一的抓手。
VENDOR_SECRET_PATTERNS = (
    ("jwt",             re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")),
    ("阿里云 AccessKey",  re.compile(r"\bLTAI[A-Za-z0-9]{10,}\b")),
    ("AWS AccessKeyId", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API Key",  re.compile(r"\bAIza[0-9A-Za-z_-]{30,45}\b")),
    ("GitHub Token",    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}")),
    ("Slack Token",     re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}")),
    ("Stripe Key",      re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("OpenAI Key",      re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("SendGrid Key",    re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")),
    ("npm Token",       re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("微信 AppID",       re.compile(r"\bwx[0-9a-f]{16}\b")),
    ("PEM 私钥",         re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----")),
)

# 占位符 / 示例值。键名和值要用**不同的严格度**：
#   - 键名短，宽松搜没问题（yourKey / testSecret 都该扔）；
#   - 值**只能看开头** —— 真实密钥是随机串，全串搜会把
#     ghp_123456…（含 123456）、sk_live_…AbCd…（含 AbCd）、
#     AKIA…EXAMPLE（含 example）全误杀。这是第一版踩的坑。
PLACEHOLDER_RE = re.compile(
    r"(placeholder|your[-_]?|changeme|todo|example|sample|demo|fake|dummy|"
    r"xxxx|yyyy|zzzz|aaaa|123456|abcd|foobar|<[a-z_ -]+>|\{\{|insert|replace)",
    re.I,
)
VALUE_PLACEHOLDER_RE = re.compile(
    r"^(?:default|undefined|null|your[-_]?|xxx|yyy|zzz|placeholder|example|"
    r"sample|demo|fake|dummy|changeme|todo|insert|replace|test[-_]?)",
    re.I,
)
REPEAT_RE = re.compile(r"(.)\1{5,}")     # xxxxxxxxxx 这种填充

DOTTED_PATH_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")

# 运行时 API 前缀。源码里往往写成 ``url:"blade-system/user/list"``，
# 真实请求地址是 ``/api/blade-system/user/list`` —— 前缀来自构建期环境变量
# 或 axios 的 baseURL。不补上的话，人拿着完整路径在结果里是搜不到的。
API_BASE_RE = re.compile(
    r"""(?:VITE|VUE_APP|REACT_APP|NEXT_PUBLIC)_
        (?P<k1>BASE_URL|BASE_API|API_URL|API_BASE|APP_BASE_API|API_PREFIX)"""
    r"""\s*[:=]\s*["'](?P<v1>[^"'\n]{1,80})["']""",
    re.X,
)
AXIOS_BASE_RE = re.compile(
    r"""\bbase_?url\s*[:=]\s*["'](?P<v2>[^"'\n]{1,80})["']""", re.I
)
# 只有这些上下文里的路径才吃 baseURL —— 页面路由（path/href）不算。
#
# 特别注意：`call`（泛化函数调用）**不在**这里。实测在一个 BladeX 站点上，
# call 上下文加前缀的 30 个接口 100% 是误报 —— `ie.btns("/Individual/Order/X")`、
# `addClass("a/goods")`、`o("/Home")` 全被套上了 /api。泛化调用的函数名太不可靠，
# 加前缀的收益抵不过误报。
BASE_ELIGIBLE_CTX = {"http", "fetch", "xhr", "jquery", "beacon", "ws"}
BASE_ELIGIBLE_KEYS = {
    "url", "uri", "api", "apiurl", "endpoint", "serviceurl", "fullurl",
    "requesturl", "target",
}


def _norm_base(raw: str) -> str:
    """把 ``/api/`` 归一成 ``/api``；不是路径形式的（含协议/域名）一律放弃。"""
    v = (raw or "").strip()
    if not v or v in ("/", ".", "./") or "://" in v or v.startswith("//"):
        return ""
    if not v.startswith("/"):
        return ""
    v = v.rstrip("/")
    if not v or len(v) > 60 or "{" in v:
        return ""
    return v

# ---- 参数回填用的正则 ----------------------------------------------------
# ① API 封装定义：`getMessageList(e){return api.get({url:"...", params:e})}`
#    这类封装的参数名在定义处看不到（params 是变量），只有调用方知道。
API_FN_DEF_RE = re.compile(
    r"""(?P<fn>[A-Za-z_$]\w{1,40})\s*\(\s*[\w$,\s]{0,60}\)\s*\{\s*"""
    r"""(?:(?:const|let|var)\s+[\w$]+\s*=\s*[^;]{1,220};\s*)?"""
    r"""return\s+[\w$.]{1,60}\.\s*(?P<m>get|post|put|delete|patch|head|options|request)\s*"""
    r"""\(\s*\{\s*url\s*:\s*["'`](?P<url>[^"'`\n]{2,200})["'`]""",
    re.I | re.S,
)
# ② 调用点：`getMessageList({current:1, size:10})`
API_FN_CALL_RE = re.compile(r"""(?P<fn>[A-Za-z_$]\w{1,40})\s*\(\s*\{(?P<o>[^{}]{1,600})\}""")
# ③ 只有参数对象里带这些键才值得回填 —— 否则匹配量太大、收益又低
API_CALL_HINT_RE = re.compile(
    r"""\b(?:current|size|page|pageNo|pageSize|pageNum|limit|offset|keyword|"""
    r"""searchKey|sort|orderBy|status|type|id|state)\s*:""",
    re.I,
)


PARAM_KEYS = {
    "params": "query", "query": "query", "search": "query",
    "data": "body", "body": "body", "payload": "body", "postData": "body",
    "formData": "body", "form": "body", "variables": "body", "headers": "header",
}
CONFIG_KEYS = {
    "method", "headers", "timeout", "url", "uri", "baseurl", "base_url", "target",
    "withcredentials", "responsetype", "transformrequest", "transformresponse",
    "adapter", "paramsserializer", "validatestatus", "onuploadprogress",
    "ondownloadprogress", "canceltoken", "signal", "mode", "credentials", "cache",
    "redirect", "referrer", "referrerpolicy", "integrity", "keepalive", "type",
    "datatype", "contenttype", "async", "crossdomain", "xhrfields", "beforesend",
    "success", "error", "complete", "processdata", "jsonp", "jsonpcallback",
    "context", "statuscode", "ifmodified", "observe", "response", "operationname",
    "params", "data", "body", "query", "payload", "formdata", "form", "variables",
}
RECURSE_KEYS = {"params", "data", "body", "query", "payload", "postdata",
                "formdata", "form", "variables"}

# PARAM_KEYS 的匹配正则预先编译（每个接口要跑十几次，现场 re.escape 太亏）
PARAM_KEY_RES = [
    (re.compile(
        rf"""(?<![\w$])["']?{re.escape(k)}["']?(?![\w$])\s*:\s*""", re.I
    ), loc)
    for k, loc in PARAM_KEYS.items()
    if loc is not None
]


def _path_of(body: str) -> str:
    """
    取 URL 的路径部分。比 urlparse 快一个数量级，热路径上够用。

    ``https://a.com/x/y?z=1`` → ``/x/y``；``//a.com/x`` → ``/x``；
    ``/x/y?z=1`` → ``/x/y``
    """
    if body.startswith("//"):
        j = body.find("/", 2)
        body = body[j:] if j > 0 else "/"
    else:
        m = HTTP_PATH_RE.match(body)
        if m:
            body = body[m.end() :] or "/"
    i = body.find("?")
    return body[:i] if i >= 0 else body


def _sample_of(value: str) -> str:
    v = str(value).strip()
    return v[:150] if LITERAL_VALUE_RE.match(v) else ""


def _valid_host(host: str) -> bool:
    h = host.lower().strip(".")
    if not h or len(h) < 4 or "." not in h:
        return False
    if h in HOST_BLOCKLIST or not HOST_RE.match(h):
        return False
    tld = h.rsplit(".", 1)[-1]
    return len(tld) >= 2 and tld.isalpha()


# 日期/时间格式模板的段。`yyyy/MM/dd` 这种看着像三级路径，实则是格式化串。
DATE_SEG_RE = re.compile(r"^(?:yyyy|yy|MM|DD|HH|hh|mm|ss)(?:\{[^}]{0,20}\})?$")


def _looks_like_route(url: str) -> bool:
    """
    首段是 PascalCase 的路径，基本可以断定是前端页面路由。

    接口路径的段几乎都是小写（/blade-vstec/dtorder/getList、/api/blade-user/...），
    而 Vue Router 的路由表是大写驼峰（/Individual/Order/AliCloud、/Console/MAAS/List）。
    """
    if url.startswith(("http://", "https://", "//")):
        url = urlparse(url).path
    seg = url.lstrip("/").split("/")[0]
    return bool(re.fullmatch(r"[A-Z][a-zA-Z0-9]{1,30}", seg))


def _looks_like_base_value(v: str) -> bool:
    v = v.strip()
    if not v or len(v) > 200:
        return False
    if re.match(r"^(https?:)?//", v) or v.startswith("/"):
        return True
    if _valid_host(v.split("/")[0].split(":")[0]):
        return True
    return bool(DOTTED_PATH_RE.match(v))


def _credible_secret(v: str) -> bool:
    """这个值本身像不像一段凭据。

    只用在「靠键名推断」的场景 —— 厂商前缀命中（VENDOR_SECRET_PATTERNS）
    不经过这里：那条正则本身已经够明确了（AIza… / ghp_… / eyJ… 不会是巧合），
    再套一层长度/字符集门槛只会把真密钥筛掉。
    """
    v = (v or "").strip()
    if len(v) < 8 or CJK_RE.search(v) or " " in v or "${" in v:
        return False
    # URL / 资源路径不是密钥
    if re.match(r"^(?:https?:)?//|^\.?/|^\w+\.(?:js|css|png|jpe?g|svg|html|json)\b", v, re.I):
        return False
    if not SECRET_VALUE_CHARS.match(v):
        return False
    if len(set(v)) <= 3 or REPEAT_RE.search(v):   # xxxxxxxxxxxx 这类填充
        return False
    if VALUE_PLACEHOLDER_RE.match(v):
        return False
    # 有数字且够长，或者纯字母但足够长（随机串一般都在 24 位以上）
    return (any(c.isdigit() for c in v) and len(v) >= 12) or len(v) >= 24


# call 上下文里函数名必须"像网络请求"才认。
# 否则 `btns(...)` / `addClass(...)` / `attachEvent(...)` / `addTable(...)`
# 这些纯 UI 代码会被当成接口候选。
NET_FN_HINT_RE = re.compile(
    r"(request|req|api|http|fetch|ajax|axios|service|client|invoke|"
    r"send|load|save|query|submit|download|upload|"
    r"get|post|put|del|update|create|remove|list|page|detail)",
    re.I,
)


def _is_net_fn(name: str) -> bool:
    """判断 ``foo.bar`` 这种调用名是否可能是网络请求函数。"""
    if not name:
        return False
    last = name.split(".")[-1].lower()
    if NON_NET_FN_RE.match(last) or NON_NET_FN_RE.match(name.lower()):
        return False
    # 单字母 / 短名字：压缩代码里的封装函数，保留但降权
    return True


def _fallback_scope(src: str, lit_end: int, limit: int = 420) -> str:
    """窄窗口兜底：从字符串末尾往后取一段，遇到顶层分号就截断。"""
    text = src[lit_end : lit_end + limit]
    if not text:
        return ""
    depths = depth_map(text)
    for i, ch in enumerate(text):
        if ch == ";" and depths[i] == 0:
            return text[:i]
    return text


# ==========================================================================
# 提取器
# ==========================================================================


class JSExtractor:
    def __init__(
        self,
        source: str,
        min_score: int = 30,
        max_endpoints: int = 8000,
        consts: ConstTable | None = None,
        base_prefix: str = "",
    ):
        self.source = source
        self.api_fns: dict[str, tuple[str, str]] = {}   # 封装函数名 → (method, url)
        self.fn_calls: list[tuple[str, list[str]]] = []  # 调用点：(函数名, 参数键)
        # 「明明有 params、但值是个变量」的接口 —— 参数名由调用方决定，静态看不到
        self.unresolved: set[tuple[str, str]] = set()
        self.min_score = min_score
        self.max_endpoints = max_endpoints
        # 运行时 API 前缀（如 /api），由源码里的 VITE_BASE_URL / baseURL 推出来
        self.base_prefix = _norm_base(base_prefix)

        # 先合并全局常量表（跨文件），再用本文件里的定义覆盖/补充
        self.consts = ConstTable()
        if consts is not None:
            self.consts.merge(consts)
        local = ConstTable().build(source)
        for k, v in local.map.items():
            self.consts.map[k] = v
        for k, v in local.alias.items():
            self.consts.alias[k] = v

        self._index: dict[tuple[str, str], Endpoint] = {}
        self._url_key: dict[str, tuple[str, str]] = {}   # url → 已入库的 (method, url)
        self._param_tries: dict[str, int] = {}   # url → 参数解析尝试次数
        self._strings: list = []
        self.endpoints: list[Endpoint] = []
        # 因为「本文件比前缀所在 chunk 先被分析」而没能补上运行时前缀的路径。
        # 收尾时由 Scanner 按最终前缀统一回填，避免结果依赖文件分析顺序。
        self.prefix_missing: set[str] = set()
        self.findings: list[Finding] = []
        self.base_urls: list[dict] = []
        self.hosts: dict[str, int] = {}
        self._seen_finding: set[tuple[str, str]] = set()

    # -- 入口 ------------------------------------------------------------

    def run(self) -> list[Endpoint]:
        # 先确定运行时 API 前缀：同一个文件里可能既有环境变量定义又有接口
        self.base_prefix = self.base_prefix or self._detect_base()
        # 字符串扫描一次就够，后面几处复用（大文件上这一项省得很明显）
        self._strings = list(iter_strings(self.source))
        self._scan_literals()
        self._scan_callsites()
        self._extract_meta()
        self._scan_api_fns()
        self._strings = []
        return self.endpoints

    # ---------------------------------------------------------------- pass 1

    def _scan_literals(self) -> None:
        src = self.source
        consumed: set[tuple[int, int]] = set()

        for lit in self._strings:
            if (lit.start, lit.end) in consumed:
                continue
            col = collapse(src, lit, self.consts)
            for r in col.literals:
                consumed.add(r)

            text = col.text.strip()
            if not text or "/" not in text or len(text) > 600:
                continue
            kind = self._classify(text)
            if kind is None:
                continue

            # 注意用 chain_start：`axios.get(BASE + "/x", ...)` 里，
            # 调用上下文在整条拼接表达式之前，而不是在字符串字面量之前
            before = src[max(0, col.chain_start - 160) : col.chain_start]

            # ---- 先做便宜的判断，把绝大部分字面量筛掉，再去做昂贵的括号配对 ----
            if self._cheap_reject(text, kind, before):
                continue
            ctx = self._context(before, "")
            score = self._score(text, kind, ctx, before, "")
            if score < self.min_score:
                continue

            # 先算出调用窗口：请求级 baseURL（{url:"x", baseURL:"/y"}）只作用于
            # 它自己那次调用；不提前拿到窗口，同一个文件里的多个前缀就没法区分
            scope = self._scope_of(src, col.chain_start, col.end)
            url = self._finalize_url(text, kind, ctx, scope)
            # 同一个接口在 bundle 里往往出现成百上千次。参数解析要做括号配对 +
            # 深度扫描，很贵；每个接口最多试 2 次（第二次是给「首次出现时参数
            # 不在同一处」的情况留的机会），之后就只做计数合并。
            # 这里用 url 而不是 (method, url) 做键：method 要拿到作用域才算得准，
            # 用组合键会出现「同一个 url 两套计数」的错乱。
            tries = self._param_tries.get(url, 0)
            if tries >= 2:
                ep = self._index.get(self._url_key.get(url)) if url in self._url_key else None
                if ep is not None:
                    ep.count += 1
                    ep.confidence = max(ep.confidence, min(score, 100))
                continue
            self._param_tries[url] = tries + 1

            method = self._method(ctx, before, scope)
            params = self._params(text, scope, method, ctx, url)

            self._upsert(
                url=url,
                raw=text,
                method=method,
                kind=kind,
                params=params,
                score=min(score, 100),
                ctx_type=ctx[0],
                fn_name=ctx[2],
                prefix_var=col.prefix_var or "",
                context=self._context_snippet(src, col.start, col.end),
                source_endpoints=col.literals,
                # PascalCase 首段 = 页面路由；但用了请求级 baseURL 的
                # （/AliYun/order/index）是真接口，别误标
                is_page=_looks_like_route(url) and not self._local_base(scope),
            )
            if len(self.endpoints) >= self.max_endpoints:
                return

    # ---------------------------------------------------------------- pass 2

    def _scan_callsites(self) -> None:
        """
        回填「URL 在常量里、参数在调用里」的场景：

            const url = "/api/user/list";
            axios.get(url, { params: { pageNo, pageSize } })

        字面量扫描只拿到了 ``/api/user/list``，方法和参数要靠这一步补。
        """
        if not self.consts.map:
            return
        src = self.source
        checked = 0
        for m in CALL_SITE_RE.finditer(src):
            if checked > 40000:
                break
            fn = m.group("fn")
            arg = m.group("arg")
            resolved = self.consts.resolve(arg)
            if resolved is None or "/" not in resolved:
                continue
            last = fn.split(".")[-1].lower()
            if last in ("require", "import", "string", "number", "boolean"):
                continue
            checked += 1

            text = resolved.strip()
            kind = self._classify(text)
            if kind is None:
                continue

            before = src[max(0, m.start() - 60) : m.start()]
            if self._cheap_reject(text, kind, before):
                continue

            ctx = self._context(before, "")
            score = self._score(text, kind, ctx, before, "") + 6  # 有明确调用点
            if score < self.min_score:
                continue

            # 先把调用窗口算出来：请求级 baseURL 只作用于它自己那次调用
            _op = src.find("(", m.start("fn"))
            _close = match_bracket(src, _op) if _op >= 0 else -1
            _scope = (src[_op : _close + 1] if _close > 0
                      else _fallback_scope(src, m.end()))
            url = self._finalize_url(text, kind, ctx, _scope)
            if self._param_tries.get(url, 0) >= 2:
                continue
            self._param_tries[url] = self._param_tries.get(url, 0) + 1

            op = src.find("(", m.start("fn"))
            if op < 0:
                continue
            close = match_bracket(src, op)
            scope = src[op : close + 1] if close > 0 else _fallback_scope(src, m.end())
            ctx = self._context(before, scope)
            method = self._method(ctx, before, scope)
            params = self._params(text, scope, method, ctx, url)

            self._upsert(
                url=url,
                raw=text,
                method=method,
                kind=kind,
                params=params,
                score=min(score, 100),
                ctx_type=ctx[0],
                fn_name=fn,
                prefix_var="",
                context=self._context_snippet(src, m.start("fn"), m.end()),
                source_endpoints=[(m.start(), m.end())],
                is_page=_looks_like_route(url) and not self._local_base(_scope),
            )

    def _scan_api_fns(self) -> None:
        """
        收集「API 封装函数名 → URL」和「调用点的参数对象」，供 scanner 做跨文件回填。

        为什么需要它：这个站（以及大量国内后台模板）的写法是

            // 定义层（主 bundle）
            getMessageList(e){ return api.get({url:"blade-vstec/tnoticevo/page", params:e}) }
            // 调用层（另一个 chunk）
            await Me.getMessageList({current:1, size:10})

        参数名只有调用方知道，而定义和调用通常**不在同一个文件**里，
        所以要由 scanner 汇总后再统一回填。
        """
        src = self.source
        if "url" not in src:
            return

        for m in API_FN_DEF_RE.finditer(src):
            raw = m.group("url").strip()
            kind = self._classify(raw)
            if kind is None:
                continue
            method = m.group("m").upper()
            self.api_fns.setdefault(
                m.group("fn"),
                (method, self._finalize_url(raw, kind, ("http", method, m.group("fn")))),
            )

        # 调用点只在「参数对象里含典型查询键」时才记 —— 否则满屏都是
        # foo({a:1}) 这种无关调用，白占内存
        for m in API_FN_CALL_RE.finditer(src):
            obj = m.group("o")
            if not API_CALL_HINT_RE.search(obj):
                continue
            keys = [k for k, _ in object_keys(obj, max_keys=30)]
            if keys:
                self.fn_calls.append((m.group("fn"), keys))


    # -- 写入 / 去重 -----------------------------------------------------

    def _upsert(
        self, *, url, raw, method, kind, params, score, ctx_type,
        fn_name, prefix_var, context, source_endpoints, is_page: bool = False,
    ) -> None:
        key = (method, url)
        self._url_key.setdefault(url, key)
        old = self._index.get(key)
        if old is not None:
            old.count += 1
            old.confidence = max(old.confidence, score)
            have = {(p.name, p.location) for p in old.params}
            for p in params:
                if (p.name, p.location) not in have:
                    old.params.append(p)
                    have.add((p.name, p.location))
            if not old.fn_name and fn_name:
                old.fn_name = fn_name
            # 同一路径可能一次来自「前缀未探到」的文件、一次来自别处；
            # 只要其中任一次被标记过，收尾就按最终前缀补上
            if url in self.prefix_missing:
                old.prefix_missing = True
            return

        # 规范化之后路径形态可能变了（相对路径补上了 /），同步修正 kind
        if url.startswith("//"):
            kind = "absolute"
        elif url.startswith("/"):
            kind = "path"

        ep = Endpoint(
            url=url, raw=raw, method=method, kind=kind, params=params,
            confidence=score, ctx_type=ctx_type, fn_name=fn_name,
            prefix_var=prefix_var, context=context,
            third_party=_is_third_party(url),
            page=is_page,
            page_src="guess" if is_page else "",
            # _finalize_url 判定「该补前缀、但当时前缀还没探到」时记录的路径
            prefix_missing=url in self.prefix_missing,
        )
        self._index[key] = ep
        self.endpoints.append(ep)

    # -- 运行时前缀 ------------------------------------------------------

    def _detect_base(self) -> str:
        """从源码里推断运行时的 API 前缀（VITE_BASE_URL / baseURL …）。"""
        for m in API_BASE_RE.finditer(self.source):
            v = _norm_base(m.group("v1"))
            if v:
                return v
        for m in AXIOS_BASE_RE.finditer(self.source):
            # 只有「全局配置」里的 baseURL 才是前缀。
            # `r.post({url:"order/index", baseURL:"/AliYun/"})` 是**单次请求**的
            # 覆盖值，当成全局前缀会让整个文件的接口都带上错的路径。
            if self._is_request_scoped_base(m.start()):
                continue
            v = _norm_base(m.group("v2"))
            if v:
                return v
        return ""

    def _is_request_scoped_base(self, pos: int) -> bool:
        """
        这个 baseURL 是不是写在「单次请求的配置对象」里？

        判据：从它往前找最近的对象字面量 ``{...}``，若该对象里还有 ``url`` 键，
        说明形如 ``{url:"...", baseURL:"..."}`` —— 属于请求级，不是全局配置。
        """
        src = self.source
        depth = 0
        i = pos - 1
        limit = max(0, pos - 2000)
        while i >= limit:
            ch = src[i]
            if ch in ")]}":
                depth += 1
            elif ch in "([{":
                if depth == 0:
                    if ch != "{":
                        return False
                    end = match_bracket(src, i)
                    if end <= pos:
                        return False
                    return bool(re.search(r"""["']?url["']?\s*:""", src[i:end], re.I))
                depth -= 1
            i -= 1
        return False

    def _finalize_url(self, text: str, kind: str, ctx: tuple, scope: str = "") -> str:
        """
        规范化路径，并把运行时前缀补上。

        只有「网络调用上下文」才补前缀 —— 页面路由（``path:"/Login"``、
        ``href:"/goods"``）虽然长得一样，但不会走 axios 的 baseURL。
        """
        url = self._normalize(text, kind)
        if not url.startswith("/") or url.startswith("//"):
            return url
        ctype, _, fn = ctx
        # assign 场景：fn 现在可能是外层调用名（service.post），也可能是配置键（url）
        eligible = ctype in BASE_ELIGIBLE_CTX or (
            ctype == "assign"
            and (
                (fn or "").lower() in BASE_ELIGIBLE_KEYS
                or bool(self._method_from_fn(fn or ""))
            )
        )
        if not eligible:
            return url
        # 页面路由不吃前缀。判据必须和 _looks_like_route 保持一致：**只看首段**
        # （/Individual/Order/AliCloud、/Console/MAAS/List —— 首段是大写驼峰）。
        #
        # 这里原先遍历**所有**段，副作用是末段 camelCase 的真接口被误伤：
        # /blade-aliyun-shop/order/QueryOrderDetail、/blade-aliyun-oss/files/OssFileUrl
        # 首段明明是 BladeX 服务名（小写连字符），却因为末段大写而丢掉了前缀。
        # 用运行时 Vue Router 路由表核对过：这两条都**不在**路由表里，是接口。
        # 而 /individual/RechargeCash 这类小写开头的也不在路由表里，
        # 所以「只看首段」不会误伤小写页面路由（该站路由全是 PascalCase 首段）。
        if _looks_like_route(url):
            return url
        # 请求级 baseURL 优先。同一个文件里多种前缀并存很常见：
        #   {url:"blade-vstec/x"}                    → 走全局 /api
        #   {url:"order/index", baseURL:"/AliYun/"}  → 走 /AliYun
        b = self._local_base(scope) or self.base_prefix
        if not b:
            # 本文件比「含 VITE_BASE_URL 的那个 chunk」先被分析，全局前缀还没探到。
            # 先记下来，由 Scanner 收尾时按最终前缀统一回填 —— 否则结果会依赖文件
            # 的处理顺序，同一个服务的接口会并存带前缀和不带前缀两种写法。
            self.prefix_missing.add(url)
            return url
        if url == b or url.startswith(b + "/"):
            return url
        # 路径里已经出现过这个前缀段就别再叠（console/api/cloud/x 不该变
        # /api/console/api/cloud/x）
        if f"{b}/" in url:
            return url
        return b + url

    @staticmethod
    def _local_base(scope: str) -> str:
        """从调用窗口里取请求级 baseURL（``{url:"x", baseURL:"/y"}``）。"""
        if not scope:
            return ""
        m = re.search(
            r"""["']?base_?url["']?\s*:\s*["'`]([^"'`\n]{1,80})["'`]""",
            scope, re.I,
        )
        return _norm_base(m.group(1)) if m else ""

    # -- 作用域 ----------------------------------------------------------

    @staticmethod
    def _scope_of(src: str, start: int, end: int) -> str:
        """
        取「同一次调用」的源码窗口。

        括号配对可能一路退到函数体（``{...}``），那样会把整段代码里的参数
        都算进来，所以额外做两道校验；校验不过就退回到窄窗口。
        """
        found = enclosing_scope(src, start)
        if found is not None:
            s, e = found
            if 0 < e - s <= 20000:
                scope = src[s:e]
                if src[s] != "{" or looks_like_object(scope[1:-1]):
                    return scope
        return _fallback_scope(src, end)

    # -- 分类 ------------------------------------------------------------

    @staticmethod
    def _classify(body: str) -> str | None:
        if SCHEME_RE.match(body):
            return None
        if body.startswith("//") and len(body) > 4:
            return "absolute"
        m = ANY_SCHEME_RE.match(body)
        if m:
            # http/https 以及 ws/wss（实时接口也值得收集）
            return "absolute" if m.group(1).lower() in ("http", "https", "ws", "wss") else None
        # 模块相对路径 ./xxx、../xxx 不是接口
        if body.startswith("./") or body.startswith("../"):
            return None
        # MIME 类型：application/json、text/javascript …
        if MIME_RE.match(body):
            return None
        if body.startswith("/"):
            if " " in body or "\n" in body or '"' in body:
                return None
            return "path"
        core = body.split("?")[0]
        if RELATIVE_PATH_RE.match(core):
            head = core.split("/", 1)[0].lower()
            if head in NON_PATH_HEADS:
                return None
            return "relative"
        return None

    @staticmethod
    def _normalize(body: str, kind: str = "") -> str:
        """
        规范化路径。

        没有前导斜杠的相对路径会补上一个 —— 源码里写 ``"api/user/list"``，
        浏览器实际请求的是 ``/api/user/list``，列表里也能和绝对路径统一，
        顺带让 ``api/user/list`` 与 ``/api/user/list`` 去重成同一条。

        如果首段看起来是个域名（``api.example.com/pgc/...``），
        就补成协议相对形式 ``//api.example.com/pgc/...``。
        """
        s = body
        # 主机名是变量拼出来的：`'http://'+serverip+':'+serverport+'/x'` 折叠后
        # 得到 `http://{serverip}:80/x`。主机不可用（这地址没法直接请求），
        # 但路径是真的 —— 剥掉 scheme + authority 只留路径。
        # 不这么做的话，变量名不但会成为主机，还会被 _params 捡成一个「参数」。
        m = PLACEHOLDER_HOST_RE.match(s)
        if m:
            tail = s[m.end():]
            slash = tail.find("/")
            if slash >= 0:
                s = tail[slash:]
        s = re.sub(
            r"\$\{\s*([A-Za-z_$][\w$]*(?:\.[\w$]+)*)\s*\}",
            lambda m: "{" + m.group(1).split(".")[-1] + "}",
            s,
        )
        s = re.sub(r"\$\{[^}]{1,80}\}", "{param}", s)
        if "?" in s:
            s = s.split("?")[0]
        # Express / Rails 风格的路由参数：/user/:id/detail → /user/{id}/detail
        s = re.sub(r":([A-Za-z_][\w]{0,40})(?=/|$)", r"{\1}", s)
        if not s.startswith("//"):
            s = re.sub(r"(?<!:)/{2,}", "/", s)
        s = s.rstrip("/")
        if not s:
            return "/"
        if kind == "relative":
            head = s.split("/", 1)[0]
            s = ("//" + s) if _valid_host(head) else ("/" + s)
        return s

    # -- 上下文 ----------------------------------------------------------

    def _context(self, before: str, scope: str) -> tuple[str, str, str]:
        """
        判断这个字符串处于什么语境。

        返回 ``(ctx_type, method, fn_name)``。
        """
        # 这个函数每个字面量都要跑一次，所以先用几个近乎免费的字符判断
        # 缩小范围，只有真的像才去跑下面的复杂正则。
        tail = before.rstrip()
        if not tail:
            return "literal", "GET", ""
        end = tail[-1]

        # 2) 配置字段：url: / path: / action=（以 : 或 = 结尾）
        if end in ":=":
            m = KEY_BEFORE_RE.search(before)
            if m:
                key = m.group("key")
                if key.lower() not in ("src", "href"):
                    # 关键的坑：`service.post({url:"...", data:x})` 这种写法里
                    # 没有 method 字段，HTTP 方法是由**外层函数名**决定的。
                    # 不往外看一层的话，所有 POST 都会被当成 GET。
                    w = CALL_WRAP_RE.search(before)
                    wrap = w.group("fn") if w else ""
                    method = self._method_from_fn(wrap) or self._cfg_method(scope)
                    return "assign", method, (wrap or key)

        # 1) 特殊构造。注意 xhr.open 的地址前面是逗号，所以要在
        #    「必须以 ( 结尾」这个判断之前处理
        low_tail = tail[-60:]
        if ("open" in low_tail or "Beacon" in low_tail or "ocation" in low_tail
                or "WebSocket" in low_tail or "EventSource" in low_tail
                or "Worker" in low_tail):
            m = SPECIAL_BEFORE_RE.search(before)
            if m:
                if m.group("ws"):
                    return "ws", "GET", "new " + m.group("ws")
                if m.group("beacon"):
                    return "beacon", "POST", "sendBeacon"
                if m.group("xhr"):
                    return "xhr", self._xhr_method(before), "XMLHttpRequest.open"
                return "location", "GET", "location"

        if end != "(":
            return "literal", self._cfg_method(scope), ""

        # 3) 函数调用：xxx( "..." )
        m = CALL_BEFORE_RE.search(before)
        if m:
            fn = m.group("fn")
            last = fn.split(".")[-1].lower()
            if last in HTTP_METHODS:
                return "http", METHOD_LABEL.get(last, "GET"), fn
            if last in ("request", "req", "ajax", "fetch", "call", "invoke",
                        "download", "upload", "query", "load", "save", "send"):
                return ("fetch" if last == "fetch" else "call",
                        METHOD_LABEL.get(last, self._cfg_method(scope)), fn)
            if last in ("$get", "$post"):
                return "jquery", ("POST" if last == "$post" else "GET"), fn
            if _is_net_fn(fn):
                # 函数名完全不像网络请求（btns / addClass / attachEvent）→ 判负分
                if not NET_FN_HINT_RE.search(last):
                    return "nonnet", self._cfg_method(scope), fn
                return "call", self._cfg_method(scope), fn
            # 明确是 console.log / split / includes 这类函数 → 判负分
            if "." in fn or len(fn) > 3:
                return "nonnet", self._cfg_method(scope), fn

        return "literal", self._cfg_method(scope), ""

    @staticmethod
    def _xhr_method(before: str) -> str:
        m = re.search(r"""open\s*\(\s*['"`]([A-Za-z]{3,7})['"`]""", before[-120:], re.I)
        if m:
            cand = m.group(1).upper()
            if cand in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                return cand
        return "GET"

    @staticmethod
    def _method_from_fn(fn: str) -> str:
        """从函数名推断 HTTP 方法：``service.post`` → POST，``api.del`` → DELETE。"""
        if not fn:
            return ""
        last = fn.split(".")[-1].lower()
        m = METHOD_LABEL.get(last)
        if m:
            return m
        return ""

    @staticmethod
    def _cfg_method(scope: str) -> str:
        m = METHOD_CFG_RE.search(scope[:400] if scope else "")
        if m:
            cand = m.group(1).upper()
            if cand in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                return cand
        return "GET"

    def _method(self, ctx: tuple, before: str, scope: str) -> str:
        if ctx[1] and ctx[1] != "GET":
            return ctx[1]
        m = METHOD_CFG_RE.search(scope[:400] if scope else "")
        if m:
            cand = m.group(1).upper()
            if cand in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                return cand
        fn = (ctx[2] or "").split(".")[-1].lower()
        if fn in METHOD_LABEL:
            return METHOD_LABEL[fn]
        return ctx[1] or "GET"

    # -- 评分 ------------------------------------------------------------

    @staticmethod
    def _cheap_reject(body: str, kind: str, before: str) -> bool:
        """
        又便宜又高命中的排除条件。

        这一步挡掉的字面量占绝大多数，作用是让昂贵的括号配对只作用在
        真正有可能是接口的字符串上（大 bundle 上这是最大的性能杠杆）。
        """
        if BADCHAR_RE.search(body) or CJK_WS_RE.search(body):
            return True
        # XML 命名空间 / 文档格式规范标识符（w3.org、ns.adobe.com…）——
        # 是格式的名字，不是任何服务器上的资源，拿去请求没有意义
        if NAMESPACE_URI_RE.search(body):
            return True
        # 拼接残留弄出来的双协议头：https://https://www.beian.gov.cn/…
        if body.count("://") > 1:
            return True
        # 浏览器插件探测串：/plugins/name/filename/version/type/ActiveXObject、
        # //AcroPDF.PDF/PDF.PdfCtrl/Adobe.SVGCtl/WMPlayer.OCX/…
        # 这些是浏览器能力探测代码里的插件名，不是路径 —— 和上面 NON_PATH_HEADS
        # 挡 undefined / function 是同一类（JS 内建标识符不可能是路径段）。
        if JS_BUILTIN_RE.search(body):
            return True
        # 非法百分号（模板残留，比如 "www.%/ads/..."）或反斜杠
        if BAD_PERCENT_RE.search(body) or "\\" in body:
            return True
        m = EXT_RE.search(body.lower())
        ext = m.group(1) if m else ""
        if ext in STATIC_EXT or ext in CODE_EXT:
            return True
        core = body.split("?")[0]
        if core in ("/", "") or core.startswith("//"):
            return True
        if kind == "absolute" and "/" not in core.replace("://", "", 1).split("/", 1)[-1]:
            # 只有域名，没有路径
            return True
        if kind == "relative" and CODE_DIR_RE.match(core):
            return True
        # 整个路径就是一个占位符：/{version}、/{id}
        if ONLY_PLACEHOLDER_RE.match(core):
            return True
        # 去掉占位符后几乎没有字母（纯符号串）
        if len(NON_ALPHA_RE.sub("", body)) < 2:
            return True
        # ---- 下面几条都是「看着像路径，实则是别的东西」----
        # ① SPA 的 hash 路由 / 页面锚点：接口请求不会带 #
        if "#" in body:
            return True
        # ② Vue Router 的 catch-all：/zsintro/:pathMatch(.*)*
        if ":pathmatch" in body.lower():
            return True
        # ③ 三段以上占位符 —— 压缩变量拼出来的碎片，如 /{a}/{r}/{d}/{o}
        segs = [x for x in core.split("/") if x]
        if sum(1 for x in segs if "{" in x) >= 3:
            return True
        # ④ 源码路径片段：/{F}/{x}/./src/hls.ts/{M}（库内部的字符串拼接）
        if re.search(r"/\.\.?/|\.(?:ts|tsx|js|jsx|vue|scss|less|css)(?:/|$)", core):
            return True
        # ⑤ Vue Router 的路由表条目 {path:"/Individual/..."} —— 页面，不是接口
        mt = ASSIGN_TARGET_RE.search(before[-60:])
        if mt and mt.group(1).lower() in ("path", "pathname"):
            return True

        # 日期格式模板：yyyy/MM/dd、MM/DD/YYYY、goods{Array}yyyy/MM/dd。
        # 真实接口路径里几乎不会出现 yyyy，见到就直接排除。
        if "yyyy" in body or "YYYY" in body:
            return True
        low = body.lower()
        if "/mm/" in low or "/dd/" in low:
            segs = [x for x in body.split("?")[0].split("/") if x]
            if sum(1 for x in segs if DATE_SEG_RE.match(x)) >= 3:
                return True
        # 赋值目标是 baseURL / API_HOST 之类 → 是基地址不是接口
        mt = ASSIGN_TARGET_RE.search(before[-60:])
        if mt and mt.group(1).lower().endswith(HARD_BASE_SUFFIXES):
            return True
        return False

    def _score(self, body: str, kind: str, ctx: tuple, before: str, scope: str) -> int:
        # 这里不用 urlparse —— 它每秒只能跑十万次量级，而本函数是热路径
        path = _path_of(body)
        low = path.lower()

        ext = ""
        m = EXT_RE.search(low)
        if m:
            ext = m.group(1)
        core = body.split("?")[0]

        ctype = ctx[0]
        score = 22

        # --- 上下文权重 ---
        if ctype in ("http", "xhr", "fetch", "jquery", "ws", "beacon"):
            score += 38
        elif ctype == "assign":
            score += 30
        elif ctype == "location":
            score += 14
        elif ctype == "call":
            fn = ctx[2] or ""
            score += 34 if STRONG_FN_RE.search(fn) else 16
        elif ctype == "nonnet":
            # console.log(...) / xxx.split(...) 这种明显不是请求
            score -= 25

        # --- 路径形状 ---
        segs = [s for s in path.split("/") if s]
        if len(segs) >= 2:
            score += 8
        if len(segs) >= 3:
            score += 4
        if API_HINT_RE.search(path):
            score += 22
        if PLACEHOLDER_RE.search(body):
            score += 6
        if "?" in body and "=" in body:
            score += 6
        if API_EXT_RE.search(low):
            score += 12
        if not ext:
            score += 6

        # --- 减分 ---
        if kind == "relative":
            if CODE_DIR_RE.match(core):
                return 0
            score -= 16
        if kind == "absolute" and len(segs) <= 1:
            score -= 25
        if ASSET_DIR_RE.match(low):
            score -= 18
        if BUNDLE_NAME_RE.search(low):
            score -= 14
        # 赋值目标是 baseURL / API_HOST / xxx_BASE_API 这类名字 → 它是基地址，不是接口。
        # 注意：只作用于「字面量就是整个右值」的情况；`BASE + "/x"` 这种
        # 链式表达式不会命中（chain_start 落在 BASE 上，before 里没有 `=`）。
        mt = ASSIGN_TARGET_RE.search(before[-60:])
        if mt and mt.group(1).lower().endswith(HARD_BASE_SUFFIXES):
            return 0
        # const NAME = "..." 且名字不像接口 —— 多半只是个地址常量。
        # 例外：值本身是「域名+路径」形态时，它是真接口，只不过少了协议头
        md = CONST_DECL_RE.search(before[-60:])
        if md and not URLISH_NAME_RE.search(md.group(1)):
            if not _valid_host(core.split("/", 1)[0]):
                score -= 35
        if len(body) > 320:
            score -= 10

        if scope and PARAMS_IN_SCOPE_RE.search(scope[:300]):
            score += 8

        return score

    # -- 参数 ------------------------------------------------------------

    def _params(
        self, url: str, scope: str, method: str, ctx: tuple, canonical: str = ""
    ) -> list[Param]:
        out: list[Param] = []
        seen: set[tuple[str, str]] = set()

        def add(name, loc, value="", required=False):
            name = str(name).strip()
            if not name or len(name) > 60:
                return
            if not SAFE_NAME_RE.match(name):
                return
            k = (name, loc)
            if k in seen:
                return
            seen.add(k)
            out.append(Param(name=name, location=loc, required=required,
                             sample=_sample_of(value), type=guess_type(value)))

        # 1) URL 自带的 query
        if "?" in url:
            try:
                full = url if "//" in url[:8] else "http://x" + url
                for k, vs in parse_qs(urlparse(full).query, keep_blank_values=True).items():
                    add(k, "query", vs[0] if vs else "")
            except Exception:
                pass

        # 2) 路径占位符
        # 先算出真正的「路径」从哪开始。`http://{serverip}:{serverport}/x` 里那两个
        # 占位符是主机和端口变量（`'http://'+serverip+':'+serverport+'/x'` 折叠来的），
        # 不是路径参数 —— 不过滤的话会凭空多出 serverip / serverport 这种假参数。
        path_from = 0
        mh = PLACEHOLDER_HOST_RE.match(url)
        if mh:
            sl = url.find("/", mh.end())
            path_from = sl if sl >= 0 else len(url)
        for ph in PLACEHOLDER_TOKEN_RE.finditer(url):
            if ph.start() < path_from:
                continue
            expr = (ph.group(1) or ph.group(2) or "").strip()
            mm = IDENT_HEAD_RE.match(expr)
            name = mm.group(0).split(".")[-1].split("[")[0] if mm else "param"
            add(name or "param", "path", expr, required=True)

        if scope:
            # 3) 配置对象里的 params / data / body / headers
            depths = depth_map(scope)
            for rx, loc in PARAM_KEY_RES:
                for m in rx.finditer(scope):
                    if depths[m.start()] > 3:
                        continue
                    got = self._keys_from_expr(scope[m.end():])
                    if got is not None:
                        for n, v in got:
                            add(n, loc, v)
                        # `{...e, productType:5}` —— 一半字面量、一半来自调用方，
                        # 同样属于「参数名看不到」，也要记下来
                        if "..." in scope[m.end():m.end() + 240] and loc in ("query", "body"):
                            self.unresolved.add((method, canonical or url))
                        break
                    # `params: e` —— 参数确实存在，只是名字在调用方手里。
                    # 记下来，交给 scanner 用站点自己的分页惯例去补。
                    if loc in ("query", "body"):
                        # 用规范化后的地址做键，才能和 scanner 的索引对上
                        self.unresolved.add((method, canonical or url))

            # 4) XHR 的 body 在后面的 .send(...) 里
            if ctx[0] == "xhr":
                pos = self.source.find(scope)
                tail = self.source[pos + len(scope) :][:600] if pos >= 0 else ""
                sm = XHR_SEND_RE.search(tail)
                if sm:
                    got = self._keys_from_expr(tail[sm.end():])
                    if got:
                        for n, v in got:
                            add(n, "body", v)

            # 5) 兜底：作用域里剩下的非配置键
            if not any(p.location in ("body", "query") for p in out):
                for _, ob in find_object_literals(scope, limit=2):
                    for n, v in object_keys(ob, max_keys=30):
                        low = n.lower()
                        if low in CONFIG_KEYS:
                            if low in RECURSE_KEYS:
                                got = self._keys_from_expr(v)
                                if got:
                                    loc = "query" if method in ("GET", "HEAD") else "body"
                                    for n2, v2 in got:
                                        add(n2, loc, v2)
                            continue
                        loc = "query" if method in ("GET", "HEAD") else "body"
                        add(n, loc, v)
                    if len(out) >= 30:
                        break

        # 路径参数排前面
        out.sort(key=lambda p: {"path": 0, "query": 1, "body": 2, "header": 3}.get(p.location, 9))
        return out[:40]

    @staticmethod
    def _keys_from_expr(rest: str, depth: int = 0) -> list[tuple[str, str]] | None:
        """从「值表达式」里取参数键，支持 JSON.stringify / qs.stringify / URLSearchParams 包装。"""
        s = rest.lstrip()
        if not s:
            return None
        s = re.sub(r"^[=(]\s*", "", s)
        if not s:
            return None
        if s[0] == "{":
            e = match_bracket(s, 0)
            return object_keys(s[1:e]) if e > 0 else None
        if s[0] == "[":
            e = match_bracket(s, 0)
            if e <= 0:
                return None
            acc: list[tuple[str, str]] = []
            for _, ob in find_object_literals(s[1:e], limit=3):
                acc.extend(object_keys(ob))
            return acc or None
        if depth < 2:
            m = re.match(r"(?:new\s+)?[A-Za-z_$][\w$.]*\s*\(", s)
            if m and re.search(
                r"(stringify|searchparams|formdata|urlencoded|encode|qs\b)",
                s[: m.end()], re.I,
            ):
                p = m.end() - 1
                e = match_bracket(s, p)
                if e > 0:
                    return JSExtractor._keys_from_expr(s[p + 1 : e], depth + 1)
        return None

    # -- 上下文片段 ------------------------------------------------------

    @staticmethod
    def _context_snippet(code: str, start: int, end: int, span: int = 180) -> str:
        a = max(0, start - span)
        b = min(len(code), end + span)
        snippet = re.sub(r"\s+", " ", code[a:b]).strip()
        return ("…" if a > 0 else "") + snippet + ("…" if b < len(code) else "")

    # -- 元信息 ----------------------------------------------------------

    def _extract_meta(self, src: str | None = None) -> None:
        src = src if src is not None else self.source
        seen_base: set[tuple[str, str]] = set()
        for m in BASEURL_RE.finditer(src):
            raw = m.group("val")
            is_literal = raw[0] in "'\"`"
            val = raw[1:-1] if is_literal else raw
            if not val or len(val) < 3:
                continue
            if CJK_RE.search(val) or not _looks_like_base_value(val):
                continue
            k = (m.group("key"), val)
            if k in seen_base:
                continue
            seen_base.add(k)
            self.base_urls.append({"key": m.group("key"), "value": val, "is_literal": is_literal})
            if len(self.base_urls) >= 200:
                break

        # 常量表里名字像「地址」的常量，也当作 baseURL 展示
        for name, val in list(self.consts.map.items())[:600]:
            if len(val) < 3 or len(name) < 4:
                continue
            low = name.lower()
            if low in BASEVAR_BLOCKLIST or not low.endswith(BASEVAR_SUFFIXES):
                continue
            if not re.match(r"^(?:https?:)?//", val) and not val.startswith("/"):
                continue
            k = (name, val)
            if k in seen_base:
                continue
            seen_base.add(k)
            self.base_urls.append({"key": name, "value": val, "is_literal": True})

        for lit in self._strings:
            b = lit.body.strip()
            if not re.match(r"^(https?:)?//", b, re.I):
                continue
            try:
                host = urlparse(b if "://" in b else "http:" + b).hostname
            except Exception:
                continue
            if host and _valid_host(host):
                self.hosts[host] = self.hosts.get(host, 0) + 1

        self._scan_findings(src)

    def _scan_findings(self, src: str) -> None:
        """从一段 JS 里找泄露的凭据。证据强弱递减：

        ① 值本身符合某家厂商的密钥格式 —— 最可靠，不看键名叫什么；
        ② 键名像凭据且值也像 —— 覆盖 `const appSecret = "..."` 这类；
        ③ 只发现键名 —— 提示"这里有个 token 字段"，值通常是运行时才填的。
        """
        # ① 厂商格式
        for label, pat in VENDOR_SECRET_PATTERNS:
            for m in pat.finditer(src):
                v = m.group(0)
                # 前缀本身已经是证据了，这里只挡明显的示例值
                if (CJK_RE.search(v) or VALUE_PLACEHOLDER_RE.match(v)
                        or REPEAT_RE.search(v)):
                    continue
                self._add_finding("secret", label, self._ctx(src, m.start()), v)

        # ② 键名 + 值都像
        for m in SECRET_KV_RE.finditer(src):
            k = m.group("k1") or m.group("k2") or ""
            v = m.group("v") or ""
            if not (SECRET_NAME_RE.search(k) or SHORT_KEY_NAME_RE.match(k)):
                continue
            if not _credible_secret(v):
                continue
            self._add_finding("secret", k, self._ctx(src, m.start()), v)

        # ③ 只记键名
        for m in TOKEN_KEY_RE.finditer(src):
            self._add_finding("auth", m.group("k"), self._ctx(src, m.start()), "")

    def _add_finding(self, kind: str, key: str, ctx: str, value: str) -> None:
        key = (key or "").strip()
        if not key:
            return
        # 有值就让值说话（已经过了 _credible_secret / 厂商前缀）；
        # 只有"只报键名"这一类才需要靠键名过滤噪音 —— 否则 pdf.js 里的
        # signature / nonce 之类的库内部字段会混进来。
        if kind == "auth" and (SECRET_KEY_DENY.search(key) or PLACEHOLDER_RE.search(key)):
            return
        if len(self.findings) >= 80:
            return
        v = (value or "").strip()
        k = (kind, key.lower(), v[:64])
        if k in self._seen_finding:
            return
        self._seen_finding.add(k)
        self.findings.append(Finding(kind=kind, key=key, value=v, context=ctx))

    @staticmethod
    def _ctx(code: str, idx: int, span: int = 120) -> str:
        a = max(0, idx - span)
        b = min(len(code), idx + span)
        return re.sub(r"\s+", " ", code[a:b]).strip()


# ==========================================================================
# 资源发现
# ==========================================================================

SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']""", re.I)
LINK_JS_RE = re.compile(
    r"""<link\b[^>]*?\bhref\s*=\s*["']([^"']+\.(?:js|mjs))(?:\?[^"']*)?["']""", re.I
)
INLINE_SCRIPT_RE = re.compile(
    r"""<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>""", re.I | re.S
)
HREF_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'#]+)["']""", re.I)
SOURCEMAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s'"]+)""")
JS_IN_JS_RE = re.compile(r"""["'`]([^"'`\n]{1,200}?\.(?:js|mjs))(?:\?[^"'`\n]*)?["'`]""")

WEBPACK_TPL_RE = re.compile(
    r"""["'`](?P<prefix>[^"'`\n]{0,160}?/)["'`]\s*\+\s*[A-Za-z_$][\w$.]*\s*\+"""
    r"""\s*(?:\s*["'`]((?:\.[^"'`\n]*?))["'`]\s*\+\s*)?"""
    r"""(?P<map>\{[^{}]{30,80000}\})\s*\[[^\]]{0,60}\]"""
    r"""(?:\s*\+\s*["'`](?P<suffix>[^"'`\n]{0,60})["'`])?""",
)
MAP_ENTRY_RE = re.compile(r"""([\w$.-]{1,40})\s*:\s*["']([^"'\s]{1,200})["']""")

# URLFinder 的 jsFuzz 思路：按已知目录爆破常见入口文件名
JS_FUZZ_NAMES = [
    "main.js", "app.js", "index.js", "login.js", "config.js", "common.js",
    "vendor.js", "chunk-vendors.js", "app.min.js", "main.min.js",
    "admin.js", "user.js", "list.js", "upload.js", "info.js", "open.js",
    "site.js", "base.js", "api.js", "service.js", "config/index.js",
]


# 第三方库 / 打包运行时的文件名特征。
# 参考 katana 的 CommonJSLibraryFileRegex 思路：这些文件里不会有业务接口，
# 但体积极大（pdfjs / element-plus 动辄几百 KB 到几 MB），
# 让它们排在业务 chunk 后面抓，能把有限的文件配额用在刀刃上。
LIBRARY_JS_RE = re.compile(
    r"(?:^|[/@])"
    r"(?:chunk[-_.]?vendors?|vendors?|runtime|polyfills?|manifest|"
    r"vue|vuex|vue-router|react|react-dom|preact|angular|svelte|solid|"
    r"jquery|zepto|lodash|underscore|ramda|moment|dayjs|date-?fns|luxon|"
    r"element-plus|element-ui|antd|ant-design|iview|view-ui|naive-ui|"
    r"axios|superagent|pinia|redux|rxjs|immutable|mobx|"
    r"echarts|highcharts|chart|d3|three|babylon|pixi|konva|leaflet|mapbox|"
    r"pdfjs|pdf\.worker|jspdf|mammoth|xlsx|jszip|pako|protobuf|socket\.io|"
    r"bignumber|decimal|tinycolor|color|core-js|regenerator|tslib|zone\.js|"
    r"sortable|dropzone|quill|tinymce|ckeditor|monaco|codemirror|"
    r"highlight|prism|markdown|katex|mathjax|swiper|slick|"
    r"crypto-js|cryptojs|jsencrypt|sm-crypto|forge|"
    r"@vue|@babel|@popperjs|node_modules|-legacy|"
    # 风控 / 验证码 / 打点类 SDK
    r"awsc|fireye|collina|et_f|um\.js|nc\.js|captcha|geetest|hcaptcha|recaptcha|"
    r"turnstile|clarity|hotjar|sentry|gtm|analytics|workbox|service-?worker|"
    r"sw\.js)[-_.@]",
    re.I,
)

# 通用第三方 CDN —— 这些域名上的 JS 基本不可能是目标站点的业务代码。
# 注意：不要收录 *本站自己的* CDN（如 bilibili 的 hdslb、juejin 的 lf-web-assets），
# 业务 chunk 往往就挂在那上面。
THIRD_PARTY_JS_HOST_RE = re.compile(
    r"(alicdn\.com|gstatic\.com|googleapis\.com|google-analytics\.com|"
    r"googletagmanager\.com|googlesyndication\.com|doubleclick\.net|"
    r"jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|bootstrapcdn\.com|"
    r"staticfile\.org|bootcdn\.cn|baomitu\.com|code\.jquery\.com|"
    r"facebook\.net|hotjar\.com|segment\.(io|com)|sentry-cdn\.com)",
    re.I,
)


def is_library_js(url: str) -> bool:
    """判断这个 JS 是不是第三方库/运行时（用来做抓取优先级排序）。"""
    path = url.split("?")[0]
    host = urlparse(path).netloc
    if host and THIRD_PARTY_JS_HOST_RE.search(host):
        return True
    name = path.rsplit("/", 1)[-1]
    return bool(LIBRARY_JS_RE.search("/" + name))


def origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else url


def dir_of(url: str) -> str:
    """返回 URL 的目录部分（带结尾斜杠）。"""
    clean = url.split("?")[0].split("#")[0]
    i = clean.rfind("/")
    return clean[: i + 1] if i > 0 else origin_of(url) + "/"


def find_script_urls(html: str, base: str) -> list[str]:
    out: list[str] = []
    for rx in (SCRIPT_SRC_RE, LINK_JS_RE):
        for m in rx.finditer(html):
            out.append(urljoin(base, m.group(1).strip()))
    return list(dict.fromkeys(out))


def find_inline_scripts(html: str) -> list[str]:
    return [m.group(1) for m in INLINE_SCRIPT_RE.finditer(html) if m.group(1).strip()]


def find_links(html: str, base: str, same_origin: str) -> list[str]:
    out: list[str] = []
    for m in HREF_RE.finditer(html):
        u = urljoin(base, m.group(1).strip())
        if u.startswith(same_origin):
            out.append(u)
    return list(dict.fromkeys(out))


def find_sourcemap_url(js: str, base: str) -> str | None:
    tail = js[-800:] if len(js) > 800 else js
    m = None
    for m in SOURCEMAP_RE.finditer(tail):
        pass
    if not m:
        m = SOURCEMAP_RE.search(js)
    return urljoin(base, m.group(1).strip()) if m else None


def collapse_dup_dirs(url: str) -> str:
    """把 ``/assets/assets/x.js`` 这种相邻重复目录折叠成 ``/assets/x.js``。"""
    p = urlparse(url)
    segs = [s for s in p.path.split("/") if s]
    out: list[str] = []
    for s in segs:
        if out and out[-1] == s:
            continue
        out.append(s)
    if len(out) == len(segs):
        return url
    return urlunparse(p._replace(path="/" + "/".join(out)))


def resolve_js_ref(ref: str, base: str) -> str | None:
    """
    把一个 JS 引用解析成绝对 URL。

    这里有个 Vite 特有的坑：``__vite__mapDeps`` 里的依赖表写的是
    ``"./assets/xxx.js"``（相对**文档根**），而 chunk 内部的
    ``import("./xxx.js")`` 是相对 **chunk 自身**。
    如果一律按 chunk 目录解析，就会得到 ``/assets/assets/xxx.js`` 这种
    根本不存在的地址，白白消耗抓取配额。

    判据：相对引用的**第一级目录名**和当前 chunk 所在目录名相同时，
    说明它是文档根相对，按 origin 解析。
    """
    ref = ref.strip()
    if not ref or " " in ref or ref.startswith("data:"):
        return None
    if ref.startswith(("http://", "https://")):
        return ref
    if ref.startswith("//"):
        # 协议相对：必须补上 scheme，否则 httpx 会直接报
        # "unknown url type"，整个文件就抓不到了
        return urljoin(base, ref)
    if ref.startswith("/"):
        return urljoin(origin_of(base), ref)

    folder = dir_of(base)
    candidate = urljoin(folder, ref)
    # 相对引用有两种含义，必须区分：
    #   ① chunk 内部 `import("./x.js")`  → 相对 chunk 自身
    #   ② Vite `__vite__mapDeps` 的依赖表 → 相对**文档根**，写 "./assets/x.js"
    #      甚至直接 "assets/x.js"（连 ./ 前缀都没有）
    # 判据：引用的第一级目录名 == 当前 chunk 所在目录名 → 属于 ②。
    # 漏判 ② 会拼出 /assets/assets/x.js 这种根本不存在的地址，
    # 每个都要发一次请求（还要再试一次折叠兜底），把抓取配额白吃掉。
    rel = re.sub(r"^(?:\./|\.\./)+", "", ref)
    first_dir = rel.split("/")[0]
    path_segs = [s for s in urlparse(folder).path.split("/") if s]
    if first_dir and path_segs and path_segs[0] == first_dir:
        candidate = urljoin(origin_of(base) + "/", rel)
    return candidate


def find_js_refs(js: str, base: str) -> list[str]:
    """从 JS 里找出它引用的其它 JS。"""
    out: list[str] = []
    for m in JS_IN_JS_RE.finditer(js):
        ref = m.group(1)
        if not (ref.startswith(("http", "//", "/")) or "/" in ref):
            continue
        url = resolve_js_ref(ref, base)
        if url:
            out.append(url)
    return list(dict.fromkeys(out))


def find_webpack_chunks(js: str, base: str) -> list[str]:
    """还原 webpack 运行时的懒加载 chunk 地址（以站点根目录为基准）。"""
    root = origin_of(base)
    out: list[str] = []
    for m in WEBPACK_TPL_RE.finditer(js):
        prefix = m.group("prefix")
        dot = m.group(2) or ""
        suffix = m.group("suffix") or ""
        if not suffix and "." not in dot:
            suffix = ".js"
        seen: set[str] = set()
        for eid, h in MAP_ENTRY_RE.findall(m.group("map")):
            if not (4 <= len(h) <= 60):
                continue
            name = f"{prefix}{eid}{dot}{h}{suffix}"
            if name in seen:
                continue
            seen.add(name)
            out.append(urljoin(root, name))
            if len(out) >= 800:
                return out
    return out


def find_ws_urls(js: str, base: str) -> list[str]:
    """抓 WebSocket / EventSource / sendBeacon 的地址。"""
    out: list[str] = []
    rx = re.compile(
        r"""new\s+(?:WebSocket|EventSource)\s*\(\s*(["'`])([^"'`\n]{4,300})\1"""
    )
    for m in rx.finditer(js):
        out.append(urljoin(base, m.group(2).strip()))
    return list(dict.fromkeys(out))


def find_js_fuzz_targets(js_urls: list[str], site_origin: str = "") -> list[str]:
    """
    根据已发现的 JS 目录 + 站点根，猜常见入口文件名。

    只在**目标站点自己的 origin** 上猜：JS 往往一半来自第三方 CDN，
    去它们的根目录爆破纯属浪费请求配额。
    """
    roots: list[str] = []
    site_host = urlparse(site_origin).netloc.lower() if site_origin else ""
    for u in js_urls:
        if not re.search(r"\.(js|mjs)(\?|$)", u, re.I):
            continue
        host = urlparse(u).netloc.lower()
        if site_host and host != site_host:
            continue
        roots.append(dir_of(u))
        roots.append(origin_of(u) + "/")
    out: list[str] = []
    for r in dict.fromkeys(roots):
        if r.count("/") > 4:  # 目录太深就跳过，避免请求量爆炸
            continue
        for n in JS_FUZZ_NAMES:
            out.append(r + n)
    return list(dict.fromkeys(out))
