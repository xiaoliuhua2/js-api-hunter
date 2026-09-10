"""
Swagger / OpenAPI 文档解析。

很多站点（尤其是 Spring Boot、.NET、FastAPI 的项目）会把完整的接口清单
直接挂在 ``/v2/api-docs``、``/openapi.json`` 这类地址上。能从 JS 里静态
扒出来的接口往往只是前端用到的那一小部分，而文档里是**全量**的，
所以这一步对「把接口找全」帮助极大。

同时支持 Swagger 2.0 和 OpenAPI 3.x。
"""

from __future__ import annotations

import re
from typing import Any

from .models import Endpoint, Param

# 值得一试的文档地址（相对站点根）
SPEC_PATHS = [
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/api-docs/swagger-config",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v2/api-docs",
    "/api/v3/api-docs",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/api/v1/swagger.json",
    "/api/v1/openapi.json",
    "/doc.html",
    "/swagger-resources",
    "/actuator/mappings",
]

# 从页面/JS 里发现文档地址的线索（swagger-ui 会把自己加载的 spec 地址写在代码里）
SPEC_HINT_RE = re.compile(
    r"""["'`](?P<u>(?:https?://[^"'`\s]{0,160}?|/|\.{1,2}/)?[^"'`\s]{0,160}?)"""
    r"""(?:v[0-9]/api-docs|api-docs|openapi\.json|openapi\.yaml|swagger\.json|"""
    r"""swagger-resources|swagger-config)["'`]""",
    re.I,
)
# 快速判断一段文本值不值得去跑上面的正则
SPEC_HINT_KEYWORDS = ("api-docs", "openapi", "swagger")

METHOD_KEYS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")

# 这几个字段存在，才认为它是真的接口文档
SPEC_MARKERS = ("swagger", "openapi", "paths", "basePath", "definitions",
                "components", "info", "apis")


def looks_like_spec(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if not isinstance(data.get("paths"), (dict, list)):
        return False
    # swagger 2.0 或 openapi 3.x 的显式标记
    if isinstance(data.get("swagger"), str) and data["swagger"].startswith("2"):
        return True
    if isinstance(data.get("openapi"), str) and data["openapi"].startswith("3"):
        return True
    # 有些工具裁剪过文档，只剩 paths；再看一眼有没有 definitions/components
    return any(k in data for k in ("definitions", "components", "basePath", "info"))


class _Spec:
    """包一层，负责 $ref 解析和 base 路径。"""

    def __init__(self, data: dict):
        self.data = data
        self.base = self._base_path()

    def _base_path(self) -> str:
        servers = self.data.get("servers")
        if isinstance(servers, list) and servers:
            url = servers[0].get("url") if isinstance(servers[0], dict) else None
            if isinstance(url, str) and url and url != "/":
                return _path_of(url)
        bp = self.data.get("basePath")
        if isinstance(bp, str) and bp and bp != "/":
            return bp
        # Swagger 2 有时把 host/basePath 拆开；host 是域名就不拼了
        return ""

    def resolve(self, node: Any, depth: int = 0) -> Any:
        """把 ``{"$ref": "#/definitions/User"}`` 展开成真实节点。"""
        if depth > 6 or not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if not isinstance(ref, str):
            return node
        if not ref.startswith("#/"):
            return {}
        cur: Any = self.data
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return {}
        return self.resolve(cur, depth + 1)

    def schema_props(self, schema: Any, depth: int = 0) -> list[tuple[str, str, str]]:
        """
        递归展开一个 schema，返回 [(参数名, 类型, 是否必填)]。

        只展开一层嵌套对象（``a.b`` 这种会拉平成 ``a.b``），避免参数爆炸。
        """
        if depth > 3:
            return []
        schema = self.resolve(schema)
        if not isinstance(schema, dict):
            return []

        # 组合类型
        for comb in ("allOf", "oneOf", "anyOf"):
            if isinstance(schema.get(comb), list):
                out: list[tuple[str, str, str]] = []
                for sub in schema[comb]:
                    out.extend(self.schema_props(sub, depth + 1))
                return out

        props = schema.get("properties")
        if not isinstance(props, dict):
            return []

        required = set(schema.get("required") or [])
        out: list[tuple[str, str, str]] = []
        for name, raw in props.items():
            node = self.resolve(raw)
            if not isinstance(node, dict):
                node = {}
            typ = node.get("type") or ("object" if "properties" in node else "")
            if not typ and isinstance(node.get("items"), dict):
                typ = "array"
            flag = "1" if name in required else ""
            out.append((str(name), str(typ or "unknown"), flag))
            # 嵌套对象再展开一层
            if depth < 2 and isinstance(node.get("properties"), dict):
                for sub, styp, sreq in self.schema_props(node, depth + 1):
                    out.append((f"{name}.{sub}", styp, sreq))
            if len(out) >= 60:
                break
        return out


def _path_of(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.\-]*://[^/]+(/.*)?$", url, re.I)
    if m:
        return (m.group(1) or "").rstrip("/")
    return url.rstrip("/") if url.startswith("/") else ""


def _join(base: str, path: str) -> str:
    if not base:
        return path
    if path.startswith(base + "/") or path == base:
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


def _param_from_entry(entry: Any, sp: _Spec) -> list[Param]:
    """OpenAPI 的 parameter 条目 → Param 列表。"""
    entry = sp.resolve(entry)
    if not isinstance(entry, dict):
        return []
    raw_in = str(entry.get("in") or "query").lower()
    # v2 的 in:body 参数本身不是参数，真正的字段在它的 schema 里
    if raw_in == "body":
        return []
    name = entry.get("name")
    if not name:
        return []
    loc = {"formdata": "body", "cookie": "header"}.get(raw_in, raw_in)
    if loc not in ("query", "path", "header", "body"):
        loc = "query"
    node = sp.resolve(entry.get("schema")) if entry.get("schema") else entry
    if not isinstance(node, dict):
        node = {}
    typ = node.get("type") or entry.get("type") or "unknown"
    if isinstance(typ, list):
        typ = "|".join(str(t) for t in typ)
    return [Param(name=str(name), location=loc, type=str(typ),
                  required=bool(entry.get("required")),
                  sample=str(entry.get("example") or node.get("example") or "")[:100])]


def parse_spec(data: dict, source_url: str, base_label: str = "") -> list[Endpoint]:
    """把一份 OpenAPI / Swagger 文档转成接口列表。"""
    if not looks_like_spec(data):
        return []

    sp = _Spec(data)
    paths = data.get("paths") or {}
    if not isinstance(paths, dict):
        return []

    out: list[Endpoint] = []
    for raw_path, item in paths.items():
        item = sp.resolve(item)
        if not isinstance(item, dict):
            continue
        path = str(raw_path)
        if not path.startswith("/") and not path.startswith("http"):
            continue
        full = _join(sp.base, path) if not path.startswith("http") else path

        # path 级别的公共参数
        common = item.get("parameters") if isinstance(item.get("parameters"), list) else []

        for method in METHOD_KEYS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue

            params: list[Param] = []
            seen: set[tuple[str, str]] = set()

            def add(p: Param):
                k = (p.name, p.location)
                if k not in seen:
                    seen.add(k)
                    params.append(p)

            for entry in common:
                for p in _param_from_entry(entry, sp):
                    add(p)
            if isinstance(op.get("parameters"), list):
                for entry in op["parameters"]:
                    for p in _param_from_entry(entry, sp):
                        add(p)

            # v3 requestBody
            body = op.get("requestBody")
            if isinstance(body, dict):
                body = sp.resolve(body)
                content = body.get("content")
                if isinstance(content, dict) and content:
                    mime = next(iter(content))
                    schema = (content.get(mime) or {}).get("schema")
                    for n, t, req in sp.schema_props(schema):
                        add(Param(name=n, location="body", type=t, required=bool(req)))
                elif isinstance(body.get("schema"), dict):
                    for n, t, req in sp.schema_props(body["schema"]):
                        add(Param(name=n, location="body", type=t, required=bool(req)))

            # v2 body / formData 已经由 parameters 覆盖；补一下 body schema
            for entry in (op.get("parameters") or []) + common:
                e = sp.resolve(entry)
                if isinstance(e, dict) and e.get("in") in ("body", "formData") and e.get("schema"):
                    for n, t, req in sp.schema_props(e["schema"]):
                        add(Param(name=n, location="body", type=t, required=bool(req)))

            # 路径里的 {id}
            for ph in re.findall(r"\{([^}/]{1,40})\}", path):
                if not any(p.name == ph for p in params):
                    add(Param(name=ph, location="path", type="string", required=True))

            # query 参数在 URL 里备份一份（部分文档把 query 写在 parameters 之外）
            for q in re.findall(r"[?&]([A-Za-z_][\w.\-]{0,40})=", path):
                if not any(p.name == q for p in params):
                    add(Param(name=q, location="query"))

            tags = op.get("tags") if isinstance(op.get("tags"), list) else []
            summary = str(op.get("summary") or op.get("description") or "")[:120]

            out.append(
                Endpoint(
                    url=full,
                    raw=full,
                    method=method.upper(),
                    kind="absolute" if full.startswith("http") else "path",
                    params=params[:80],
                    confidence=100,           # 来自接口文档，直接可信
                    ctx_type="openapi",
                    fn_name=summary or (base_label or "OpenAPI"),
                    context=f"[{data.get('openapi') or data.get('swagger') or 'spec'}] "
                            f"{method.upper()} {full}  {summary}",
                    source=source_url,
                    source_kind="openapi",
                )
            )
            if len(out) >= 5000:
                return out

    return out
