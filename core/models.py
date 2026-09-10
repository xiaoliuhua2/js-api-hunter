"""数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Param:
    name: str
    location: str = "query"   # query | path | body | header
    type: str = "unknown"
    required: bool = False
    sample: str = ""
    inferred: bool = False   # True = 由站点自身的分页惯例推断出来的，不是从代码里读到的

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Endpoint:
    url: str
    raw: str = ""
    method: str = "GET"
    kind: str = "path"        # path | relative | absolute
    params: list[Param] = field(default_factory=list)
    confidence: int = 50
    context: str = ""
    source: str = ""          # 来源 JS 文件 URL
    source_kind: str = "js"   # js | html | sourcemap | openapi | fuzz
    ctx_type: str = "literal"  # 触发方式：axios/fetch/xhr/jquery/call/assign/location/ws/beacon/openapi/runtime
    fn_name: str = ""          # 触发它的函数名（便于人工判断）
    prefix_var: str = ""       # 拼在路径前面、无法静态解析的变量名（通常是运行时 baseURL）
    third_party: bool = False  # 统计/广告/监控类第三方接口（GA、GTM、Sentry…）
    page: bool = False         # 前端页面路由（Vue Router 的 path:"/Individual/..."），不是接口
    page_src: str = ""         # page 的来源：route=前端路由表命中（权威）；guess=命名启发式（可能误判）
    prefix_missing: bool = False  # 提取时运行时前缀还没探到（本文件比前缀先被分析），收尾时统一回填
    runtime_hit: bool = False  # 是否被运行时（真实浏览器）观测到过
    runtime_sample: str = ""   # 运行时观测到的完整请求地址样例（含 query）
    runtime_status: int = 0    # 运行时观测到的响应状态码
    stack: list[str] = field(default_factory=list)  # 触发它的调用栈（来自运行时 hook）
    tags: list[str] = field(default_factory=list)
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class Finding:
    kind: str = "auth"        # auth | secret
    key: str = ""
    value: str = ""
    context: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Resource:
    url: str
    status: int = 0
    size: int = 0
    kind: str = "js"          # js | html | sourcemap | inline
    error: str = ""
    endpoints: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
