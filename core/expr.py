"""
表达式折叠（constant folding）。

静态扫 JS 时最大的漏报来源是「接口地址不是一个完整字符串」：

    axios.get("/api/" + type + "/list", ...)
    const BASE = "/api/v1";  axios.get(BASE + "/user/info")
    request(`${ApiPrefix}/order/${id}/detail`)

如果只匹配孤立的字符串字面量，上面三条最多只能捞到半截路径。
jsluice 用 tree-sitter 的 ``CollapsedString()`` 解决这个问题；
这里用一个轻量的「常量表 + 相邻操作数回扫」来近似，不依赖 AST。
"""

from __future__ import annotations

import re

IDENT = r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*"
_IDENT_RE = re.compile(IDENT)

_SINGLE = r"'((?:\\.|[^'\\])*)'"
_DOUBLE = r'"((?:\\.|[^"\\])*)"'
_BACKTICK = r"`((?:\\.|[^`\\])*)`"
_LIT = f"(?:{_SINGLE}|{_DOUBLE}|{_BACKTICK})"

# const/let/var NAME = "字面量"
CONST_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*" + _LIT, re.S)
# 普通赋值 / 对象属性 NAME: "字面量"（排除 ==、!=、+= 等）
ASSIGN_RE = re.compile(
    r"(?<![=!<>+\-*/%&|^])([A-Za-z_$][\w$]*)\s*[:=]\s*" + _LIT, re.S
)
# const A = B;  —— 标识符到标识符的别名
IDENT_ALIAS_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*[;,)\n\r]"
)

# 拼接链最多向两侧各回溯多少个操作数
MAX_OPS = 10
MAX_RESOLVE_DEPTH = 3


def _lit_body(match: re.Match) -> str | None:
    """从三个捕获组里取出真正命中的那段字符串内容。"""
    for g in match.groups()[1:4]:
        if g is not None:
            return g
    return None


class ConstTable:
    """
    标识符 → 字符串字面量 的映射表。

    只收录「值里带斜杠」的常量 —— 地址类常量必然含 ``/``，
    这样能自动过滤掉 ``MODE = "prod"`` 这类无关赋值。
    """

    def __init__(self) -> None:
        self.map: dict[str, str] = {}
        self.alias: dict[str, str] = {}  # const A = B 这种别名

    def __len__(self) -> int:
        return len(self.map)

    def build(self, src: str) -> "ConstTable":
        for m in CONST_RE.finditer(src):
            val = _lit_body(m)
            if val:
                self.map.setdefault(m.group(1), val)
        for m in ASSIGN_RE.finditer(src):
            val = _lit_body(m)
            if val and "/" in val and len(val) <= 300:
                self.map.setdefault(m.group(1), val)
        # const A = B;  —— 别名链，让 ``const URL = API_BASE`` 也能解析
        for m in IDENT_ALIAS_RE.finditer(src):
            name, other = m.group(1), m.group(2)
            if name != other:
                self.alias.setdefault(name, other)
        return self

    def merge(self, other: "ConstTable") -> None:
        for k, v in other.map.items():
            self.map.setdefault(k, v)
        for k, v in other.alias.items():
            self.alias.setdefault(k, v)

    def resolve(self, expr: str, depth: int = 0) -> str | None:
        """把 ``BASE_API`` / ``this.baseUrl`` 解析成字面量，解析不到返回 None。"""
        if depth >= MAX_RESOLVE_DEPTH:
            return None
        expr = expr.strip()
        if not _IDENT_RE.fullmatch(expr):
            return None
        for cand in (expr, expr.split(".")[-1]):
            v = self.map.get(cand)
            if v is not None:
                if _IDENT_RE.fullmatch(v):  # const A = B 这种再套一层
                    inner = self.resolve(v, depth + 1)
                    return inner if inner is not None else v
                return v
            alias = self.alias.get(cand)
            if alias is not None:
                return self.resolve(alias, depth + 1)
        return None


# --------------------------------------------------------------------------
# 模板串 / 转义
# --------------------------------------------------------------------------

TEMPLATE_RE = re.compile(r"\$\{\s*([^}]{0,120}?)\s*\}")


def template_to_path(body: str, consts: ConstTable | None = None) -> str:
    """把模板串内容转成路径形式：``/user/${id}`` → ``/user/{id}``。"""

    def repl(m: re.Match) -> str:
        expr = m.group(1).strip()
        if consts is not None:
            v = consts.resolve(expr)
            if v is not None:
                return v
        short = _IDENT_RE.match(expr)
        name = short.group(0).split(".")[-1] if short else "param"
        return "{" + (name or "param") + "}"

    return TEMPLATE_RE.sub(repl, body)


def unescape(s: str) -> str:
    """去掉 JS 字符串里多余的转义斜杠。"""
    if "\\" not in s:
        return s
    s = s.replace("\\/", "/")
    s = re.sub(r"\\u002[fF]", "/", s)
    s = re.sub(r"\\([\\'\"`])", r"\1", s)
    return s


# --------------------------------------------------------------------------
# 拼接链折叠
# --------------------------------------------------------------------------


def _skip_ws_back(s: str, i: int) -> int:
    while i > 0 and s[i - 1] in " \t\r\n":
        i -= 1
    return i


def _skip_ws_fwd(s: str, i: int) -> int:
    n = len(s)
    while i < n and s[i] in " \t\r\n":
        i += 1
    return i


_IDENT_START_RE = re.compile(r"[A-Za-z_$]")
_IDENT_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$."
)


def _operand_back(s: str, i: int):
    """
    从位置 i 往前读一个操作数。返回 (start, end, kind, text) 或 None。

    只认字符串和标识符/成员表达式，遇到括号等复杂结构就放弃 ——
    宁可少折叠，也不要猜错。

    注意：这里全程用下标扫描，**不要** 写 ``s[:j]`` 之类的切片 ——
    在几 MB 的 bundle 上那是 O(n²)，实测能把单文件分析拖到 20 秒以上。
    """
    j = _skip_ws_back(s, i)
    if j <= 0:
        return None
    ch = s[j - 1]
    if ch in "'\"`":
        k = j - 2
        while k >= 0:
            if s[k] == "\\":
                k -= 2
                continue
            if s[k] == ch:
                return k, j, ("tpl" if ch == "`" else "str"), s[k + 1 : j - 1]
            k -= 1
        return None

    k = j
    while k > 0 and s[k - 1] in _IDENT_CHARS:
        k -= 1
    if k == j:
        return None
    text = s[k:j]
    if text.endswith("."):
        text = text[:-1]
        j -= 1
    if not text or not _IDENT_START_RE.match(text[0]):
        return None
    return k, j, "ident", text


def _operand_fwd(s: str, i: int):
    """从位置 i 往后读一个操作数。返回 (start, end, kind, text) 或 None。"""
    n = len(s)
    j = _skip_ws_fwd(s, i)
    if j >= n:
        return None
    ch = s[j]
    if ch in "'\"`":
        k = j + 1
        while k < n:
            if s[k] == "\\":
                k += 2
                continue
            if s[k] == ch:
                return j, k + 1, ("tpl" if ch == "`" else "str"), s[j + 1 : k]
            k += 1
        return None
    m = _IDENT_RE.match(s, j)  # 用 pos 参数匹配，避免切片复制大字符串
    if m:
        end = m.end()
        k = _skip_ws_fwd(s, end)
        # 后面跟着 ( 或 [ 说明是函数调用 / 取下标，不是简单值
        if k < n and s[k] in "([":
            return None
        return j, end, "ident", m.group(0)
    return None


class Collapsed:
    """一次折叠的结果。"""

    __slots__ = ("text", "start", "end", "chain_start", "literals",
                 "prefix_var", "has_expr")

    def __init__(self, text, start, end, chain_start, literals, prefix_var, has_expr):
        self.text = text
        self.start = start            # 最左字符串字面量的起点
        self.end = end                # 最右字符串字面量的终点
        self.chain_start = chain_start  # 整条拼接表达式的起点（含前置变量）
        self.literals = literals      # 被本次折叠吃掉的字符串区间 [(s,e), ...]
        self.prefix_var = prefix_var  # 开头那个解析不出值的变量名（可能是运行时 baseURL）
        self.has_expr = has_expr      # 路径里是否含 {占位符}

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Collapsed {self.text!r}>"


def collapse(src: str, lit, consts: ConstTable) -> Collapsed:
    """
    以 ``lit`` 为中心，向两侧把 ``+`` 拼接链折叠成一个字符串。

    解析不出值的标识符会变成 ``{变量名}`` 占位符；位于链首、解析不出值的
    标识符会被丢弃并记入 ``prefix_var``（它通常是运行时的 baseURL）。
    """
    center_kind = "tpl" if lit.quote == "`" else "str"
    ops: list[tuple[str, str]] = [(center_kind, lit.body)]
    literals: list[tuple[int, int]] = [(lit.start, lit.end)]
    has_expr = False

    # ---- 向后回溯 ----
    cursor = lit.start
    ident_used = 0
    for _ in range(MAX_OPS):
        j = _skip_ws_back(src, cursor)
        if j <= 0 or src[j - 1] != "+" or src[j - 2 : j] == "++":
            break
        op = _operand_back(src, j - 1)
        if op is None:
            break
        start, end, kind, text = op
        # 排除 `++` / `+=` 误判
        if start > 0 and src[start - 1] in "+-*/%=!<>":
            break
        if kind == "ident":
            ident_used += 1
            if ident_used > 1:  # 只允许一个前置变量，通常是 baseURL
                break
        elif kind == "str":
            literals.append((start, end))
        ops.insert(0, (kind, text))
        cursor = start

    chain_start = cursor

    # ---- 向前展开 ----
    cursor = lit.end
    for _ in range(MAX_OPS):
        j = _skip_ws_fwd(src, cursor)
        if j >= len(src) or src[j] != "+" or src[j : j + 2] == "++":
            break
        op = _operand_fwd(src, j + 1)
        if op is None:
            break
        start, end, kind, text = op
        if kind == "str":
            literals.append((start, end))
        ops.append((kind, text))
        cursor = end

    # ---- 组装 ----
    prefix_var = None
    parts: list[str] = []
    for idx, (kind, text) in enumerate(ops):
        if kind in ("str", "tpl"):
            body = template_to_path(text, consts) if kind == "tpl" else text
            if "{" in body:
                has_expr = True
            parts.append(unescape(body))
            continue
        resolved = consts.resolve(text)
        if resolved is not None:
            parts.append(unescape(resolved))
            continue
        if idx == 0:
            prefix_var = text.split(".")[-1]
            continue
        has_expr = True
        parts.append("{" + text.split(".")[-1] + "}")

    return Collapsed(
        "".join(parts),
        min(s for s, _ in literals),
        max(e for _, e in literals),
        chain_start,
        literals,
        prefix_var,
        has_expr,
    )
