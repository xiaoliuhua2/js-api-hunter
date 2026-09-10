"""
轻量级 JS 词法/结构辅助工具。

不依赖任何第三方 JS 解析器：用「字符串扫描 + 括号配对」的方式，
在不做完整 AST 解析的前提下拿到对象字面量的键、调用参数窗口等信息。

这样做的好处是速度快（几 MB 的 bundle 也能秒级处理）、对压缩代码鲁棒，
坏处是精度不如真正的 AST —— 因此所有结果都带置信度评分。
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------
# 字符串字面量扫描
# --------------------------------------------------------------------------

# 依次匹配 '...' / "..." / `...`，模板串允许跨行
STRING_RE = re.compile(
    r"'(?:\\.|[^'\\\n])*'"
    r'|"(?:\\.|[^"\\\n])*"'
    r"|`(?:\\.|[^`\\])*`",
    re.S,
)

IDENT_RE = re.compile(r"^[A-Za-z_$][\w$]*$")


class StrLit:
    """一个字符串字面量出现的位置与内容。"""

    __slots__ = ("raw", "quote", "body", "start", "end")

    def __init__(self, raw: str, start: int, end: int):
        self.raw = raw
        self.quote = raw[0]
        self.body = raw[1:-1]
        self.start = start
        self.end = end

    def __repr__(self) -> str:  # pragma: no cover
        return f"<StrLit {self.body[:40]!r}@{self.start}>"


def iter_strings(code: str):
    """按源码顺序产出所有字符串字面量。"""
    for m in STRING_RE.finditer(code):
        yield StrLit(m.group(0), m.start(), m.end())


# --------------------------------------------------------------------------
# 括号配对
# --------------------------------------------------------------------------

_OPEN2CLOSE = {"(": ")", "[": "]", "{": "}"}


def match_bracket(text: str, start: int, max_scan: int = 120_000) -> int:
    """
    从 ``text[start]`` 处的左括号开始向后找到配对的右括号，返回其下标。

    找不到返回 -1。会正确跳过字符串与转义字符。

    ``max_scan`` 限制最远扫描距离：压缩代码里整个模块可能被包在一个巨大的
    对象/函数里，不设上限的话每个字面量都可能扫完整个文件（O(n²)）。
    超过上限就直接放弃，让调用方退回保守窗口。
    """
    open_ch = text[start]
    close_ch = _OPEN2CLOSE.get(open_ch)
    if close_ch is None:
        return -1

    depth = 0
    i = start
    n = min(len(text), start + max_scan)
    quote = None
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
            i += 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def line_of(code: str, index: int) -> int:
    """返回 index 所在的 1-based 行号。"""
    return code.count("\n", 0, index) + 1


def enclosing_scope(code: str, idx: int, max_back: int = 1200) -> tuple[int, int] | None:
    """
    找出包含 ``code[idx]`` 的最内层括号区间，返回 (start, end)。

    用于把「参数解析窗口」限制在同一次调用内部 —— 否则相邻调用的
    参数对象会互相污染。找不到时返回 ``None``（由调用方决定兜底策略，
    不要在这里返回假区间，否则调用方无法区分）。

    ``max_back`` 不宜太大：这个函数会被每个字面量调用一次，往左多扫
    一格就是 O(n²) 的风险。语句边界（深度为 0 时的 ``;``）可以直接收工。
    """
    depth = 0
    i = idx - 1
    limit = max(0, idx - max_back)
    while i >= limit:
        ch = code[i]
        if ch == ";":
            if depth == 0:
                return None
        elif ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                end = match_bracket(code, i)
                if end > idx:
                    return i, end
                return None
            depth -= 1
        i -= 1
    return None


def depth_map(text: str) -> list[int]:
    """返回与 text 等长的深度数组（下标 i 处所在括号嵌套深度）。"""
    out = [0] * (len(text) + 1)
    depth = 0
    quote = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                out[i] = depth
                i += 1
                if i < n:
                    out[i] = depth
                i += 1
                continue
            if ch == quote:
                quote = None
            out[i] = depth
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in "([{":
            out[i] = depth
            depth += 1
            i += 1
            continue
        elif ch in ")]}":
            depth = max(0, depth - 1)
        out[i] = depth
        i += 1
    out[n] = depth
    return out


# --------------------------------------------------------------------------
# 顶层切分 & 对象字面量解析
# --------------------------------------------------------------------------


def split_top_level(text: str, sep: str = ",") -> list[str]:
    """在括号深度 0 处按 sep 切分，忽略字符串内部的 sep。"""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    n = len(text)
    quote = None
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\":
                if i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        parts.append("".join(buf))
    return [p for p in parts if p.strip()]


def find_object_literals(text: str, limit: int = 8, max_body: int = 6000):
    """
    返回文本中出现的对象字面量，元素为 (start, body_text)。

    只返回「看起来像对象字面量」的：左花括号后面不能是语句块特征，
    这里用一个宽松启发式 —— 跳过紧跟 ``{`` 的空白后必须像 ``key:`` 或 ``...``
    （或为空对象），否则视为代码块跳过。
    """
    results: list[tuple[int, str]] = []
    i = 0
    n = len(text)
    while i < n and len(results) < limit:
        if text[i] != "{":
            i += 1
            continue
        if i > 0 and text[i - 1] == "$":
            i += 1  # ${...} 模板插值，不是对象字面量
            continue
        end = match_bracket(text, i)
        if end < 0:
            break
        body = text[i + 1 : end]
        if len(body) <= max_body and _looks_like_object(body):
            results.append((i, body))
        i = end + 1
    return results


_OBJECT_KEY_RE = re.compile(
    r"""^\s*(?:\.\.\.)?(?:([A-Za-z_$][\w$]*)|['"]([^'"]{1,80})['"])\s*:"""
)
_SHORTHAND_RE = re.compile(r"^[A-Za-z_$][\w$]*$")


def looks_like_object(body: str) -> bool:
    """判断一段花括号内部文本更像对象字面量还是语句块。"""
    return _looks_like_object(body)


def _looks_like_object(body: str) -> bool:
    b = body.strip()
    if not b:
        return True  # 空对象
    if b.startswith("..."):
        return True
    first = split_top_level(b, ",")[0] if b else ""
    return bool(_OBJECT_KEY_RE.match(first) or _SHORTHAND_RE.match(first.strip()))


def object_keys(body: str, max_keys: int = 60) -> list[tuple[str, str]]:
    """
    解析对象字面量的顶层键，返回 [(键名, 值的片段)]。

    支持 ``{a: 1, "b-c": x, d}`` 这类写法；``...spread`` 会被跳过。
    """
    out: list[tuple[str, str]] = []
    for part in split_top_level(body, ","):
        part = part.strip()
        if not part or part.startswith("..."):
            continue
        m = _OBJECT_KEY_RE.match(part)
        if m:
            name = m.group(1) or m.group(2)
            value = part[m.end() :].strip()
            out.append((name, value))
            continue
        if _SHORTHAND_RE.match(part):  # ES6 简写 {a, b}
            out.append((part, part))
        if len(out) >= max_keys:
            break
    return out


def guess_type(value: str) -> str:
    """根据值的字面量形式粗略推断参数类型。"""
    v = value.strip()
    if not v:
        return "unknown"
    if v[0] in "'\"`":
        return "string"
    if re.match(r"^-?\d", v):
        return "number"
    if re.match(r"^(true|false)\b", v):
        return "boolean"
    if v.startswith("["):
        return "array"
    if v.startswith("{"):
        return "object"
    if re.match(r"^null\b", v):
        return "null"
    if IDENT_RE.match(v):
        return "unknown"
    return "expression"
