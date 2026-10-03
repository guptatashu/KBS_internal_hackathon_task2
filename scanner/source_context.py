"""Everything a rule needs to know about one file."""
import re
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any, Callable

from preprocessor.comment_stripper import strip_comments
from preprocessor.text_sanitizer import LINE_SPLIT, escape_unicode, defang_chat_tokens
from .function_parser import extract_functions

MAX_SNIPPET_CHARS = 200
_NEWLINE_RE = re.compile(r"\r\n|\r|\n")


def _build_line_starts(text):
    starts = [0]
    for m in _NEWLINE_RE.finditer(text):
        starts.append(m.end())
    return starts


def _sanitize_snippet(line):
    """Evidence snippets are excerpts of UNTRUSTED source: sanitize before they go anywhere."""
    s = escape_unicode(defang_chat_tokens(line))
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > MAX_SNIPPET_CHARS:
        s = s[:MAX_SNIPPET_CHARS] + " ..."
    return s


@dataclass
class FileContext:
    path: str
    is_dependency: bool
    meta: dict
    code: str               # comments removed AND string contents masked -> what rules match against
    masked_lines: list      # same, split by line
    functions: list
    line_of: Callable[[int], int]       # character offset in `code` -> original 1-based line number
    visible_lines: list = field(repr=False, default_factory=list)

    def function_at(self, line):
        """The function containing this line, or None."""
        for f in self.functions:
            if f.line <= line <= f.end_line:
                return f
        return None

    def snippet(self, line):
        """Sanitized text of this line with comments removed (strings intact) -> evidence."""
        idx = line - 1
        raw = self.visible_lines[idx] if 0 <= idx < len(self.visible_lines) else ""
        return _sanitize_snippet(raw)


def build_file_context(file, *, is_dependency=False, meta=None):
    text = file["content"]
    if text.startswith("\ufeff"):
        text = text[1:]
    code = strip_comments(text, mask_strings=True)
    visible = strip_comments(text)
    starts = _build_line_starts(code)
    line_of = lambda offset: bisect_right(starts, offset)   # 1-based, original file's line

    return FileContext(
        path=file["path"],
        is_dependency=is_dependency,
        meta=meta or {},
        code=code,
        masked_lines=LINE_SPLIT.split(code),
        functions=extract_functions(code, line_of),
        line_of=line_of,
        visible_lines=LINE_SPLIT.split(visible),
    )
