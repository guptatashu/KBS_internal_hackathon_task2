"""
Component 5, step 1: choose and render the source code that will be sent to the LLM.

 - Comments are removed (a classic place to hide text aimed at an AI; also saves tokens). The remover keeps
   line structure, so line numbers match Component 4's evidence.
 - Every line is sanitized (invisible/bidi/control characters made visible, chat-template tokens defanged).
 - Lines are prefixed with their ORIGINAL line number so the model can cite them and we can verify the citations.
 - A deterministic function index (from Component 4's parser) is attached to each file as extra evidence.
 - Project files come first; dependency (library) files only if they still fit. If something does not fit it is
   truncated at a line boundary or omitted, and that is reported so the model never "analyzes" code it did not see.
"""
import re

from preprocessor.comment_stripper import strip_comments
from preprocessor.text_sanitizer import LINE_SPLIT, defang_chat_tokens, escape_unicode
from scanner.source_context import build_file_context

MAX_LINE_CHARS = 400
MIN_PARTIAL_CHARS = 2000        # don't bother sending a file prefix smaller than this
FILE_OVERHEAD_CHARS = 250       # header/footer lines around each file
MAX_FUNCTIONS_PER_FILE = 120
_SPECIAL_RE = re.compile(r"\b(constructor|receive|fallback)\s*\(")


def _render_lines(stripped):
    """-> list of (line_number, '   12 | code') for the non-blank lines."""
    out = []
    for number, line in enumerate(LINE_SPLIT.split(stripped), start=1):
        line = line.rstrip()
        if not line.strip():
            continue
        line = escape_unicode(defang_chat_tokens(line))
        if len(line) > MAX_LINE_CHARS:
            line = line[:MAX_LINE_CHARS] + " ..."
        out.append((number, f"{number:>5} | {line}"))
    return out


def _function_index(file, is_dependency, shown_through):
    try:
        ctx = build_file_context(file, is_dependency=is_dependency)
    except Exception:
        return []
    return [
        {"name": f.name, "line": f.line, "visibility": f.visibility, "mutability": f.mutability,
         "modifiers": list(f.modifiers)[:8]}
        for f in ctx.functions if f.line <= shown_through
    ][:MAX_FUNCTIONS_PER_FILE]


def build_source_view(payload, budget_chars):
    """
    -> {"files": [...], "omitted": [...], "charsSent": int, "functionNames": set}
    Each file: {path, isDependency, lineCount, shownThroughLine, truncated, text, functions, shownLines}
    """
    files = (payload.get("original") or {}).get("files") or []
    dep = {f.get("path"): f.get("isDependency") is True
           for f in ((payload.get("meta") or {}).get("files") or []) if isinstance(f, dict)}
    items = [(dep.get(f["path"], False), i, f) for i, f in enumerate(files)
             if isinstance(f, dict) and isinstance(f.get("path"), str) and isinstance(f.get("content"), str)]
    items.sort(key=lambda t: (t[0], t[1]))          # project code first, original order otherwise

    sent, omitted, used = [], [], 0
    names = set()
    for is_dep, _, f in items:
        stripped = strip_comments(f["content"].lstrip("\ufeff"))
        split = LINE_SPLIT.split(stripped)
        line_count = len(split) - 1 if split and split[-1] == "" else len(split)   # a final newline is not a line
        rendered = _render_lines(stripped)
        total = sum(len(text) + 1 for _, text in rendered)
        remaining = budget_chars - used - FILE_OVERHEAD_CHARS

        if total <= remaining:
            shown, truncated = rendered, False
        elif not is_dep and remaining >= MIN_PARTIAL_CHARS:
            shown, size = [], 0
            for number, text in rendered:
                if size + len(text) + 1 > remaining:
                    break
                shown.append((number, text))
                size += len(text) + 1
            truncated = True
        else:
            omitted.append({"path": f["path"], "isDependency": is_dep,
                            "reason": "did not fit in the size budget"})
            continue

        shown_through = shown[-1][0] if truncated and shown else line_count
        text = "\n".join(t for _, t in shown)
        used += len(text) + FILE_OVERHEAD_CHARS
        functions = _function_index(f, is_dep, shown_through)
        names.update(fn["name"] for fn in functions)
        names.update(_SPECIAL_RE.findall("\n".join(LINE_SPLIT.split(stripped)[:shown_through])))
        sent.append({"path": f["path"], "isDependency": is_dep, "lineCount": line_count,
                     "shownThroughLine": shown_through, "truncated": truncated,
                     "text": text, "functions": functions, "shownLines": {n for n, _ in shown}})

    return {"files": sent, "omitted": omitted, "charsSent": used, "functionNames": names}
