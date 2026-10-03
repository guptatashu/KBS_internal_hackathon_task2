"""
Component 3 (minimal): Component 2 output -> payload the scanner and the AI step accept.

It keeps the original files, the proxy flag, and a per-file isDependency flag (a path-based guess at
"library code"). Comment stripping and string masking happen later, inside the scanner and the AI source view.
"""
import re

# Rough guess at "library code" from the file path.
_DEPENDENCY_RE = re.compile(r"^@|node_modules/|^lib/|openzeppelin|solmate|solady", re.I)


def _fail(code, message):
    return {"ok": False, "error": {"code": code, "message": message}}


def preprocess_source(source):
    """Accepts Component 2's full result ({"ok", "data"}) or just its data dict."""
    try:
        if isinstance(source, dict) and "ok" in source:
            if not source["ok"]:
                return _fail("INVALID_INPUT", "Component 2 reported an error; nothing to preprocess.")
            source = source.get("data")
        files = source.get("files") if isinstance(source, dict) else None
        if not isinstance(files, list) or not files:
            return _fail("INVALID_INPUT", "Expected contract data containing a non-empty 'files' list.")

        clean = [
            {"path": f["path"], "content": f["content"]}
            for f in files
            if isinstance(f, dict) and isinstance(f.get("path"), str) and isinstance(f.get("content"), str)
        ]
        if not clean:
            return _fail("INVALID_INPUT", "No usable files (each needs a string 'path' and 'content').")

        return {
            "ok": True,
            "payload": {
                "contract": {
                    "name": source.get("contractName"),
                    "compilerVersion": source.get("compilerVersion"),
                },
                "original": {"files": clean},
                "meta": {
                    "isProxy": bool(source.get("isProxy")),
                    "implementationAddress": source.get("implementationAddress"),
                    "files": [
                        {"path": f["path"], "isDependency": bool(_DEPENDENCY_RE.search(f["path"]))}
                        for f in clean
                    ],
                },
            },
        }
    except Exception as err:
        return _fail("PREPROCESS_ERROR", "Unexpected error while processing the source code.")
