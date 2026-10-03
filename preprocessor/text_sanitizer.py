"""Helpers that make untrusted contract text safe to display."""
import re
import unicodedata

LINE_SPLIT = re.compile(r"\r\n|\r|\n")

_ESCAPE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def escape_unicode(text):
    """Replace invisible / control / bidi characters with visible \\uXXXX text."""
    out = []
    for ch in text:
        if ch == "\t":
            out.append(ch)
        elif unicodedata.category(ch) in _ESCAPE_CATEGORIES or (ch.isspace() and ch != " "):
            cp = ord(ch)
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\u{{{cp:x}}}")
        else:
            out.append(ch)
    return "".join(out)


_CHAT_TOKEN_RE = re.compile(r"<\|[^|>\n]{1,40}\|>|\[/?INST\]|<</?SYS>>|</?s>", re.I)


def defang_chat_tokens(text):
    """Break up special chat-template tokens so they can't act as instructions."""
    return _CHAT_TOKEN_RE.sub(lambda m: m.group(0)[0] + "\u200b" + m.group(0)[1:], text)
