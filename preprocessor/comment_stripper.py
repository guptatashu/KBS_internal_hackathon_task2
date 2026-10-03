"""Remove comments (and optionally mask string contents) from Solidity source.

Everything removed is replaced by spaces and line breaks are kept, so the result has
exactly the same length and line structure as the input. Line numbers and character
offsets therefore match the original file.
"""


def strip_comments(text, *, mask_strings=False):
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if c == "/" and nxt == "/":                      # // line comment
            while i < n and text[i] not in "\r\n":
                out.append(" ")
                i += 1

        elif c == "/" and nxt == "*":                    # /* block comment */
            out.append("  ")
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                out.append(text[i] if text[i] in "\r\n" else " ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2

        elif c in "\"'":                                 # string literal
            quote = c
            out.append(c)
            i += 1
            while i < n and text[i] != quote and text[i] not in "\r\n":
                if text[i] == "\\" and i + 1 < n and text[i + 1] not in "\r\n":
                    out.append("  " if mask_strings else text[i:i + 2])
                    i += 2
                    continue
                out.append(" " if mask_strings else text[i])
                i += 1
            if i < n and text[i] == quote:
                out.append(quote)
                i += 1

        else:
            out.append(c)
            i += 1
    return "".join(out)
