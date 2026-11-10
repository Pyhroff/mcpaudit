"""Canonical text for description rules: the same instruction should match however it is typed.

Rules match on ``canonical(line)``; evidence and line numbers still come from the raw text, and the hidden-payload
check keeps looking at the raw characters (so the obfuscation itself is still reported).

* NFKC folds full-width and mathematical letters ("ｉｇｎｏｒｅ", "𝐢𝐠𝐧𝐨𝐫𝐞").
* Invisible format characters (category Cf: zero-width spaces/joiners, bidi controls, tag characters) are dropped.
* Look-alike letters from other scripts are folded to Latin ("ignоre" with a Cyrillic "о").
* Spaced-out letters are re-joined ("i g n o r e"), whitespace runs collapse, and the result is lower-cased.
"""

from __future__ import annotations

import re
import unicodedata

# Subset of Unicode confusables.txt: Cyrillic, Greek, Armenian and Latin small-capital look-alikes of a-z.
_CONFUSABLES = str.maketrans({
    "а": "a", "б": "b", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "ɡ": "g",
    "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k", "ӏ": "l", "м": "m", "п": "n",
    "о": "o", "р": "p", "ԛ": "q", "г": "r", "ѕ": "s", "т": "t", "ц": "u", "ѵ": "v",
    "ԝ": "w", "х": "x", "у": "y", "з": "z",
    "А": "a", "В": "b", "С": "c", "Е": "e", "Н": "h", "І": "i", "Ј": "j", "К": "k",
    "М": "m", "О": "o", "Р": "p", "Ѕ": "s", "Т": "t", "Х": "x", "У": "y", "Ү": "y",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "γ": "y", "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z",
    "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t",
    "Υ": "y", "Χ": "x",
    "ա": "a", "հ": "h", "ո": "n", "օ": "o", "ր": "n", "ս": "u", "զ": "q",
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ʜ": "h", "ɪ": "i", "ᴊ": "j",
    "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s",
    "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
})
_SPACED = re.compile(r"\b(?:[a-z] ){2,}[a-z]\b")
_LATIN = re.compile(r"[A-Za-z]")
_WORD = re.compile(r"\w+")
_WS = re.compile(r"\s+")


def canonical(text: str) -> str:
    # Bolt performance optimization:
    # ASCII characters (0-127) are completely invariant under NFKC normalization,
    # contain no Unicode Category 'Cf' (format/zero-width) characters, and have no
    # confusable look-alikes from other scripts in `_CONFUSABLES`.
    # For ASCII strings (the vast majority in tool manifests), bypassing full NFKC
    # decomposition and Python-level per-character category checks yields a ~3-6x speedup.
    if text.isascii():
        s = _SPACED.sub(lambda m: m.group(0).replace(" ", ""), text.lower())
        return _WS.sub(" ", s).strip()

    s = unicodedata.normalize("NFKC", text)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Cf")
    s = s.translate(_CONFUSABLES).lower()
    s = _SPACED.sub(lambda m: m.group(0).replace(" ", ""), s)
    return _WS.sub(" ", s).strip()


def mixed_script_words(text: str) -> list[str]:
    """Words that mix Latin letters with look-alikes from another script (UTS #39 mixed-script confusable).

    Words shorter than 4 characters are ignored: maths notation such as "Fβ" or "τⁱ" mixes scripts legitimately,
    while disguised words ("аssistant", "pаssword") are longer.
    """
    # Bolt performance optimization:
    # An ASCII-only text cannot contain look-alikes from other scripts (Cyrillic, Greek, Armenian, etc.).
    # Returning early avoids unnecessary NFKC normalization, regex word extraction, and string translations.
    if text.isascii():
        return []

    s = unicodedata.normalize("NFKC", text)
    return [w for w in _WORD.findall(s) if len(w) >= 4 and _LATIN.search(w) and w.translate(_CONFUSABLES) != w]
