"""Canonical text for description rules: the same instruction should match however it is typed.

Rules match on ``canonical(line)``; evidence and line numbers still come from the raw text, and the hidden-payload
check keeps looking at the raw characters (so the obfuscation itself is still reported).

* NFKC folds full-width and mathematical letters ("ｉｇｎｏｒｅ", "𝐢𝐠𝐧𝐨𝐫𝐞").
* Unicode tag characters (U+E0020-U+E007E) are decoded to the ASCII they mirror. They render as nothing, but a
  model still reads them, so "ASCII smuggling" hides a whole instruction in them; dropping them would erase the
  payload before the rules could see it.
* Other invisible format characters (category Cf: zero-width spaces/joiners, bidi controls) are dropped.
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
# U+E0020-U+E007E mirror printable ASCII 0x20-0x7E one-to-one.
_TAG_DECODE = {cp: cp - 0xE0000 for cp in range(0xE0020, 0xE007F)}
_SPACED = re.compile(r"\b(?:[a-z] ){2,}[a-z]\b")
_LATIN = re.compile(r"[A-Za-z]")
_WORD = re.compile(r"\w+")
# Bolt performance optimization: Pre-compile whitespace collapse regex at module scope.
_WHITESPACE_RUN_RE = re.compile(r"\s+")


def canonical(text: str) -> str:
    # Bolt performance optimization: Fast path for ASCII text.
    # ASCII text is invariant under NFKC normalization, contains no Category 'Cf'
    # characters (invisible format characters), and contains no confusable substitutions.
    # Checking text.isascii() avoids Unicode normalization, character-by-character filtering,
    # and confusable translation table scans for standard tool descriptions (~2.7x speedup).
    if text.isascii():
        s = text.lower()
    else:
        s = unicodedata.normalize("NFKC", text.translate(_TAG_DECODE))
        s = "".join(ch for ch in s if unicodedata.category(ch) != "Cf")
        s = s.translate(_CONFUSABLES).lower()
    if " " in s:
        s = _SPACED.sub(lambda m: m.group(0).replace(" ", ""), s)
    return _WHITESPACE_RUN_RE.sub(" ", s).strip()


def mixed_script_words(text: str) -> list[str]:
    """Words that mix Latin letters with look-alikes from another script (UTS #39 mixed-script confusable).

    Words shorter than 4 characters are ignored: maths notation such as "Fβ" or "τⁱ" mixes scripts legitimately,
    while disguised words ("аssistant", "pаssword") are longer.
    """
    # Bolt performance optimization: ASCII text cannot contain mixed-script confusables
    # because all confusables in _CONFUSABLES are non-ASCII characters.
    if text.isascii():
        return []
    s = unicodedata.normalize("NFKC", text)
    return [w for w in _WORD.findall(s) if len(w) >= 4 and _LATIN.search(w) and w.translate(_CONFUSABLES) != w]


# Characters that render as nothing (or reorder what is shown) while a model still reads them: zero-width
# spaces/joiners, invisible maths operators, bidi embedding/override/isolate controls ("Trojan Source"), the BOM,
# and the Unicode tag block used for ASCII smuggling.
_HIDDEN_SINGLE = frozenset(
    "\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff"
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
_CANCEL_TAG = "\U000e007f"
_BLACK_FLAG = "\U0001f3f4"


def _is_emoji(ch: str) -> bool:
    o = ord(ch)
    return 0x1F300 <= o <= 0x1FAFF or 0x2600 <= o <= 0x27BF or 0x2B00 <= o <= 0x2BFF or o in (0xFE0F, 0x2764)


def _is_tag(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def hidden_characters(text: str) -> list[str]:
    """Invisible characters in ``text`` that can hide or disguise content from a human reviewer.

    Two legitimate emoji constructions are not reported: a zero-width joiner between two emoji ("👩\u200d💻") and the
    tag sequence of a subdivision flag ("🏴" + tag letters + CANCEL TAG, e.g. the flag of Scotland).
    """
    if text.isascii():
        return []
    found: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if _is_tag(ch):
            j = i
            while j < n and _is_tag(text[j]):
                j += 1
            run = text[i:j]
            flag = i > 0 and text[i - 1] == _BLACK_FLAG and run.endswith(_CANCEL_TAG) and len(run) >= 2
            if not flag:
                found.extend(run)
            i = j
            continue
        if ch in _HIDDEN_SINGLE:
            emoji_zwj = ch == "\u200d" and 0 < i < n - 1 and _is_emoji(text[i - 1]) and _is_emoji(text[i + 1])
            if not emoji_zwj:
                found.append(ch)
        i += 1
    return found
