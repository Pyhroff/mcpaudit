"""Static check: scan tool descriptions for prompt-injection / "tool
poisoning" patterns -- text aimed at the calling MODEL rather than at the
human deciding whether to install the tool.

This is the part of MCP's threat model unique to it: a tool's description
is untrusted content that a client hands straight to the LLM as part of its
system context, every single turn, and the user never reads it. A
malicious or compromised server can smuggle instructions there that never
show up in any UI.
"""

from __future__ import annotations

import re

from mcpaudit.findings import Finding, Severity
from mcpaudit.manifest import ServerManifest

# Phrases that target the model's behavior rather than describe the tool.
# Deliberately broad/heuristic -- false positives are expected and fine for
# a scanner whose job is "flag for human review", not "auto-block".
_IMPERATIVE_PATTERNS = [
    (r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b", "instruction-override phrasing"),
    (r"\bdo\s+not\s+(tell|inform|mention|show)\s+the\s+user\b", "instructs the model to hide something from the user"),
    (r"\balways\s+call\s+this\s+tool\s+first\b", "coerces tool-call ordering"),
    (r"\bbefore\s+using\s+any\s+other\s+tools?\b", "coerces tool-call ordering"),
    (r"\byou\s+must\s+(always|never)\b", "imperative directive aimed at the model"),
    (r"\bthis\s+is\s+(a\s+)?(system|admin|override)\s+(message|instruction)\b", "claims elevated authority"),
    (r"<\s*(system|instructions?|important)\s*>", "embedded fake system/instruction tag"),
    (r"\bsend\s+(the\s+)?(contents?|results?|data|output)\s+to\s+https?://", "exfiltration-shaped instruction"),
    (r"\bdisregard\s+(the\s+)?(system\s+prompt|user'?s?\s+request)\b", "instruction-override phrasing"),
]

_MAX_REASONABLE_DESC_LEN = 800  # beyond this, treat length itself as suspicious
_ZERO_WIDTH_RE = re.compile(r"[​‌‍⁠﻿]")


def scan_descriptions(manifest: ServerManifest) -> list[Finding]:
    findings: list[Finding] = []

    known_tool_names = {t.name for t in manifest.tools}

    for tool in manifest.tools:
        text = tool.description or ""
        lower = text.lower()

        for pattern, label in _IMPERATIVE_PATTERNS:
            if re.search(pattern, lower):
                findings.append(Finding(
                    check="description_scan", tool=tool.name, severity=Severity.HIGH,
                    title=f"Model-directed instruction in description ({label})",
                    detail=f"Tool '{tool.name}' description matched a pattern suggesting it is "
                           f"talking to the calling model, not describing the tool to a human "
                           f"({label}): {text[:300]!r}",
                ))

        if _ZERO_WIDTH_RE.search(text):
            findings.append(Finding(
                check="description_scan", tool=tool.name, severity=Severity.HIGH,
                title="Zero-width / invisible characters in description",
                detail=f"Tool '{tool.name}' description contains zero-width Unicode characters, "
                       f"a common way to hide text from a human reviewer while a model still reads it.",
            ))

        if len(text) > _MAX_REASONABLE_DESC_LEN:
            findings.append(Finding(
                check="description_scan", tool=tool.name, severity=Severity.MEDIUM,
                title="Unusually long tool description",
                detail=f"Tool '{tool.name}' description is {len(text)} characters. Legitimate tool "
                       f"descriptions are normally a sentence or two; excessive length is a common way "
                       f"to bury extra instructions past where a reviewer stops reading.",
            ))

        # Cross-tool poisoning: description references another *declared* tool
        # name alongside imperative language -- a classic way one tool
        # hijacks how a completely different tool gets used.
        for other in known_tool_names:
            if other != tool.name and other and re.search(
                rf"\b{re.escape(other)}\b.{{0,40}}\b(must|always|instead|never)\b", lower
            ):
                findings.append(Finding(
                    check="description_scan", tool=tool.name, severity=Severity.MEDIUM,
                    title="Cross-tool instruction",
                    detail=f"Tool '{tool.name}' description references another tool ('{other}') "
                           f"with directive language -- possible cross-tool poisoning.",
                ))

        if not text.strip():
            findings.append(Finding(
                check="description_scan", tool=tool.name, severity=Severity.LOW,
                title="Empty tool description",
                detail=f"Tool '{tool.name}' has no description at all -- can't be reviewed by a human "
                       f"or reasoned about safely by a model.",
            ))

    return findings
