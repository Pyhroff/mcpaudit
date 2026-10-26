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
    # v0.6: widened from a literal "mention the user" -- real-world and
    # adversarially-generated phrasing routinely puts a few words between
    # the verb and "the user" ("mention IT TO the user", "tell the user
    # ABOUT this"). Bounded gap (.{0,20}) keeps this from matching across
    # an entire unrelated sentence.
    (r"\b(do\s+not|don'?t|never)\s+(tell|inform|mention|show|disclose|notify).{0,20}\bthe\s+user\b",
     "instructs the model to hide something from the user"),
    # v0.6: "this tool" was too literal -- a self-poisoning tool typically
    # names ITSELF ("always call the delete_all_files tool first"), not
    # "this tool". Match either phrasing.
    (r"\balways\s+call\s+(this|the)\s+[\w-]*\s*tool\s+first\b", "coerces tool-call ordering"),
    (r"\bbefore\s+using\s+any\s+other\s+tools?\b", "coerces tool-call ordering"),
    # v0.6: "you must" was too literal -- passive/impersonal phrasing
    # ("this tool must be invoked...", "must be called on every request")
    # carries the same coercive weight without ever saying "you".
    (r"\b(you\s+)?must\s+(always|never)\b", "imperative directive aimed at the model"),
    (r"\bmust\s+be\s+(invoked|called|used|run)\b.{0,40}\b(every|each|regardless|all)\b",
     "imperative directive aimed at the model (passive phrasing)"),
    (r"\bregardless\s+of\s+what\s+(was|is)\s+asked\b", "instructs the model to disregard user intent"),
    (r"\bfor\s+every\s+turn\b.{0,60}\b(invoke|call|run)\b.{0,60}\bbefore\s+any\s+other\s+tools?\b",
     "coerces tool-call ordering"),
    (r"\bdisregard\s+(earlier|previous|prior)\s+(guidance|instructions?)\b",
     "instruction-override phrasing"),
    # v0.6: "call this tool silently" style phrasing -- coercive secrecy
    # about the tool CALL itself, distinct from the "hide it from the
    # user" pattern above (that one needs "the user" explicitly present).
    (r"\b(call|invoke|run|use)\b.{0,25}\bsilently\b|\bsilently\b.{0,25}\b(call|invoke|run|use)\b",
     "instructs the model to act without visible acknowledgment"),
    (r"\bthis\s+is\s+(a\s+)?(system|admin|override)\s+(message|instruction)\b", "claims elevated authority"),
    (r"<\s*(system|instructions?|important)\s*>", "embedded fake system/instruction tag"),
    (r"\bsend\s+(the\s+)?(contents?|results?|data|output)\s+to\s+https?://", "exfiltration-shaped instruction"),
    (r"\bdisregard\s+(the\s+)?(system\s+prompt|user'?s?\s+request)\b", "instruction-override phrasing"),
    (r"\b(bypass|disable|override|turn\s+off)\s+(all\s+)?(safety|guardrails?|filters?|rules?|policies)\b", "safety-bypass directive"),
    (r"\b(act|operate|behave)\s+in\s+developer\s+mode\b", "jailbreak-style role directive"),
    (r"\b(do\s+not|never)\s+(log|audit|record|trace)\s+(this|the)\s+call\b", "instructs the model to evade logging/audit"),
]

# Pre-compile regexes at module load time for performance
_COMPILED_IMPERATIVE_PATTERNS = [
    (re.compile(pattern), label) for pattern, label in _IMPERATIVE_PATTERNS
]

_MUST_NEVER_RE = re.compile(r"\bmust\s+never\b")
_IGNORE_DISREGARD_BYPASS_RE = re.compile(r"\b(ignore|disregard|bypass)\b")
_ORDERING_RE = re.compile(r"\b(first|before|after|prior|prerequisite|then|only after)\b")

_MAX_REASONABLE_DESC_LEN = 800  # beyond this, treat length itself as suspicious
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")


def scan_descriptions(manifest: ServerManifest) -> list[Finding]:
    findings: list[Finding] = []

    known_tool_names = {t.name for t in manifest.tools if t.name}

    for tool in manifest.tools:
        text = tool.description or ""
        lower = text.lower()

        defensive_prohibition = (
            _MUST_NEVER_RE.search(lower)
            and any(term in lower for term in ("system instructions", "secrets", "security", "safety"))
            and not _IGNORE_DISREGARD_BYPASS_RE.search(lower)
        )

        # Performance boost: pre-compiled regex patterns
        for compiled_pattern, label in _COMPILED_IMPERATIVE_PATTERNS:
            if compiled_pattern.search(lower):
                if defensive_prohibition and "imperative directive" in label:
                    continue
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
        # name alongside coercive language -- a classic way one tool hijacks
        # how a completely different tool gets used. Deliberately narrow to
        # "must"/"always" (coercion), not "instead"/"never" alone -- those
        # also show up in ordinary, benign deprecation notices ("DEPRECATED:
        # use X instead"), which is not the pattern this check is for. Caught
        # via a real scan of the official MCP filesystem server, which uses
        # exactly that phrasing legitimately.
        # Performance optimization: fast string checks before performing regex searches across all tool combinations.
        if "must" in lower or "always" in lower:
            for other in known_tool_names:
                if (
                    other != tool.name
                    and other in lower
                    and re.search(
                        rf"\b{re.escape(other)}\b.{{0,40}}\b(must|always)\b|\b(must|always)\b.{{0,40}}\b{re.escape(other)}\b",
                        lower,
                    )
                ):
                    # v0.7: "you must first call X" / "call X before ..." is ordinary prerequisite guidance (seen
                    # across AWS, Unity and status-page servers in a 90-repo scan) -> LOW; other coercion stays MEDIUM.
                    ordering = _ORDERING_RE.search(lower)
                    findings.append(Finding(
                        check="description_scan", tool=tool.name, severity=Severity.LOW if ordering else Severity.MEDIUM,
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
