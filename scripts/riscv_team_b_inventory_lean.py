"""Lean surface parser and evidence records for Team B inventory."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

OPEN_BRACKETS = "([{⟨⦃"
CLOSE_BRACKETS = ")]}⟩⦄"

DECLARATION = re.compile(
    r"^(?:@\[[^\]]*\]\s*)?"
    r"(?:(?:private|protected|noncomputable|partial)\s+)*"
    r"(?P<kind>theorem|lemma|def|abbrev|structure|instance)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.']*)",
    re.MULTILINE,
)

NAMESPACE_LINE = re.compile(r"^namespace\s+([A-Za-z0-9_.']+)\s*$", re.MULTILINE)
END_LINE = re.compile(r"^end\s+([A-Za-z0-9_.']+)\s*$", re.MULTILINE)

CONTROL_TYPE = re.compile(
    r"\bMutationControl\s+([A-Za-z0-9_.']+)\s+([A-Za-z0-9_.']+)\s+where\b"
)
CONTROL_NAME_FIELD = re.compile(r"\bname\s*:=\s*\"([^\"]*)\"")

STRICTLY_WEAKER = re.compile(
    r"([A-Za-z0-9_.']+)\.strictly_weaker\s+([A-Za-z0-9_.']+)\s+([A-Za-z0-9_.']+)"
)
FALLBACK_DEVICE = re.compile(r"\bstrictly_weaker_of_not_original\b")

SELECTOR_GUARD = re.compile(r"row\.(is[A-Z][A-Za-z0-9]*)\s*=\s*true")
SHIFT_KIND_GUARD = re.compile(
    r"row\.(?:semantic\.)?kind\s*=\s*ShiftKind\.([a-z]+)"
)
SELECTOR_ENUM_GUARD = re.compile(
    r"row\.selector\s*=\s*[A-Za-z0-9_]*Selector\.([a-z0-9]+)"
)

MANIFEST_ENTRY = re.compile(
    r"proof\(\.[^,]+,\s*\"([^\"]+)\",\s*\.([a-z_0-9]+)"
)


# ---------------------------------------------------------------------------
# Lean surface parsing


def strip_comments(text: str) -> str:
    """Blank out ``--`` line comments and nested ``/- -/`` block comments.

    Length and line structure are preserved (comment characters become
    spaces), so every downstream offset still maps to the original file.
    String literals are honoured: comment markers inside them are kept.
    """

    out = list(text)
    i = 0
    n = len(text)
    depth = 0
    in_string = False
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if depth > 0:
            if ch == "/" and nxt == "-":
                depth += 1
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if ch == "-" and nxt == "/":
                depth -= 1
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if ch != "\n":
                out[i] = " "
            i += 1
            continue
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == "/" and nxt == "-":
            depth = 1
            out[i] = out[i + 1] = " "
            i += 2
            continue
        if ch == "-" and nxt == "-":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _scan_top_level(text: str) -> tuple[int, int]:
    """Return (index of first top-level ``:``, index of statement end).

    The statement end is the first top-level ``:=`` or ``where`` keyword;
    either index is ``len(text)`` when absent. Bracket depth covers ASCII and
    the Lean anonymous-constructor brackets; string literals are skipped.
    """

    depth = 0
    in_string = False
    colon = -1
    end = len(text)
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch in OPEN_BRACKETS:
            depth += 1
            i += 1
            continue
        if ch in CLOSE_BRACKETS:
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0:
            if ch == ":" and i + 1 < n and text[i + 1] == "=":
                end = i
                break
            if ch == ":" and colon < 0:
                colon = i
                i += 1
                continue
            if ch == "w" and text[i : i + 5] == "where":
                before = text[i - 1] if i > 0 else " "
                after = text[i + 5] if i + 5 < n else " "
                if not (before.isalnum() or before in "_'") and not (
                    after.isalnum() or after in "_'"
                ):
                    end = i
                    break
        i += 1
    if colon < 0 or colon > end:
        colon = end
    return colon, end


def _binder_groups(text: str) -> list[str]:
    """Explicit ``( ... )`` binder groups at top level, in order."""

    groups: list[str] = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch in OPEN_BRACKETS:
            if depth == 0 and ch == "(":
                start = i
            depth += 1
        elif ch in CLOSE_BRACKETS:
            depth -= 1
            if depth == 0 and start >= 0 and ch == ")":
                groups.append(text[start + 1 : i].strip())
                start = -1
    return groups


def _binder_name(group: str) -> str:
    head = group.split(":", 1)[0].strip()
    return head.split()[0] if head.split() else ""


@dataclass
class Declaration:
    kind: str
    name: str
    qualified: str
    file: str
    line: int
    binders: list[str]
    goal: str
    body: str


@dataclass
class ConclusionInfo:
    name: str
    file: str
    line: int
    row_type: str
    guards: list[str]
    opcodes: list[str]
    guarded: bool
    unknown_guards: list[str]


@dataclass
class LoadBearingInfo:
    name: str
    qualified: str
    file: str
    line: int
    classification: str  # "unconditional" | "conditional"
    hypotheses: list[str]
    control_ref: str | None
    original: str | None
    sound_term: str | None
    derived_from: str | None


@dataclass
class ControlInfo:
    definition: str
    qualified: str
    control_name: str
    weakened: str
    conclusion: str
    file: str
    line: int
    row_type: str = ""
    guards: list[str] = field(default_factory=list)
    certifies: list[str] = field(default_factory=list)
    guarded: bool = False
    unknown_guards: list[str] = field(default_factory=list)
    corollaries: list[LoadBearingInfo] = field(default_factory=list)
    derived_corollaries: list[LoadBearingInfo] = field(default_factory=list)
    status: str = "no-corollary"
    original: str | None = None
    soundness_in_file: bool = False
    soundness_theorems: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "definition": self.definition,
            "qualified": self.qualified,
            "control_name": self.control_name,
            "weakened": self.weakened,
            "conclusion": self.conclusion,
            "file": self.file,
            "line": self.line,
            "row_type": self.row_type,
            "guards": self.guards,
            "certifies": self.certifies,
            "guarded": self.guarded,
            "unknown_guards": self.unknown_guards,
            "status": self.status,
            "original": self.original,
            "soundness_in_file": self.soundness_in_file,
            "soundness_theorems": self.soundness_theorems,
            "corollaries": [
                {
                    "name": c.name,
                    "qualified": c.qualified,
                    "file": c.file,
                    "line": c.line,
                    "classification": c.classification,
                    "hypotheses": c.hypotheses,
                    "original": c.original,
                    "sound_term": c.sound_term,
                }
                for c in self.corollaries
            ],
            "derived_corollaries": [
                {
                    "name": c.name,
                    "file": c.file,
                    "line": c.line,
                    "classification": c.classification,
                    "derived_from": c.derived_from,
                }
                for c in self.derived_corollaries
            ],
            "flags": self.flags,
        }


def parse_declarations(path: Path, root: Path) -> list[Declaration]:
    raw = path.read_text(encoding="utf-8")
    text = strip_comments(raw)
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)

    # Namespace context per character offset, so each declaration can be
    # reported under its certificate-index qualified name.
    events: list[tuple[int, str, str]] = []
    for match in NAMESPACE_LINE.finditer(text):
        events.append((match.start(), "push", match.group(1)))
    for match in END_LINE.finditer(text):
        events.append((match.start(), "pop", match.group(1)))
    events.sort()

    matches = list(DECLARATION.finditer(text))
    declarations: list[Declaration] = []
    for index, match in enumerate(matches):
        start = match.end()
        stop = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[start:stop]
        # A namespace/end line inside the block belongs to the next context;
        # truncate the block there so bodies do not swallow file structure.
        for offset, _, _ in events:
            if start < offset < stop:
                block = text[start:offset]
                break
        stack: list[str] = []
        for offset, action, namespace in events:
            if offset > match.start():
                break
            if action == "push":
                stack.append(namespace)
            elif stack and stack[-1] == namespace:
                stack.pop()
        colon, end = _scan_top_level(block)
        declarations.append(
            Declaration(
                kind=match.group("kind"),
                name=match.group("name"),
                qualified=".".join([*stack, match.group("name")]),
                file=rel,
                line=text.count("\n", 0, match.start()) + 1,
                binders=_binder_groups(block[:colon]),
                goal=block[colon + 1 : end].strip() if colon < end else "",
                body=block[end:],
            )
        )
    return declarations
