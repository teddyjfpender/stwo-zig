#!/usr/bin/env python3
"""Fail-closed source authority for typed logical-work producer sites.

The checker deliberately recognizes syntax, not text. Zig comments, quoted
strings, character literals, and multiline-string lines are discarded before
calls are inspected. Each registered site must occur exactly once in a planned
``expectProducer(.site)`` call and exactly once in a configured completed-delta
call. This makes deleting both sides, substituting a tag, duplicating a tag, or
inventing an unregistered tag observable before the runtime ledger is sealed.

This is an independent source gate. The Zig ``Site`` enum and runtime
expected/completed arrays remain the execution authority once wired.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence


SCHEMA = "stwo.typed-air.work-site-source-authority.v1"
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class AuthorityError(ValueError):
    """The typed-site authority is malformed or incomplete."""

    def __init__(self, issues: str | Iterable[str]):
        if isinstance(issues, str):
            normalized = (issues,)
        else:
            normalized = tuple(issues)
        if not normalized:
            normalized = ("unknown typed-site authority error",)
        self.issues = normalized
        super().__init__("; ".join(normalized))


class LiteralShape(str, Enum):
    ENUM_ARGUMENT = "enum_argument"
    NAMED_FIELD = "named_field"


@dataclass(frozen=True)
class CallSpec:
    name: str
    shape: LiteralShape
    field: str | None = None
    argument: int | None = None


@dataclass(frozen=True)
class SiteSpec:
    name: str
    plan_paths: tuple[str, ...] = ()
    completion_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthoritySpec:
    sites: tuple[SiteSpec, ...]
    sources: tuple[str, ...]
    plan_calls: tuple[CallSpec, ...] = (
        CallSpec("expectProducer", LiteralShape.ENUM_ARGUMENT, argument=0),
    )
    completion_calls: tuple[CallSpec, ...] = (
        CallSpec("recordCompletedDelta", LiteralShape.NAMED_FIELD, "site"),
    )


@dataclass(frozen=True)
class Occurrence:
    role: str
    site: str
    path: str
    line: int
    column: int
    call: str

    def canonical(self) -> dict[str, object]:
        return {
            "call": self.call,
            "column": self.column,
            "line": self.line,
            "path": self.path,
            "role": self.role,
            "site": self.site,
        }


@dataclass(frozen=True)
class AuthorityReport:
    sites: tuple[str, ...]
    sources: tuple[str, ...]
    occurrences: tuple[Occurrence, ...]

    def canonical(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "registered_site_count": len(self.sites),
            "source_count": len(self.sources),
            "plan_occurrence_count": sum(
                occurrence.role == "plan" for occurrence in self.occurrences
            ),
            "completion_occurrence_count": sum(
                occurrence.role == "completion"
                for occurrence in self.occurrences
            ),
            "sites": list(self.sites),
            "sources": list(self.sources),
            "occurrences": [
                occurrence.canonical() for occurrence in self.occurrences
            ],
        }


@dataclass(frozen=True)
class LoadedAuthority:
    spec: AuthoritySpec
    source_root: Path


@dataclass(frozen=True)
class _Token:
    value: str
    line: int
    column: int


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise AuthorityError(f"{label} must be a bare Zig identifier")
    return value


def _relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise AuthorityError(f"{label} must be a nonempty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise AuthorityError(f"{label} must be a normalized POSIX relative path")
    return value


def _unique(values: Sequence[str], label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise AuthorityError(f"{label} contains duplicates")
    return tuple(values)


def _validate_call_spec(spec: CallSpec, label: str) -> None:
    _identifier(spec.name, f"{label} name")
    if spec.shape is LiteralShape.ENUM_ARGUMENT:
        if spec.field is not None:
            raise AuthorityError(f"{label} enum_argument call cannot name a field")
        if (
            not isinstance(spec.argument, int)
            or isinstance(spec.argument, bool)
            or spec.argument < 0
        ):
            raise AuthorityError(
                f"{label} enum_argument call needs a nonnegative argument index"
            )
        return
    if spec.shape is LiteralShape.NAMED_FIELD:
        _identifier(spec.field, f"{label} field")
        if spec.argument is not None:
            raise AuthorityError(f"{label} named_field call cannot name an argument")
        return
    raise AuthorityError(f"{label} has unsupported literal shape")


def _validate_spec(spec: AuthoritySpec) -> None:
    if not spec.sites:
        raise AuthorityError("authority must register at least one site")
    if not spec.sources:
        raise AuthorityError("authority must register at least one source")
    source_set = set(_unique(spec.sources, "authority sources"))
    names = [_identifier(site.name, "site name") for site in spec.sites]
    _unique(names, "authority sites")
    if names != sorted(names):
        raise AuthorityError("authority sites must be sorted by name")
    for site in spec.sites:
        for role, paths in (
            ("plan", site.plan_paths),
            ("completion", site.completion_paths),
        ):
            _unique(paths, f"site {site.name} {role} paths")
            unknown = set(paths) - source_set
            if unknown:
                raise AuthorityError(
                    f"site {site.name} has unregistered {role} paths: "
                    f"{sorted(unknown)}"
                )
    if not spec.plan_calls or not spec.completion_calls:
        raise AuthorityError("plan and completion call sets must be nonempty")
    for index, call in enumerate(spec.plan_calls):
        _validate_call_spec(call, f"plan call {index}")
    for index, call in enumerate(spec.completion_calls):
        _validate_call_spec(call, f"completion call {index}")
    plan_names = _unique([call.name for call in spec.plan_calls], "plan calls")
    completion_names = _unique(
        [call.name for call in spec.completion_calls], "completion calls"
    )
    overlap = set(plan_names) & set(completion_names)
    if overlap:
        raise AuthorityError(f"call names have ambiguous roles: {sorted(overlap)}")


def _tokens(source: str, path: str) -> tuple[_Token, ...]:
    """Tokenize the Zig subset needed by the authority, excluding inert text."""

    tokens: list[_Token] = []
    offset = 0
    line = 1
    column = 1
    length = len(source)

    def advance() -> str:
        nonlocal offset, line, column
        char = source[offset]
        offset += 1
        if char == "\n":
            line += 1
            column = 1
        else:
            column += 1
        return char

    while offset < length:
        char = source[offset]
        if char.isspace():
            advance()
            continue

        if source.startswith("//", offset):
            while offset < length and source[offset] != "\n":
                advance()
            continue

        if source.startswith("/*", offset):
            start_line, start_column = line, column
            advance()
            advance()
            depth = 1
            while offset < length and depth:
                if source.startswith("/*", offset):
                    advance()
                    advance()
                    depth += 1
                elif source.startswith("*/", offset):
                    advance()
                    advance()
                    depth -= 1
                else:
                    advance()
            if depth:
                raise AuthorityError(
                    f"{path}:{start_line}:{start_column}: unterminated block comment"
                )
            continue

        # Every Zig multiline-string content line begins with two backslashes.
        if source.startswith("\\\\", offset):
            while offset < length and source[offset] != "\n":
                advance()
            continue

        if char in {'"', "'"}:
            quote = char
            start_line, start_column = line, column
            advance()
            closed = False
            while offset < length:
                current = advance()
                if current == "\\":
                    if offset >= length:
                        break
                    advance()
                    continue
                if current == quote:
                    closed = True
                    break
                if current == "\n":
                    break
            if not closed:
                raise AuthorityError(
                    f"{path}:{start_line}:{start_column}: unterminated literal"
                )
            continue

        start_line, start_column = line, column
        if char.isascii() and (char.isalpha() or char == "_"):
            start = offset
            advance()
            while offset < length:
                current = source[offset]
                if not current.isascii() or not (
                    current.isalnum() or current == "_"
                ):
                    break
                advance()
            tokens.append(_Token(source[start:offset], start_line, start_column))
            continue

        tokens.append(_Token(char, start_line, start_column))
        advance()

    return tuple(tokens)


def _closing_paren(tokens: Sequence[_Token], opening: int, path: str) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for index in range(opening, len(tokens)):
        value = tokens[index].value
        if value in pairs:
            stack.append(pairs[value])
        elif value in pairs.values():
            if not stack or value != stack.pop():
                token = tokens[index]
                raise AuthorityError(
                    f"{path}:{token.line}:{token.column}: unbalanced delimiter"
                )
            if not stack:
                return index
    token = tokens[opening]
    raise AuthorityError(
        f"{path}:{token.line}:{token.column}: unterminated producer call"
    )


def _call_arguments(body: Sequence[_Token]) -> list[list[_Token]]:
    if not body:
        return []
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    arguments: list[list[_Token]] = [[]]
    for token in body:
        if token.value in pairs:
            stack.append(pairs[token.value])
        elif token.value in pairs.values():
            if not stack or token.value != stack.pop():
                raise AssertionError("call body delimiters were not balanced")
        if token.value == "," and not stack:
            arguments.append([])
        else:
            arguments[-1].append(token)
    if not arguments[-1]:
        arguments.pop()
    return arguments


def _enum_argument(
    body: Sequence[_Token], call: _Token, path: str, argument: int
) -> _Token:
    arguments = _call_arguments(body)
    if argument >= len(arguments):
        raise AuthorityError(
            f"{path}:{call.line}:{call.column}: {call.value} has no site "
            f"argument {argument}"
        )
    candidate = arguments[argument]
    if (
        len(candidate) != 2
        or candidate[0].value != "."
        or _IDENTIFIER.fullmatch(candidate[1].value) is None
    ):
        raise AuthorityError(
            f"{path}:{call.line}:{call.column}: {call.value} argument "
            f"{argument} must be one bare enum literal"
        )
    return candidate[1]


def _named_field(
    body: Sequence[_Token], call: _Token, path: str, field: str
) -> _Token:
    matches: list[_Token] = []
    malformed = False
    for index in range(max(0, len(body) - 2)):
        if not (
            body[index].value == "."
            and body[index + 1].value == field
            and body[index + 2].value == "="
        ):
            continue
        if (
            index + 4 < len(body)
            and body[index + 3].value == "."
            and _IDENTIFIER.fullmatch(body[index + 4].value) is not None
            and (
                index + 5 == len(body)
                or body[index + 5].value in {",", "}", ")"}
            )
        ):
            matches.append(body[index + 4])
        else:
            malformed = True
    if malformed or len(matches) != 1:
        raise AuthorityError(
            f"{path}:{call.line}:{call.column}: {call.value} must contain exactly "
            f"one .{field} = .site literal"
        )
    return matches[0]


def _scan_source(
    *,
    path: str,
    source: str,
    calls: Mapping[str, tuple[str, CallSpec]],
) -> list[Occurrence]:
    tokens = _tokens(source, path)
    occurrences: list[Occurrence] = []
    index = 0
    while index < len(tokens):
        call = tokens[index]
        configured = calls.get(call.value)
        if configured is None or index + 1 >= len(tokens):
            index += 1
            continue
        # A function declaration is not an executable call.
        if index > 0 and tokens[index - 1].value == "fn":
            index += 1
            continue
        if tokens[index + 1].value != "(":
            index += 1
            continue
        closing = _closing_paren(tokens, index + 1, path)
        role, spec = configured
        body = tokens[index + 2 : closing]
        if spec.shape is LiteralShape.ENUM_ARGUMENT:
            assert spec.argument is not None
            site = _enum_argument(body, call, path, spec.argument)
        else:
            assert spec.field is not None
            site = _named_field(body, call, path, spec.field)
        occurrences.append(
            Occurrence(
                role=role,
                site=site.value,
                path=path,
                line=site.line,
                column=site.column,
                call=call.value,
            )
        )
        # Keep scanning inside the call. A nested configured call is still an
        # executable occurrence and must not be able to hide a duplicate.
        index += 1
    return occurrences


def check_authority(
    spec: AuthoritySpec,
    source_text: Mapping[str, str],
) -> AuthorityReport:
    """Validate one complete typed-site source authority."""

    _validate_spec(spec)
    expected_sources = set(spec.sources)
    actual_sources = set(source_text)
    if actual_sources != expected_sources:
        raise AuthorityError(
            "source inventory drifted: "
            f"missing={sorted(expected_sources - actual_sources)}, "
            f"unregistered={sorted(actual_sources - expected_sources)}"
        )
    calls: dict[str, tuple[str, CallSpec]] = {}
    for role, specs in (
        ("plan", spec.plan_calls),
        ("completion", spec.completion_calls),
    ):
        for call in specs:
            calls[call.name] = (role, call)

    occurrences: list[Occurrence] = []
    for path in sorted(spec.sources):
        source = source_text[path]
        if not isinstance(source, str):
            raise AuthorityError(f"source {path} is not text")
        occurrences.extend(_scan_source(path=path, source=source, calls=calls))

    registered = {site.name: site for site in spec.sites}
    issues: list[str] = []
    for occurrence in occurrences:
        if occurrence.site not in registered:
            issues.append(
                f"{occurrence.path}:{occurrence.line}:{occurrence.column}: "
                f"unregistered {occurrence.role} site .{occurrence.site}"
            )

    for site in spec.sites:
        for role, allowed_paths in (
            ("plan", site.plan_paths),
            ("completion", site.completion_paths),
        ):
            found = [
                occurrence
                for occurrence in occurrences
                if occurrence.site == site.name and occurrence.role == role
            ]
            if not found:
                issues.append(f"registered site .{site.name} is missing its {role} call")
                continue
            if len(found) != 1:
                locations = ", ".join(
                    f"{item.path}:{item.line}:{item.column}" for item in found
                )
                issues.append(
                    f"registered site .{site.name} has duplicate {role} calls: "
                    f"{locations}"
                )
                continue
            if allowed_paths and found[0].path not in allowed_paths:
                issues.append(
                    f"registered site .{site.name} {role} call is in "
                    f"{found[0].path}, allowed={list(allowed_paths)}"
                )
    if issues:
        raise AuthorityError(issues)

    ordered = tuple(
        sorted(
            occurrences,
            key=lambda item: (
                item.site,
                item.role,
                item.path,
                item.line,
                item.column,
            ),
        )
    )
    return AuthorityReport(
        sites=tuple(site.name for site in spec.sites),
        sources=tuple(sorted(spec.sources)),
        occurrences=ordered,
    )


def _string_list(value: object, label: str, *, paths: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AuthorityError(f"{label} must be a list")
    converted = [
        _relative_path(item, f"{label} entry")
        if paths
        else _identifier(item, f"{label} entry")
        for item in value
    ]
    return _unique(converted, label)


def _call_specs(value: object, label: str) -> tuple[CallSpec, ...]:
    if not isinstance(value, list) or not value:
        raise AuthorityError(f"{label} must be a nonempty list")
    result: list[CallSpec] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise AuthorityError(f"{label}[{index}] must be an object")
        allowed = {"name", "shape", "field", "argument"}
        if set(raw) - allowed:
            raise AuthorityError(f"{label}[{index}] has unknown fields")
        try:
            shape = LiteralShape(raw.get("shape"))
        except ValueError as error:
            raise AuthorityError(f"{label}[{index}] has invalid shape") from error
        result.append(
            CallSpec(
                name=_identifier(raw.get("name"), f"{label}[{index}] name"),
                shape=shape,
                field=(
                    _identifier(raw.get("field"), f"{label}[{index}] field")
                    if "field" in raw
                    else None
                ),
                argument=(
                    raw.get("argument", 0)
                    if shape is LiteralShape.ENUM_ARGUMENT
                    else raw.get("argument")
                ),
            )
        )
    return tuple(result)


def load_manifest(path: Path) -> LoadedAuthority:
    """Load a reviewed manifest without reading any declared source yet."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuthorityError(f"cannot read authority manifest {path}: {error}") from error
    if not isinstance(raw, dict):
        raise AuthorityError("authority manifest must be an object")
    allowed = {
        "schema",
        "source_root",
        "sources",
        "sites",
        "plan_calls",
        "completion_calls",
    }
    if set(raw) - allowed:
        raise AuthorityError("authority manifest has unknown fields")
    if raw.get("schema") != SCHEMA:
        raise AuthorityError("authority manifest schema is unsupported")
    source_root_raw = raw.get("source_root", ".")
    if not isinstance(source_root_raw, str) or not source_root_raw:
        raise AuthorityError("source_root must be a nonempty path")
    source_root = (path.parent / source_root_raw).resolve()
    sources = _string_list(raw.get("sources"), "sources", paths=True)
    sites_raw = raw.get("sites")
    if not isinstance(sites_raw, list):
        raise AuthorityError("sites must be a list")
    sites: list[SiteSpec] = []
    for index, item in enumerate(sites_raw):
        if not isinstance(item, dict):
            raise AuthorityError(f"sites[{index}] must be an object")
        if set(item) - {"name", "plan_paths", "completion_paths"}:
            raise AuthorityError(f"sites[{index}] has unknown fields")
        sites.append(
            SiteSpec(
                name=_identifier(item.get("name"), f"sites[{index}] name"),
                plan_paths=_string_list(
                    item.get("plan_paths", []),
                    f"sites[{index}] plan_paths",
                    paths=True,
                ),
                completion_paths=_string_list(
                    item.get("completion_paths", []),
                    f"sites[{index}] completion_paths",
                    paths=True,
                ),
            )
        )
    spec = AuthoritySpec(
        sites=tuple(sites),
        sources=sources,
        plan_calls=_call_specs(raw.get("plan_calls"), "plan_calls"),
        completion_calls=_call_specs(
            raw.get("completion_calls"), "completion_calls"
        ),
    )
    _validate_spec(spec)
    return LoadedAuthority(spec=spec, source_root=source_root)


def check_manifest(path: Path) -> AuthorityReport:
    loaded = load_manifest(path)
    source_text: dict[str, str] = {}
    for relative in loaded.spec.sources:
        source = loaded.source_root / relative
        resolved = source.resolve()
        try:
            resolved.relative_to(loaded.source_root)
        except ValueError as error:
            raise AuthorityError(f"source escapes source_root: {relative}") from error
        if source.is_symlink() or not resolved.is_file():
            raise AuthorityError(f"source is not a regular non-symlink file: {relative}")
        try:
            source_text[relative] = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise AuthorityError(f"cannot read source {relative}: {error}") from error
    return check_authority(loaded.spec, source_text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        report = check_manifest(args.manifest)
    except AuthorityError as error:
        parser.error(str(error))
    print(json.dumps(report.canonical(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
