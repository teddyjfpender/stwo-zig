"""Validate the official source-derived Cairo witness and LogUp topology."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


NAME_RE = re.compile(r"[a-z][a-z0-9_]*")


def check(
    root: Path,
    *,
    cairo_revision: str,
) -> list[str]:
    relative_path = "vectors/cairo/official/witness_feed_topology_v1.json"
    try:
        encoded = (root / relative_path).read_bytes()
        document = json.loads(encoded)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid topology: {error}"]
    if (
        not isinstance(document, dict)
        or document.get("schema") != "stwo-zig-cairo-witness-feed-topology-v1"
        or document.get("version") != 1
    ):
        return [f"{relative_path}: invalid schema"]

    errors: list[str] = []
    source = document.get("source")
    generator = document.get("generator")
    components = document.get("components")
    if (
        not isinstance(source, dict)
        or not isinstance(generator, dict)
        or not isinstance(components, list)
    ):
        return [f"{relative_path}: source, generator, and components are required"]
    if source.get("revision") != cairo_revision:
        errors.append(f"{relative_path}: source revision drifted")
    source_tree = source.get("tree")
    if (
        not isinstance(source_tree, str)
        or re.fullmatch(r"[0-9a-f]{40}", source_tree) is None
        or not isinstance(source.get("commit_timestamp"), int)
    ):
        errors.append(f"{relative_path}: source identity is invalid")

    generator_path = generator.get("path")
    if generator_path != "scripts/generate_cairo_witness_topology.py":
        errors.append(f"{relative_path}: generator path drifted")
    else:
        try:
            digest = hashlib.sha256((root / generator_path).read_bytes()).hexdigest()
        except OSError as error:
            errors.append(f"{relative_path}: unable to hash generator: {error}")
        else:
            if generator.get("sha256") != digest:
                errors.append(f"{relative_path}: generator digest drifted")
    try:
        rewriter_digest = _closure_sha256(
            root / "tools/cairo-witness-compiler/rewriter"
        )
    except OSError as error:
        errors.append(f"{relative_path}: unable to hash rewriter closure: {error}")
    else:
        if generator.get("rewriter_closure_sha256") != rewriter_digest:
            errors.append(f"{relative_path}: rewriter closure digest drifted")

    names: list[str] = []
    feed_count = 0
    lookup_field_count = 0
    lookup_word_count = 0
    logup_column_count = 0
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            errors.append(f"{relative_path}: component {index} is invalid")
            continue
        producer = component.get("producer")
        sub_words = component.get("sub_words_per_row")
        feeds = component.get("feeds")
        lookup_words = component.get("lookup_words_per_row")
        lookup_fields = component.get("lookup_fields")
        logup_columns = component.get("logup_columns")
        if (
            not _is_name(producer)
            or not isinstance(sub_words, int)
            or sub_words < 0
            or not isinstance(feeds, list)
            or not isinstance(lookup_words, int)
            or lookup_words <= 0
            or not isinstance(lookup_fields, list)
            or not lookup_fields
            or not isinstance(logup_columns, list)
            or not logup_columns
        ):
            errors.append(f"{relative_path}: component {index} geometry is invalid")
            continue
        names.append(producer)
        feed_count += _validate_feeds(errors, relative_path, producer, sub_words, feeds)
        valid_fields = _validate_lookup_fields(
            errors,
            relative_path,
            producer,
            lookup_words,
            lookup_fields,
        )
        lookup_field_count += len(lookup_fields)
        lookup_word_count += lookup_words
        logup_column_count += _validate_logup_columns(
            errors,
            relative_path,
            producer,
            logup_columns,
            valid_fields,
        )
    if names != sorted(set(names)) or len(names) != 64:
        errors.append(f"{relative_path}: component order or count drifted")
    expected_counts = (1_780, 1_598, 11_025, 780)
    if (
        feed_count,
        lookup_field_count,
        lookup_word_count,
        logup_column_count,
    ) != expected_counts:
        errors.append(f"{relative_path}: aggregate topology counts drifted")

    errors.extend(
        _check_zig_pins(root, relative_path, encoded, source_tree)
    )
    return errors


def _validate_feeds(
    errors: list[str],
    path: str,
    producer: str,
    sub_words: int,
    feeds: list[object],
) -> int:
    valid = 0
    seen: set[tuple[str, int]] = set()
    for index, feed in enumerate(feeds):
        if not isinstance(feed, dict):
            errors.append(f"{path}: {producer} feed {index} is invalid")
            continue
        field = feed.get("field")
        target = feed.get("target")
        instance = feed.get("instance")
        relation = feed.get("relation")
        word_base = feed.get("word_base")
        width = feed.get("words_per_instance")
        identity = (field, instance)
        if (
            not _is_name(field)
            or not _is_name(target)
            or not all(
                isinstance(value, int) and value >= 0
                for value in (instance, relation, word_base)
            )
            or not isinstance(width, int)
            or width <= 0
            or word_base + width > sub_words
            or identity in seen
        ):
            errors.append(f"{path}: {producer} feed {index} geometry is invalid")
            continue
        seen.add(identity)
        valid += 1
    return valid


def _validate_lookup_fields(
    errors: list[str],
    path: str,
    producer: str,
    lookup_words: int,
    fields: list[object],
) -> dict[str, int]:
    valid: dict[str, int] = {}
    next_word = 0
    for index, field in enumerate(fields):
        if not isinstance(field, dict):
            errors.append(f"{path}: {producer} lookup field {index} is invalid")
            continue
        name = field.get("name")
        base = field.get("word_base")
        width = field.get("words")
        if (
            not _is_name(name)
            or not isinstance(base, int)
            or base != next_word
            or not isinstance(width, int)
            or width <= 0
            or base + width > lookup_words
            or name in valid
        ):
            errors.append(f"{path}: {producer} lookup field {index} geometry is invalid")
            continue
        valid[name] = width
        next_word += width
    if next_word != lookup_words:
        errors.append(f"{path}: {producer} lookup word extent drifted")
    return valid


def _validate_logup_columns(
    errors: list[str],
    path: str,
    producer: str,
    columns: list[object],
    fields: dict[str, int],
) -> int:
    valid = 0
    for index, column in enumerate(columns):
        if (
            not isinstance(column, dict)
            or not _valid_logup_use(column.get("a"), fields)
            or (
                column.get("b") is not None
                and not _valid_logup_use(column.get("b"), fields)
            )
        ):
            errors.append(f"{path}: {producer} LogUp column {index} is invalid")
            continue
        valid += 1
    return valid


def _valid_logup_use(value: object, fields: dict[str, int]) -> bool:
    if not isinstance(value, dict):
        return False
    field = value.get("field")
    multiplicity = value.get("multiplicity")
    return (
        _is_name(field)
        and field in fields
        and isinstance(value.get("negative"), bool)
        and (
            multiplicity in ("1", "enabler")
            or (_is_name(multiplicity) and fields.get(multiplicity) == 1)
        )
    )


def _check_zig_pins(
    root: Path,
    relative_path: str,
    encoded: bytes,
    source_tree: object,
) -> list[str]:
    loader_path = root / "src/frontends/cairo/witness/feed_topology.zig"
    try:
        loader = loader_path.read_text(encoding="utf-8")
    except OSError as error:
        return [f"{relative_path}: unable to read Zig topology pin: {error}"]
    digest_pins = re.findall(
        r'^pub const expected_sha256 = "([0-9a-f]{64})";$',
        loader,
        flags=re.MULTILINE,
    )
    tree_pins = re.findall(
        r'^pub const expected_source_tree = "([0-9a-f]{40})";$',
        loader,
        flags=re.MULTILINE,
    )
    errors = []
    if digest_pins != [hashlib.sha256(encoded).hexdigest()]:
        errors.append(f"{relative_path}: Zig artifact digest pin drifted")
    if tree_pins != [source_tree]:
        errors.append(f"{relative_path}: Zig source-tree pin drifted")
    return errors


def _closure_sha256(root: Path) -> str:
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not {"target", "__pycache__", ".git"}.intersection(
            path.relative_to(root).parts
        )
        and path.suffix != ".pyc"
    )
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def _is_name(value: object) -> bool:
    return isinstance(value, str) and NAME_RE.fullmatch(value) is not None
