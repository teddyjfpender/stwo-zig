"""Canonical reconstruction of the RISC-V public-output word framing."""

from __future__ import annotations

import struct
from typing import Any, Mapping

from .contract import BenchmarkError


def reconstruct_public_output(public_values: Mapping[str, Any]) -> bytes:
    if public_values.get("schema") != "riscv-public-values-diagnostic-v1":
        raise BenchmarkError("public-values diagnostic schema drifted")
    public_data = public_values.get("public_data")
    if not isinstance(public_data, dict):
        raise BenchmarkError("public-values diagnostic has no public_data object")
    io = public_data.get("io_entries")
    if not isinstance(io, dict):
        raise BenchmarkError("public-values diagnostic has no io_entries object")
    output_len = io.get("output_len")
    output_len_addr = io.get("output_len_addr")
    output_data_addr = io.get("output_data_addr")
    words = io.get("output_words")
    if (
        not isinstance(output_len, int)
        or isinstance(output_len, bool)
        or output_len < 0
        or not isinstance(output_len_addr, int)
        or not isinstance(output_data_addr, int)
        or not isinstance(words, list)
        or not words
    ):
        raise BenchmarkError("public output framing is invalid")
    length_word = words[0]
    if (
        not isinstance(length_word, dict)
        or length_word.get("addr") != output_len_addr
        or length_word.get("value") != output_len
    ):
        raise BenchmarkError("public output length word is invalid")
    expected_data_words = (output_len + 3) // 4
    if len(words) != expected_data_words + 1:
        raise BenchmarkError("public output word count is invalid")
    encoded = bytearray()
    for index, word in enumerate(words[1:]):
        if (
            not isinstance(word, dict)
            or word.get("addr") != output_data_addr + index * 4
            or not isinstance(word.get("value"), int)
            or isinstance(word.get("value"), bool)
            or not 0 <= word["value"] <= 0xFFFF_FFFF
        ):
            raise BenchmarkError("public output word is invalid")
        encoded.extend(struct.pack("<I", word["value"]))
    if any(encoded[output_len:]):
        raise BenchmarkError("public output padding is nonzero")
    return bytes(encoded[:output_len])
