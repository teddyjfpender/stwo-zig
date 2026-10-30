"""Host ABI codec for OP Stack's pinned BootInfoStruct (not a proof verifier).

The range journal is five ABI words. Aggregation has a distinct six-word ABI;
never substitute an execution state root for an OP L2 output root.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OpStackRangeJournal:
    l1_head: bytes
    l2_pre_output_root: bytes
    l2_post_output_root: bytes
    l2_block_number: int
    rollup_config_hash: bytes

    def __post_init__(self) -> None:
        for value in (self.l1_head, self.l2_pre_output_root,
                      self.l2_post_output_root, self.rollup_config_hash):
            if type(value) is not bytes or len(value) != 32:
                raise ValueError("journal commitments must be exactly 32 bytes")
        if type(self.l2_block_number) is not int or not 0 <= self.l2_block_number < 1 << 64:
            raise ValueError("journal block number must fit uint64")

    def encode(self) -> bytes:
        return (self.l1_head + self.l2_pre_output_root + self.l2_post_output_root
                + self.l2_block_number.to_bytes(32, "big") + self.rollup_config_hash)

    @classmethod
    def decode(cls, data: bytes) -> OpStackRangeJournal:
        if type(data) is not bytes or len(data) != 5 * 32:
            raise ValueError("range journal must be exactly five ABI words")
        return cls(data[:32], data[32:64], data[64:96],
                   int.from_bytes(data[96:128], "big"), data[128:160])
