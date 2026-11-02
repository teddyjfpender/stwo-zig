"""Preserve every Cairo memory value while exercising F252-tagged integers."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from .bridge import digest, write_new


def spill(value):
    result = copy.deepcopy(value)
    memory = result['memory']
    small, large = memory['small_values'], memory['f252_values']
    base = len(large)
    large.extend([[(word >> (32 * i)) & 0xffffffff for i in range(8)] for word in small])
    memory['address_to_id'] = [0x40000000 + base + index if index < len(small) else index
                               for index in memory['address_to_id']]
    # Keep the original small table so this also exercises zero multiplicities
    # and cross-table aliases. Every address still resolves to the same integer.
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    identity = digest(args.source)
    write_new(args.out, spill(json.loads(args.source.read_text())))
    if digest(args.source) != identity:
        raise ValueError('reference input changed')
    write_new(args.out.with_name(args.out.name + '.receipt.json'),
              dict(schema='keth-blake-spill-fixture-v1', source_sha256=identity,
                   output_sha256=digest(args.out), logical_memory_values_preserved=True))
