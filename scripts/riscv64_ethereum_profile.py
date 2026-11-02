#!/usr/bin/env python3
"""Attribute a complete RV64 execution census; this report never claims a proof."""
import argparse
import hashlib
import heapq
import json
from pathlib import Path
import struct


SCHEMA = 'rv64-ethereum-profile-v1'
# Classification uses only explicit symbol-name tokens, never caller identity.
CRYPTO_TOKENS = ('keccak', 'sha256', 'sha512', 'sha2', 'sha3', 'secp256k1',
                 'k256', 'p256', 'bls12', 'bn254', 'substrate_bn', 'kzg', 'poseidon')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value, message):
    require(type(value) is int and 0 <= value < 1 << 64, message)
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def functions(raw):
    """Read defined nonempty STT_FUNC ranges from a static ELF64 RISC-V image."""
    require(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01', 'Expected ELF64 little endian')
    require(struct.unpack_from('<HH', raw, 16) == (2, 243), 'Expected RISC-V ET_EXEC')
    shoff = struct.unpack_from('<Q', raw, 40)[0]
    stride, count = struct.unpack_from('<HH', raw, 58)
    require(stride >= 64 and count > 0 and shoff + stride * count <= len(raw), 'Invalid ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, shoff + i * stride) for i in range(count)]
    tables = [s for s in sections if s[1] == 2]
    require(tables, 'ELF has no static symbol table')
    result = set()
    for section in tables:
        offset, size, link, entry = section[4], section[5], section[6], section[9]
        require(entry >= 24 and size % entry == 0 and offset + size <= len(raw) and link < count,
                'Invalid ELF symbol table')
        strings = sections[link]
        require(strings[1] == 3 and strings[4] + strings[5] <= len(raw), 'Invalid symbol strings')
        names = raw[strings[4]:strings[4] + strings[5]]
        for pos in range(offset, offset + size, entry):
            name, info, _, index, address, length = struct.unpack_from('<IBBHQQ', raw, pos)
            if info & 15 != 2 or index == 0 or length == 0:
                continue
            require(index < count and sections[index][2] & 4, 'Function is outside executable section')
            require(address + length <= 1 << 64, 'Function address overflow')
            owner = sections[index]
            require(owner[3] <= address and address + length <= owner[3] + owner[5],
                    'Function range exceeds executable section')
            require(name < len(names), 'Invalid function name offset')
            end = names.find(b'\0', name)
            require(end >= 0, 'Unterminated function name')
            label = names[name:end].decode('utf-8', errors='strict')
            require(bool(label), 'Empty function name')
            result.add((address, length, label))
    return sorted(result)


def attribute(start, counts, symbols):
    """Shortest containing range wins; aliases break ties by start then name."""
    pending = iter(symbols)
    next_symbol = next(pending, None)
    active = []
    totals = {}
    unknown = 0
    for i, count in enumerate(counts):
        pc = start + 4 * i
        while next_symbol is not None and next_symbol[0] <= pc:
            address, length, name = next_symbol
            heapq.heappush(active, (length, -address, name, address + length))
            next_symbol = next(pending, None)
        while active and active[0][3] <= pc:
            heapq.heappop(active)
        if not count:
            continue
        if active:
            length, negative_address, name, _ = active[0]
            key = (-negative_address, length, name)
            totals[key] = totals.get(key, 0) + count
        else:
            unknown += count
    rows = []
    for (address, length, name), count in totals.items():
        matches = [token for token in CRYPTO_TOKENS if token in name.lower()]
        rows.append(dict(name=name, start=address, end=address + length, instructions=count,
                         group='crypto' if matches else 'other', matched_name_tokens=matches))
    rows.sort(key=lambda item: (-item['instructions'], item['start'], item['name']))
    return rows, unknown


def build(execution, elf_raw):
    require(execution.get('status') == 'completed' and execution.get('verified_output') is True,
            'A completed execution with verified_output=true is required')
    require(execution.get('elf_sha256') == sha(elf_raw), 'Execution ELF SHA256 differs')
    retired = uint(execution.get('instructions'), 'Invalid retired instruction total')
    require(retired > 0, 'Empty execution')
    profile = execution.get('pc_profile')
    require(isinstance(profile, dict), 'Missing dense pc_profile')
    start = uint(profile.get('start'), 'Invalid profile start')
    end = uint(profile.get('end'), 'Invalid profile end')
    require(start < end and start % 4 == end % 4 == 0 and end - start <= 8 * 1024 * 1024,
            'Invalid aligned profile range (maximum 8MiB)')
    counts = profile.get('counts')
    require(isinstance(counts, list) and len(counts) == (end - start) // 4, 'Profile count geometry differs')
    for count in counts:
        uint(count, 'Invalid instruction count')
    require(uint(profile.get('outside'), 'Missing or invalid outside count') == 0,
            'Profile has retired instructions outside its range')
    require(sum(counts) == retired, 'Profile counts do not account for all retirements')
    symbols = functions(elf_raw)
    rows, unknown = attribute(start, counts, symbols)
    grouped = {group: sum(row['instructions'] for row in rows if row['group'] == group)
               for group in ('crypto', 'other')}
    require(sum(grouped.values()) + unknown == retired, 'Internal attribution mismatch')
    domain = 1 << max(5, (retired - 1).bit_length())
    return dict(schema=SCHEMA, proof_verified=False, execution_verified_output=True,
                elf_sha256=sha(elf_raw), input_sha256=execution.get('input_sha256'),
                output=execution.get('output'), instructions=retired,
                accounting=dict(function_instructions=retired - unknown, unknown_instructions=unknown,
                                retired_padding_instructions=0, total=retired),
                classification=dict(rule='Explicit symbol-name tokens only; not an instruction or call-graph classification',
                                    tokens=list(CRYPTO_TOKENS), groups=grouped),
                symbol_policy='Half-open nonzero STT_FUNC ranges; shortest range, highest start, lexical alias; zero-size symbols infer no range',
                functions=rows,
                proof_cost_model=dict(kind='Structural row model, not a proof or timing estimate',
                                      domain_rows=domain, log_size=domain.bit_length() - 1,
                                      padding_rows=domain - retired, bytes_per_base_field_column=4 * domain,
                                      current_full_profile_max_log_size=22,
                                      fits_current_full_profile=retired < 1 << 22,
                                      column_count=None,
                                      limitation='Column counts require the admitted opcode encoding plan. No RV64 continuation or aggregate proof is provided. Crypto attribution does not predict provider work.'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execution', required=True, type=Path)
    parser.add_argument('--elf', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    execution_raw, elf_raw = args.execution.read_bytes(), args.elf.read_bytes()
    report = build(json.loads(execution_raw), elf_raw)
    report['sources'] = {name: dict(path=str(path.resolve()), sha256=sha(raw), bytes=len(raw))
                         for name, path, raw in (('execution', args.execution, execution_raw),
                                                 ('elf', args.elf, elf_raw),
                                                 ('profiler', Path(__file__), Path(__file__).read_bytes()))}
    report['report_id'] = sha(json.dumps(report, sort_keys=True, separators=(',', ':')).encode())
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
