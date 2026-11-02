"""Checked full-Statement adapter for legacyFull and joined Word16 CSP evidence.

This is a report/statement checker, not a proof verifier. The runner must invoke
both pinned fresh verifiers successfully before calling checked_pair. No clock,
rights, complete ROM, endpoint, or cell-coverage field is omitted from the common
Statement. Native histogram equality is separate observed-coverage evidence.
"""
from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path
try:
    from . import riscv64_csp_full_proofs as legacy
except ImportError:
    import riscv64_csp_full_proofs as legacy

OPCODES = tuple('ADD SUB SLL SLT SLTU XOR SRL SRA OR AND ADDI SLTI SLTIU XORI ORI ANDI SLLI SRLI SRAI ADDW SUBW SLLW SRLW SRAW ADDIW SLLIW SRLIW SRAIW LB LH LW LD LBU LHU LWU SB SH SW SD BEQ BNE BLT BGE BLTU BGEU JAL JALR LUI AUIPC MUL MULH MULHSU MULHU DIV DIVU REM REMU MULW DIVW DIVUW REMW REMUW FENCE ECALL EBREAK'.split())
PCS = {'pow_bits': 26, 'fri_config': {'log_blowup_factor': 1, 'log_last_layer_degree_bound': 0, 'n_queries': 70, 'fold_step': 1}, 'lifting_log_size': None}
STATEMENT_FIELDS = {'program', 'steps', 'initial_pc', 'final_pc', 'initial_registers', 'final_registers', 'cells', 'register_clocks', 'memory_clocks', 'opcodes'}
CPU_FIELDS = {'steps', 'initial_pc', 'final_pc', 'initial_registers', 'final_registers', 'register_clocks'}
BUNDLE_FIELDS = {'schema', 'geometry', 'cpu', 'epoch', 'division_requests', 'multiplication_requests', 'ls_count', 'memory_words', 'claims'}

def integer(value, bits, label):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f'Noncanonical {label}')
    return value

def coverage(report, steps):
    if report.get('opcode_names') != list(OPCODES):
        raise ValueError('Unknown opcode coverage schema')
    values = report.get('opcode_histogram')
    if not isinstance(values, list) or len(values) != len(OPCODES):
        raise ValueError('Missing complete opcode coverage')
    for value in values:
        integer(value, 64, 'opcode count')
    if sum(values) != steps or values[-2:] != [0, 0]:
        raise ValueError('Coverage count/profile differs from complete ordinary RV64IM execution')
    return values

def check_cpu(cpu, expected_steps):
    if set(cpu) != CPU_FIELDS or integer(cpu['steps'], 32, 'steps') != expected_steps or not 0 < expected_steps < 1 << 22:
        raise ValueError('Incomplete or changed CPU statement')
    for field in ('initial_pc', 'final_pc'):
        if integer(cpu[field], 64, field) & 3:
            raise ValueError('Unaligned PC')
    for field in ('initial_registers', 'final_registers', 'register_clocks'):
        if not isinstance(cpu[field], list) or len(cpu[field]) != 32:
            raise ValueError('Incomplete register coverage')
        for value in cpu[field]:
            integer(value, 32 if field == 'register_clocks' else 64, field)
    if cpu['initial_registers'][0] or cpu['final_registers'][0] or cpu['register_clocks'][0]:
        raise ValueError('Noncanonical x0')
    for i, clock in enumerate(cpu['register_clocks']):
        if clock > 4 * expected_steps or (clock and clock % 4 == 0) or (clock == 0 and cpu['initial_registers'][i] != cpu['final_registers'][i]):
            raise ValueError('Invalid register clock')

def cells(path, expected, steps):
    integer(expected, 32, 'memory word count')
    if expected > 1 << 20:
        raise ValueError('Benchmark sidecar allocation budget exceeded')
    path = Path(path)
    size = 16 + 46 * expected
    if path.stat().st_size != size:
        raise ValueError('RAM sidecar size/coverage differs')
    raw = path.read_bytes()
    if raw[:8] != b'RV64RAM1' or struct.unpack_from('<II', raw, 8) != (expected, expected):
        raise ValueError('RAM sidecar header differs')
    result, clocks = [], []
    previous = -1
    for i in range(expected):
        address, before, e0, t0, r0 = struct.unpack_from('<QQHIB', raw, 16 + 23 * i)
        after_address, after, e1, t1, r1 = struct.unpack_from('<QQHIB', raw, 16 + 23 * (expected + i))
        if (address & 7 or address > (1 << 64) - 8 or address <= previous or address != after_address or
                e0 != 0 or t0 != 0 or e1 != 1 or not 0 < t1 <= 4 * steps or t1 % 4 or
                not 0 < r0 <= 3 or r1 != r0 or (not r0 & 2 and before != after)):
            raise ValueError('RAM epochs/clocks/rights/address coverage differ')
        previous = address
        result.append({'address': address, 'initial': before, 'final': after, 'readable': bool(r0 & 1), 'writable': bool(r0 & 2)})
        clocks.append(t1)
    return result, clocks

def security(producer, receiver, workers, new):
    for value in (producer, receiver):
        if value.get('pcs_config') != PCS:
            raise ValueError('Actual producer/receiver PCS configuration differs')
        if value.get('workers') != workers or value.get('build_mode') != 'ReleaseFast':
            raise ValueError('Actual worker/build settings differ')
    if producer.get('pow_bits') != 26 or producer.get('fri_queries') != 70:
        raise ValueError('Missing explicit proof security parameters')
    if new:
        if (producer.get('physical_proof_verified') is not True or receiver.get('physical_proof_verified') is not True or
                producer.get('expected_output_bound_to_terminal_ram') is not True):
            raise ValueError('Missing complete Word16 proof/fresh CSP output binding')
    elif any(v.get('verified') is not True or v.get('whole_guest_proof') is not True for v in (producer, receiver)):
        raise ValueError('Missing complete legacy proof/fresh verification')

def checked_pair(old_statement, bundle, sidecar, old_config, new_config, old_report, new_report, old_fresh, new_fresh):
    if set(old_statement) != STATEMENT_FIELDS or set(bundle) != BUNDLE_FIELDS:
        raise ValueError('Changed statement schema needs explicit review')
    expected_steps = old_config['expected_steps']
    if new_config['expected_steps'] != expected_steps or old_config.get('profile_only') is not False:
        raise ValueError('Complete execution coverage differs')
    for key in ('symbols', 'expected_digest', 'max_steps'):
        if old_config['guest'][key] != new_config['guest'][key]:
            raise ValueError('Trusted CSP request differs')
    for field, pin in [('elf', 'elf_sha256'), ('input', 'input_sha256')]:
        old_sha = legacy.digest(Path(old_config['guest'][field]))
        new_sha = legacy.digest(Path(new_config['guest'][field]))
        if old_sha != new_sha or new_sha != new_config[pin]:
            raise ValueError('Trusted ELF/input pins differ')
    workers = integer(new_config['workers'], 16, 'workers')
    if not 1 <= workers <= 64:
        raise ValueError('Invalid workers')
    security(old_report, old_fresh, workers, False)
    security(new_report, new_fresh, workers, True)
    if new_report.get('geometry') != bundle['geometry']:
        raise ValueError('Reported physical geometry differs from verified bundle')
    old_cpu = {k: old_statement[k] for k in CPU_FIELDS}
    check_cpu(old_cpu, expected_steps)
    check_cpu(bundle['cpu'], expected_steps)
    if integer(bundle['schema'], 32, 'schema') != 4:
        raise ValueError('Unreviewed Word16 wire schema')
    if integer(bundle['epoch'], 16, 'epoch') != 1:
        raise ValueError('Only genesis single-execution epoch mapping is admitted')
    old_coverage = coverage(old_report, expected_steps)
    new_coverage = coverage(new_report, expected_steps)
    if old_coverage != new_coverage or old_statement['opcodes'] != [bool(v) for v in old_coverage]:
        raise ValueError('Native opcode coverage or legacy proof support mask differs')
    for field, names in [('division_requests', ('DIV', 'DIVU', 'REM', 'REMU', 'DIVW', 'DIVUW', 'REMW', 'REMUW')),
                         ('multiplication_requests', ('MUL', 'MULH', 'MULHSU', 'MULHU', 'MULW')),
                         ('ls_count', ('LB', 'LH', 'LW', 'LD', 'LBU', 'LHU', 'LWU', 'SB', 'SH', 'SW', 'SD'))]:
        if integer(bundle[field], 32, field) != sum(new_coverage[OPCODES.index(name)] for name in names):
            raise ValueError('Declared provider coverage differs from native execution')
    for report, field in ((old_report, 'instructions'), (new_report, 'steps'), (new_fresh, 'steps')):
        if report.get(field) != expected_steps:
            raise ValueError('Reported/fresh instruction coverage differs')
    if old_config.get('control_policy') != 'limbs24_v2' or old_report.get('control_policy') != 'limbs24_v2' or old_fresh.get('control_policy') != 'limbs24_v2':
        raise ValueError('Legacy control policy not independently pinned')
    legacy.validate_expected_statement(old_statement, old_config)
    memory, clocks = cells(sidecar, bundle['memory_words'], expected_steps)
    normalized = {'program': old_statement['program'], **bundle['cpu'], 'cells': memory, 'memory_clocks': clocks, 'opcodes': [bool(v) for v in new_coverage]}
    # The program copied here was checked against the complete independently
    # parsed ELF above; the pinned fresh Word16 verifier independently loads the
    # same ELF. Native observed coverage is checked separately, not represented
    # as a new public per-opcode AIR counter claim.
    legacy.validate_expected_statement(normalized, old_config)
    if normalized != old_statement:
        raise ValueError('Complete CPU/RAM statement semantics differ')
    return {'semantic_statement_sha256': legacy.semantic_statement_digest(normalized),
            'coverage_sha256': hashlib.sha256(json.dumps(dict(zip(OPCODES, new_coverage)), sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'memory_words': len(memory), 'clock_rights_complete_coverage_checked': True,
            'coverage_scope': 'matching observed native histogram; complete steps/software/CPU/RAM claims independently fresh-verified; no separate per-opcode AIR counter claim'}
