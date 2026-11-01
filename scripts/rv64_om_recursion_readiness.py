#!/usr/bin/env python3
"""Bounded structural cost audit; NEVER a proof verifier or recursive receiver."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

P = (1 << 31) - 1
ROOT = Path(__file__).resolve().parents[1]
AUTHORITIES = {
    'src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/closure.zig': 'cbaea4ea44d07ffe2bcb59dd0087f88b36429406eff25665849f1bd523c29ba8',
    'src/prover/lookups/verifier_kernel.zig': '4047f640e8293e508fe1c6239e5db3b66bcba65b6668190263290577450adb11',
    'src/prover/lookups/utils.zig': 'a65c6e609dad7c9bad7f323131ec312bb7ecbab7fb6eaa50c438194f00673fb4',
    'src/core/channel/raw_mod_m31.zig': 'a45bc12b7580611d519523dd451cb2f0d7ee1d6e1d3842708c813ceb4cb754f7',
    'src/core/channel/blake2s.zig': '6e436fb3cb2d864b72ad2c06c9cedf05f047b5543bf70f7a9e96e2cb0e26a4fb',
    'src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/wire.zig': '992e8d68a39365ee839d3a7a976bf20d3636211e632c05d39bd26ee33f9e67ca',
    'src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/manifest_wire.zig': '421bc509af6ebfde2bb071ec4e85a0b19f6bb969b32e5a826ca564481299578c',
}

class Invalid(ValueError):
    pass

class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0
    def take(self, n):
        if n < 0 or n > len(self.data) - self.at:
            raise Invalid('truncated framing')
        out = self.data[self.at:self.at+n]
        self.at += n
        return out
    def integer(self, maximum=0xffffffff):
        n, = struct.unpack('<I', self.take(4))
        if n > maximum:
            raise Invalid('structural bound exceeded')
        return n
    def fields(self, n):
        # Iterate without constructing a tuple plane or numerical proof graph.
        for _ in range(n * 8):
            if self.integer() >= P:
                raise Invalid('noncanonical OM31 coordinate')
    def finish(self):
        if self.at != len(self.data):
            raise Invalid('trailing framing')

def parse_child(data):
    if len(data) > 16 << 20:
        raise Invalid('child size bound')
    r = Reader(data)
    if r.take(8) != b'RV64LGKO' or r.integer() != 8:
        raise Invalid('not current OM31 child')
    n = r.integer(64)
    if not n:
        raise Invalid('empty child')
    heights = []
    for _ in range(n):
        height = r.integer(30)
        if not height:
            raise Invalid('empty instance')
        heights.append(height)
        r.fields(2)
    layers = r.integer(30)
    if layers != max(heights):
        raise Invalid('layer/instance mismatch')
    coefficients = []
    for layer in range(layers):
        rounds = r.integer(30)
        # Current verifier Eq suffix requires this topology, independently of
        # whether field values happen to satisfy any numerical claim.
        if rounds != layer:
            raise Invalid('sumcheck layer topology')
        lengths = []
        for _ in range(rounds):
            length = r.integer(4)
            lengths.append(length)
            r.fields(length)
        coefficients.append(lengths)
    r.fields(4 * sum(heights))
    r.finish()
    return heights, coefficients

def numerical_cost(heights, coefficients):
    """Literal ForField(OM31) verifier_kernel operations, not circuit gates.

    Horner starts at zero and counts every source multiplication/addition.
    Eq(x,y) uses3mul+1add+2sub per coordinate. scaleBase for OM31
    currently calls one full field multiplication. No constant folding counted.
    Excludes channel internals, terminal/binding/PCS and root closure.
    """
    layers = len(coefficients)
    out = dict(om31_mul=0, om31_add=0, om31_sub=0,
               equality_checks=0, secure_draws=0, mix_calls=0,
               mixed_secure_values=0, blake_compressions=0)
    def mix(n):
        out['mix_calls'] += 1
        out['mixed_secure_values'] += n
        # Channel hashes32-byte digest +32B per OM31; standard Blake2s,
        # including one final compression even for an empty payload.
        out['blake_compressions'] += (32 + n * 32 + 63) // 64
    for layer, lengths in enumerate(coefficients):
        active = [h for h in heights if h >= layers-layer]
        k = len(active)
        for _ in active:
            mix(2)
        out['secure_draws'] += 3 + len(lengths)  # alpha,lambda,rounds,mask reduction
        for length in lengths:
            out['om31_mul'] += 3 * length
            out['om31_add'] += 3 * length + 1
            out['equality_checks'] += 1
            mix(length)
        for h in active:
            d = layer - (layers-h)
            out['om31_mul'] += 13 + 3*d
            out['om31_add'] += 9 + d
            out['om31_sub'] += 2 + 2*d
            mix(4)
        out['equality_checks'] += 1
    # Every OM31 raw-mod draw hashes exactly37 bytes, one compression; no retry.
    out['blake_compressions'] += out['secure_draws']
    out['blake_G_calls'] = 80 * out['blake_compressions']
    out['closure'] = dict(om31_mul=4*len(heights), om31_add=len(heights),
                          equality_checks=len(heights)+1,
                          guessed_inverse_hints=len(heights))
    return out

def manifest(data, cpu_count, truth_count):
    if len(data) > 64 << 20:
        raise Invalid('manifest size bound')
    r = Reader(data)
    if r.take(8) != b'RV64MGK1':
        raise Invalid('not OM31 services manifest')
    r.take(32)
    if r.integer(64) != cpu_count+truth_count:
        raise Invalid('roster count mismatch')
    children = []
    for ordinal in range(cpu_count+truth_count):
        if r.integer() != ordinal:
            raise Invalid('noncanonical manifest order')
        r.take(32)
        local = r.integer(1)
        if bool(local) != (ordinal < cpu_count):
            raise Invalid('wrong local child kind')
        if local:
            r.take(32)
            raw = r.take(r.integer(16 << 20))
            heights, coefficients = parse_child(raw)
            children.append(dict(ordinal=ordinal, bytes=len(raw), sha256=sha(raw),
                                 instance_heights=heights,
                                 exact_coefficient_lengths=coefficients,
                                 numerical=numerical_cost(heights, coefficients)))
    r.finish()
    return children

def sha(data):
    return hashlib.sha256(data).hexdigest()

def bounded_read(path, limit):
    with path.open('rb') as f:
        data = f.read(limit+1)
    if len(data) > limit:
        raise Invalid('input file size bound')
    return data

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--roster', type=Path)
    p.add_argument('--contracts', type=Path)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    for path, expected in AUTHORITIES.items():
        if sha((ROOT/path).read_bytes()) != expected:
            raise Invalid('cost authority changed; review literal count before updating pin: '+path)
    raw_bundle = bounded_read(args.bundle/'bundle.json', 16 << 20)
    bundle = json.loads(raw_bundle)
    if (bundle.get('field_degree') != 8 or bundle.get('core_schema') != 7 or
            bundle.get('profile') != 'RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V1'):
        raise Invalid('unsupported current field/schema')
    contracts = None
    if bool(args.roster) != bool(args.contracts):
        raise Invalid('roster and contracts must be supplied together')
    if args.contracts:
        roster_bytes = bounded_read(args.roster, 16 << 20)
        roster = json.loads(roster_bytes)
        for kind in ['cpus', 'truths']:
            if [v['declaration'] for v in bundle[kind]] != [v['declaration'] for v in roster[kind]]:
                raise Invalid('layout declaration differs from source-derived contracts')
        contracts = json.loads(bounded_read(args.contracts, 16 << 20))
        if contracts['bundle_sha256'] != sha(roster_bytes):
            raise Invalid('source roster/contract identity mismatch')
    raw_stage = bounded_read(args.bundle/'stage-one.bin', 64 << 20)
    children = manifest(raw_stage, len(bundle['cpus']), len(bundle['truths']))
    cs = contracts['contracts'] if contracts else []
    if contracts and len(cs) != len(bundle['cpus'])+len(bundle['truths']):
        raise Invalid('contract count mismatch')
    totals = {}
    for child in children:
        for name, value in child['numerical'].items():
            if isinstance(value, int):
                totals[name] = totals.get(name, 0)+value
    exposure = [dict(ordinal=i, kind='cpu' if i < len(children) else 'truth',
        composition_split=c['composition_split'],
        committed_columns=[t['columns'] for t in c['trees']],
        lifted_leaf_base_words_per_query=c['lifted_leaf_base_words_per_query'],
        secure_oods_samples_lower_bound=c['secure_oods_samples_lower_bound'],
        secure_oods_samples_upper_bound=c['secure_oods_samples_upper_bound'],
        secure_oods_samples_exact=c.get('secure_oods_samples_exact'),
        binding_interaction_planes_per_role=c['binding_planes_per_local_role'] if i < len(children) else 0,
        binding_bytes=c['binding_bytes']) for i,c in enumerate(cs)]
    report = dict(schema='rv64-om-recursion-readiness-v1', accepting_receiver=False,
        whole_protocol_128=False, circuit_gate_count=False,
        scope='Actual OM child topology and literal numerical-kernel cost. No proof verification or full recursive graph construction.',
        source_contract_declarations_matched=contracts is not None,
        bundle_sha256=sha(raw_bundle), stage_one_sha256=sha(raw_stage),
        profile=bundle['profile'], beta=contracts['beta'] if contracts else None, authority_sha256=AUTHORITIES,
        layout_declarations={k:[v['declaration'] for v in bundle[k]] for k in ['cpus','truths']},
        numerical_totals=totals, children=children, pcs_binding_exposure=exposure,
        pcs_beta_source='Supplied source contract; physical STARK config is not decoded or verified by this tool.',
        exclusions=['child.begin/challenges/receipt digest/eta and ordered global manifest hashing',
            'terminal projection and Eq/carry/anchor algebra',
            'MAIN arithmetic and global RAM/KIO/Wire closure constraints',
            'PCS transcript, Merkle multiproofs, DEEP and FRI verification',
            'actual OM31-to-QM31 circuit lowering/constant folding and outer circuit proof/fold'])
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(cpu_children=len(children), beta=contracts['beta'] if contracts else None, numerical_totals=totals),indent=2))

if __name__ == '__main__':
    main()
