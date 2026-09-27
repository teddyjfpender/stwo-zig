"""Static candidate accounting, not a proving or memory benchmark."""
from pathlib import Path
import json, re
HERE = Path(__file__).resolve().parent
log = (HERE / 'census.log').read_text()
assert 'Build Summary: 4/4 steps succeeded; 8/8 tests passed' in log
assert 'CANONICAL_PLANNING_CENSUS child_verified=true queries=70 pow_bits=26 parent_emitted=false parent_proved=false' in log

def rows(prefix):
    return [{k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', line)}
            for line in log.splitlines() if line.startswith(prefix)]

residual = rows('BLAKE3_RESIDUAL_FUSION_CENSUS ')
arithmetic = rows('BLAKE3_ARITHMETIC_CENSUS lane=')
assert [r['lane'] for r in residual] == [1500, 1502, 1504]
assert [r['lane'] for r in arithmetic] == [1500, 1502, 1504]
assert all(r['prelinear_both'] == 0 for r in residual)
counts = {key: sum(r[key] for r in residual) for key in
          ('prelinear_add', 'prelinear_sub', 'prelinear_neg', 'prelinear_products')}
assert sum(counts[k] for k in ('prelinear_add', 'prelinear_sub', 'prelinear_neg')) == counts['prelinear_products']
linear = sum(r['linear'] for r in residual)
multiply = sum(r['multiply'] for r in residual) + sum(r['fma'] for r in arithmetic)
subtractions = counts['prelinear_sub']
def padded(n):
    return 1 << max(1, (max(n, 1) - 1).bit_length())
# Current linear: 21 main + 27 preprocessing + 3 proof-kind + 8 interaction.
# Current multiply/FMA: 17 main + 10 preprocessing + 8 interaction.
# Proposed subtraction-product: 17 main + 7 fixed routing + 8 interaction.
# The proposed component does not yet exist. Four degree-two constraints plus
# enabler binding, three input wire consumptions and one output emission assumed.
cohorts = [
    dict(name='linear', width=59, before_rows=linear, after_rows=linear-subtractions),
    dict(name='multiply_fma', width=35, before_rows=multiply, after_rows=multiply-subtractions),
    dict(name='proposed_subtract_product', width=32, before_rows=0, after_rows=subtractions),
]
for c in cohorts:
    c['before_domain'] = padded(c['before_rows']) if c['before_rows'] else 0
    c['after_domain'] = padded(c['after_rows']) if c['after_rows'] else 0
    c['base_field_element_delta'] = c['width'] * (c['after_domain']-c['before_domain'])
result = dict(scope='canonical_child_planning_only', counts=counts, cohorts=cohorts,
              base_field_byte_delta=4*sum(c['base_field_element_delta'] for c in cohorts),
              excludes=['LDE and FRI geometry', 'composition columns', 'Merkle trees',
                        'next-level verifier/hash work', 'allocator peak', 'runtime'],
              candidate_implemented=False)
(HERE/'analysis.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
