"""Replay the pinned V3 model and its layout/profile envelope.
Compact decode (qualified on GKR) is admitted; every other classic opt-in
layout, the Zbb bridge, wide clock and a receiver/profile mismatch are rejected.
Usage: check_v3_model.py BUNDLE FRESH_RECEIVER SOURCE_BOUNDS EXPECTED_MODEL_JSON"""
import copy, importlib.util, json, pathlib, sys, tempfile
here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('composed_model', here / 'model.py')
model = importlib.util.module_from_spec(spec); spec.loader.exec_module(model)
bundle_path, receiver_path, source_path, expected_path = map(pathlib.Path, sys.argv[1:])
assert model.run_v3(bundle_path, receiver_path, source_path) == json.loads(expected_path.read_text())
b0 = json.loads(bundle_path.read_text())
r0 = json.JSONDecoder().raw_decode(receiver_path.read_text().lstrip())[0]
def geo(k, v): return lambda b, r: [c['declaration']['geometry'].__setitem__(k, v) for c in b['cpus']]
admitted = [('cpu_compact_decode', geo('cpu_compact_decode', True))]
rejected = [(k, geo(k, True)) for k in ('mul_u8_pairs', 'ls_fused_pairs', 'alu_fused_tail', 'ls_dword_fused_pairs')]
rejected += [('wide_clock_log23', geo('cpu_log', 23)), ('no_u8_pairs', geo('cpu_u8_pairs', False)),
             ('zbb_bridge', lambda b, r: b['cpus'][0]['declaration']['bridges'].__setitem__('zbb', 5)),
             ('conjectured_receiver_label', lambda b, r: r.__setitem__('profile', model.PROFILES['conjectured128_b2_q108_p20_fold4']['receiver_profile']))]
def run(edit, profile='proven_beta2_q256_p0_fold4'):
    b, r = copy.deepcopy(b0), copy.deepcopy(r0); edit(b, r)
    with tempfile.TemporaryDirectory() as td:
        bp, rp = pathlib.Path(td, 'b.json'), pathlib.Path(td, 'r.json')
        bp.write_text(json.dumps(b)); rp.write_text(json.dumps(r))
        return model.run_v3(bp, rp, source_path, profile)
for name, edit in admitted:
    run(edit); print('ADMIT', name)
for name, edit in rejected:
    try: run(edit)
    except AssertionError: print('REJECT', name)
    else: raise AssertionError('scope expansion accepted: ' + name)
# A proven-profile receiver report never satisfies the conjectured mode.
try: run(lambda b, r: None, 'conjectured128_b2_q108_p20_fold4')
except AssertionError: print('REJECT proven_receiver_under_conjectured_profile')
else: raise AssertionError('conjectured mode accepted a proven-profile receiver')
print(f'PASS V3 model equality, {len(admitted)} admitted and {len(rejected) + 1} rejected mutations')
