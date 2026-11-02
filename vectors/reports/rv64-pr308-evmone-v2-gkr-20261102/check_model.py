"""Replay the reviewed v2 envelope and reject unauthorized scope expansion."""
import copy, importlib.util, json, pathlib, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('composed_model', root / 'vectors/reports/rv64-composed-security-20261102/model.py')
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
bundle_path, receiver_path = map(pathlib.Path, sys.argv[1:])
b = json.loads(bundle_path.read_text())
r = json.JSONDecoder().raw_decode(receiver_path.read_text().lstrip())[0]
assert model.run(bundle_path, receiver_path) == model.run(bundle_path, receiver_path, True)
mutations = [
    ('proof_count', lambda b, r: r['source_shape'].__setitem__('native_proofs', 31)),
    ('columns', lambda b, r: r['source_shape'].__setitem__('max_columns', 7372)),
    ('constraints', lambda b, r: r['source_shape'].__setitem__('max_constraints', 6129)),
    ('lookup_support', lambda b, r: r['source_lookup_only_conditional_degrees'].__setitem__('rational_identity', 3804538945)),
    ('negative_support', lambda b, r: r['source_lookup_only_conditional_degrees'].__setitem__('rational_identity', -1)),
    ('v3_truth', lambda b, r: b['truths'][0]['declaration'].__setitem__('family', 'sha256')),
    ('throughput_keccak', lambda b, r: b['truths'][0]['declaration'].__setitem__('logs', [18, 21])),
    ('fused_tail', lambda b, r: b['cpus'][0]['declaration']['geometry'].__setitem__('cpu_fused_tail', True)),
    ('u8_pairs', lambda b, r: b['cpus'][0]['declaration']['geometry'].__setitem__('cpu_u8_pairs', True)),
    ('bulk_bridge', lambda b, r: b['cpus'][0]['declaration']['bridges'].__setitem__('bulk', {})),
    ('not_completed', lambda b, r: r.__setitem__('completed_ethereum_block', False)),
    ('wrong_profile', lambda b, r: r.__setitem__('profile', 'experimental-om31-local-gkr-q70-p26-fold4')),
]
with tempfile.TemporaryDirectory() as td:
    bp, rp = pathlib.Path(td) / 'bundle.json', pathlib.Path(td) / 'receiver.json'
    for name, mutate in mutations:
        bb, rr = copy.deepcopy(b), copy.deepcopy(r)
        mutate(bb, rr)
        bp.write_text(json.dumps(bb)); rp.write_text(json.dumps(rr))
        try:
            model.run(bp, rp, True)
        except AssertionError:
            print('REJECT', name)
        else:
            raise AssertionError('scope expansion accepted: ' + name)
print('PASS original model equality and12 unauthorized scope mutations')
