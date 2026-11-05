# Independent proof-file parity: sha256 every file under the run proof dir and
# match against every hash in the M3 reference receipt (by relative name).
import hashlib, json, sys, os
run, ref = sys.argv[1], sys.argv[2]
blk = json.load(open(ref))["block"]
proof = os.path.join(run, "case/batch/trial-0", str(blk), "proof")
files = {}
for d, _, fs in os.walk(proof):
    for f in fs:
        p = os.path.join(d, f)
        files[os.path.relpath(p, proof)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
def flat(v, pre=""):
    out = {}
    if isinstance(v, dict):
        for k, x in v.items(): out.update(flat(x, pre + k + "/"))
    else: out[pre.rstrip("/")] = v
    return out
r = flat(json.load(open(ref))["proof_sha256"])
by_hash = {}
for k, h in files.items(): by_hash.setdefault(h, []).append(k)
by_base = {}
for k, h in files.items(): by_base.setdefault(os.path.basename(k), []).append(h)
ok = bad = 0; bad_list = []
for k, h in r.items():
    base = k.split("/")[-1]
    if base == "tree_sha256" or base == "bundle":
        hit = h in by_hash
    else:
        hit = h in by_base.get(base, [])
    if hit: ok += 1
    else: bad += 1; bad_list.append(k)
print(json.dumps({"run": run, "files_on_disk": len(files), "reference_hashes": len(r), "matched": ok, "unmatched": bad_list}))
