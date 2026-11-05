#!/usr/bin/env python3
"""Cross-proof LogUp mass of a block from its accepted bundle.json (binding note 10.2). Run on the pod:
python3 -I scripts/rv64_m5_mass_census.py 26235156 24628607. ram is a lower bound (secp/sha/arith/JUMPDEST words omitted)."""
import json, math, sys
p = 2**31 - 1
out = {}
for b in sys.argv[1:]:
    P = f"/workspace/m3/runs/integrate/{b}-2gpu-cold1/case/batch/trial-0/{b}/proof/bundle.json"
    d = json.load(open(P))
    ram = kio = 0
    K = SP = 0
    per = []
    for c in d["cpus"]:
        r = c["request"]
        k = r["calls"][0]; bu = r.get("bulk", {}); s = r.get("sponge", {"calls": 0, "perms": 0})
        bulk = 6*bu.get("calls", 0) + 4*bu.get("copy_words", 0) + 2*bu.get("set_words", 0) + 4*bu.get("ucopy_rows", 0) + 8*bu.get("cmp_calls", 0) + 4*bu.get("cmp_words", 0)
        seg_ram = 2*r["ls_count"] + 2*r.get("ls_dword", 0) + 50*k + 58*s["calls"] + 36*s["perms"] + bulk
        seg_kio = 50*k + 100*(s["calls"] + s["perms"])
        per.append(seg_ram)
        ram += seg_ram; kio += seg_kio; K += k; SP += s["perms"]
    mb = 2*d["memory_words"]
    ram += mb
    kio += 50*(K + SP)
    out[b] = dict(cpu_segments=len(d["cpus"]), ram_lower_bound=ram, ram_log2=round(math.log2(ram), 2), ram_margin_bits=round(math.log2(p/ram), 2),
                  max_segment_ram=max(per), init_plus_teardown=mb, kio=kio, kio_log2=round(math.log2(kio), 2), keccak_calls=K, sponge_perms=SP)
print(json.dumps(out, indent=1))
