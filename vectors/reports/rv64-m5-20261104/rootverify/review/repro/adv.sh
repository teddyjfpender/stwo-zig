#!/bin/bash
# Adversarial table-trust cases against the root-only receiver (CPU only).
set -u
R=${R:-/workspace/m3/build/m5-rootverify/zig-out/bin/rv64-word16-ethereum-recursion-receiver}
S=/workspace/m3/scratch/m5-rootverify
W=/workspace/m3/scratch/m5-rootverify-rev; mkdir -p $W
P=conjectured128_b2_q108_p20_fold4; FIX=12884901888; HOST=34359738368
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false
unset STWO_ZIG_RV64_SETUP_CACHE
B=${B:-26235156}
RUN=/workspace/m3/runs/m5-rootverify/$B-2gpu-m4base
PROOF=$RUN/case/batch/trial-0/$B/proof
SELF=$(sha256sum $R | cut -d' ' -f1)
cd /workspace/m3/src/m5-rootverify
run() { name=$1; tbl=$2; shift 2; echo "== $name load=$(cut -d' ' -f1 /proc/loadavg)"; $R --security-profile $P verify-root-candidate $S/$B-request.json $PROOF $tbl $FIX $HOST "$@" > $W/$name.json 2> $W/$name.err; rc=$?; echo "exit=$rc"; if [ $rc = 0 ]; then python3 -c "import json;d=json.load(open('$W/$name.json'));print('ACCEPTED root',d['root_digest'][:16],'table_root',d['table_root'][:16])"; else tail -2 $W/$name.err; fi; }
# A1: stale round-1 table, as-is (expected refused), then header relabelled only (no reseal).
cp $S/old/vk-both.json $W/a1-stale.json
python3 - $W/a1-stale.json $W/a1-relabel.json $SELF <<'PY'
import json,sys
t=json.load(open(sys.argv[1])); print("stale header receiver", t["header"]["receiver_sha256"][:16])
t["header"]["receiver_sha256"]=sys.argv[3]; t["header"]["source_commit"]="forged"; t["derived_from"]=["nothing"]
json.dump(t,open(sys.argv[2],"w"),indent=1)
PY
run A1-stale $W/a1-stale.json
run A1-relabel $W/a1-relabel.json
# A3: table in the producer's run tree, next to (not under) proof/.
cp $S/tables/vk-both.json $(dirname $PROOF)/vk-producer.json
run A3-sibling $(dirname $PROOF)/vk-producer.json
rm -f $(dirname $PROOF)/vk-producer.json
# A4: control
run A0-control $S/tables/vk-both.json
