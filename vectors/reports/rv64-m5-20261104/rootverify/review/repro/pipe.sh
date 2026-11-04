#!/bin/bash
# Review pipeline (CPU only, no GPU lock): build, unit tests, derive, corpus, adversarial A-cases.
set -u
SRC=/workspace/m3/src/m5-rootverify-rev; BUILD=/workspace/m3/build/m5-rootverify-rev; RUNS=/workspace/m3/runs/m5-rootverify-rev
S=/workspace/m3/scratch/m5-rootverify-rev; mkdir -p $BUILD $RUNS $S/tables $S/out
ZIG=/workspace/zig/zig; export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
cd $SRC
lock() { flock -w 3600 /workspace/m3/locks/build.$((RANDOM%3+1)).lock "$@"; }
STAGE=${1:-all}
if [ $STAGE = all ] || [ $STAGE = build ]; then
echo "== test $(date +%T)"
lock $ZIG build test-riscv64-m5-rootverify -Doptimize=ReleaseSafe -Dimplementation-commit=$(cat $SRC/.m3-commit) -Dimplementation-dirty=false --cache-dir $SRC/.zig-cache --summary all > $RUNS/test.log 2>&1; echo "test exit=$?"; tail -4 $RUNS/test.log
echo "== receiver build $(date +%T)"
(cd $SRC/src/integrations/riscv_cuda && lock $ZIG build build-rv64-ethereum-recursion-receiver --cache-dir $SRC/.zig-cache -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha -Doptimize=ReleaseFast --prefix $BUILD/zig-out > $RUNS/recv-build.log 2>&1); echo "build exit=$?"; tail -3 $RUNS/recv-build.log
fi
R=$BUILD/zig-out/bin/rv64-word16-ethereum-recursion-receiver; sha256sum $R
P=conjectured128_b2_q108_p20_fold4; FIX=12884901888; HOST=34359738368
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE
O=/workspace/m3/scratch/m5-rootverify
proof() { ls -d /workspace/m3/runs/m5-rootverify/$1-2gpu-m4base/case/batch/trial-0/$1/proof; }
step() { name=$1; shift; echo "== $name load=$(cut -d' ' -f1 /proc/loadavg) $(date +%T)"; t0=$(date +%s.%N); "$@" > $S/out/$name.json 2> $S/out/$name.stderr; rc=$?; t1=$(date +%s.%N); echo "exit=$rc wall=$(python3 -c "print(round($t1-$t0,3))") load_end=$(cut -d' ' -f1 /proc/loadavg)"; [ $rc = 0 ] || grep -m2 "error" $S/out/$name.stderr; }
COMMIT=$(cat $SRC/.m3-commit)
if [ $STAGE = all ] || [ $STAGE = derive ]; then
step derive-26235156 $R --security-profile $P derive-vk-tables $O/26235156-request.json $(proof 26235156) $S/tables/vk-26235156.json $FIX $HOST --source-commit $COMMIT
step derive-24628607 $R --security-profile $P derive-vk-tables $O/24628607-request.json $(proof 24628607) $S/tables/vk-24628607.json $FIX $HOST --source-commit $COMMIT
step derive-both $R --security-profile $P derive-vk-tables $O/24628607-request.json $(proof 24628607) $S/tables/vk-both.json $FIX $HOST --merge $S/tables/vk-26235156.json
ROOT=$(python3 -c "import json;print(json.load(open('$S/out/derive-both.json'))['table_root'])"); echo "pin=$ROOT"
for b in 26235156 24628607; do
step verify-$b $R --security-profile $P verify-root-candidate $O/$b-request.json $(proof $b) $S/tables/vk-both.json $FIX $HOST
step verify-pinned-$b $R --security-profile $P verify-root-candidate $O/$b-request.json $(proof $b) $S/tables/vk-both.json $FIX $HOST --table-root $ROOT
done
# A1 again: v0 stale table relabelled to this receiver (now must fail on root), and a v0 table of the old binary as-is.
python3 - $O/tables/vk-both.json $S/a1-relabel.json $(sha256sum $R | cut -d' ' -f1) <<'PY'
import json,sys
t=json.load(open(sys.argv[1])); t["header"]["receiver_sha256"]=sys.argv[3]; json.dump(t,open(sys.argv[2],"w"),indent=1)
PY
step A1-relabel-v0 $R --security-profile $P verify-root-candidate $O/26235156-request.json $(proof 26235156) $S/a1-relabel.json $FIX $HOST
fi
if [ $STAGE = all ] || [ $STAGE = corpus ]; then
for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
echo "== corpus $b $(date +%T) load=$(cut -d' ' -f1 /proc/loadavg)"
python3 scripts/rv64_m5_rootverify_corpus.py run --run /workspace/m3/runs/m5-rootverify/$b-2gpu-m4base --donor /workspace/m3/runs/m5-rootverify/$o-2gpu-m4base --table $S/tables/vk-both.json --donor-table $S/tables/vk-$o.json --receiver $R --out $RUNS/corpus-$b.json --jobs 4 --work $S/corpus > $RUNS/corpus-$b.log 2>&1; echo "corpus exit=$?"; tail -1 $RUNS/corpus-$b.log
done
fi
echo ALLDONE
