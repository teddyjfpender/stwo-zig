#!/bin/bash
# fold-v3 adversarial review: --audit independence (A1) and pinned --merge input (A2). CPU only, no GPU lock.
#   FORMAT=old|canon bash adv.sh
set -u
FORMAT=${FORMAT:-old}
SRC=/workspace/m3/src/m6-fold-v3
S=/workspace/m3/scratch/m6-fold-v3/adv-$FORMAT; rm -rf $S; mkdir -p $S/tables $S/out
NEW=/workspace/m3/build/m6-fold-v3-adv/zig-out/bin/rv64-word16-ethereum-recursion-receiver
OLD=/workspace/m3/build/m6-fold-v3/zig-out/bin/rv64-word16-ethereum-recursion-receiver
P=conjectured128_b2_q108_p20_fold4; FIX=12884901888; HOST=34359738368
COMMIT=$(cat $SRC/.m3-commit)
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE
if [ $FORMAT = canon ]; then RUNS=/workspace/m3/runs/m5-integrate; RT=b1-canon; export STWO_RV64_OUTER_PROFILE=m5_outer_canonical_r1_b2_q108_p20_fold4_v1; OLDT=$SRC/vectors/reports/rv64-m6-20261105/fold-v3/step3-canon/tables
else RUNS=/workspace/m3/runs/integrate; RT=scale; unset STWO_RV64_OUTER_PROFILE; OLDT=$SRC/vectors/reports/rv64-m6-20261105/fold-v3/step3-old/tables; fi
cd $SRC
sha256sum $NEW $OLD; echo "format=$FORMAT commit=$COMMIT"
proof() { ls -d $RUNS/$1-2gpu-$RT/case/batch/trial-0/$1/proof; }
req() { python3 - "$1" "$RUNS/$1-2gpu-$RT/request.json" "$S" <<'PY'
import json,sys
b,src,s=sys.argv[1:]
r=json.load(open(src)); r["workers"]=16; r["output_directory"]=f"{s}/capture-{b}"
json.dump(r,open(f"{s}/{b}-request.json","w"),indent=1)
PY
}
step() { name=$1; shift; echo "== $name load=$(cut -d' ' -f1 /proc/loadavg) $(date +%T)"; t0=$(date +%s.%N); python3 -c "import resource,subprocess,sys;rc=subprocess.call(sys.argv[3:],stdout=open(sys.argv[1],'w'),stderr=open(sys.argv[2],'w'));print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,file=open(sys.argv[2]+'.rss','w'));sys.exit(rc)" $S/out/$name.json $S/out/$name.stderr "$@"; rc=$?; t1=$(date +%s.%N); echo "exit=$rc wall=$(python3 -c "print(round($t1-$t0,3))") load_end=$(cut -d' ' -f1 /proc/loadavg) maxrss_kb=$(cat $S/out/$name.stderr.rss)"; [ $rc = 0 ] || grep -m3 "error" $S/out/$name.stderr; }
req 26235156; req 24628607
R=$NEW
step derive-26235156 $R --security-profile $P derive-vk-tables $S/26235156-request.json $(proof 26235156) $S/tables/vk-26235156.json $FIX $HOST --source-commit $COMMIT
step derive-24628607 $R --security-profile $P derive-vk-tables $S/24628607-request.json $(proof 24628607) $S/tables/vk-24628607.json $FIX $HOST --source-commit $COMMIT
ROOT156=$(python3 -c "import json;print(json.load(open('$S/out/derive-26235156.json'))['table_root'])")
BAD=$(python3 -c "print('00'*32)")
echo "-- A2 negative: wrong pin on the merge input must be refused"
step derive-both-badpin $R --security-profile $P derive-vk-tables $S/24628607-request.json $(proof 24628607) $S/tables/vk-bad.json $FIX $HOST --merge $S/tables/vk-26235156.json --table-root $BAD
step derive-both $R --security-profile $P derive-vk-tables $S/24628607-request.json $(proof 24628607) $S/tables/vk-both.json $FIX $HOST --merge $S/tables/vk-26235156.json --table-root $ROOT156
ROOT=$(python3 -c "import json;print(json.load(open('$S/out/derive-both.json'))['table_root'])"); echo "pin=$ROOT"
for b in 26235156 24628607; do
step verify-pinned-$b $R --security-profile $P verify-root-candidate $S/$b-request.json $(proof $b) $S/tables/vk-both.json $FIX $HOST --table-root $ROOT
step audit-$b $R --security-profile $P verify-root-candidate $S/$b-request.json $(proof $b) $S/tables/vk-both.json $FIX $HOST --table-root $ROOT --audit
done
# Before/after on the native-table family + audit cases: NEW receiver with its table, OLD (dd7df2402-equivalent 0f2a4146) with its receipt table.
CASES=RV24-native-artifact-flip-unsealed,RV25-native-artifact-flip-resealed,RV26-native-section-dropped,RV27-native-artifacts-rotated,RV28-native-fixed-root-forged,RV29-native-source-root-forged,RV30-native-forged-pinned,RV31-native-forged-audit,RV32-audit-control
for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
if [ "${FULL:-0}" = 1 ]; then SEL=""; else SEL="--cases $CASES"; fi
echo "== NEW corpus $b $(date +%T) load=$(cut -d' ' -f1 /proc/loadavg)"
python3 scripts/rv64_m5_rootverify_corpus.py run --run $RUNS/$b-2gpu-$RT --donor $RUNS/$o-2gpu-$RT --table $S/tables/vk-both.json \
  --donor-table $S/tables/vk-$o.json --receiver $NEW --out $S/rv-new-$b.json --jobs 3 --work $S/rvwork $SEL > $S/rv-new-$b.log 2>&1
echo "exit=$? $(tail -1 $S/rv-new-$b.log)"
echo "== OLD corpus $b $(date +%T) load=$(cut -d' ' -f1 /proc/loadavg)"
python3 scripts/rv64_m5_rootverify_corpus.py run --run $RUNS/$b-2gpu-$RT --donor $RUNS/$o-2gpu-$RT --table $OLDT/vk-both.json \
  --donor-table $OLDT/vk-$o.json --receiver $OLD --out $S/rv-old-$b.json --jobs 3 --work $S/rvwork --cases RV31-native-forged-audit,RV32-audit-control > $S/rv-old-$b.log 2>&1
echo "exit=$? $(tail -1 $S/rv-old-$b.log)"
done
rm -rf $S/rvwork $S/capture-*
echo ADV_DONE
