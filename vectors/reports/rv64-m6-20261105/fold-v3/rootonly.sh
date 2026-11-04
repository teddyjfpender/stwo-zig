#!/bin/bash
# M6 fold-v3: standalone root-only receiver with the receiver-derived native VK table (CPU only, no GPU lock).
#   FORMAT=old|canon TAG=<run tag> CORPUS=0|1 bash rootonly.sh
# old   = M5 default format (r1 exact binary, flat native; byte-identical to M3/M4/M5 default receipts):
#         proofs of /workspace/m3/runs/integrate/<b>-2gpu-scale (M3 integrate)
# canon = M5 canonical outer profile m5_outer_canonical_r1_b2_q108_p20_fold4_v1: /workspace/m3/runs/m5-integrate/<b>-2gpu-b1-canon
# Every step is a separate fresh process: no GPU, no producer store, no setup cache env, private native dir.
set -u
FORMAT=${FORMAT:-old}; TAG=${TAG:-r1}; CORPUS=${CORPUS:-0}
SRC=/workspace/m3/src/m6-fold-v3
S=/workspace/m3/scratch/m6-fold-v3/$FORMAT-$TAG; mkdir -p $S/tables $S/out
R=${RECEIVER:-/workspace/m3/build/m6-fold-v3/zig-out/bin/rv64-word16-ethereum-recursion-receiver}
P=conjectured128_b2_q108_p20_fold4; FIX=12884901888; HOST=34359738368
COMMIT=$(cat $SRC/.m3-commit)
export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE
if [ $FORMAT = canon ]; then RUNS=/workspace/m3/runs/m5-integrate; RT=b1-canon; export STWO_RV64_OUTER_PROFILE=m5_outer_canonical_r1_b2_q108_p20_fold4_v1
else RUNS=/workspace/m3/runs/integrate; RT=scale; unset STWO_RV64_OUTER_PROFILE; fi
cd $SRC
sha256sum $R; nproc; echo "format=$FORMAT outer profile: ${STWO_RV64_OUTER_PROFILE:-<default r1>} commit=$COMMIT"
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
step derive-26235156 $R --security-profile $P derive-vk-tables $S/26235156-request.json $(proof 26235156) $S/tables/vk-26235156.json $FIX $HOST --source-commit $COMMIT
step derive-24628607 $R --security-profile $P derive-vk-tables $S/24628607-request.json $(proof 24628607) $S/tables/vk-24628607.json $FIX $HOST --source-commit $COMMIT
step derive-both $R --security-profile $P derive-vk-tables $S/24628607-request.json $(proof 24628607) $S/tables/vk-both.json $FIX $HOST --merge $S/tables/vk-26235156.json
ROOT=$(python3 -c "import json;print(json.load(open('$S/out/derive-both.json'))['table_root'])"); echo "pin=$ROOT"
for rep in 1 2 3; do for b in 26235156 24628607; do
step verify-pinned-$b-r$rep $R --security-profile $P verify-root-candidate $S/$b-request.json $(proof $b) $S/tables/vk-both.json $FIX $HOST --table-root $ROOT
done; done
for b in 26235156 24628607; do
step audit-$b $R --security-profile $P verify-root-candidate $S/$b-request.json $(proof $b) $S/tables/vk-both.json $FIX $HOST --table-root $ROOT --audit
done
if [ $CORPUS = 1 ]; then for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
echo "== rootverify corpus $b $(date +%T) load=$(cut -d' ' -f1 /proc/loadavg)"
python3 scripts/rv64_m5_rootverify_corpus.py run --run $RUNS/$b-2gpu-$RT --donor $RUNS/$o-2gpu-$RT --table $S/tables/vk-both.json \
  --donor-table $S/tables/vk-$o.json --receiver $R --out $S/rv-corpus-$b.json --jobs 4 --work $S/rvwork > $S/rv-corpus-$b.log 2>&1
echo "exit=$? $(tail -1 $S/rv-corpus-$b.log)"
echo "== profiles corpus v3 m5-root $b $(date +%T) load=$(cut -d' ' -f1 /proc/loadavg)"
python3 scripts/rv64_m5_negative_corpus.py run --format m5-root --run $RUNS/$b-2gpu-$RT --donor $RUNS/$o-2gpu-$RT --receiver $R \
  --out $S/pc-corpus-$b.json --jobs 4 --work $S/pcwork \
  --receiver-argv "[\"{receiver}\", \"--security-profile\", \"{profile}\", \"verify-root-candidate\", \"{request}\", \"{proof}\", \"$S/tables/vk-both.json\", \"{fixed}\", \"{host}\", \"--table-root\", \"$ROOT\"]" \
  > $S/pc-corpus-$b.log 2>&1
echo "exit=$? $(tail -1 $S/pc-corpus-$b.log)"
done; fi
rm -rf $S/rvwork $S/pcwork $S/capture-*
echo ROOTONLY_DONE
