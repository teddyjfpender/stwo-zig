# run.sh <tag> [KEY=VAL...]: GPU-native repro (gate-6 env, addon-4) + nvidia-smi samples
T=$1; shift
D=/workspace/m3/runs/m8-gn-bind/rev
( while true; do nvidia-smi --query-compute-apps=pid,used_memory --format=csv,noheader | sed "s/^/$(date +%T) /"; nvidia-smi --query-gpu=index,memory.used --format=csv,noheader | sed "s/^/$(date +%T) gpu /"; sleep 2; done ) > $D/$T.smi 2>&1 &
S=$!
python3 /workspace/m3/runs/m8-gn-bind/repro.py $T STWO_RV64_M8_JOBS_LIBRARY=/workspace/m3/build/m8-gn-bind/addon-4/libstwo-rv64-jobs.so STWO_RV64_M8_OUTER_FS_LIBRARY=/workspace/m3/build/m8-gn-bind/addon-4/libstwo-rv64-outer-fs-ops.so "$@" > $D/$T.log 2>&1
echo EXIT $? >> $D/$T.log
kill $S
rm -rf /workspace/m3/runs/m8-gn-bind/repro-$T
