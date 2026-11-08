#!/bin/bash
# gn-shape: real-block class-build parity. usage: parity.sh <n> <block> [legacy 1|0]
set -u
N=$1; BLOCK=${2:-26235156}; LEGACY=${3:-1}
S=m8-gn-shape
B=/workspace/m3/build/$S
R=/workspace/m3/runs/$S
RUN=$R/parity-$N
mkdir -p $RUN
case $BLOCK in
  24628607) DONOR=/workspace/m3/runs/m8-gpu/daemon-24628607-r2-gate-gate-12-00-baseline ;;
  *) DONOR=/workspace/m3/runs/m8-gpu/daemon-26235156-r2-gate-gate-11-00-baseline ;;
esac
python3 - "$DONOR" "$RUN" "$BLOCK" <<"PY"
import json, sys, pathlib
donor, run, block = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
req = json.loads((donor / f"request-{block}.json").read_text())
req["output_directory"] = str(run / f"capture-{block}")
(run / f"request-{block}.json").write_text(json.dumps(req, indent=1))
man = json.loads((donor / "manifest.json").read_text())
man["blocks"][block]["request"] = str(run / f"request-{block}.json")
man["execution_order"] = [int(block)]
man["recursion_mode"] = "serial"
(run / "manifest.json").write_text(json.dumps(man, indent=1))
env = json.loads((donor / "receipt.json").read_text())["environment"]
env.update(STWO_RV64_GPU_DEVICES="0", STWO_RV64_GPU_DEVICE_CAPS=env["STWO_RV64_GPU_DEVICE_CAPS"].split(",")[0])
(run / "env.sh").write_text("".join(f"export {k}=\x27{v}\x27\n" for k, v in sorted(env.items())))
PY
# Optional class-miss block (a second, never-warmed block): MISS=<block>
if [ -n "${MISS:-}" ]; then
  case $MISS in
    24628607) MDONOR=/workspace/m3/runs/m8-gpu/daemon-24628607-r2-gate-gate-12-00-baseline ;;
    *) MDONOR=/workspace/m3/runs/m8-gpu/daemon-26235156-r2-gate-gate-11-00-baseline ;;
  esac
  python3 - "$MDONOR" "$RUN" "$MISS" <<"PY"
import json, sys, pathlib
donor, run, block = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
req = json.loads((donor / f"request-{block}.json").read_text())
req["output_directory"] = str(run / f"capture-{block}")
(run / f"request-{block}.json").write_text(json.dumps(req, indent=1))
PY
  export STWO_RV64_M8_GN_SHAPE_MISS_REQUEST=$RUN/request-$MISS.json STWO_RV64_M8_GN_SHAPE_MISS_BLOCK=$MISS
fi
cd $RUN
source $RUN/env.sh
export STWO_RV64_M8_JOBS_LIBRARY=/workspace/m3/build/m8-gn-bind/addon-1/libstwo-rv64-jobs.so STWO_RV64_M8_PARITY_DEVICE=1
export STWO_RV64_M8_JOBS_ARENA_BYTES=${ARENA:-8589934592} STWO_RV64_M8_JOBS_PINNED_BYTES=${PINNED:-1073741824}
export STWO_RV64_M8_GN_SHAPE_LEGACY=$LEGACY TMPDIR=/workspace/m3/tmp
echo "START $(date -u +%FT%TZ)" > $RUN/status
timeout 900 flock -w 3600 /workspace/m3/locks/gpu.lock $B/zig-out/bin/rv64-m8-class-build-parity $RUN/manifest.json $RUN/out > $RUN/stdout.log 2> $RUN/stderr.log
echo "EXIT $? $(date -u +%FT%TZ)" >> $RUN/status
rm -rf $RUN/capture-$BLOCK $RUN/out/proof ${MISS:+$RUN/capture-$MISS}
