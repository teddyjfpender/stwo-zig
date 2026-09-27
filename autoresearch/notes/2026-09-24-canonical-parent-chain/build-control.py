"""Freeze the pre-quotient roster control, restoring production sources in finally."""
from pathlib import Path
import os,shutil,subprocess
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
files=['src/frontends/riscv/recursion/air/blake3_parent_row_storage.zig','src/frontends/riscv/recursion/air/blake3_native_parent_rows.zig']
saved={name:(ROOT/name).read_bytes() for name in files}
variants={name:data.decode() for name,data in saved.items()}
variants[files[0]]=variants[files[0]].replace('@import("qm31_quotient_accumulate_v1.zig"),','')
variants[files[1]]=variants[files[1]].replace('.materializeNative(','.materialize(').replace('.{ 3, 4, 5, 18, 19, 20 }, .{ fused.multiply, fused.inverse, fused.linear, query_fused.opening, query_fused.native, fused.quotient }','.{ 3, 4, 5, 18, 19 }, .{ fused.multiply, fused.inverse, fused.linear, query_fused.opening, query_fused.native }')
assert all(variants[name].encode()!=saved[name] for name in files)
assert 'qm31_quotient_accumulate_v1' not in variants[files[0]]
assert '18, 19, 20' not in variants[files[1]]
try:
    for name in files:
        for prefix,data in [('candidate-source',saved[name]),('control-source',variants[name].encode())]:
            out=HERE/prefix/name;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
        (ROOT/name).write_text(variants[name])
    env=os.environ.copy()
    env.update(STWO_RISCV_PARENT_PREPARATION_PROFILE='1',STWO_RISCV_RECURSIVE_PARENT_PROFILE='1',STWO_RISCV_PARENT_BENCH_ALLOCATOR='smp',STWO_RISCV_PARENT_BENCH_WORKERS='8')
    subprocess.run(['python3','scripts/zig_serial_build.py','--cwd','src/integrations/riscv_metal','test-blake3-native-parent-chain-aot',f'-Dmetal-core-aot-bundle={ROOT}/zig-out/share/stwo-zig/metal/core','-Doptimize=ReleaseFast','--summary','all'],cwd=ROOT,env=env,check=True)
    candidates=list((ROOT/'src/integrations/riscv_metal/.zig-cache/o').glob('*/test'))
    binary=max(candidates,key=lambda p:p.stat().st_mtime_ns)
    shutil.copy(binary,HERE/'control-parent-test')
    print('CONTROL_BINARY',binary,flush=True)
finally:
    for name,data in saved.items():
        current=(ROOT/name).read_bytes()
        if current==variants[name].encode(): (ROOT/name).write_bytes(data)
        elif current!=data: raise RuntimeError(f'Concurrent source edit requires merge: {name}')
    print('Production quotient sources restored.',flush=True)
