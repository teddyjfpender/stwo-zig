from pathlib import Path
import json,subprocess,sys
H=Path(__file__).resolve().parent;R=H.parents[2];m=Path(json.loads((H/'proof-baseline-mirror.json').read_text())['path']);sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='canonical-keccak-before'):
 subprocess.run(['/opt/homebrew/opt/zig@0.15/bin/zig','build','bench-keccakf-blake3-system','-Doptimize=ReleaseFast','-j1','--summary','all'],cwd=m/'src/integrations/riscv_cpu',check=True)
