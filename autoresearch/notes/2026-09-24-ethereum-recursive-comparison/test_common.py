from pathlib import Path
import subprocess,sys
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='ethereum-auth-parser-tests'):
 subprocess.run(['cargo','test','--locked'],cwd=H/'common',check=True)
