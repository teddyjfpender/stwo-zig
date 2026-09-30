"""Start the paired H200 comparison immediately after full proof qualification."""

import os
from pathlib import Path
import subprocess
import time

qualification = Path('/workspace/remote-v7-imported.log')
for _ in range(300):
    report = qualification.read_text() if qualification.exists() else ''
    if 'COMPLETE: canonical NVIDIA suite accepted by official Rust verifier' in report:
        break
    if 'Traceback (most recent call last)' in report or 'RuntimeError:' in report:
        raise RuntimeError('candidate qualification failed; comparison withheld')
    time.sleep(2)
else:
    raise TimeoutError('candidate qualification did not complete in ten minutes')

environment = dict(os.environ,
                   STWO_HOPPER_BASELINE='/workspace/candidate-v6.bin',
                   STWO_HOPPER_OUT='/workspace/hopper-v7-experiments')
with Path('/workspace/hopper-v7-comparison.log').open('w') as log:
    subprocess.run(['python3', '/workspace/compare.py'], env=environment,
                   stdout=log, stderr=subprocess.STDOUT, check=True)
