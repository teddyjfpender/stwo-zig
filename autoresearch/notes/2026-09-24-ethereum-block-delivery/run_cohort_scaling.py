from pathlib import Path
import subprocess, sys
h = Path(__file__).resolve().parent
for batch in (16, 32, 64):
    subprocess.run([sys.executable, str(h / 'run_auth_cohort.py'), '--batch', str(batch)], check=True)
