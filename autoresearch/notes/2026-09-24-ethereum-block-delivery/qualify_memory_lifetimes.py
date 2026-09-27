from pathlib import Path
import subprocess, sys, os
h=Path(__file__).resolve().parent
for batch in (16,32,64):
    subprocess.run([sys.executable,str(h/'run_auth_memory_lifetimes.py'),'--batch',str(batch)],check=True,env={**os.environ,'STWO_HOST_MEMORY_PROFILE':'1'})
with (h/'build-stream-memory-lifetimes.log').open('x') as log:
    subprocess.run([sys.executable,str(h/'build_stream_memory_lifetimes.py')],stdout=log,stderr=subprocess.STDOUT,check=True)
with (h/'test-stream-memory-lifetimes.log').open('x') as log:
    subprocess.run([sys.executable,str(h/'test_stream_proof.py')],stdout=log,stderr=subprocess.STDOUT,check=True)
subprocess.run([sys.executable,str(h/'run_stream_memory_lifetimes.py'),'--profile','canonical','--limit','2048'],check=True)
