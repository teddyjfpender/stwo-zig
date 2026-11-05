cd /workspace/m3/src/m7-integrate
python3 scripts/rv64_m7_integration_stack.py run --manifest /workspace/m3/runs/m7-integrate/p1-headline-before-20261106-05-manifest.json --out /workspace/m3/runs/m7-integrate/p1-headline-before-20261106-05 --ownership-profile-pair > /workspace/m3/runs/m7-integrate/p1-headline-before-20261106-05.log 2>&1
printf "%s\n" "$?" > /workspace/m3/runs/m7-integrate/p1-headline-before-20261106-05.exit
