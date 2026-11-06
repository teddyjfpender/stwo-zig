#!/usr/bin/env python3
"""rv64_m8_rss_cap.py <max_gb> <log> -- cmd...: run cmd in its own process group; SIGKILL that group
if its total RSS exceeds max_gb (the pod's 92 GB container cgroup is shared by every stream; one
uncapped ptxas run on the Keccak truth shard 47 under __launch_bounds__(128,4) hit the cgroup OOM)."""
import os, signal, subprocess, sys, time
cap = float(sys.argv[1]) * 1e9; log = sys.argv[2]; cmd = sys.argv[sys.argv.index("--") + 1:]
p = subprocess.Popen(cmd, stderr=open(log, "w"), start_new_session=True)
peak = 0; t = time.time()
def tree_rss(root):
    total = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        try:
            stat = open(f"/proc/{pid}/stat").read().split()
            if int(stat[4]) == root:  # same session/process group
                total += int(open(f"/proc/{pid}/statm").read().split()[1]) * 4096
        except Exception: pass
    return total
while p.poll() is None:
    r = tree_rss(p.pid); peak = max(peak, r)
    if r > cap:
        os.killpg(p.pid, signal.SIGKILL); p.wait(); print(f"KILLED rss>{cap/1e9:.0f}GB peak_gb={peak/1e9:.2f}"); sys.exit(3)
    time.sleep(1)
print(f"EXIT {p.returncode} seconds={time.time()-t:.0f} peak_rss_gb={peak/1e9:.2f}")
sys.exit(p.returncode)
