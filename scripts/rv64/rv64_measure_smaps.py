"""Private rv64_measure ownership: classify, parse_smaps, census."""

def make_helpers(
    Path,
    bisect,
    glob,
    json,
    threading,
    time,
):
    def classify(name, flags):
        if name.startswith("/dev/nvidia"):
            return "nvidia_device_mapping"
        if name == "[heap]":
            return "heap_brk"
        if name.startswith("[stack"):
            return "stack"
        if name.startswith("["):
            return "special"
        if name.startswith("/memfd:") or "(deleted)" in name:
            return "memfd_or_deleted"
        if name.startswith("/"):
            if "libstwo" in name:
                return "file:libstwo-native"
            if "libcuda" in name or "libnvidia" in name:
                return "file:libcuda-driver"
            if name.endswith((".so", ".so.1", ".so.6")) or ".so." in name:
                return "file:other-shared-lib"
            if "/bin/" in name:
                return "file:driver-binary"
            return "file:data"
        return "anon"


    def parse_smaps(pid):
        """Per-mapping Rss/Pss/Private/Anonymous (bytes) from /proc/PID/smaps."""
        maps, current = [], None
        with open(f"/proc/{pid}/smaps") as handle:
            for line in handle:
                first = line.split(None, 1)[0]
                if "-" in first and not first.endswith(":"):
                    parts = line.split(None, 5)
                    lo, hi = (int(x, 16) for x in parts[0].split("-"))
                    current = {"lo": lo, "size": hi - lo, "perms": parts[1], "name": parts[5].strip() if len(parts) > 5 else ""}
                    maps.append(current)
                elif first.endswith(":") and current is not None:
                    key = first[:-1]
                    if key == "VmFlags":
                        current["flags"] = line.split(None, 1)[1].split() if " " in line.strip() else []
                    elif key in ("Rss", "Pss", "Private_Clean", "Private_Dirty", "Shared_Clean", "Shared_Dirty", "Anonymous", "Locked", "AnonHugePages", "Swap"):
                        current[key] = int(line.split()[1]) * 1024
        return maps


    def census(maps, pinned=None):
        """Aggregate an smaps snapshot by category and by size class; pinned = [(addr,size)] from the shim."""
        pinned = sorted(pinned or [])
        starts = [p[0] for p in pinned]
        cats, sizes = {}, {}
        total = 0
        pinned_rss = 0
        for m in maps:
            rss = m.get("Rss", 0)
            total += rss
            cat = classify(m["name"], m.get("flags", []))
            if cat == "anon" and pinned:
                i = bisect.bisect_right(starts, m["lo"] + m["size"] - 1) - 1
                if i >= 0 and pinned[i][0] + pinned[i][1] > m["lo"]:
                    cat = "anon:cuda_pinned_host"
                    pinned_rss += rss
            c = cats.setdefault(cat, {"mappings": 0, "rss": 0, "private": 0, "anonymous": 0, "vsize": 0})
            c["mappings"] += 1
            c["rss"] += rss
            c["private"] += m.get("Private_Clean", 0) + m.get("Private_Dirty", 0)
            c["anonymous"] += m.get("Anonymous", 0)
            c["vsize"] += m["size"]
            if cat.startswith("anon"):
                size = m["size"]
                klass = "<=128KiB" if size <= 128 << 10 else "<=2MiB" if size <= 2 << 20 else "<=64MiB" if size <= 64 << 20 else "<=1GiB" if size <= 1 << 30 else ">1GiB"
                s = sizes.setdefault(klass, {"mappings": 0, "rss": 0})
                s["mappings"] += 1
                s["rss"] += rss
        top = sorted(maps, key=lambda m: m.get("Rss", 0), reverse=True)[:40]
        return {"rss_total_bytes": total, "categories": cats, "anon_size_classes": sizes, "pinned_rss_bytes": pinned_rss,
                "top_mappings": [{"lo": hex(m["lo"]), "size": m["size"], "rss": m.get("Rss", 0), "anon": m.get("Anonymous", 0),
                                  "perms": m["perms"], "name": m["name"], "flags": " ".join(m.get("flags", []))} for m in top]}


    def rollup(pid):
        out = {}
        with open(f"/proc/{pid}/smaps_rollup") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 3 and parts[0].endswith(":") and parts[2] == "kB":
                    out[parts[0][:-1]] = int(parts[1]) * 1024
        return out


    class SmapsSampler:
        """Polls the producer (found by a marker in its argv) and keeps the smaps snapshot at peak RSS.

    smaps_rollup every `interval` s (cheap); a full smaps parse when RSS grows >1% past the last
    full snapshot, so the kept snapshot is within ~1% + one interval of the true peak."""

        def __init__(self, marker, out, interval=0.25):
            self.marker, self.out, self.interval = marker, Path(out), interval
            self.stop_event = threading.Event()
            self.series, self.peak, self.peak_maps, self.pid, self.error = [], 0, None, None, None
            self.thread = threading.Thread(target=self.run, daemon=True)

        def find(self):
            for path in glob.glob("/proc/[0-9]*/cmdline"):
                try:
                    argv = Path(path).read_bytes().split(b"\0")
                except OSError:
                    continue
                if argv and self.marker.encode() in b" ".join(argv) and b"combined-batch" in argv:
                    return int(path.split("/")[2])
            return None

        def run(self):
            start = time.monotonic()
            try:
                while not self.stop_event.is_set() and self.pid is None:
                    self.pid = self.find()
                    if self.pid is None:
                        time.sleep(0.1)
                snap_rss = 0
                while not self.stop_event.is_set():
                    try:
                        r = rollup(self.pid)
                    except OSError:
                        break
                    t = round(time.monotonic() - start, 3)
                    rss = r.get("Rss", 0)
                    self.series.append([t, rss, r.get("Anonymous", 0), r.get("Pss_File", 0), r.get("Pss_Anon", 0)])
                    if rss > self.peak:
                        self.peak = rss
                        if rss > snap_rss * 1.01:
                            try:
                                self.peak_maps = (t, parse_smaps(self.pid))
                                snap_rss = rss
                            except OSError:
                                break
                    time.sleep(self.interval)
            except Exception as error:  # never break a proving run
                self.error = repr(error)

        def start(self):
            self.thread.start()
            return self

        def finish(self, pinned=None):
            self.stop_event.set()
            self.thread.join(timeout=30)
            result = {"schema": "rv64-smaps-census/v1", "label": "measured", "pid": self.pid, "interval_s": self.interval,
                      "peak_rss_bytes_sampled": self.peak, "error": self.error,
                      "series_columns": ["t_s", "rss", "anonymous", "pss_file", "pss_anon"], "series": self.series}
            if self.peak_maps:
                result["peak_t_s"] = self.peak_maps[0]
                result["peak_census"] = census(self.peak_maps[1], pinned)
                result["peak_vmas_columns"] = ["lo", "size", "rss", "anonymous", "perms", "name"]
                result["peak_vmas"] = [[m["lo"], m["size"], m.get("Rss", 0), m.get("Anonymous", 0), m["perms"], m["name"]] for m in self.peak_maps[1] if m.get("Rss", 0)]
            self.out.parent.mkdir(parents=True, exist_ok=True)
            with open(self.out, "w") as handle:
                json.dump(result, handle)
            return result

    return (classify, parse_smaps, census, rollup, SmapsSampler,)
