"""Private rv64_m4_resident ownership: tree_sha, store_components, store_key."""

def make_helpers(
    B,
    BASELINE_RUNS,
    FIELD_HASH,
    M3,
    MARK,
    P,
    Path,
    R,
    STORE_FORMAT,
    STORE_ROOT,
    hashlib,
    json,
    os,
    selectors,
    shutil,
    signal,
    subprocess,
    threading,
    time,
):
    def tree_sha(directory):
        """Order-independent content hash of a catalogue tree (relative path + file sha)."""
        h = hashlib.sha256(b"rv64-m4-catalogue-tree/v1\x00")
        root = Path(directory)
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            h.update(str(path.relative_to(root)).encode() + b"\x00" + bytes.fromhex(P.sha(path)))
        return h.hexdigest()


    def store_components(paths, catalogues, profile):
        build = B.load(paths["receipt"]) if paths["receipt"].is_file() else {}
        elf = M3 / "inputs/guest.elf"
        return {"store_format": STORE_FORMAT, "driver_sha256": P.sha(paths["driver"]),
                "library_sha256": P.sha(paths["library"]), "catalogue_sha256": tree_sha(catalogues),
                "catalogue_dir": str(catalogues), "build_catalogues": build.get("catalogues"),
                "elf_sha256": P.sha(elf), "profile": profile, "field_hash": FIELD_HASH}


    def store_key(components):
        keyed = {k: v for k, v in components.items() if k not in ("catalogue_dir", "build_catalogues")}
        blob = json.dumps(keyed, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(STORE_FORMAT.encode() + b"\x00" + blob).hexdigest()


    def open_store(components, mode):
        """fresh: new empty store dir; reuse: existing dir whose store.json must match exactly."""
        if mode == "none":
            return None, None
        key = store_key(components)
        directory = STORE_ROOT / key[:24]
        manifest = directory / "store.json"
        if mode == "fresh":
            if directory.exists():
                shutil.rmtree(directory)
            (directory / "setup").mkdir(parents=True)
            B.atomic_json(manifest, {"schema": STORE_FORMAT, "key": key, "components": components,
                                     "created_unix": time.time()})
        else:
            if not manifest.is_file():
                raise SystemExit(f"store {directory} missing: run with --store fresh first")
            recorded = B.load(manifest)
            if recorded.get("key") != key or recorded.get("components", {}).get("driver_sha256") != components["driver_sha256"]:
                raise SystemExit("ArtifactStore key mismatch: refusing to load " + str(directory))
        return directory, key


    def store_census(directory):
        if directory is None or not directory.exists():
            return None
        files = [p for p in directory.rglob("*") if p.is_file()]
        return {"files": len(files), "bytes": sum(p.stat().st_size for p in files),
                "setup_artifacts": sum(1 for p in files if p.suffix == ".rv64-setup"),
                "class_artifacts": sum(1 for p in files if p.suffix == ".rv64-class")}


    def baseline(block):
        path = BASELINE_RUNS / f"{block}-2gpu-scale/receipt.json"
        return B.load(path), path


    def m3_parity(block, proof, leaves):
        """Byte parity against the M3 integrate receipt for this block (the M4 baseline)."""
        try:
            control, path = baseline(block)
        except FileNotFoundError as error:
            # 25229951 was accepted at M3 only as a diagnostic run (no -2gpu-scale receipt).
            # Informational parity: never fail a served request over it.
            return {"baseline_receipt": None, "byte_identical": None, "unavailable": repr(error)}
        ref = control["proof_sha256"]
        native = {p.name: P.sha(p) for p in sorted(proof.glob("*.bin"))}
        result = {"baseline_receipt": str(path), "native_bins": native == ref["native"],
                  "bundle": P.sha(proof / "bundle.json") == ref["bundle"]}
        try:
            snap = R.recursive_snapshot(proof, leaves)
            result["recursive_tree"] = snap["tree_sha256"] == ref["recursive"]["tree_sha256"]
            result["recursive_proofs"] = snap["proof_sha256"] == ref["recursive"]["proof_sha256"]
            result["recursive_mismatched"] = sorted(k for k, v in snap["proof_sha256"].items() if ref["recursive"]["proof_sha256"].get(k) != v)[:40]
            result["root_sha256"] = snap["proof_sha256"].get("root.proof")
            result["baseline_root_sha256"] = ref["recursive"]["proof_sha256"].get("root.proof")
            result["proof_count"] = len(snap["proof_sha256"])
        except Exception as error:
            result["recursive_error"] = repr(error)
        result["native_mismatched"] = sorted(k for k in set(native) | set(ref["native"]) if native.get(k) != ref["native"].get(k))
        result["byte_identical"] = all(result.get(k) is True for k in ("native_bins", "bundle", "recursive_tree", "recursive_proofs"))
        return result


    def markers(log):
        out = {}
        for m in MARK.finditer(log):
            fields = dict(kv.split("=", 1) for kv in m[5].split() if "=" in kv)
            out[(int(m[1]), int(m[2]))] = {"iteration": int(m[3]), "request_wall_ns": int(m[4]), **fields}
        return out


    def nsys_directory(run, root=None):
        """Unique trace storage; keep the standard run/nsys path for consumers."""
        link = run / "nsys"
        if root is None:
            link.mkdir()
        else:
            if link.exists() or link.is_symlink():
                raise FileExistsError(link)
            target = Path(root).expanduser().resolve() / run.parent.name / run.name
            target.mkdir(parents=True, exist_ok=False)
            link.symlink_to(target, target_is_directory=True)
        return link


    def nsys_api_census(sqlite):
        """cuLibraryLoadData / cuLibraryUnload / cudaMallocFromPoolAsync / sync counts from an nsys sqlite."""
        import sqlite3
        if not Path(sqlite).is_file():
            return None
        db = sqlite3.connect(str(sqlite))
        try:
            rows = db.execute("SELECT s.value, COUNT(*), SUM(r.end-r.start), MIN(r.start), MAX(r.end) FROM CUPTI_ACTIVITY_KIND_RUNTIME r "
                              "JOIN StringIds s ON r.nameId = s.id GROUP BY s.value").fetchall()
        except Exception as error:
            return {"error": repr(error)}
        finally:
            pass
        out = {name: {"count": n, "seconds": round((t or 0) / 1e9, 4), "first_ns": a, "last_ns": b} for name, n, t, a, b in rows}
        db.close()
        keep = ("cuLibraryLoadData", "cuLibraryUnload", "cudaMallocFromPoolAsync", "cudaStreamSynchronize", "cudaMemPoolTrimTo",
                "cudaLaunchKernel", "cudaMemcpyAsync", "cuModuleLoadData", "cuLibraryGetKernel", "cuKernelGetFunction")
        return {k: v for k, v in out.items() if any(k.startswith(p) for p in keep)}


    def nsys_window_counts(sqlite, windows):
        """Per-request counts of library loads / pool mallocs / syncs, by UTC window (nsys session start + offset)."""
        import sqlite3
        db = sqlite3.connect(str(sqlite))
        try:
            start = db.execute("SELECT utcEpochNs FROM TARGET_INFO_SESSION_START_TIME").fetchone()[0]
            names = ("cuLibraryLoadData", "cuLibraryUnload", "cudaMallocFromPoolAsync", "cudaStreamSynchronize", "cudaLaunchKernel")
            out = []
            for lo, hi in windows:
                row = {}
                for name in names:
                    row[name] = db.execute("SELECT COUNT(*) FROM CUPTI_ACTIVITY_KIND_RUNTIME r JOIN StringIds s ON r.nameId=s.id "
                                           "WHERE s.value LIKE ? AND r.start + ? BETWEEN ? AND ?", (name + "%", start, lo, hi)).fetchone()[0]
                out.append(row)
            before = db.execute("SELECT COUNT(*) FROM CUPTI_ACTIVITY_KIND_RUNTIME r JOIN StringIds s ON r.nameId=s.id "
                                "WHERE s.value LIKE 'cuLibraryLoadData%' AND r.start + ? < ?", (start, windows[0][0])).fetchone()[0] if windows else None
            return {"session_start_utc_ns": start, "requests": out, "cuLibraryLoadData_before_first_request": before}
        except Exception as error:
            return {"error": repr(error)}
        finally:
            db.close()


    class PhysicalBudgetGuard:
        """Hold physical CUDA allocation under the harness GPU lease, through exit."""
        def __init__(self, binary, run, environment):
            self.process = None
            self.record = None
            self.stop = threading.Event()
            self.failure = []
            self.watcher = None
            self.stderr = (run / "budget-guard.stderr").open("wb")
            self.path = run / "budget-guard.json"
            binary = Path(binary).resolve()
            self.record = {"binary": str(binary), "sha256": P.sha(binary), "requested_limit_bytes": 28000000000}
            try:
                self.process = subprocess.Popen([str(binary), "--limit-bytes", "28000000000", "--devices", "0,1"],
                                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
                                                env={k:v for k,v in environment.items() if k != "LD_PRELOAD" and not k.startswith("STWO_")})
                selector = selectors.DefaultSelector()
                selector.register(self.process.stdout, selectors.EVENT_READ)
                try:
                    if not selector.select(timeout=60):
                        raise RuntimeError("physical budget guard ready timeout")
                    line = self.process.stdout.readline()
                finally:
                    selector.close()
                ready = json.loads(line)
                if (ready.get("schema") != "rv64-physical-budget-guard/v1" or not ready.get("ready") or
                        ready.get("requested_limit_bytes") != 28000000000 or
                        sorted(d["device"] for d in ready.get("devices", [])) != [0, 1]):
                    raise RuntimeError("invalid physical budget guard ready record")
                for device in ready["devices"]:
                    held = device["held_physical_bytes"]
                    ceiling = device["prover_physical_ceiling_bytes"]
                    if held <= 0 or ceiling != device["total_bytes"] - held or not 0 < ceiling <= 28000000000:
                        raise RuntimeError("physical budget ceiling not enforced")
                self.record.update(pid=self.process.pid, ready=ready, status="HOLDING", claim="enforced physical ceiling, not a measured peak")
                B.atomic_json(self.path, self.record)
                self.check()
            except BaseException:
                self.close()
                raise

        def check(self):
            if self.process is None or self.process.poll() is not None or self.failure:
                raise RuntimeError("physical budget guard exited before prover; result invalid")

        def supervise(self, producer):
            def watch():
                while not self.stop.wait(0.01):
                    if self.process.poll() is not None:
                        self.failure.append("guard exited while prover alive")
                        try:
                            os.killpg(producer.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        return
            self.watcher = threading.Thread(target=watch, daemon=True)
            self.watcher.start()

        def close(self):
            self.stop.set()
            if self.watcher:
                self.watcher.join(timeout=5)
            if self.process:
                if self.process.poll() is None:
                    try:
                        self.process.stdin.write(b"\n")
                        self.process.stdin.flush()
                        self.process.stdin.close()
                        self.process.wait(timeout=30)
                    except (BrokenPipeError, subprocess.TimeoutExpired):
                        self.process.kill()
                        self.process.wait(timeout=30)
                if self.process.returncode != 0:
                    self.failure.append(f"guard terminal exit {self.process.returncode}")
                if self.record is not None:
                    self.record.update(exit_code=self.process.returncode, status="INVALID" if self.failure else "RELEASED", failure=self.failure)
                    B.atomic_json(self.path, self.record)
            self.stderr.close()


    def cgroup_cpu_delta(before, after):
        if not before.get('known') or not after.get('known'):
            return {'known': False, 'quiet': False}
        try:
            values = {'psi_some_total_us': after['cpu_pressure']['some']['total'] - before['cpu_pressure']['some']['total'],
                      'psi_full_total_us': after['cpu_pressure']['full']['total'] - before['cpu_pressure']['full']['total'],
                      'nr_throttled': after['cpu_stat']['nr_throttled'] - before['cpu_stat']['nr_throttled'],
                      'throttled_us': after['cpu_stat']['throttled_usec'] - before['cpu_stat']['throttled_usec']}
            if min(values.values()) < 0 or before['cpu_max'] != after['cpu_max']:
                return {'known': False, 'quiet': False, 'reason': 'counter reset or CPU quota changed'}
            return dict(values, known=True, quiet=all(value == 0 for value in values.values()))
        except KeyError:
            return {'known': False, 'quiet': False, 'reason': 'required pressure/throttling counter absent'}


    def loaded_native_runtime(pid, expected):
        """Reject addon DT_NEEDED accidentally mapping a second/old native image."""
        expected = str(Path(expected).resolve())
        lines = (Path('/proc') / str(pid) / 'maps').read_text().splitlines()
        native = set()
        for line in lines:
            columns = line.split(None, 5)
            if len(columns) == 6 and Path(columns[5]).name == 'libstwo-rv64-native.so':
                native.add(str(Path(columns[5]).resolve()))
        if native != {expected}:
            raise RuntimeError(f'loaded native runtime mismatch: expected={expected} mapped={sorted(native)}')
        return {'pid': pid, 'expected': expected, 'mapped_native_libraries': sorted(native),
                'exactly_one_selected_native_runtime': True, 'checked_utc_ns': time.time_ns()}


    def service_wall_ns(name, service):
        """Refuse failed/incomplete requests before interpreting timing markers."""
        if service.get("ok") is False or service.get("accepted") is False or service.get("error"):
            raise RuntimeError(f"service request {name} failed: {service.get('error') or service!r}")
        wall = service.get("request_wall_ns")
        if type(wall) is not int or wall <= 0:
            raise RuntimeError(f"service request {name} has no valid request_wall_ns: {service!r}")
        return wall


    def ledger_rows(receipt, commit, milestone="M4", notes=""):
        """One progress row per served request (protocol row schema), for vectors/reports/progress/resident.jsonl."""
        rows = []
        rss = round(receipt["producer_process"].get("peak_rss_bytes", 0) / 2**30, 2)
        peaks = (receipt.get("physical_gpu_memory") or {}).get("peak_used_bytes") or {}
        verdicts = {(v["block"], v.get("trial")): v for v in receipt.get("receivers", [])}
        for r in receipt["requests"]:
            s = r.get("stages") or {}
            v = verdicts.get((r["block"], r["trial"]))
            rows.append({"date": time.strftime("%Y-%m-%d"), "commit": commit, "stream": "resident", "milestone": milestone,
                         "block": r["block"], "gpus": 2, "request_s": s.get("request_wall_s"), "capture_s": s.get("capture_s"),
                         "setup_s": s.get("setup_s"), "native_s": s.get("native_prove_s"), "recursion_s": s.get("recursion_s"),
                         "verifier_s": round(v["process"]["wall_ns"] / 1e9, 2) if v else None,
                         "rss_peak_gib": rss, "device_peak_gb": {k: round(x / 1e9, 2) for k, x in peaks.items()},
                         "proof_bytes": r.get("proof_bytes_root"),
                         "byte_identical_to": "M3 integrate scale receipt" if (r.get("parity_vs_m3") or {}).get("byte_identical") else None,
                         "receiver_accepted": v["accepted"] if v else None, "label": "M",
                         "service_position": r["ordinal"], "service_trial": r["trial"], "loading": receipt.get("loading"),
                         "store_mode": receipt["store"]["mode"], "load_avg_1m": receipt["load_avg_before"][0],
                         "run": Path(receipt["run"]).name, "notes": notes})
        return rows


    def print_summary(receipt):
        rows = []
        for r in receipt["requests"]:
            s = r.get("stages") or {}
            rows.append({"block": r["block"], "trial": r["trial"], "request_s": s.get("request_wall_s"), "capture": s.get("capture_s"),
                         "setup": s.get("setup_s"), "native": s.get("native_prove_s"), "recursion": s.get("recursion_s"),
                         "m3_identical": (r.get("parity_vs_m3") or {}).get("byte_identical"),
                         "setup_hits": (r.get("marker") or {}).get("setup_disk_hits"), "resident_hits": (r.get("marker") or {}).get("setup_resident_hits")})
        print(json.dumps({"run": receipt["run"], "process_wall_s": round(receipt["producer_process"]["wall_ns"] / 1e9, 2),
                          "service_overhead_s": receipt["service_overhead_s"], "rss_gib": round(receipt["producer_process"].get("peak_rss_bytes", 0) / 2**30, 2),
                          "cuda_api": {k: v["count"] for k, v in (receipt.get("cuda_api") or {}).items() if isinstance(v, dict) and "count" in v},
                          "requests": rows}, indent=1))

    return (tree_sha, store_components, store_key, open_store, store_census, baseline, m3_parity, markers, nsys_directory, nsys_api_census, nsys_window_counts, PhysicalBudgetGuard, cgroup_cpu_delta, loaded_native_runtime, service_wall_ns, ledger_rows, print_summary,)
