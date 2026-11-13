"""Private rv64_m5_negative_corpus ownership: root_node, digest_list, coherent_swap."""

def make_helpers(
    OUTER_GKR_MAGIC,
    OUTER_GKR_VERSIONS,
    bundle,
    flip,
    hashlib,
    json,
    shutil,
    swap,
):
    def root_node(tree):
        return max(tree["nodes"], key=lambda n: n.get("leaf_count", 0))


    def digest_list(path):
        return list(hashlib.sha256(path.read_bytes()).digest())


    def coherent_swap(proof, kind, a, b):
        """Swap two segment files AND their bundle entries (declaration, request, claims, proof hash) together."""
        files = {"cpus": "cpu", "truths": "truth"}[kind]
        swap(proof / f"{files}-{a}.bin", proof / f"{files}-{b}.bin")
        bundle(proof, lambda v: v[kind].__setitem__(slice(None), [v[kind][b] if i == a else v[kind][a] if i == b else e for i, e in enumerate(v[kind])]))


    def coherent_drop_last_cpu(proof):
        last = None

        def edit(v):
            nonlocal last
            last = len(v["cpus"]) - 1
            v["cpus"].pop()
        bundle(proof, edit)
        (proof / f"cpu-{last}.bin").unlink()


    def coherent_dup_cpu(proof, src, dst):
        shutil.copyfile(proof / f"cpu-{src}.bin", proof / f"cpu-{dst}.bin")
        bundle(proof, lambda v: v["cpus"].__setitem__(dst, json.loads(json.dumps(v["cpus"][src]))))


    def coherent_terminal_value_flip(proof):
        """Flip the low value byte of the middle TERMINAL RAM cell in cells.bin
    (layout: cells_wire.zig, 16-byte header, n initial then n terminal 23-byte
    cells: address u64, value u64, epoch u16, tick u32, rights u8) and rewrite
    bundle.json cells_sha256. Rights, epoch and tick stay canonical, so only
    the RAM TEARDOWN closure (the global LogUp-GKR ram relation) can reject.
    This is the M3 analogue of the M5 teardown obligation (binding note 9.F2)."""
        path = proof / "cells.bin"
        data = bytearray(path.read_bytes())
        n = int.from_bytes(data[8:12], "little")
        if n == 0 or len(data) != 16 + 2 * n * 23:
            raise ValueError(f"unexpected cells.bin layout n={n} len={len(data)}")
        offset = 16 + n * 23 + (n // 2) * 23 + 8
        data[offset] ^= 0x01
        path.write_bytes(bytes(data))
        h = digest_list(path)
        bundle(proof, lambda v: v.__setitem__("cells_sha256", h))
        return offset


    def coherent_flip(proof, name, setter):
        offset = flip(proof / name, "mid")
        h = digest_list(proof / name)
        bundle(proof, lambda v: setter(v, h))
        return offset


    def gkr_offset(data):
        offsets = [data.find(OUTER_GKR_MAGIC + v.to_bytes(4, "little")) for v in OUTER_GKR_VERSIONS]
        return min((offset for offset in offsets if offset >= 0), default=-1)


    def gkr_section(path):
        data = path.read_bytes()
        at = gkr_offset(data)
        if at < 0:
            raise RuntimeError(f"no outer GKR section (magic OGKR v1/v2) in {path.name}: format not wired")
        return bytearray(data), at


    def gkr_flip(path, delta=96):
        data, at = gkr_section(path)
        data[at + delta] ^= 0x01
        path.write_bytes(bytes(data))
        return at + delta


    def gkr_zero(path, words=64):
        data, at = gkr_section(path)
        end = min(len(data), at + 8 + 4 * words)
        data[at + 8:end] = bytes(end - at - 8)
        path.write_bytes(bytes(data))
        return at


    def cross_format(c):
        """Replace the whole proof directory by the ALT proof of the same block under another named format."""
        alt = c.get("alt_proof")
        if not alt:
            raise RuntimeError("needs --alt-format-run")
        shutil.rmtree(c["proof"])
        shutil.copytree(alt, c["proof"])


    def no_store(c):
        """RO08: every producer cache / store the receiver could consult is absent."""
        for name in ("artifact-store", "store", "setup-cache", "vk-cache", "fold-class-cache"):
            shutil.rmtree(c["proof"] / name, ignore_errors=True)
        empty = c["proof"].parent / "empty-store"
        empty.mkdir(exist_ok=True)
        for key in ("STWO_RV64_ARTIFACT_STORE", "STWO_RV64_STORE", "STWO_ZIG_RV64_SETUP_CACHE", "STWO_RV64_VK_CACHE"):
            c["env"].pop(key, None)
        c["env"]["STWO_RV64_ARTIFACT_STORE"] = str(empty)
        c["env"]["STWO_RV64_FOLD_CLASS_CACHE"] = "0"


    def other_table_root(c):
        if not c.get("donor_table_root"):
            raise RuntimeError("needs --table-root and --donor-table-root")
        c["argv"]["table_root"] = c["donor_table_root"]


    def sidecar_edit(proof):
        """Edit every integer named like a statement field in producer JSON sidecars (report/tree/root statement)."""
        names = {"kappa", "leaf_count", "cpu_proofs", "seg_hi", "seg_lo", "depth", "chi", "bus", "mass"}

        def walk(v):
            if isinstance(v, dict):
                for k in list(v):
                    if k in names and isinstance(v[k], int):
                        v[k] += 1
                    else:
                        walk(v[k])
            elif isinstance(v, list):
                for x in v:
                    walk(x)
        edited = 0
        for path in list(proof.rglob("*.json")):
            try:
                value = json.loads(path.read_text())
            except Exception:
                continue
            walk(value)
            path.write_text(json.dumps(value))
            edited += 1
        return edited

    return (root_node, digest_list, coherent_swap, coherent_drop_last_cpu, coherent_dup_cpu, coherent_terminal_value_flip, coherent_flip, gkr_offset, gkr_section, gkr_flip, gkr_zero, cross_format, no_store, other_table_root, sidecar_edit,)
