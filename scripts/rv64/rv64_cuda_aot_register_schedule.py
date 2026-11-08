#!/usr/bin/env python3
"""Register-pressure scheduling of oversized AOT constraint groups (M8 T5).

The admitted catalogue lowers every single-group module above 32 KiB into a
"bounded" form: one volatile local-memory slot per live SSA value and
noinline instruction slices (scripts/rv64_cuda_partition_grouped.py
bound_ssa_module). For the Keccak truth group 174 that is an 11,368 B private
frame per thread and 95 ms per launch [M census1, 24628607 warm].

This pass keeps every arithmetic operation of the original SSA group and only
changes WHEN values are produced and WHERE they live:

* order: one of a few topological orders (the recording order of the native
  evaluator, the emitted root-first postorder) chosen by the smallest
  simulated live set. A topological order evaluates the same operation on the
  same operands, so each value is bit-identical.
* input masks: loaded at each use instead of being held across the group
  (a re-load reads the same committed word).
* parameters / constants: re-read at each use (parameters are immutable for the
  launch; constants are literals).
* roots: each residual's reverse-RLC term is added to `folded` as soon as the
  residual exists. Canonical M31/OM31 addition is exact modular arithmetic, so
  the order of terms does not change `folded` or the atomically added output.

The emitted group is ordinary SSA (no volatile banks); ptxas allocates the
registers. Kernel name, argument list and y-grid are unchanged, so the
catalogue header and every launcher stay valid.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re

MARKER = "// rv64-aot-register-scheduled/v1"
DECL = re.compile(r"\s*const (uint32_t|OM31) (v\d+)=(.*);$")
CONST_ARRAY = re.compile(r"\s*const uint32_t (c\d+)\[8\]=\{[^}]*\};$")
VALUE = re.compile(r"\bv\d+\b")


class Group:
    """One original `<name>_part_<g>` SSA function, parsed line by line."""

    def __init__(self, function_text):
        lines = function_text.splitlines()
        start = next(i for i, line in enumerate(lines) if "OM31 folded=zero();" in line)
        self.header = "\n".join(lines[:start + 1])
        self.nodes = {}  # v -> (kind, op, expression, children)
        self.order = []  # emitted order of declarations
        self.roots = []  # (value, folded line), emitted order
        self.const_arrays = {}  # cN -> line
        self.tail = []
        for line in lines[start + 1:]:
            if line.startswith("}"):
                self.tail.append(line)
                continue
            m = DECL.match(line)
            if m:
                kind, value, expression = m.groups()
                if expression.startswith("tree"):
                    op = "input"
                elif expression.startswith("from_words(parameters"):
                    op = "param"
                elif expression.startswith("from_words(c"):
                    op = "const"
                elif re.fullmatch(r"\d+u", expression):
                    op = "bconst"
                else:
                    op = "op"
                children = VALUE.findall(expression)
                for child in children:
                    if child not in self.nodes:
                        raise ValueError("use before original SSA definition")
                self.nodes[value] = (kind, op, expression, children)
                self.order.append(value)
                continue
            m = CONST_ARRAY.match(line)
            if m:
                self.const_arrays[m[1]] = line
                continue
            if "folded=add(folded," in line:
                used = VALUE.findall(line)
                if len(used) != 1:
                    raise ValueError("unexpected root accumulation")
                self.roots.append((used[0], line))
                continue
            if ("const OM31 result=" in line or "_add(output+" in line or
                    line.startswith(" const uint64_t stride=") or line.startswith(" store(output,")):
                self.tail.append(line)
                continue
            raise ValueError("unrecognised SSA line: " + line[:120])
        if not self.roots:
            raise ValueError("group has no roots")

    def width(self, value):
        return 1 if self.nodes[value][0] == "uint32_t" else 8

    def is_leaf(self, value):
        return self.nodes[value][1] in ("param", "const", "bconst")

    def is_input(self, value):
        return self.nodes[value][1] == "input"

    def operations(self, order):
        return [v for v in order if self.nodes[v][1] == "op"]

    def simulate(self, ops):
        """Peak live words when inputs and leaves are re-read at each use."""
        root_count = collections.Counter(v for v, _ in self.roots)
        uses = collections.Counter()
        for v in ops:
            for c in self.nodes[v][3]:
                if self.nodes[c][1] == "op":
                    uses[c] += 1
        for v, _ in self.roots:
            uses[v] += 1
        live = peak = loads = 0
        for v in ops:
            loads += sum(1 for c in self.nodes[v][3] if self.is_input(c))
            live += self.width(v)
            peak = max(peak, live)
            for c in self.nodes[v][3]:
                if self.nodes[c][1] == "op":
                    uses[c] -= 1
                    if uses[c] == 0:
                        live -= self.width(c)
            for _ in range(root_count[v]):
                uses[v] -= 1
                if uses[v] == 0:
                    live -= self.width(v)
        return peak, loads

    def candidates(self):
        recording = sorted(self.order, key=lambda v: int(v[1:]))
        return {"postorder": self.operations(self.order), "recording": self.operations(recording)}

    def check_topological(self, ops):
        seen = set()
        for v in ops:
            for c in self.nodes[v][3]:
                if self.nodes[c][1] == "op" and c not in seen:
                    raise ValueError("schedule is not topological")
            seen.add(v)
        if len(seen) != len(self.operations(self.order)):
            raise ValueError("schedule dropped or duplicated an operation")

    def emit(self, ops):
        self.check_topological(ops)
        roots_by_value = collections.defaultdict(list)
        for v, line in self.roots:
            roots_by_value[v].append(line)
        out = [self.header]
        # Literal constants first: compile-time values, no live register cost.
        out.extend(self.const_arrays.values())
        for v in self.order:
            if self.nodes[v][1] in ("const", "bconst"):
                out.append(f" const {self.nodes[v][0]} {v}={self.nodes[v][2]};")
        reload = 0
        for v in ops:
            kind, _, expression, children = self.nodes[v]
            rename = {}
            for c in dict.fromkeys(children):
                ckind, cop, cexpr, _ = self.nodes[c]
                if cop in ("input", "param"):
                    name = f"{c}_r{reload}"
                    reload += 1
                    out.append(f" const {ckind} {name}={cexpr};")
                    rename[c] = name
            expression = VALUE.sub(lambda m: rename.get(m[0], m[0]), expression)
            out.append(f" const {kind} {v}={expression};")
            out.extend(roots_by_value.pop(v, []))
        # Roots that are leaves or inputs themselves (never seen in ops).
        for v, lines in list(roots_by_value.items()):
            kind, op, expression, _ = self.nodes[v]
            if op not in ("input", "param"):
                if op not in ("const", "bconst"):
                    raise ValueError("unscheduled root")
                out.extend(lines)
                continue
            name = f"{v}_r{reload}"
            reload += 1
            out.append(f" const {kind} {name}={expression};")
            out.extend(line.replace(v, name) for line in lines)
        out.extend(self.tail)
        return "\n".join(out) + "\n"

    def emit_sliced(self, ops, target_ops):
        """Cut the scheduled order into noinline slices at minimal-live boundaries.

        ptxas allocates each slice separately, which bounds its memory on very
        large groups (shard 47: > 40 GB RSS as one function). Values live across
        a cut travel through small ping-pong local arrays; each slice returns its
        partial fold (exact, order-independent addition). Operations, operands
        and roots are unchanged.
        """
        self.check_topological(ops)
        n = len(ops)
        pieces = max(1, round(n / target_ops))
        pos = {v: i for i, v in enumerate(ops)}
        root_values = {v for v, _ in self.roots}
        last = {}
        for i, v in enumerate(ops):
            for c in self.nodes[v][3]:
                if self.nodes[c][1] == "op":
                    last[c] = max(last.get(c, -1), i)
        delta = [0] * (n + 2)
        for v, i in pos.items():
            if v in last:
                delta[i + 1] += self.width(v)
                delta[last[v] + 1] -= self.width(v)
        cost, running = [0] * (n + 1), 0
        for b in range(n + 1):
            running += delta[b]
            cost[b] = running
        cuts = [0]
        for k in range(1, pieces):
            ideal, window = k * n // pieces, max(1, n // (4 * pieces))
            lo, hi = max(cuts[-1] + 1, ideal - window), min(n - 1, ideal + window)
            if lo <= hi:
                cuts.append(min(range(lo, hi + 1), key=lambda b: (cost[b], abs(b - ideal))))
        cuts.append(n)

        def carried(b):
            return [v for v in ops[:b] if v in last and last[v] >= b]

        boundary = {b: carried(b) for b in cuts[1:-1]}
        slots = {}
        width_b = width_e = 1
        for b, values in boundary.items():
            base = [v for v in values if self.width(v) == 1]
            ext = [v for v in values if self.width(v) == 8]
            slots[b] = {**{v: i for i, v in enumerate(base)}, **{v: i for i, v in enumerate(ext)}}
            width_b, width_e = max(width_b, len(base)), max(width_e, len(ext))
        header_name = re.search(r"void ([A-Za-z0-9_]+)\(", self.header)[1]
        roots_by_value = collections.defaultdict(list)
        for v, line in self.roots:
            roots_by_value[v].append(line)
        args = ("const uint32_t *tree0,const uint32_t *tree1,const uint32_t *tree2,const uint64_t *column_offsets,"
                "const uint32_t *parameters,const uint32_t *powers,uint32_t trace_log,uint32_t eval_log,uint32_t row,"
                "const uint32_t *t5_bi,const OM31 *t5_ei,uint32_t *t5_bo,OM31 *t5_eo")
        functions, calls, reload = [], [], 0
        for k in range(len(cuts) - 1):
            a, b = cuts[k], cuts[k + 1]
            body = []
            text_ops = []
            loaded = set()
            for v in ops[a:b]:
                kind, _, expression, children = self.nodes[v]
                rename = {}
                for c in dict.fromkeys(children):
                    ckind, cop, cexpr, _ = self.nodes[c]
                    if cop in ("input", "param"):
                        name = f"{c}_r{reload}"
                        reload += 1
                        text_ops.append(f" const {ckind} {name}={cexpr};")
                        rename[c] = name
                    elif cop == "op" and pos[c] < a and c not in loaded:
                        array = "t5_bi" if self.width(c) == 1 else "t5_ei"
                        text_ops.append(f" const {ckind} {c}={array}[{slots[a][c]}];")
                        loaded.add(c)
                expression = VALUE.sub(lambda m: rename.get(m[0], m[0]), expression)
                text_ops.append(f" const {kind} {v}={expression};")
                text_ops.extend(roots_by_value.pop(v, []))
            if b in boundary:
                for v in boundary[b]:
                    out_array = "t5_bo" if self.width(v) == 1 else "t5_eo"
                    if pos[v] >= a or v in loaded:
                        text_ops.append(f" {out_array}[{slots[b][v]}]={v};")
                    else:  # passes through this slice untouched
                        in_array = "t5_bi" if self.width(v) == 1 else "t5_ei"
                        text_ops.append(f" {out_array}[{slots[b][v]}]={in_array}[{slots[a][v]}];")
            used = set(VALUE.findall("\n".join(text_ops)))
            consts = [line for cname, line in self.const_arrays.items() if re.search(r"\b" + cname + r"\b", "\n".join(text_ops + [self.nodes[u][2] for u in used if u in self.nodes and self.nodes[u][1] == "const"]))]
            for u in self.order:
                if self.nodes[u][1] in ("const", "bconst") and u in used:
                    body.append(f" const {self.nodes[u][0]} {u}={self.nodes[u][2]};")
            name = f"{header_name}_s{k}"
            functions.append(f"__device__ __noinline__ OM31 {name}({args}){{\n OM31 folded=zero();\n" + "\n".join(consts + body + text_ops) + "\n return folded;\n}\n")
            src, dst = (k + 1) % 2, k % 2
            calls.append(f" folded=add(folded,{name}(tree0,tree1,tree2,column_offsets,parameters,powers,trace_log,eval_log,row,"
                         f"t5_b[{src}],t5_e[{src}],t5_b[{dst}],t5_e[{dst}]));")
        if roots_by_value:
            raise ValueError("root left outside every slice")
        part = [self.header, f" uint32_t t5_b[2][{width_b}]; OM31 t5_e[2][{width_e}];", *calls, *self.tail]
        report = {"slices": len(cuts) - 1, "carried_words_at_cuts": [cost[b] for b in cuts[1:-1]],
                  "carry_slots": [width_b, width_e]}
        return "".join(functions) + "\n".join(part) + "\n", report


def schedule_group(function_text, slice_ops=0):
    group = Group(function_text)
    best = None
    report = {}
    for name, ops in group.candidates().items():
        peak, loads = group.simulate(ops)
        report[name] = {"peak_live_words": peak, "input_loads": loads}
        if best is None or (peak, loads) < (best[1], best[2]):
            best = (name, peak, loads, ops)
    report["selected"] = best[0]
    report["operations"] = len(best[3])
    if slice_ops:
        text, sliced = group.emit_sliced(best[3], slice_ops)
        report.update(sliced)
        return text, report
    return group.emit(best[3]), report


def split_module(text):
    parts = list(re.finditer(r"__device__ __noinline__ void ([A-Za-z0-9_]+)_part_(\d+)\(", text))
    entry = text.index('extern "C" __global__ void')
    return parts, entry


def lower_module(raw_text, admitted_text, launch_bounds, slice_ops=0):
    """Return the scheduled module for one admitted single-group shard.

    `raw_text` is the original case-N-domain.cu (never lowered). The admitted
    shard (possibly already bank-lowered) only supplies its group id and the
    exported dispatcher, which keeps the shard symbol and its y-grid.
    """
    selected = re.findall(r"__device__ __noinline__ void ([A-Za-z0-9_]+)_part_(\d+)\(", admitted_text)
    if len(selected) != 1:
        raise ValueError("register scheduling needs exactly one root group per module")
    name, group = selected[0][0], int(selected[0][1])
    parts, entry = split_module(raw_text)
    if group >= len(parts) or int(parts[group][2]) != group or parts[group][1] != name:
        raise ValueError("raw group does not match admitted source")
    end = parts[group + 1].start() if group + 1 < len(parts) else entry
    function = raw_text[parts[group].start():end]
    body, report = schedule_group(function, slice_ops)
    kernel = admitted_text[admitted_text.index('extern "C" __global__ void'):]
    if launch_bounds:
        kernel = kernel.replace('extern "C" __global__ void', f'extern "C" __global__ void __launch_bounds__({launch_bounds})', 1)
    # The single group is called exactly once by the dispatcher; inlining it lets
    # the kernel's launch bounds govern its register allocation.
    body = body.replace("__device__ __noinline__ void", "__device__ __forceinline__ void", 1)
    prefix = raw_text[:parts[0].start()]
    report.update({"group": group, "symbol": re.search(r'extern "C" __global__ void (?:__launch_bounds__\([^)]*\) )?([A-Za-z0-9_]+)\(', kernel)[1],
                   "launch_bounds": launch_bounds})
    return MARKER + "\n" + prefix + body + kernel, report


def lower_plain(raw_text, launch_bounds):
    """Schedule a single-kernel `composition_codegen.emit` module in place."""
    entry = raw_text.index('extern "C" __global__ void')
    if "__device__ __noinline__" in raw_text or raw_text.count('extern "C" __global__ void') != 1:
        raise ValueError("expected one plain composition kernel")
    end = raw_text.index("\n}\n", entry) + 3
    body, report = schedule_group(raw_text[entry:end])
    if launch_bounds:
        body = body.replace('extern "C" __global__ void', f'extern "C" __global__ void __launch_bounds__({launch_bounds})', 1)
    report.update({"symbol": re.search(r'extern "C" __global__ void (?:__launch_bounds__\([^)]*\) )?([A-Za-z0-9_]+)\(', body)[1], "launch_bounds": launch_bounds})
    return MARKER + "\n" + raw_text[:entry] + body + raw_text[end:], report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("raw", type=Path, help="original case-N-domain.cu")
    ap.add_argument("admitted", type=Path, help="admitted single-group shard (raw or bank-lowered), or '-' for a plain kernel")
    ap.add_argument("output", type=Path)
    ap.add_argument("--launch-bounds", default="", help="e.g. '128' or '128,2'")
    ap.add_argument("--slice-ops", type=int, default=0, help="cut the group into noinline slices of about this many operations")
    args = ap.parse_args()
    if str(args.admitted) == "-":
        text, report = lower_plain(args.raw.read_text(), args.launch_bounds)
    else:
        text, report = lower_module(args.raw.read_text(), args.admitted.read_text(), args.launch_bounds, args.slice_ops)
    args.output.write_text(text)
    report["output_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    print(json.dumps(report))


if __name__ == "__main__":
    main()
