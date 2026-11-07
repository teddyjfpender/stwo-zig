"""Host checks for the M8 T5 register scheduler (no GPU).

The scheduled module must evaluate the same operations on the same operands.
Both programs are interpreted under one deterministic semantics (M31 base
arithmetic; any fixed 8-word product for OM31) and must produce the same
folded value; operation multisets, roots and the tail must be preserved.
GPU bit-exactness against the admitted objects is checked separately by
tests/cuda/rv64/aot_register_schedule/bench_truth.cu.
"""
import collections
import hashlib
from pathlib import Path
import random
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_cuda_aot_register_schedule as S

P = 2147483647


def om(*w):
    return tuple(x % P for x in w)


class Machine:
    """One fixed interpretation of the emitted SSA vocabulary."""

    def __init__(self, seed):
        rng = random.Random(seed)
        self.params = [om(*(rng.randrange(P) for _ in range(8))) for _ in range(64)]
        self.powers = [om(*(rng.randrange(P) for _ in range(8))) for _ in range(256)]
        self.seed = seed

    def load(self, tree, column, offset):
        # Independent of access order: the scheduled program reads in another order.
        return int.from_bytes(hashlib.sha256(f"{self.seed}/{tree}/{column}/{offset}".encode()).digest()[:8], "little") % P

    def namespace(self, consts):
        add = lambda a, b: om(*(x + y for x, y in zip(a, b)))
        sub = lambda a, b: om(*(x - y for x, y in zip(a, b)))
        # Not the OM31 product: any deterministic, non-commutative-free mixing
        # works, because both programs must apply the same op to the same values.
        mul = lambda a, b: om(*(sum(a[i] * b[(j - i) % 8] * (1 + i) for i in range(8)) for j in range(8)))
        return {
            "q_add": lambda a, b: (a + b) % P, "q_sub": lambda a, b: (a - b) % P, "q_mul": lambda a, b: (a * b) % P,
            "add": add, "sub": sub, "mul": mul, "scale": lambda a, s: om(*(x * s for x in a)),
            "base": lambda x: om(x, 0, 0, 0, 0, 0, 0, 0), "zero": lambda: om(*[0] * 8),
            "P_": lambda k: self.params[k // 8], "W_": lambda k: self.powers[k // 8], "C_": lambda name: consts[name],
            "L_": self.load,
        }


RELOAD_DECL = re.compile(r"\s*const (uint32_t|OM31) (v\d+(?:_r\d+)?)=(.*);$")


def postorder(lines, roots):
    """Root-first postorder of the declarations, as composition_codegen.schedule emits."""
    decl = {}
    for line in lines:
        m = S.DECL.match(line)
        if m:
            decl[m[2]] = line
    seen, order = set(), []
    def visit(v):
        if v in seen:
            return
        for c in S.VALUE.findall(S.DECL.match(decl[v])[3]):
            visit(c)
        seen.add(v)
        order.append(decl[v])
    for r in roots:
        visit(r)
    return [l for l in lines if not S.DECL.match(l)] + order


def to_python(expr):
    expr = re.sub(r"tree(\d)\[column_offsets\[(\d+)\]\+composition_mask_row\(row,trace_log,eval_log,(-?\d+)\)\]", r"L_(\1,\2,\3)", expr)
    expr = re.sub(r"from_words\(parameters\+(\d+)u\)", r"P_(\1)", expr)
    expr = re.sub(r"from_words\(powers\+(\d+)u\)", r"W_(\1)", expr)
    expr = re.sub(r"from_words\((c\d+)\)", r"C_('\1')", expr)
    expr = expr.replace("q::", "q_")
    expr = re.sub(r"\b(\d+)u\b", r"\1", expr)
    return expr


def evaluate(function_text, machine):
    consts = {}
    for name, words in re.findall(r"const uint32_t (c\d+)\[8\]=\{([^}]*)\};", function_text):
        consts[name] = om(*(int(w.rstrip("u")) for w in words.split(",")))
    env = machine.namespace(consts)
    folded = env["zero"]()
    for line in function_text.splitlines():
        m = RELOAD_DECL.match(line)
        if m:
            env[m[2]] = eval(to_python(m[3]), env)
            continue
        m = re.match(r"\s*folded=add\(folded,(.*)\);$", line)
        if m:
            folded = env["add"](folded, eval(to_python(m[1]), env))
    return folded


def synthetic(fractions=24, seed=7):
    """A grouped module shaped like a LogUp fraction sum: every denominator is
    used by both the numerator and the denominator chain (the Keccak case)."""
    rng = random.Random(seed)
    lines, v = [], [0]

    def new(kind, expr):
        v[0] += 1
        lines.append(f" const {kind} v{v[0]}={expr};")
        return f"v{v[0]}"

    lines.append(" const uint32_t c900[8]={0u,1u,0u,0u,0u,0u,0u,0u};")
    basis = new("OM31", "from_words(c900)")
    one = new("uint32_t", "1u")
    z = new("OM31", "from_words(parameters+8u)")
    alpha = new("OM31", "from_words(parameters+16u)")
    # Each fraction is folded in as it is produced (the native evaluator's
    # recording order): numerator N' = N*d + n*D and denominator D' = D*d both
    # read d and D, so the root-first postorder (all of D's chain first) keeps
    # every denominator live while recording order keeps O(1) of them.
    den = num = None
    for i in range(fractions):
        a = new("uint32_t", f"tree1[column_offsets[{2 * i}]+composition_mask_row(row,trace_log,eval_log,0)]")
        b = new("uint32_t", f"tree1[column_offsets[{2 * i + 1}]+composition_mask_row(row,trace_log,eval_log,{rng.choice([0, -1])})]")
        ab = new("uint32_t", f"q::mul({a},{b})")
        lifted = new("OM31", f"scale({basis},{ab})")
        d = new("OM31", f"sub(add(mul({alpha},base({a})),{lifted}),{z})")
        n = new("uint32_t", f"q::sub({b},{one})")
        if den is None:
            den, num = d, new("OM31", f"base({n})")
            continue
        num = new("OM31", f"add(mul({num},{d}),scale({den},{n}))")
        den = new("OM31", f"mul({den},{d})")
    prefix = new("uint32_t", "tree2[column_offsets[900]+composition_mask_row(row,trace_log,eval_log,0)]")
    root = new("OM31", f"sub(scale({den},{prefix}),{num})")
    small = new("uint32_t", f"q::sub({prefix},{one})")
    body = "\n".join(postorder(lines, [root, small]))
    roots = f" folded=add(folded,mul(from_words(powers+8u),{root}));\n folded=add(folded,scale(from_words(powers+0u),{small}));"
    head = "#include \"rv64/composition.cuh\"\nusing namespace stwo::cuda::rv64;\n__device__ __forceinline__ void t_add(uint32_t *p,uint32_t v){}\n"
    part = ("__device__ __noinline__ void t_part_0(const uint32_t *tree0,const uint32_t *tree1,const uint32_t *tree2,const uint64_t *column_offsets,"
            "const uint32_t *parameters,const uint32_t *powers,const uint32_t *denominator_inverses,uint32_t *output,uint32_t trace_log,uint32_t eval_log,uint32_t row){\n OM31 folded=zero();\n"
            + body + "\n" + roots + "\n const OM31 result=scale(folded,denominator_inverses[row>>trace_log]); const uint64_t stride=uint64_t(1)<<eval_log;\n"
            + "".join(f" t_add(output+{c}u*stride+row,coordinate(result,{c}u));\n" for c in range(8)) + "}\n")
    kernel = ('extern "C" __global__ void t_shard_0(const uint32_t *a,const uint32_t *b,const uint32_t *c,const uint64_t *offsets,const uint32_t *p,'
              'const uint32_t *powers,const uint32_t *inv,uint32_t *out,uint32_t tl,uint32_t el,uint32_t first,uint32_t rows){uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;'
              'if(i>=rows)return;switch(blockIdx.y){\n case 0u:t_part_0(a,b,c,offsets,p,powers,inv,out,tl,el,first+i);return;\n}}\n')
    return head + part + kernel, part


def operations(text):
    """Multiset of (kind, op expression) with reload names folded back."""
    out = collections.Counter()
    for line in text.splitlines():
        m = S.DECL.match(line)
        if m and not re.match(r"(tree|from_words\(parameters)", m[3]):
            out[(m[1], re.sub(r"\b(v\d+)_r\d+\b", r"\1", m[3]))] += 1
    return out


class Scheduler(unittest.TestCase):
    def test_same_operations_same_value_lower_peak(self):
        raw, part = synthetic()
        lowered, report = S.lower_module(raw, raw, "128,2")
        self.assertTrue(lowered.startswith(S.MARKER))
        self.assertIn('__launch_bounds__(128,2) t_shard_0(', lowered)
        self.assertIn("__device__ __forceinline__ void t_part_0(", lowered)
        self.assertLess(report[report["selected"]]["peak_live_words"], report["postorder"]["peak_live_words"])
        start = lowered.index("t_part_0(")
        scheduled = lowered[lowered.rfind("__device__", 0, start):lowered.index('extern "C"', start)]
        self.assertEqual(operations(part), operations(scheduled))
        for seed in range(4):
            self.assertEqual(evaluate(part, Machine(seed)), evaluate(scheduled, Machine(seed)))
        self.assertEqual(part.count("t_add(output+"), scheduled.count("t_add(output+"))
        self.assertEqual(sorted(re.findall(r"folded=add\(folded,.*\);", part)),
                         sorted(re.sub(r"\b(v\d+)_r\d+\b", r"\1", x) for x in re.findall(r"folded=add\(folded,.*\);", scheduled)))

    def test_inputs_and_parameters_are_reloaded_at_use(self):
        raw, _ = synthetic(4)
        lowered, _ = S.lower_module(raw, raw, "")
        body = lowered[lowered.index("t_part_0("):lowered.index('extern "C"')]
        # every consumer reads a fresh reload; no original input name survives as an operand
        for line in body.splitlines():
            m = S.DECL.match(line)
            if m and not m[2].count("_r"):
                self.assertFalse(re.search(r"tree\d\[", m[3]), line)

    def test_rejects_multi_group_and_mismatched_raw(self):
        raw, _ = synthetic(2)
        two = raw.replace(" case 0u:", " case 0u:t_part_0(a,b,c,offsets,p,powers,inv,out,tl,el,first+i);return;\n case 1u:")
        doubled = two.replace('extern "C"', raw[raw.index("__device__ __noinline__"):raw.index('extern "C"')].replace("t_part_0", "t_part_1") + 'extern "C"')
        with self.assertRaises(ValueError):
            S.lower_module(doubled, doubled, "")
        with self.assertRaises(ValueError):
            S.lower_module(raw.replace("t_part_0", "u_part_0"), raw, "")

    def test_slices_keep_every_operation_and_root(self):
        raw, part = synthetic(24)
        lowered, report = S.lower_module(raw, raw, "128,4", slice_ops=40)
        self.assertGreater(report["slices"], 2)
        region = lowered[lowered.index("__device__ __noinline__ OM31"):lowered.index('extern "C"')]
        def ops(text):
            out = collections.Counter()
            for line in text.splitlines():
                m = S.DECL.match(line)
                if m and not re.match(r"(tree|from_words\(parameters|t5_[be]i\[|\d+u$|from_words\(c\d+\)$)", m[3]):
                    out[(m[1], re.sub(r"\b(v\d+)_r\d+\b", r"\1", m[3]))] += 1
            return out
        self.assertEqual(ops(part), ops(region))
        roots = lambda text: sorted(re.sub(r"\b(v\d+)_r\d+\b", r"\1", x) for x in re.findall(r"folded=add\(folded,(?:mul|scale)\(from_words\(powers\+\d+u\),v[0-9_r]+\)\);", text))
        self.assertEqual(roots(part), roots(region))
        # every carried load in slice k reads a slot that slice k-1 stored (ping-pong arrays)
        slices = re.split(r"__device__ __noinline__ OM31 ", region)[1:]
        for k in range(1, len(slices)):
            stored = set(re.findall(r"t5_([be])o\[(\d+)\]=", slices[k - 1]))
            loaded = set(re.findall(r"=t5_([be])i\[(\d+)\]", slices[k]))
            self.assertLessEqual(loaded, stored)
        self.assertEqual(region.count("folded=add(folded,t_part_0_s"), report["slices"])
        self.assertEqual(lowered.count("t_part_0_s0(tree0"), 1)

    def test_parameter_staging_precedes_row_check(self):
        raw, part = synthetic(5)
        lowered, report = S.lower_module(raw, raw, "128,4", stage=True)
        kernel = lowered[lowered.index('extern "C"'):]
        self.assertEqual(report["staged_parameter_words"], 24)  # parameters+16u is the largest OM31 read
        self.assertLess(kernel.index("__syncthreads();"), kernel.index("if(i>=rows)return;"))
        self.assertIn("t_part_0(a,b,c,offsets,t5_parameters,powers", kernel)
        self.assertIn("t5_parameters[j]=p[j]", kernel)
        start = lowered.index("t_part_0(")
        scheduled = lowered[lowered.rfind("__device__", 0, start):lowered.index('extern "C"', start)]
        self.assertEqual(evaluate(part, Machine(2)), evaluate(scheduled, Machine(2)))

    def test_plain_kernel(self):
        raw, part = synthetic(3)
        body = part[part.index("{\n") + 2:part.rindex(" const OM31 result=")]
        plain = ('#include "rv64/composition.cuh"\nusing namespace stwo::cuda::rv64;\nextern "C" __global__ void p_k(const uint32_t *tree0,const uint32_t *tree1,const uint32_t *tree2,\n'
                 'const uint64_t *column_offsets,const uint32_t *parameters,const uint32_t *powers,\nconst uint32_t *denominator_inverses,uint32_t *output,uint32_t trace_log,uint32_t eval_log,\n'
                 'uint32_t first_row,uint32_t rows) {\n const uint32_t local=blockIdx.x*blockDim.x+threadIdx.x;\n if(local>=rows) return;\n const uint32_t row=first_row+local;\n'
                 + body + " const OM31 result=scale(folded,denominator_inverses[row>>trace_log]);\n const uint64_t stride=uint64_t(1)<<eval_log;\n"
                 " store(output,stride,row,add(load(output,stride,row),result));\n}\n")
        lowered, report = S.lower_plain(plain, "128,4")
        self.assertIn("__launch_bounds__(128,4) p_k(", lowered)
        self.assertEqual(evaluate(plain, Machine(1)), evaluate(lowered, Machine(1)))
        self.assertEqual(report["symbol"], "p_k")


if __name__ == "__main__":
    unittest.main()
