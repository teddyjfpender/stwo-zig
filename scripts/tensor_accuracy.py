#!/usr/bin/env python3
"""Accuracy of the proved integer model vs the float model (tensor frontend).

Takes a public llama2.c checkpoint (Llama architecture: GQA, RMSNorm, RoPE,
SwiGLU), runs a float32 reference forward in numpy, quantizes it into exactly
the integer model `src/tensor/lm.zig` proves (int8 weights and activations,
power-of-two requant shift plan, RMSNorm via isqrt / reciprocal, RoPE table,
exp-table softmax with the division inequality, SiLU table, int8 LM head with
least-maximiser greedy), runs a bit-exact numpy emulation of that integer
forward, and reports agreement metrics. `tensor-accuracy` (Zig) replays the
same model file and windows through `lm.buildModel`; `compare` checks the
emulation against it bit for bit; Zig proves + verifies some requests.

Run with `python3 -I`. Downloaded files are data only (parsed with struct /
numpy; nothing is imported or executed from them).

  prepare  --ckpt stories260K.bin --tok tok512.bin --corpus text.txt --out DIR
  export   --dir DIR --config NAME        model.bin (+ windows) for tensor-accuracy
  eval     --dir DIR --config NAME [--plan zig_plan.bin]  metrics JSON
  compare  --dir DIR --config NAME --zig zig_out.bin

Configs (see design/tensor-frontend/accuracy.md):
  matched-h0 / matched-h1   int8 model with a scale-matched plan (residual,
                            softmax temperature and SiLU scales match the
                            float model); h = headroom bits on data-chosen shifts
  lmcal-h1                  per-tensor max-abs int8 weights, every shift from
                            lm.calibrate (Zig plan file) -- the "naive" path
  wide-a12r16               EMULATION ONLY (not implemented in Zig, not proved):
                            12-bit activations, 16-bit residual increments
"""
import argparse
import json
import math
import os
import struct
import sys

import numpy as np

# ---------------------------------------------------------------------------
# checkpoint / tokenizer (llama2.c formats)


def load_ckpt(path):
    raw = open(path, "rb").read()
    dim, hidden, n_layers, n_heads, n_kv, vocab, seq_len = struct.unpack("7i", raw[:28])
    shared = vocab > 0
    vocab = abs(vocab)
    w = np.frombuffer(raw[28:], dtype="<f4")
    hs = dim // n_heads
    kv_dim = n_kv * hs
    off = 0

    def take(*shape):
        nonlocal off
        n = int(np.prod(shape))
        a = w[off:off + n].reshape(shape).astype(np.float32)
        off += n
        return a

    m = dict(dim=dim, hidden=hidden, n_layers=n_layers, n_heads=n_heads, n_kv=n_kv, vocab=vocab, seq_len=seq_len)
    m["emb"] = take(vocab, dim)
    m["rms_att"] = take(n_layers, dim)
    m["wq"] = take(n_layers, dim, dim)
    m["wk"] = take(n_layers, kv_dim, dim)
    m["wv"] = take(n_layers, kv_dim, dim)
    m["wo"] = take(n_layers, dim, dim)
    m["rms_ffn"] = take(n_layers, dim)
    m["w1"] = take(n_layers, hidden, dim)
    m["w2"] = take(n_layers, dim, hidden)
    m["w3"] = take(n_layers, hidden, dim)
    m["rms_final"] = take(dim)
    take(seq_len, hs // 2)
    take(seq_len, hs // 2)
    m["wcls"] = m["emb"] if shared else take(vocab, dim)
    assert off == w.size, (off, w.size)
    return m


def load_tok(path, vocab):
    raw = open(path, "rb").read()
    (max_len,) = struct.unpack("i", raw[:4])
    p = 4
    pieces, scores = [], []
    for _ in range(vocab):
        (sc,) = struct.unpack("f", raw[p:p + 4])
        (ln,) = struct.unpack("i", raw[p + 4:p + 8])
        pieces.append(raw[p + 8:p + 8 + ln].decode("utf-8", "replace"))
        scores.append(sc)
        p += 8 + ln
    return pieces, scores


def encode(text, pieces, scores, lookup):
    """llama2.c run.c encode(): BOS, dummy prefix, codepoints (byte fallback +3), greedy best-score merges."""
    toks = [1]
    if text:
        toks.append(lookup[" "])
    for ch in text:
        if ch in lookup:
            toks.append(lookup[ch])
        else:
            toks.extend(b + 3 for b in ch.encode("utf-8"))
    while True:
        best, bi, bid = -1e10, -1, -1
        for i in range(len(toks) - 1):
            s = pieces[toks[i]] + pieces[toks[i + 1]]
            j = lookup.get(s)
            if j is not None and scores[j] > best:
                best, bi, bid = scores[j], i, j
        if bi < 0:
            break
        toks[bi:bi + 2] = [bid]
    return toks


# ---------------------------------------------------------------------------
# float32 reference (llama2.c run.c semantics)


def rms(x, g, eps=1e-5):
    return (x / np.sqrt(np.mean(x * x, axis=-1, keepdims=True) + eps)) * g


def rope_f(x, n_h, hs):
    B, T, _ = x.shape
    x = x.reshape(B, T, n_h, hs // 2, 2)
    i = np.arange(hs // 2)
    freq = 1.0 / (10000.0 ** (2 * i / hs))
    ang = np.arange(T)[:, None] * freq[None, :]
    c = np.cos(ang).astype(np.float32)[None, :, None, :]
    s = np.sin(ang).astype(np.float32)[None, :, None, :]
    x0, x1 = x[..., 0], x[..., 1]
    return np.stack([x0 * c - x1 * s, x0 * s + x1 * c], axis=-1).reshape(B, T, n_h * hs)


def float_forward(m, toks):
    D, H, KV = m["dim"], m["n_heads"], m["n_kv"]
    hs = D // H
    rep = H // KV
    B, T = toks.shape
    x = m["emb"][toks]
    rec = {"resid": [], "ao": [], "mo": [], "q": [], "k": [], "v": [], "att_logit": [], "gate": [], "up": []}
    mask = np.triu(np.full((T, T), -np.inf, dtype=np.float32), 1)
    for l in range(m["n_layers"]):
        xn = rms(x, m["rms_att"][l])
        q = xn @ m["wq"][l].T
        k = xn @ m["wk"][l].T
        v = xn @ m["wv"][l].T
        rec["q"].append(q)
        rec["k"].append(k)
        rec["v"].append(v)
        qr = rope_f(q, H, hs).reshape(B, T, H, hs)
        kr = rope_f(k, KV, hs).reshape(B, T, KV, hs)
        kr = np.repeat(kr, rep, axis=2)
        vv = np.repeat(v.reshape(B, T, KV, hs), rep, axis=2)
        sc = np.einsum("bthe,bjhe->bhtj", qr, kr) / np.sqrt(hs)
        rec["att_logit"].append(sc + mask)
        sc = sc + mask
        sc = sc - sc.max(-1, keepdims=True)
        p = np.exp(sc)
        p /= p.sum(-1, keepdims=True)
        o = np.einsum("bhtj,bjhe->bthe", p, vv).reshape(B, T, D)
        ao = o @ m["wo"][l].T
        rec["ao"].append(ao)
        x = x + ao
        xn = rms(x, m["rms_ffn"][l])
        g = xn @ m["w1"][l].T
        u = xn @ m["w3"][l].T
        rec["gate"].append(g)
        rec["up"].append(u)
        mo = (g / (1 + np.exp(-g)) * u) @ m["w2"][l].T
        rec["mo"].append(mo)
        x = x + mo
        rec["resid"].append(x)
    logits = rms(x, m["rms_final"]) @ m["wcls"].T
    return logits.astype(np.float32), rec


# ---------------------------------------------------------------------------
# integer model (bit-exact emulation of lm.buildModel, dense, unfused QKV)


def requant(acc, s):
    acc = np.asarray(acc, dtype=np.int64)
    if s == 0:
        return acc
    return (acc + (1 << (s - 1))) >> s


def choose_shift_sym(acc, bits=8):
    """model.chooseShift (int8) generalised to `bits`: smallest s >= 1 with requant in range."""
    mx = int(np.max(np.abs(acc))) if acc.size else 0
    top = (1 << (bits - 1)) - 1
    for s in range(1, 30):
        if mx <= (top << s) - (1 << (s - 1)):
            return s
    return 30


def choose_shift_bits(acc, ob):
    """transformer.chooseShiftBits: asymmetric range [-2^(ob-1), 2^(ob-1))."""
    mx = max(0, int(acc.max()))
    mn = min(0, int(acc.min()))
    lim = 1 << (ob - 1)
    for s in range(1, 21):
        if requant(mx, s) < lim and requant(mn, s) >= -lim:
            return s
    raise OverflowError("RequantOverflow")


def exp_table(log=10):
    d = np.arange(1 << log)
    return np.where(d < 256, np.round(256.0 * np.exp(-d / 16.0)), 0).astype(np.int64)


def silu_table(bits=8, frac=4):
    n = 1 << bits
    v = (np.arange(n) - n // 2) / float(1 << frac)
    s = v / (1 + np.exp(-v))
    # Zig: @round (half away from zero); numpy rounds half to even
    q = np.sign(s * (1 << frac)) * np.floor(np.abs(s * (1 << frac)) + 0.5)
    return np.clip(q, -(n // 2), n // 2 - 1).astype(np.int64)


def zround(x):
    """Zig @round: half away from zero."""
    return np.sign(x) * np.floor(np.abs(x) + 0.5)


def rope_table(T, dh):
    half = dh // 2
    R = np.zeros((T, half, 2, 2), dtype=np.int64)
    for t in range(T):
        for i in range(half):
            th = t * math.pow(10000.0, -2.0 * i / dh)
            c = int(zround(128.0 * math.cos(th)))
            s = int(zround(128.0 * math.sin(th)))
            R[t, i] = [[c, -s], [s, c]]
    return R


def isqrt_vec(n):
    n = n.astype(np.int64)
    r = np.floor(np.sqrt(n.astype(np.float64))).astype(np.int64)
    r = np.where(r * r > n, r - 1, r)
    r = np.where((r + 1) * (r + 1) <= n, r + 1, r)
    return r


class Refuse:
    """Per-window refusal tracking: the prover refuses a window whose values leave the plan's ranges."""

    def __init__(self, B):
        self.bad = np.zeros(B, dtype=bool)
        self.where = {}

    def check(self, name, v, lo, hi):
        ax = tuple(range(1, v.ndim))
        b = ((v < lo) | (v > hi)).any(axis=ax) if v.ndim > 1 else (v < lo) | (v > hi)
        new = b & ~self.bad
        if new.any():
            self.where[name] = self.where.get(name, 0) + int(new.sum())
        self.bad |= b


class Cfg:
    def __init__(self, name):
        self.name = name
        self.mode = "matched"  # or "lmcal"
        self.headroom = 0
        self.A = 8  # activation bits (matmul inputs / outputs)
        self.R = 8  # residual increment + embedding bits
        self.S = 8  # attention score bits
        self.silu_bits = 8
        self.silu_frac = 4
        self.u_shift = 6
        self.inv_bits = 15  # LayerCfg.INV_BITS
        self.margin = 1.05
        self.G = 64
        # proved wide widths (Zig lm.ModelCfg.act_bits / resid_bits): the
        # RMSNorm constants of transformer.rmsParams and int8 logits
        self.zig_wide = False
        self.logit_bits = None  # None: A bits (emulation); 8 in Zig


CONFIGS = {}


def _cfg(name, mode="matched", h=0, S=8, A=8, R=8, zig=False):
    c = Cfg(name)
    c.mode, c.headroom, c.S, c.A, c.R = mode, h, S, A, R
    if A > 8:  # wider SiLU table (same +-8 range, finer), finer RMSNorm reciprocal / u
        c.silu_bits, c.silu_frac, c.inv_bits = A, A - 4, 15 + 2 * (A - 8)
        c.u_shift = c.inv_bits - 4 - 10  # u = 2^10 x / rms (16-bit), was 2^5
    if zig:
        c.zig_wide = True
        c.logit_bits = 8
        if A > 8:  # transformer.LayerCfg.INV_BITS_WIDE / U_SHIFT_WIDE
            c.inv_bits, c.u_shift = 21, 10
    CONFIGS[name] = c


# implemented in Zig (lm.ModelCfg.score_bits), proved
_cfg("lmcal-h1", "lmcal", 1)
_cfg("lmcal-s13-h1", "lmcal", 1, S=13)
_cfg("matched-s8-h0", S=8)
_cfg("matched-s13-h0", S=13)
_cfg("matched-s13-h1", h=1, S=13)
# emulation only (no Zig / proof support)
_cfg("emu-s13-r16-h0", S=13, R=16)
_cfg("emu-a12-s13-r16-h0", S=13, A=12, R=16)
_cfg("emu-a16-s13-r16-h0", S=13, A=16, R=16)
# implemented in Zig (lm.ModelCfg.act_bits / resid_bits), proved
_cfg("matched-a12-s13-r16-h0", S=13, A=12, R=16, zig=True)
_cfg("matched-a12-s13-r16-h1", h=1, S=13, A=12, R=16, zig=True)
_cfg("matched-a10-s13-r16-h0", S=13, A=10, R=16, zig=True)
_cfg("matched-a8-s13-r16-h0", S=13, A=8, R=16, zig=True)


def pad_to(a, shape):
    out = np.zeros(shape, dtype=a.dtype)
    out[tuple(slice(0, s) for s in a.shape)] = a
    return out


class IntModel:
    """Integer model + its quantization. Shapes padded to powers of two.

    Calibration (`calib=True` forward on a batch): every shift is decided stage
    by stage on the whole calibration batch (data-chosen shifts: the record
    rule of the Zig builder, max over the batch, + headroom), weights are
    quantized when their op is reached (scale-matched targets need the input
    scale). Replay (`calib=False`): the stored plan and weights; values outside
    the plan's ranges mark the window refused (Zig: error.RequantOverflow).
    """

    def __init__(self, m, cfg, log_t):
        self.cfg = cfg
        self.fm = m
        self.D = m["dim"]
        self.lD = int(math.ceil(math.log2(self.D)))
        self.Dp = 1 << self.lD
        self.H, self.KV = m["n_heads"], m["n_kv"]
        self.lH = int(math.ceil(math.log2(self.H)))
        self.lKV = int(math.ceil(math.log2(self.KV)))
        assert (1 << self.lH) == self.H and (1 << self.lKV) == self.KV and self.Dp == self.D, "only power-of-two D / heads"
        self.dh = self.D // self.H
        self.lF = int(math.ceil(math.log2(m["hidden"])))
        self.Fp = 1 << self.lF
        self.lV = int(math.ceil(math.log2(m["vocab"])))
        self.Vp = 1 << self.lV
        self.L = m["n_layers"]
        self.log_t = log_t
        self.T = 1 << log_t
        self.W = {}  # name -> int weights [K, N]
        self.wscale = {}
        self.shift = {}  # name -> shift
        self.scale = {}  # name -> float scale of the op's output
        self.clipped = {}
        self.R_tab = rope_table(self.T, self.dh)
        self.E_tab = exp_table(cfg.S + 2)
        self.silu = silu_table(cfg.silu_bits, cfg.silu_frac)
        self.f_stats = None  # float calibration stats (matched mode)

    # canonical plan order of lm.buildModel (dense layers, unfused QKV)
    def plan_names(self):
        out = []
        for l in range(self.L):
            if l > 0 or self.cfg.R > self.cfg.A:
                out.append(f"l{l}.rms1.s0")
            out += [f"l{l}.rms1.y", f"l{l}.q", f"l{l}.k", f"l{l}.v", f"l{l}.S", f"l{l}.o", f"l{l}.rms2.s0", f"l{l}.rms2.y", f"l{l}.gate", f"l{l}.up", f"l{l}.had", f"l{l}.down"]
        return out + ["head.s0", "head.y", "logits"]

    def plan(self):
        return [self.shift[n] for n in self.plan_names()]

    def set_plan(self, shifts):
        names = self.plan_names()
        assert len(shifts) == len(names), (len(shifts), len(names))
        for n, s in zip(names, shifts):
            self.shift[n] = int(s)

    # --- weights ------------------------------------------------------------

    def eff_weight(self, name):
        """Float weight [K, N] as the integer op sees it (gains folded into the rows)."""
        m = self.fm
        if name == "logits":
            return pad_to((m["wcls"] * m["rms_final"][None, :]).T, (self.Dp, self.Vp))
        l = int(name.split(".")[0][1:])
        op = name.split(".")[1]
        g1, g2 = m["rms_att"][l][:, None], m["rms_ffn"][l][:, None]
        if op == "q":
            return m["wq"][l].T * g1
        if op == "k":
            return m["wk"][l].T * g1
        if op == "v":
            return m["wv"][l].T * g1
        if op == "o":
            return m["wo"][l].T
        if op == "gate":
            return pad_to(m["w1"][l].T * g2, (self.Dp, self.Fp))
        if op == "up":
            return pad_to(m["w3"][l].T * g2, (self.Dp, self.Fp))
        if op == "down":
            return pad_to(m["w2"][l].T, (self.Fp, self.Dp))
        raise KeyError(name)

    def quant_free(self, name):
        Wf = self.eff_weight(name)
        sc = float(np.abs(Wf).max()) / 127.0
        self.W[name] = np.clip(zround(Wf / sc), -127, 127).astype(np.int64)
        self.wscale[name] = sc

    def quant_target(self, name, s_in, s_out):
        """Choose (shift, weight scale) so the op's output scale is exactly s_out."""
        Wf = self.eff_weight(name)
        mw = float(np.abs(Wf).max())
        sh = int(math.floor(math.log2(s_out * 127.0 / (s_in * mw))))
        sh = min(30, max(1, sh))
        sc = s_out / (s_in * (1 << sh))
        Wi = zround(Wf / sc)
        self.clipped[name] = int((np.abs(Wi) > 127).sum())
        self.W[name] = np.clip(Wi, -127, 127).astype(np.int64)
        self.wscale[name] = sc
        self.shift[name] = sh
        self.scale[name] = s_out

    # --- ops ------------------------------------------------------------------

    def matmul(self, name, x, s_in, calib, rf, target=None, bits=None):
        bits = bits or self.cfg.A
        if calib:
            if target is not None:
                self.quant_target(name, s_in, target)
            else:
                if name not in self.W:
                    self.quant_free(name)
        acc = x @ self.W[name]
        if calib and target is None and name not in self.shift:
            self.shift[name] = min(30, choose_shift_sym(acc, bits) + self.cfg.headroom)
            self.scale[name] = s_in * self.wscale[name] * (1 << self.shift[name])
        y = requant(acc, self.shift[name])
        lim = 1 << (bits - 1)
        rf.check(name, y, -lim, lim - 1)
        return y, acc

    def rmsnorm(self, name, x, x_int8, calib, rf):
        cfg = self.cfg
        A = cfg.A
        lim = 1 << (A - 1)
        if x_int8:
            rf.check(name + ".in", x, -lim, lim - 1)
            xs = x
        else:
            if calib:
                s0 = 0
                while True:
                    v = requant(np.array([x.max(), x.min()]), s0)
                    if v[0] <= lim - 1 and v[1] >= -lim:
                        break
                    s0 += 1
                self.shift[name + ".s0"] = min(30, s0 + cfg.headroom)
            xs = requant(x, self.shift[name + ".s0"])
            rf.check(name + ".s0", xs, -lim, lim - 1)
        ld = self.lD
        s1 = ld - 8 if ld >= 8 else 0
        m1 = 8 - ld if ld < 8 else 0
        ceps = 1 << s1
        if cfg.zig_wide and A > 8:  # transformer.rmsParams
            d = ld + 2 * A - 27
            s1, m1 = max(d, 0), max(-d, 0)
            ceps = 1 << (12 + s1 - m1)
        ss = (xs * xs).sum(-1)
        rt = isqrt_vec(((ss + ceps) << m1) >> s1)
        inv = (1 << cfg.inv_bits) // rt
        u = requant(xs * inv[..., None], cfg.u_shift)
        rf.check(name + ".u", u, -(1 << 15), (1 << 15) - 1)
        acc = u * cfg.G
        if calib:
            self.shift[name + ".y"] = min(30, choose_shift_bits(acc, A) + cfg.headroom)
        y = requant(acc, self.shift[name + ".y"])
        rf.check(name + ".y", y, -lim, lim - 1)
        # float scale of y in units of the normalised (pre-gain) activation
        # rt ~ 16 rms(xs), inv ~ 2^(K-4) / rms, u ~ 2^(K-4-u_shift) x / rms
        if cfg.zig_wide:  # rt ~ rms(xs) sqrt(D 2^(m1 - s1)) exactly (up to eps / rounding)
            s_y = (1 << self.shift[name + ".y"]) / (float(1 << (cfg.inv_bits - cfg.u_shift)) / math.sqrt(self.D * 2.0 ** (m1 - s1)) * cfg.G)
        else:
            s_y = (1 << self.shift[name + ".y"]) / (float(1 << (cfg.inv_bits - 4 - cfg.u_shift)) * cfg.G)
        return y, s_y

    def rope(self, x, nh, rf, name):
        B, T, _ = x.shape
        xr = x.reshape(B, T, nh, self.dh // 2, 2)
        R = self.R_tab[:T]  # [T, half, bo, bi]
        acc = np.einsum("zthic,tioc->zthio", xr, R)
        y = requant(acc, 7)
        lim = 1 << self.cfg.A  # 9-bit output for A = 8
        rf.check(name, y, -lim, lim - 1)
        return y.reshape(B, T, nh * self.dh)

    def forward(self, toks, calib=False, head_last=None):
        """head_last = k: the head runs on the last k positions only (as lm.buildModel:
        2^max(log_out, 1) rows); None: every position (accuracy metrics)."""
        cfg = self.cfg
        B, T = toks.shape
        rf = Refuse(B)
        fs = self.f_stats
        rec = {"resid": [], "logit_scale": None}
        if calib:
            if cfg.mode == "matched":
                # residual stream scale: every increment and the embedding fit R bits
                rmax = max([float(np.abs(self.fm["emb"]).max())] + [fs["ao"][l] for l in range(self.L)] + [fs["mo"][l] for l in range(self.L)])
                self.s_r = rmax * cfg.margin / ((1 << (cfg.R - 1)) - 1)
            else:
                self.s_r = float(np.abs(self.fm["emb"]).max()) / 127.0
            lim = (1 << (cfg.R - 1)) - 1
            self.W["emb"] = np.clip(zround(self.fm["emb"] / self.s_r), -lim, lim).astype(np.int64)
            self.W["emb"] = pad_to(self.W["emb"], (self.Vp, self.Dp))
        x = self.W["emb"][toks]
        s_r = self.s_r
        T_ = T
        bias = np.where(np.arange(T_)[None, :] <= np.arange(T_)[:, None], 0, -((1 << cfg.S) + 256)).astype(np.int64)
        lg = self.lH - self.lKV
        for l in range(self.L):
            p = f"l{l}"
            y1, s_y1 = self.rmsnorm(p + ".rms1", x, l == 0 and cfg.R <= cfg.A, calib, rf)
            v, _ = self.matmul(p + ".v", y1, s_y1, calib, rf, target=None)
            if calib and cfg.mode == "matched":
                # softmax temperature exact: s_q s_k 2^sS = sqrt(dh) / 16 (S in 1/16 nat);
                # sS >= 1 integer, the spare factor X >= 1 is split evenly (headroom)
                c = math.sqrt(self.dh) / 16.0
                top = (1 << (cfg.A - 1)) - 1
                s_qmin = fs["q"][l] * cfg.margin / top
                s_kmin = fs["k"][l] * cfg.margin / top
                sS = max(1, int(math.floor(math.log2(c / (s_kmin * s_qmin)))))  # sS = 1 and X < 1: q/k overflow (refusal)
                X = c / ((1 << sS) * s_qmin * s_kmin)
                self.shift[p + ".S"] = sS
                self.qk_spare = getattr(self, "qk_spare", {})
                self.qk_spare[l] = X
                k, _ = self.matmul(p + ".k", y1, s_y1, calib, rf, target=s_kmin * math.sqrt(X))
                q, _ = self.matmul(p + ".q", y1, s_y1, calib, rf, target=s_qmin * math.sqrt(X))
            else:
                k, _ = self.matmul(p + ".k", y1, s_y1, calib, rf, target=None)
                q, _ = self.matmul(p + ".q", y1, s_y1, calib, rf, target=None)
            qr = self.rope(q, self.H, rf, p + ".ropeq")
            kr = self.rope(k, self.KV, rf, p + ".ropek")
            qh = qr.reshape(B, T, 1 << self.lKV, 1 << lg, self.dh)
            kh = kr.reshape(B, T, 1 << self.lKV, self.dh)
            sacc = np.einsum("btkge,bjke->bkgtj", qh, kh).reshape(B, self.H, T, T)
            if calib and cfg.mode != "matched":
                self.shift[p + ".S"] = min(30, choose_shift_bits(sacc, cfg.S) + cfg.headroom)
            S = requant(sacc, self.shift[p + ".S"])
            slim = 1 << (cfg.S - 1)
            rf.check(p + ".S", S, -slim, slim - 1)
            val = S + bias
            mrow = val.max(-1, keepdims=True)
            d = mrow - val
            d = np.clip(d, 0, (1 << (cfg.S + 2)) - 1)  # only refused windows (S out of range) can leave the domain
            e = self.E_tab[d]
            den = e.sum(-1)  # [B, H, T]
            vh = v.reshape(B, T, 1 << self.lKV, self.dh)
            eg = e.reshape(B, 1 << self.lKV, 1 << lg, T, T)
            acc = np.einsum("bkgtj,bjkc->btkgc", eg, vh).reshape(B, T, self.H, self.dh)
            dn = den.transpose(0, 2, 1)[..., None]  # [B, T, H, 1]
            o = np.floor_divide(2 * acc + dn, 2 * dn).reshape(B, T, self.D)
            s_v = self.scale.get(p + ".v")
            matched = cfg.mode == "matched"
            ao, _ = self.matmul(p + ".o", o, s_v, calib, rf, target=s_r if calib and matched else None, bits=cfg.R if matched else cfg.A)
            h = x + ao
            y2, s_y2 = self.rmsnorm(p + ".rms2", h, False, calib, rf)
            if calib and cfg.mode == "matched":
                g, _ = self.matmul(p + ".gate", y2, s_y2, calib, rf, target=1.0 / (1 << cfg.silu_frac), bits=cfg.silu_bits)
            else:
                g, _ = self.matmul(p + ".gate", y2, s_y2, calib, rf, target=None, bits=cfg.silu_bits)
            u, _ = self.matmul(p + ".up", y2, s_y2, calib, rf, target=None)
            n = 1 << cfg.silu_bits
            act = self.silu[np.clip(g, -(n // 2), n // 2 - 1) + n // 2]
            hacc = act * u
            if calib:
                self.shift[p + ".had"] = min(30, choose_shift_sym(hacc, cfg.A) + cfg.headroom)
                self.scale[p + ".had"] = self.scale[p + ".up"] / (1 << cfg.silu_frac) * (1 << self.shift[p + ".had"])
            hm = requant(hacc, self.shift[p + ".had"])
            lim = 1 << (cfg.A - 1)
            rf.check(p + ".had", hm, -lim, lim - 1)
            s_hm = self.scale.get(p + ".had")
            mo, _ = self.matmul(p + ".down", hm, s_hm, calib, rf, target=s_r if calib and matched else None, bits=cfg.R if matched else cfg.A)
            x = h + mo
            rec["resid"].append(x)
        xh = x if head_last is None else x[:, -head_last:]
        yf, s_yf = self.rmsnorm("head", xh, False, calib, rf)
        logits, lacc = self.matmul("logits", yf, s_yf, calib, rf, target=None, bits=cfg.logit_bits)
        rec["logit_scale"] = s_yf * self.wscale["logits"] * (1 << self.shift["logits"])
        rec["logit_acc_scale"] = None if "logits" not in self.wscale else s_yf * self.wscale["logits"]
        rec["logit_acc"] = lacc
        return logits, rf, rec


def float_stats(m, toks):
    _, r = float_forward(m, toks)
    return {k: [float(np.abs(a).max()) for a in r[k]] for k in ("ao", "mo", "q", "k", "v", "gate")}


def build_int(m, cfg, calib_toks, log_t, zig_plan=None):
    im = IntModel(m, cfg, log_t)
    im.f_stats = float_stats(m, calib_toks)
    im.forward(calib_toks, calib=True)
    if zig_plan is not None:
        im.set_plan(zig_plan)
    return im


# ---------------------------------------------------------------------------
# metrics


def softmax(z):
    z = z - z.max(-1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(-1, keepdims=True)


def least_argmax(L):
    return np.argmax(L, axis=-1)  # numpy argmax returns the first maximiser


def topk_stable(L, k):
    # order by (-value, index): stable sort of -L
    return np.argsort(-L, axis=-1, kind="stable")[..., :k]


def metrics(m, im, toks):
    V = m["vocab"]
    fl, frec = float_forward(m, toks)
    il, rf, irec = im.forward(toks, calib=False)
    ok = ~rf.bad
    il = il[..., :V].astype(np.float64)
    lacc = irec["logit_acc"][..., :V].astype(np.float64)
    out = {"windows": int(toks.shape[0]), "T": int(toks.shape[1]), "refused_windows": int(rf.bad.sum()), "refused_at": rf.where}
    if ok.sum() == 0:
        return out
    fl, il, lacc = fl[ok], il[ok], lacc[ok]
    ft = least_argmax(fl)
    it = least_argmax(il)
    at = least_argmax(lacc)
    out["positions"] = int(ft.size)
    out["top1_agree"] = float((ft == it).mean())
    out["top1_agree_last_pos"] = float((ft[:, -1] == it[:, -1]).mean())
    out["top1_agree_acc_logits"] = float((ft == at).mean())
    # refused windows counted as disagreement at every position (the prover returns no token there);
    # the metrics above are over the non-refused windows only, which are easier than the refused ones
    n_all = int(toks.shape[0])
    out["top1_agree_all_windows"] = float((ft == it).sum() / (n_all * toks.shape[1]))
    out["top1_agree_last_pos_all_windows"] = float((ft[:, -1] == it[:, -1]).sum() / n_all)
    # ties at the int8 maximum (the least maximiser is taken)
    mx = il.max(-1, keepdims=True)
    out["mean_int8_ties_at_max"] = float((il == mx).sum(-1).mean())
    f5 = topk_stable(fl, 5)
    i5 = topk_stable(il, 5)
    ov = np.array([len(set(a) & set(b)) for a, b in zip(f5.reshape(-1, 5), i5.reshape(-1, 5))])
    out["top5_overlap"] = float(ov.mean() / 5)
    out["float_top1_in_int_top5"] = float(np.mean([a[0] in set(b) for a, b in zip(f5.reshape(-1, 5), i5.reshape(-1, 5))]))
    s = irec["logit_scale"]
    p = softmax(fl.astype(np.float64))
    q = softmax(il * s)
    out["kl_float_int_nats"] = float(np.mean(np.sum(p * (np.log(p + 1e-30) - np.log(q + 1e-30)), -1)))
    qa = softmax(lacc * irec["logit_acc_scale"])
    out["kl_float_intacc_nats"] = float(np.mean(np.sum(p * (np.log(p + 1e-30) - np.log(qa + 1e-30)), -1)))
    fz = fl - fl.mean(-1, keepdims=True)
    iz = il * s - (il * s).mean(-1, keepdims=True)
    cos = (fz * iz).sum(-1) / (np.linalg.norm(fz, axis=-1) * np.linalg.norm(iz, axis=-1) + 1e-30)
    out["logit_cosine_centered"] = float(cos.mean())
    # next-token cross-entropy on the text (both models)
    tgt = toks[ok][:, 1:]
    lp_f = np.log(p[:, :-1] + 1e-30)
    lp_i = np.log(q[:, :-1] + 1e-30)
    out["xent_float_nats"] = float(-np.take_along_axis(lp_f, tgt[..., None], -1).mean())
    out["xent_int_nats"] = float(-np.take_along_axis(lp_i, tgt[..., None], -1).mean())
    out["next_token_acc_float"] = float((ft[:, :-1] == tgt).mean())
    out["next_token_acc_int"] = float((it[:, :-1] == tgt).mean())
    layers = []
    for l in range(m["n_layers"]):
        xf = frec["resid"][l][ok].astype(np.float64)
        xi = irec["resid"][l][ok].astype(np.float64) * im.s_r
        rel = np.linalg.norm(xi - xf, axis=-1) / (np.linalg.norm(xf, axis=-1) + 1e-30)
        cs = (xi * xf).sum(-1) / (np.linalg.norm(xi, axis=-1) * np.linalg.norm(xf, axis=-1) + 1e-30)
        layers.append({"layer": l, "resid_rel_l2": float(rel.mean()), "resid_cosine": float(cs.mean())})
    out["per_layer"] = layers
    return out


# ---------------------------------------------------------------------------
# files


def write_model(path, im, log_out=0, weight_log_cols=6):
    cfg = im.cfg
    wide = cfg.A != 8 or cfg.R != 8
    assert 8 <= cfg.S <= 14 and (not wide or cfg.zig_wide), "only the zig_wide configs have wide activations / residuals in Zig"
    hdr = [im.log_t, im.lD, im.lH, im.lKV, im.lF, im.L, im.lV, log_out, 0, weight_log_cols, cfg.S] + ([cfg.A, cfg.R] if wide else [])
    order = []
    for l in range(im.L):
        order += [f"l{l}.q", f"l{l}.k", f"l{l}.v", f"l{l}.o", f"l{l}.gate", f"l{l}.up", f"l{l}.down"]
    order += ["logits", "emb"]
    W = dict(im.W)
    if cfg.R > 8:  # lm.ModelCfg.embLoIndex: Emb = 2^8 EmbHi + EmbLo, both int8
        e = W["emb"]
        lo = ((e + 128) & 255) - 128
        hi = (e - lo) >> 8
        assert np.array_equal(hi * 256 + lo, e)
        W["emb"], W["emb_lo"] = hi, lo
        order.append("emb_lo")
    with open(path, "wb") as fo:
        fo.write(b"STWOACC2" if wide else b"STWOACC1")
        fo.write(struct.pack(f"<{len(hdr)}I", *hdr))
        gains = np.full((2 * im.L + 1) * im.Dp, cfg.G, dtype="<i4")
        fo.write(struct.pack("<I", gains.size))
        fo.write(gains.tobytes())
        plan = np.array(im.plan(), dtype=np.uint8) if all(n in im.shift for n in im.plan_names()) else np.zeros(0, np.uint8)
        fo.write(struct.pack("<I", plan.size))
        fo.write(plan.tobytes())
        fo.write(struct.pack("<I", len(order)))
        for n in order:
            w = W[n]
            assert w.min() >= -128 and w.max() <= 127
            fo.write(struct.pack("<I", w.size))
            fo.write(w.astype(np.int8).tobytes())


def write_windows(path, toks):
    with open(path, "wb") as fo:
        fo.write(struct.pack("<II", *toks.shape))
        fo.write(toks.astype("<u4").tobytes())


def read_zig_out(path, T, D, V):
    raw = open(path, "rb").read()
    (n,) = struct.unpack("<I", raw[:4])
    p = 4
    res = []
    for _ in range(n):
        (err,) = struct.unpack("<i", raw[p:p + 4])
        p += 4
        lg = np.frombuffer(raw[p:p + 8 * V], dtype="<i4").reshape(2, V)
        p += 8 * V
        hid = np.frombuffer(raw[p:p + 4 * T * D], dtype="<i4").reshape(T, D)
        p += 4 * T * D
        res.append((err, lg, hid))
    return res


def read_plan(path):
    raw = open(path, "rb").read()
    (n,) = struct.unpack("<I", raw[:4])
    return list(raw[4:4 + n])


# ---------------------------------------------------------------------------


def cmd_prepare(a):
    m = load_ckpt(a.ckpt)
    pieces, scores = load_tok(a.tok, m["vocab"])
    lookup = {}
    for i, s in enumerate(pieces):
        lookup.setdefault(s, i)
    text = open(a.corpus, "r", encoding="utf-8", errors="replace").read()
    stories = [s.strip() for s in text.split("<|endoftext|>") if s.strip()][1:]  # first is a cut-off fragment
    T = 1 << a.log_t
    need = (a.n_calib + a.n_eval) * T
    stream = []
    used = 0
    for s in stories:
        stream += encode(s, pieces, scores, lookup)
        used += 1
        if len(stream) >= need:
            break
    if len(stream) < need:
        sys.exit("corpus too short")
    w = np.array(stream[:need], dtype=np.int64).reshape(-1, T)
    os.makedirs(a.out, exist_ok=True)
    np.savez(os.path.join(a.out, "windows.npz"), calib=w[:a.n_calib], eval=w[a.n_calib:], log_t=a.log_t)
    meta = {"ckpt": os.path.abspath(a.ckpt), "tok": os.path.abspath(a.tok), "corpus": os.path.abspath(a.corpus), "stories_used": used,
            "tokens": need, "log_t": a.log_t, "n_calib": a.n_calib, "n_eval": a.n_eval, "model": {k: m[k] for k in ("dim", "hidden", "n_layers", "n_heads", "n_kv", "vocab", "seq_len")}}
    json.dump(meta, open(os.path.join(a.out, "meta.json"), "w"), indent=1)
    print(json.dumps(meta))


def load_dir(d):
    meta = json.load(open(os.path.join(d, "meta.json")))
    w = np.load(os.path.join(d, "windows.npz"))
    return meta, load_ckpt(meta["ckpt"]), w["calib"], w["eval"], int(w["log_t"])


def cmd_export(a):
    meta, m, cal, ev, log_t = load_dir(a.dir)
    im = build_int(m, CONFIGS[a.config], cal, log_t)
    if a.no_plan:
        im.shift = {}
    write_model(os.path.join(a.dir, f"{a.config}.model.bin"), im)
    write_windows(os.path.join(a.dir, "calib.win.bin"), cal)
    write_windows(os.path.join(a.dir, "eval.win.bin"), ev)
    print(json.dumps({"config": a.config, "plan": im.plan() if not a.no_plan else None, "s_r": im.s_r, "clipped": im.clipped}))


def cmd_eval(a):
    meta, m, cal, ev, log_t = load_dir(a.dir)
    cfg = CONFIGS[a.config]
    zp = read_plan(a.plan) if a.plan else None
    im = build_int(m, cfg, cal, log_t, zp)
    r = {"config": a.config, "model": meta["model"], "log_t": log_t, "plan": im.plan(), "plan_source": "zig lm.calibrate" if zp else "python stage-wise",
         "s_r": im.s_r, "weight_clipped": im.clipped, "qk_spare_factor": getattr(im, "qk_spare", None), "headroom": cfg.headroom, "A": cfg.A, "R": cfg.R, "S": cfg.S}
    r["eval"] = metrics(m, im, ev)
    r["calib"] = {k: v for k, v in metrics(m, im, cal).items() if k in ("top1_agree", "refused_windows", "kl_float_int_nats")}
    s = json.dumps(r, indent=1)
    if a.out:
        open(a.out, "w").write(s)
    print(s)


def cmd_compare(a):
    meta, m, cal, ev, log_t = load_dir(a.dir)
    cfg = CONFIGS[a.config]
    zp = read_plan(a.plan) if a.plan else None
    im = build_int(m, cfg, cal, log_t, zp)
    toks = ev[:a.n]
    il, rf, irec = im.forward(toks, head_last=2)
    zo = read_zig_out(a.zig, im.T, im.Dp, im.Vp)
    n_eq = n_ref = n_mis = 0
    for i, (err, lg, hid) in enumerate(zo[:a.n]):
        if err != 0 or rf.bad[i]:
            n_ref += 1
            if (err != 0) != bool(rf.bad[i]):
                n_mis += 1
            continue
        same = np.array_equal(lg, il[i, -2:]) and np.array_equal(hid, irec["resid"][-1][i])
        n_eq += int(same)
        n_mis += int(not same)
    r = {"config": a.config, "windows": len(zo[:a.n]), "bit_identical": n_eq, "refused_both": n_ref, "mismatch": n_mis}
    print(json.dumps(r))
    if n_mis:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("prepare")
    p.add_argument("--ckpt", required=True)
    p.add_argument("--tok", required=True)
    p.add_argument("--corpus", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--log-t", type=int, default=6)
    p.add_argument("--n-calib", type=int, default=64)
    p.add_argument("--n-eval", type=int, default=256)
    p = sp.add_parser("export")
    p.add_argument("--dir", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--no-plan", action="store_true")
    p = sp.add_parser("eval")
    p.add_argument("--dir", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--plan")
    p.add_argument("--out")
    p = sp.add_parser("compare")
    p.add_argument("--dir", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--zig", required=True)
    p.add_argument("--plan")
    p.add_argument("--n", type=int, default=64)
    a = ap.parse_args()
    {"prepare": cmd_prepare, "export": cmd_export, "eval": cmd_eval, "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    main()
