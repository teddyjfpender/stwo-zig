//! M9 stream m9-outer-gkr: the node-side outer LogUp-GKR relation for the CURRENT (post-M8, D2
//! coalesced) recursion node shapes, and its in-circuit verifier cost at the real shapes.
//!
//! Default OFF. `STWO_RV64_M9_OUTER_GKR` is read only by the CPU prototype tool
//! (`rv64-m9-outer-gkr-tool`); no producer, receiver, job or profile reads it. Unset or "0" = off,
//! "1" = on, anything else is refused (never silently off).
//!
//! What this file adds on top of the M5/M7 profile (`profile.zig`, `section.zig`, `circuit.zig`,
//! `binding_v2.zig`, `tuples.zig`), without changing any of them:
//! - classes derived at RUN TIME from a node's `RECURSION_NODE_SHAPE raw=[...]` rows (the M5 classes
//!   are comptime constants for the M4-era 24628607 census), with a class id derived from the row logs;
//! - the node relation built from the ORIGINAL lookup tuple authority (`tuples.rowFor`) over MAIN and
//!   preprocessed rows, combined with the circuit LogUp elements (`om31.witness.Elements`), in the
//!   lane-major instance layout of the profile;
//! - an end-to-end CPU node round: GKR section -> native receiver (strict draws, closure, terminal)
//!   -> late v2 binding columns (anchored Eq + cyclic prefix) -> in-circuit verifier (valid) and
//!   tamper rejection;
//! - a SHAPE-ONLY verifier cost: the in-circuit gadget's gate counts depend only on the class (a test
//!   pins fabricated == honest at the same shape), so the real-shape cost (2^26-2^27 fractions, too
//!   big for a CPU prover) is counted exactly from the circuit code on a fabricated section.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("profile.zig");
const S = @import("section.zig");
const CG = @import("circuit.zig");
const T = @import("tuples.zig");
const B2 = @import("binding_v2.zig");
const Legacy = @import("binding.zig");
const W = @import("stwo_circuit_cpu_integration").om31.witness;
const M31 = core.fields.m31.M31;
const O = core.fields.om31.OM31;

pub const FLAG = "STWO_RV64_M9_OUTER_GKR";

pub const Selection = enum { off, on };
/// Strict flag parse: unset/"0" off, "1" on, anything else refused.
pub fn selectionFrom(value: ?[]const u8) error{InvalidM9OuterGkrFlag}!Selection {
    const v = value orelse return .off;
    if (std.mem.eql(u8, v, "0")) return .off;
    if (std.mem.eql(u8, v, "1")) return .on;
    return error.InvalidM9OuterGkrFlag;
}
pub fn selection() error{InvalidM9OuterGkrFlag}!Selection {
    return selectionFrom(std.posix.getenv(FLAG));
}

/// The five variable components of a recursion node, in RECURSION_NODE_SHAPE order.
pub const VARIABLE = [5]P.Component{ .eq, .qm31_ops, .triple_xor, .m_31_to_u_32, .blake_g_gate };
/// Fixed lookup tables, identical on every node (xor8, xor12, xor4, xor7, xor9, range_check_16);
/// row logs as in profile.zig's classes and the GPU_OUTER `logs={...}` receipts [M].
pub const FIXED_TABLE_LOGS = [6]u8{ 16, 20, 8, 14, 18, 16 };

fn ceilLog2(n: u64) u8 {
    if (n <= 1) return 0;
    return @intCast(64 - @clz(n - 1));
}
/// Row logs of all 11 components from the raw rows of the five variable ones (padded to 2^k).
pub fn rowLogs(raw: [5]u64) [P.N_COMPONENTS]u8 {
    var out: [P.N_COMPONENTS]u8 = undefined;
    for (raw, 0..) |r, i| out[i] = @max(1, ceilLog2(r));
    out[5..].* = FIXED_TABLE_LOGS;
    return out;
}
/// Scale every row log down by `shift` (CPU-provable copy of a real roster; the roster, lane groups
/// and relation are unchanged, only the row counts shrink).
pub fn scaled(row_logs: [P.N_COMPONENTS]u8, shift: u8) [P.N_COMPONENTS]u8 {
    var out = row_logs;
    for (&out) |*r| r.* = if (r.* > shift) r.* - shift else 1;
    return out;
}

/// Class id derived from the row logs (tag 0x9 in the top nibble; the M5 constants use < 0x100).
/// The receiver derives the class from the node statement and recomputes this id; the wire never
/// selects it (section.decode pins `expected`).
pub fn classId(row_logs: [P.N_COMPONENTS]u8) u32 {
    var h: u32 = 0x811c9dc5;
    for (row_logs) |r| h = (h ^ r) *% 0x01000193;
    return 0x9000_0000 | (h & 0x0fff_ffff);
}

pub const OwnedClass = struct {
    class: P.Class,
    pub fn deinit(self: *OwnedClass, a: std.mem.Allocator) void {
        a.free(self.class.instances);
        self.* = undefined;
    }
};
/// Run-time class for one node shape, binding v2 (DW-R1 closed construction) unless `v1` is asked.
pub fn classFor(a: std.mem.Allocator, name: []const u8, row_logs: [P.N_COMPONENTS]u8, version: P.BindingVersion) !OwnedClass {
    var buf: [P.MAX_INSTANCES]P.Instance = undefined;
    const got = try P.instancesFor(row_logs, &buf);
    const owned = try a.dupe(P.Instance, got);
    errdefer a.free(owned);
    const class = P.Class{ .id = classId(row_logs), .name = name, .row_logs = row_logs, .instances = owned, .binding_version = version };
    try class.validate();
    return .{ .class = class };
}

/// Real leaf class shape: the D2 CPU leaf (b4 q54 p20 natives), max over the 10 full CPU leaves of
/// 24628607/26235156 [M, RECURSION_NODE_SHAPE raw rows in
/// vectors/reports/rv64-m7-20261105/d2-composed/combined-d2-package/*/producer.stderr, as tabulated in
/// scripts/rv64_m9_leaf_fanin_model.py NATIVE["cpu"]].
pub const LEAF_CPU_D2_RAW = [5]u64{ 179654, 5533212, 337632, 875134, 3376320 };

// ------------------------------------------------------------------------------------------------
// The node relation from the original tuple authority.

const Rng = S.Rng;
fn randomM31(rng: *Rng) M31 {
    return M31.fromCanonical(rng.coordinate());
}
/// The tuple authority is generic over an extension field; on base-embedded rows every value it
/// produces is in the base field (affine in MAIN/preprocessed with M31 constants).
fn base(v: O) !M31 {
    const c = v.toM31Array();
    for (c[1..]) |x| if (!x.isZero()) return error.OuterGkrTupleShape;
    return c[0];
}
fn ppWidth(c: P.Component) usize {
    return switch (c) {
        .triple_xor => 5,
        .m_31_to_u_32 => 3,
        .blake_g_gate => 11,
        .verify_bitwise_xor_12 => 3,
        else => 0,
    };
}

/// Lane-major fractions of every GKR instance of `class`, from MAIN/preprocessed rows of the four
/// GKR-bound components through `tuples.rowFor` and `Elements.combine` (denominator = sum alpha^i t_i - z).
/// Row values are pseudo-random field elements: the GKR argument is over arbitrary fractions, so
/// range validity of the rows is not needed here (the closure term below carries the classic side).
pub fn nodeInputs(a: std.mem.Allocator, class: *const P.Class, elements: *const W.Elements, seed: u64) !S.Inputs {
    const k = class.instances.len;
    var out = S.Inputs{ .numerators = try a.alloc([]M31, k), .denominators = try a.alloc([]O, k) };
    var made: usize = 0;
    errdefer {
        for (out.numerators[0..made], out.denominators[0..made]) |n, d| {
            a.free(n);
            a.free(d);
        }
        a.free(out.numerators);
        a.free(out.denominators);
    }
    for (class.instances, 0..) |inst, g| {
        const count = @as(usize, 1) << @intCast(inst.variables());
        out.numerators[g] = try a.alloc(M31, count);
        out.denominators[g] = a.alloc(O, count) catch |e| {
            a.free(out.numerators[g]);
            return e;
        };
        made += 1;
    }
    var lookups_buf: [32]T.LookupFor(O) = undefined;
    var main_buf: [64]O = undefined;
    var pp_buf: [16]O = undefined;
    var tuple_buf: [6]M31 = undefined;
    for (0..P.N_COMPONENTS) |ci| {
        const comp: P.Component = @enumFromInt(ci);
        if (!P.gkrBound(comp)) continue;
        const rows = @as(usize, 1) << @intCast(class.row_logs[ci]);
        const main = main_buf[0..P.FACTS[ci].main];
        const pp = pp_buf[0..ppWidth(comp)];
        for (0..rows) |row| {
            // One MAIN/preprocessed row per (component, row), shared by all of its lane groups.
            var rng = Rng.init(seed ^ (@as(u64, ci) << 56), row);
            for (main) |*v| v.* = O.fromBase(randomM31(&rng));
            for (pp) |*v| v.* = O.fromBase(randomM31(&rng));
            const lookups = try T.rowFor(O, comp, main, pp, &lookups_buf);
            var offset: usize = 0;
            for (class.instances, 0..) |inst, g| {
                if (inst.component != comp) continue;
                const lanes = @as(usize, 1) << @intCast(inst.lane_log);
                for (0..lanes) |lane| {
                    const l = lookups[offset + lane];
                    const index = lane * rows + row;
                    out.numerators[g][index] = try base(l.numerator);
                    for (tuple_buf[0..l.len], l.tuple[0..l.len]) |*t, v| t.* = try base(v);
                    out.denominators[g][index] = elements.combine(tuple_buf[0..l.len]);
                }
                offset += lanes;
            }
            if (offset != lookups.len) return error.OuterGkrTupleShape;
        }
    }
    return out;
}

// ------------------------------------------------------------------------------------------------
// End-to-end CPU node round.

pub const NodeReport = struct {
    class_id: u32,
    layers: u32,
    instances: usize,
    fractions: u64,
    section_bytes: usize,
    draws: u32,
    native_verified: bool,
    closure_ok: bool,
    closure_wrong_rejected: bool,
    terminal_ok: bool,
    binding_components: u32,
    binding_wrong_target_rejected: bool,
    circuit_valid: bool,
    circuit_tamper_rejected: bool,
    cost: CG.Cost,
    prove_ns: u64,
    native_verify_ns: u64,
    binding_ns: u64,
    circuit_ns: u64,
};

fn challengeElements(seed: u64) W.Elements {
    var rng = Rng.init(seed, 0x5eed);
    var zc: [8]M31 = undefined;
    var ac: [8]M31 = undefined;
    for (&zc) |*x| x.* = randomM31(&rng);
    for (&ac) |*x| x.* = randomM31(&rng);
    return W.Elements.init(O.fromM31Array(zc), O.fromM31Array(ac));
}

/// Prove the node's outer GKR section on the CPU and run every receiver-side check on it.
pub fn runNode(a: std.mem.Allocator, class: *const P.Class, seed: u64) !NodeReport {
    const elements = challengeElements(seed);
    var inputs = try nodeInputs(a, class, &elements, seed);
    defer inputs.deinit(a);
    var timer = try std.time.Timer.start();
    const start = S.benchChannel();
    var section = try S.proveCpu(a, &start, class, &inputs);
    defer section.deinit(a);
    const prove_ns = timer.lap();

    // Native receiver: fresh codec round trip, strict draws, closure, terminal vs the inputs' MLEs.
    const words = try S.encode(a, &section);
    defer a.free(words);
    var decoded = try S.decode(a, class, words);
    defer decoded.deinit(a);
    var channel = S.benchChannel();
    var verified = try S.verify(a, &channel, &decoded);
    defer verified.deinit(a);
    // The classic side of the node (eq, qm31_ops, the small tables, public bus) supplies the
    // opposite sum in production; here it is the honest complement.
    const external = verified.root_sum.neg();
    try S.requireClosure(&verified, external);
    const closure_wrong_rejected = if (S.requireClosure(&verified, external.add(O.one()))) |_| false else |_| true;
    const terminal = try S.terminalExpected(a, &inputs, &verified);
    defer a.free(terminal);
    try S.requireTerminal(&verified, terminal);
    const native_verify_ns = timer.lap();

    // Late v2 binding: gamma/rho drawn after the section; per GKR component the anchored Eq and the
    // cyclic prefix close exactly on the target fixed by the terminal claims.
    var strict = S.StrictChannel{ .inner = channel };
    const ch = Legacy.drawChallenges(&strict, class.instances.len);
    if (strict.rejected) return error.OuterGkrDrawRejected;
    const point = verified.artifact.ood_point;
    var bound: u32 = 0;
    var wrong_rejected = true;
    for (0..P.N_COMPONENTS) |ci| {
        const comp: P.Component = @enumFromInt(ci);
        if (!P.gkrBound(comp)) continue;
        const projection = try B2.projectFromInputs(a, class, comp, point, &inputs, &ch);
        defer a.free(projection);
        const target = Legacy.expectedBoundary(class, comp, verified.artifact.claims_to_verify_by_instance, &ch);
        const z_row = point[point.len - class.row_logs[ci] ..];
        var cols = try B2.columns(a, z_row, projection, target);
        cols.deinit(a);
        if (B2.columns(a, z_row, projection, target.add(O.one()))) |c| {
            var cc = c;
            cc.deinit(a);
            wrong_rejected = false;
        } else |_| {}
        bound += 1;
    }
    const binding_ns = timer.lap();

    // In-circuit verifier on the honest section (valid) and on a tampered closure (unsatisfiable).
    const cost = try CG.measure(a, &decoded, external, terminal);
    const bad = try CG.measure(a, &decoded, external.add(O.one()), terminal);
    const circuit_ns = timer.lap();

    return .{
        .class_id = class.id,
        .layers = class.layers(),
        .instances = class.instances.len,
        .fractions = class.fractions(),
        .section_bytes = S.sectionBytes(class),
        .draws = verified.draws,
        .native_verified = true,
        .closure_ok = true,
        .closure_wrong_rejected = closure_wrong_rejected,
        .terminal_ok = true,
        .binding_components = bound,
        .binding_wrong_target_rejected = wrong_rejected,
        .circuit_valid = cost.valid,
        .circuit_tamper_rejected = !bad.valid,
        .cost = cost,
        .prove_ns = prove_ns,
        .native_verify_ns = native_verify_ns,
        .binding_ns = binding_ns,
        .circuit_ns = circuit_ns,
    };
}

// ------------------------------------------------------------------------------------------------
// Shape-only verifier cost at the real shape.

/// A section with the exact wire shape of `class` and pseudo-random canonical, NONZERO coordinates
/// (so every leading coefficient and every root denominator is nonzero and the gadget emits its full
/// graph). It is not a valid proof: only the gate counts of `CG.measure` on it are used.
pub fn fabricatedSection(a: std.mem.Allocator, class: *const P.Class, seed: u64) !S.Section {
    const words = try a.alloc(u32, S.wordCount(class));
    defer a.free(words);
    words[0..5].* = .{ P.MAGIC, class.version(), class.id, @intCast(class.instances.len), class.layers() };
    var rng = Rng.init(seed, 0xfab);
    for (words[5..]) |*w| w.* = @intCast(rng.next() % (core.fields.m31.Modulus - 1) + 1);
    return S.decode(a, class, words);
}

/// In-circuit verifier gate counts for one child section of `class` [D: counted from the circuit
/// code]. `valid` is meaningless here (fabricated proof) and is reset to false.
pub fn verifierCost(a: std.mem.Allocator, class: *const P.Class) !CG.Cost {
    var section = try fabricatedSection(a, class, 0x4d39);
    defer section.deinit(a);
    var cost = try CG.measure(a, &section, O.zero(), null);
    cost.valid = false;
    return cost;
}

/// Facts (fractions) of the node's GKR: sum over instances of 2^(row_log + lane_log).
pub fn facts(class: *const P.Class) u64 {
    return class.fractions();
}
