//! Composition IR export cases: services (see catalog.zig for the pattern).
//! The CPU-proof side of the v3 services, built as `services/air_components.zig`
//! (`Bridges`) assembles them: Keccak and secp/SHA/arith/curve word16 bridges,
//! bulk memory (incl. JUMPDEST), Keccak sponge and LS-D64.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("record.zig");
const K = @import("case.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Lane = R.Lane;
const Sink = R.Sink;
const Q = R.Q;
const Case = K.Case;

const KB = A.crypto.keccak.word16_bridge;
const SB = A.crypto.secp256k1.word16_bridge;
const BM = A.crypto.bulk_memory;
const KS = A.crypto.keccak_sponge;
const LSD = A.memory.load_store_dword;

/// Bridge components all share the native (fixed, main, previous main,
/// interaction, previous interaction) `emitFor`; `needs(component, tree,
/// column)` mirrors the component's own maskPoints / packed_rows previous-row
/// selection (the native kernels leave unselected previous slots zero).
fn pipeCase(a: std.mem.Allocator, comptime C: type, name: []const u8, group: []const u8, value: C, comptime needs: fn (*const C, u8, usize) bool) !Case {
    const Emit = struct {
        const Ctx = struct { c: *const C, tree: u8 };
        fn has(ctx: Ctx, column: usize) bool {
            return needs(ctx.c, ctx.tree, column);
        }
        fn run(alloc: std.mem.Allocator, c: *const C, sink: *Sink) anyerror!void {
            const w = c.widths();
            const f = try R.Masks.init(alloc, 0, w[0], {}, R.never);
            defer f.deinit(alloc);
            const m = try R.Masks.init(alloc, 1, w[1], Ctx{ .c = c, .tree = 1 }, has);
            defer m.deinit(alloc);
            const i = try R.Masks.init(alloc, 2, w[2], Ctx{ .c = c, .tree = 2 }, has);
            defer i.deinit(alloc);
            c.emitFor(Lane, f.current, m.current, m.previous, i.current, i.previous, sink);
        }
    };
    return K.caseWith(a, C, name, group, value, value.widths(), Emit.run);
}

fn keccakNeeds(c: *const KB.component.Component, tree: u8, column: usize) bool {
    return if (tree == 1) KB.layout.previousMainFor(c.kind, column) else KB.layout.previousInterFor(c.kind, column);
}
// The secp bridge layout is one shape for every packet kind (`.bridge`).
fn secpNeeds(_: *const SB.component.Component, tree: u8, column: usize) bool {
    return if (tree == 1) SB.layout.previousMainFor(.bridge, column) else SB.layout.previousInterFor(.bridge, column);
}
fn bulkNeeds(c: *const BM.component.Component, tree: u8, column: usize) bool {
    return if (tree == 1) BM.layout.previousMainFor(c.kind, column) else BM.layout.previousInterFor(c.kind, column);
}
fn spongeNeeds(c: *const KS.component.Component, tree: u8, column: usize) bool {
    return if (tree == 1) KS.layout.previousMainFor(c.kind, column) else KS.layout.previousInterFor(c.kind, column);
}
fn dwordNeeds(c: *const LSD.component.Component, tree: u8, column: usize) bool {
    return if (tree == 1) LSD.layout.previousMain(column) else c.previousInter(column);
}

fn random(comptime V: type, rng: std.Random) V {
    var v = std.mem.zeroes(V);
    R.randomize(&v, rng);
    return v;
}

/// Case builders from ANY instance (offsets must already be zero); names
/// come from the instance's kind/layout. `kind` tags are static strings.
pub fn fromKeccakBridge(a: std.mem.Allocator, value: KB.component.Component) !Case {
    const name = switch (value.kind) {
        inline else => |k| "keccak_bridge." ++ @tagName(k),
    };
    return pipeCase(a, KB.component.Component, name, "keccak_bridge", value, keccakNeeds);
}
pub fn fromSecpBridge(a: std.mem.Allocator, value: SB.component.Component) !Case {
    const name = switch (value.kind) {
        inline else => |k| "secp_bridge." ++ @tagName(k),
    };
    return pipeCase(a, SB.component.Component, name, "secp_bridge", value, secpNeeds);
}
pub fn fromBulkMemory(a: std.mem.Allocator, value: BM.component.Component) !Case {
    const name = switch (value.kind) {
        inline else => |k| "bulk_memory." ++ @tagName(k),
    };
    return pipeCase(a, BM.component.Component, name, "bulk_memory", value, bulkNeeds);
}
pub fn fromKeccakSponge(a: std.mem.Allocator, value: KS.component.Component) !Case {
    const name = switch (value.kind) {
        inline else => |k| "keccak_sponge." ++ @tagName(k),
    };
    return pipeCase(a, KS.component.Component, name, "keccak_sponge", value, spongeNeeds);
}
pub fn fromDword(a: std.mem.Allocator, value: LSD.component.Component) !Case {
    return pipeCase(a, LSD.component.Component, if (value.pairs != null) "ls_dword.fused_pairs" else "ls_dword.plain", "ls_dword", value, dwordNeeds);
}

/// One entry per distinct component type whose `asProverComponent()` ctx is
/// that type (the `Bridges` fields of services/air_components.zig).
pub const handlers = .{
    .{ KB.component.Component, fromKeccakBridge },
    .{ SB.component.Component, fromSecpBridge },
    .{ BM.component.Component, fromBulkMemory },
    .{ KS.component.Component, fromKeccakSponge },
    .{ LSD.component.Component, fromDword },
};

const LOG = 5;

fn push(a: std.mem.Allocator, out: *std.ArrayList(Case), case: Case) !void {
    var c = case;
    errdefer c.deinit(a);
    try out.append(a, c);
}

/// Appends one sample case per exported component kind/layout.
pub fn all(a: std.mem.Allocator, rng: std.Random, out: *std.ArrayList(Case)) !void {
    // 1. Keccak word16 bridge (its only kind is `.bridge`).
    for (std.enums.values(KB.layout.Kind)) |kind| {
        const c = KB.component.Component{ .kind = kind, .log_size = LOG, .rows = 1, .first_id = 5, .offsets = .{ 0, 0, 0 }, .claims = random(KB.types.Claims, rng), .challenges = random(KB.types.Challenges, rng) };
        _ = try KB.types.validateGeometry(c.rows, c.first_id, c.log_size);
        try push(a, out, try fromKeccakBridge(a, c));
    }
    // 2. secp-family word16 bridge, one case per v3 family (add, double,
    // sha256, arith256_mod and every curve family).
    for (std.enums.values(T.Family)) |family| if (family != .keccak) {
        const kind = T.bridgeKind(family);
        const c = SB.component.Component{ .kind = kind, .log_size = LOG, .rows = 1, .first_id = 7, .offsets = .{ 0, 0, 0 }, .claims = random(SB.types.Claims, rng), .challenges = random(SB.types.Challenges, rng) };
        _ = try SB.types.validateGeometry(kind, c.rows, c.first_id, c.log_size);
        try push(a, out, try fromSecpBridge(a, c));
    };
    // 3. Bulk memory, every v3 kind (memcpy/memset, unaligned copy, memcmp, JUMPDEST).
    for (T.bulk_kinds) |kind| {
        const c = BM.component.Component{ .kind = kind, .log_size = LOG, .rows = 3, .offsets = .{ 0, 0, 0 }, .claims = random(BM.types.Claims, rng), .challenges = random(BM.types.Challenges, rng) };
        _ = try BM.types.validateGeometry(kind, c.rows, c.log_size);
        try push(a, out, try fromBulkMemory(a, c));
    }
    // 4. Keccak sponge (call and permutation rows).
    for (T.sponge_kinds) |kind| {
        const c = KS.component.Component{ .kind = kind, .log_size = LOG, .rows = 3, .first_id = 9, .offsets = .{ 0, 0, 0 }, .claims = random(KS.types.Claims, rng), .challenges = random(KS.types.Challenges, rng) };
        _ = try KS.types.validateGeometry(kind, c.rows, c.log_size);
        try push(a, out, try fromKeccakSponge(a, c));
    }
    // 5. LS-D64, historical and fused-pair layouts.
    const Pairs = @typeInfo(@FieldType(LSD.component.Component, "pairs")).optional.child;
    for ([_]bool{ false, true }) |fused| {
        const c = LSD.component.Component{ .log_size = LOG, .rows = 3, .offsets = .{ 0, 0, 0 }, .claims = random(LSD.types.Claims, rng), .challenges = random(LSD.types.Challenges, rng), .pairs = if (fused) random(Pairs, rng) else null };
        try push(a, out, try fromDword(a, c));
    }
}
