//! Variable-roster transport only. Hashes detect corruption; independent keys,
//! Expected image/state and execution.verify still establish acceptance.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = @import("execution.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const T = @import("types.zig");
const G = @import("../protocol.zig");
const Geo = @import("../../word16_execution/geometry.zig").Geometry;
const Cells = @import("../../word16_execution/cells_wire.zig");
const Cell = @import("../../word16_execution/memory/statement.zig").Cell;
const Receipt = @import("../../rv64_ethereum_batch_receipt.zig");
pub const Limits = struct { max_cpus: usize = 256, max_truths: usize = 256, max_metadata_bytes: usize = 16 << 20, max_memory_words: u32 = 1 << 22, max_proof_bytes: u64 = 64 << 20, max_total_proof_bytes: u64 = 1 << 30, max_total_steps: u64 = 1 << 30, max_native_row_sum: u64 = 1 << 32 };
pub const CompactRequest = struct {
    cpu: @FieldType(G.Old.Request, "cpu"),
    epoch: u16,
    division_requests: u32,
    multiplication_requests: u32,
    memory_epoch: u16,
    ls_count: u32,
    /// v2 families (Keccak, ADD, DOUBLE).
    calls: [3]u32,
    /// v3 SHA-256 calls; omitted from JSON when zero (v2 bytes unchanged).
    sha256_calls: u32 = 0,
    /// v3 arith256_mod calls; omitted from JSON when zero.
    arith256_mod_calls: u32 = 0,
    /// v3 curve/field calls (families 5..11); omitted from JSON when all zero.
    curve_calls: [T.CURVES]u32 = @splat(0),
    /// Bulk-memory rows (v3); omitted from JSON when zero.
    bulk: T.BulkCounts = .{},
    /// Keccak-sponge rows and first IO11 ID (v3); omitted from JSON when zero.
    sponge: T.SpongeCounts = .{},
    /// LS-D64 rows (v3); omitted from JSON when zero. `ls_count` is then the
    /// core LS32 share.
    ls_dword: u32 = 0,
    pub fn from(r: P.Request) @This() {
        return .{ .cpu = r.base.cpu, .epoch = r.base.epoch, .division_requests = r.base.division_requests, .multiplication_requests = r.base.multiplication_requests, .memory_epoch = r.base.memory.epoch, .ls_count = r.base.memory.ls_count, .calls = r.calls[0..3].*, .sha256_calls = r.calls[3], .arith256_mod_calls = r.calls[4], .curve_calls = r.calls[T.FIRST_CURVE..].*, .bulk = r.bulk, .sponge = r.sponge, .ls_dword = r.ls_dword };
    }
    fn anyCurve(self: @This()) bool {
        for (self.curve_calls) |c| if (c != 0) return true;
        return false;
    }
    pub fn expand(self: @This(), initial: []const Cell, terminal: []const Cell) P.Request {
        return .{ .base = .{ .cpu = self.cpu, .epoch = self.epoch, .division_requests = self.division_requests, .multiplication_requests = self.multiplication_requests, .memory = .{ .initial = initial, .terminal = terminal, .epoch = self.memory_epoch, .ls_count = self.ls_count } }, .calls = self.all(), .bulk = self.bulk, .sponge = self.sponge, .ls_dword = self.ls_dword };
    }
    pub fn all(self: @This()) [T.FAMILIES]u32 {
        return self.calls ++ [2]u32{ self.sha256_calls, self.arith256_mod_calls } ++ self.curve_calls;
    }
    pub fn jsonStringify(self: @This(), jws: anytype) !void {
        try jws.beginObject();
        inline for (std.meta.fields(@This())) |field| {
            if (comptime std.mem.eql(u8, field.name, "bulk")) {
                if (self.bulk.any()) {
                    try jws.objectField(field.name);
                    try jws.write(self.bulk);
                }
            } else if (comptime std.mem.eql(u8, field.name, "sponge")) {
                if (self.sponge.any()) {
                    try jws.objectField(field.name);
                    try jws.write(self.sponge);
                }
            } else if (comptime std.mem.eql(u8, field.name, "curve_calls")) {
                if (self.anyCurve()) {
                    try jws.objectField(field.name);
                    try jws.write(self.curve_calls);
                }
            } else if (comptime !std.mem.eql(u8, field.name, "sha256_calls") and !std.mem.eql(u8, field.name, "arith256_mod_calls") and !std.mem.eql(u8, field.name, "ls_dword")) {
                try jws.objectField(field.name);
                try jws.write(@field(self, field.name));
            } else if (@field(self, field.name) != 0) {
                try jws.objectField(field.name);
                try jws.write(@field(self, field.name));
            }
        }
        try jws.endObject();
    }
};
/// Transport claims: the v2 vector plus an optional v3 SHA-256 bridge entry.
pub const WireClaims = struct {
    base: G.Old.Claims,
    extras: [3]T.ExtraClaims,
    sha256: ?T.ExtraClaims = null,
    arith256_mod: ?T.ExtraClaims = null,
    /// Curve/field bridge claims (families 5..11); present iff the bridge is,
    /// the whole field omitted when no curve bridge is present.
    curves: [T.CURVES]?T.ExtraClaims = @splat(null),
    /// Bulk-memory claims (desc, copy, set); present iff the roster has bulk.
    bulk: ?[3]T.BulkClaims = null,
    /// Bulk extension claims (ucopy, cdesc, cmp); present iff the roster has
    /// an extension kind, omitted otherwise (aligned-only bytes unchanged).
    bulk_ext: ?[3]T.BulkClaims = null,
    /// Keccak-sponge claims (call, perm); present iff the roster has a sponge.
    sponge: ?[2]T.SpongeClaims = null,
    /// JUMPDEST claims (jdesc, jscan, jtab); present iff the roster has them.
    jumpdest: ?[3]T.BulkClaims = null,
    /// LS-D64 head/tail claims; each present iff that instance is.
    ls_dword: ?T.DwordClaims = null,
    ls_dword_tail: ?T.DwordClaims = null,
    fn from(c: E.CpuClaims, bridges: T.Logs) @This() {
        var curves: [T.CURVES]?T.ExtraClaims = @splat(null);
        for (&curves, T.FIRST_CURVE..) |*out, k| out.* = if (bridges.at(@enumFromInt(k)) != null) c.extras[k] else null;
        return .{ .base = c.base, .extras = c.extras[0..3].*, .sha256 = if (bridges.sha256 != null) c.extras[3] else null, .arith256_mod = if (bridges.arith256_mod != null) c.extras[4] else null, .curves = curves, .bulk = if (bridges.bulk.any()) c.bulk[0..T.BULK_BASE].* else null, .bulk_ext = if (bridges.bulk.anyExtension()) c.bulk[T.BULK_BASE..T.BULK_EXT].* else null, .sponge = if (bridges.sponge.any()) c.sponge else null, .jumpdest = if (bridges.bulk.jump()) c.bulk[T.BULK_EXT..].* else null, .ls_dword = if (bridges.ls_dword != null) c.ls_dword[0] else null, .ls_dword_tail = if (bridges.ls_dword_tail != null) c.ls_dword[1] else null };
    }
    fn expand(self: @This()) E.CpuClaims {
        var extras: [T.FAMILIES]T.ExtraClaims = undefined;
        extras[0..5].* = self.extras ++ [2]T.ExtraClaims{ self.sha256 orelse T.ExtraClaims.zero(), self.arith256_mod orelse T.ExtraClaims.zero() };
        for (extras[T.FIRST_CURVE..], self.curves) |*out, c| out.* = c orelse T.ExtraClaims.zero();
        return .{ .base = self.base, .extras = extras, .bulk = (self.bulk orelse zeroBulk()) ++ (self.bulk_ext orelse zeroBulk()) ++ (self.jumpdest orelse zeroBulk()), .sponge = self.sponge orelse @splat(T.SpongeClaims.zero()), .ls_dword = .{ self.ls_dword orelse T.DwordClaims.zero(), self.ls_dword_tail orelse T.DwordClaims.zero() } };
    }
    fn anyCurve(self: @This()) bool {
        for (self.curves) |c| if (c != null) return true;
        return false;
    }
    pub fn jsonStringify(self: @This(), jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("base");
        try jws.write(self.base);
        try jws.objectField("extras");
        try jws.write(self.extras);
        if (self.sha256) |extra| {
            try jws.objectField("sha256");
            try jws.write(extra);
        }
        if (self.arith256_mod) |extra| {
            try jws.objectField("arith256_mod");
            try jws.write(extra);
        }
        if (self.anyCurve()) {
            try jws.objectField("curves");
            try jws.write(self.curves);
        }
        if (self.bulk) |b| {
            try jws.objectField("bulk");
            try jws.write(b);
        }
        if (self.bulk_ext) |b| {
            try jws.objectField("bulk_ext");
            try jws.write(b);
        }
        if (self.sponge) |b| {
            try jws.objectField("sponge");
            try jws.write(b);
        }
        if (self.jumpdest) |b| {
            try jws.objectField("jumpdest");
            try jws.write(b);
        }
        if (self.ls_dword) |b| {
            try jws.objectField("ls_dword");
            try jws.write(b);
        }
        if (self.ls_dword_tail) |b| {
            try jws.objectField("ls_dword_tail");
            try jws.write(b);
        }
        try jws.endObject();
    }
};
fn zeroBulk() [T.BULK_BASE]T.BulkClaims {
    return @splat(T.BulkClaims.zero());
}
fn serviceCalls(r: CompactRequest) u64 {
    var n: u64 = r.bulk.ecalls() + r.sponge.calls + r.ls_count + r.ls_dword;
    for (r.all()) |c| n += c;
    return n;
}
pub const CpuDeclaration = struct { geometry: Geo, bridges: T.Logs };
/// Keccak truth declaration `logs[1]`: 0 compact (unchanged bytes), 21
/// throughput-v1 (the chi table log), and 21 | 4 << 8 throughput-quartet-v1
/// (same tables, batch width four). Every other word is rejected.
pub const KECCAK_THROUGHPUT_QUARTET_WORD: u32 = 21 | (4 << 8);
pub fn keccakProfileWord(policy: A.crypto.keccak.equations.BatchPolicy) u32 {
    return switch (policy) {
        .throughput_v1 => policy.tableLog(.chi),
        .throughput_quartet_v1 => KECCAK_THROUGHPUT_QUARTET_WORD,
        else => 0,
    };
}
pub fn keccakPolicy(word: u32) !A.crypto.keccak.equations.BatchPolicy {
    return switch (word) {
        0 => .triple_v2,
        21 => .throughput_v1,
        KECCAK_THROUGHPUT_QUARTET_WORD => .throughput_quartet_v1,
        else => error.InvalidServicesTruthGeometry,
    };
}
pub const TruthDeclaration = struct {
    family: T.Family,
    first_id: u32,
    calls: u32,
    logs: [2]u32,
    pub fn from(t: R.Truth) @This() {
        return .{ .family = t.family(), .first_id = t.first(), .calls = t.count(), .logs = switch (t) {
            // logs[1] names the Keccak lookup profile: 0 compact (unchanged
            // bytes), else the throughput chi-table log (21).
            .keccak => |k| .{ k.setup.log, keccakProfileWord(k.setup.policy) },
            .secp => |s| s.setup.logs,
            .sha256 => |h| .{ h.setup.log, 0 },
            .arith256_mod => |h| .{ h.setup.log, 0 },
            .curve => |h| .{ h.setup.log, 0 },
        } };
    }
};
const File = struct { bytes: u64, sha256: [32]u8 };
const Cpu = struct { declaration: CpuDeclaration, request: CompactRequest, claims: WireClaims, proof: File };
const Truth = struct { declaration: TruthDeclaration, claims: [3]G.Q, proof: File };
pub const Metadata = struct { schema: u32 = 1, core_schema: u32 = G.Old.SCHEMA, cpus: []const Cpu, truths: []const Truth, specs: []const [32]u8, roots: []const G.Receipt, seal: [32]u8, memory_words: u32, cells_sha256: [32]u8 };
pub const Loaded = struct {
    cpu_declarations: []CpuDeclaration,
    truth_declarations: []TruthDeclaration,
    bundle: E.Bundle,
    pub fn deinit(self: *Loaded, a: std.mem.Allocator) void {
        self.bundle.deinit(a);
        a.free(self.cpu_declarations);
        a.free(self.truth_declarations);
    }
};
fn hash(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return out;
}
fn hashCells(dir: std.fs.Dir, words: u32) ![32]u8 {
    var f = try dir.openFile("cells.bin", .{});
    defer f.close();
    if (try f.getEndPos() != 16 + 46 * @as(u64, words)) return error.InvalidMemorySidecarSize;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = try f.read(&buf);
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    return h.finalResult();
}
fn proofName(buf: []u8, truth: bool, index: usize) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}-{d}.bin", .{ if (truth) "truth" else "cpu", index });
}
fn rowSum(g: Geo) !u64 {
    var n: u64 = 4 * 65536 + 256 + 32;
    inline for (std.meta.fields(Geo)) |field| {
        if (comptime std.mem.endsWith(u8, field.name, "_log")) {
            if (comptime field.type == u32) {
                n = try std.math.add(u64, n, @as(u64, 1) << @intCast(@field(g, field.name)));
            } else if (comptime field.type == ?u32) {
                if (@field(g, field.name)) |log| n = try std.math.add(u64, n, @as(u64, 1) << @intCast(log));
            }
        }
    }
    return n;
}
/// Native admission only, before sidecar/key allocation. Proof acceptance still
/// invokes complete independent-material/image admission in execution.verify.
pub fn validate(m: Metadata, limits: Limits) !void {
    if (m.schema != 1 or m.core_schema != G.Old.SCHEMA or m.specs.len != m.cpus.len + m.truths.len or m.roots.len != m.specs.len) return error.InvalidServicesWireRoster;
    try validateDeclarations(m.cpus, m.truths, m.memory_words, limits);
    for (m.cpus) |cpu| {
        // v3 claim presence must match the declared bridges exactly.
        if ((cpu.claims.sha256 != null) != (cpu.declaration.bridges.sha256 != null)) return error.InvalidServicesWireRequest;
        if ((cpu.claims.arith256_mod != null) != (cpu.declaration.bridges.arith256_mod != null)) return error.InvalidServicesWireRequest;
        if ((cpu.claims.bulk != null) != cpu.declaration.bridges.bulk.any()) return error.InvalidServicesWireRequest;
        if ((cpu.claims.jumpdest != null) != cpu.declaration.bridges.bulk.jump()) return error.InvalidServicesWireRequest;
        if ((cpu.claims.bulk_ext != null) != cpu.declaration.bridges.bulk.anyExtension()) return error.InvalidServicesWireRequest;
        if ((cpu.claims.sponge != null) != cpu.declaration.bridges.sponge.any()) return error.InvalidServicesWireRequest;
        if ((cpu.claims.ls_dword != null) != (cpu.declaration.bridges.ls_dword != null)) return error.InvalidServicesWireRequest;
        if ((cpu.claims.ls_dword_tail != null) != (cpu.declaration.bridges.ls_dword_tail != null)) return error.InvalidServicesWireRequest;
        for (cpu.claims.curves, T.FIRST_CURVE..) |c, k| if ((c != null) != (cpu.declaration.bridges.at(@enumFromInt(k)) != null)) return error.InvalidServicesWireRequest;
        const claims = cpu.claims.expand();
        try claims.canonical();
        for (claims.extras, 0..) |c, k| if (cpu.declaration.bridges.at(@enumFromInt(k)) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
        for (T.bulk_kinds, claims.bulk) |kind, c| if (cpu.declaration.bridges.bulk.at(kind) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
        for (T.sponge_kinds, claims.sponge) |kind, c| if (cpu.declaration.bridges.sponge.at(kind) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
        for (claims.ls_dword, 0..) |c, k| if (cpu.declaration.bridges.dwordLog(k) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
    }
    for (m.truths) |truth| {
        // Single-component v3 truths (SHA-256, arith256_mod, curves) carry
        // only the first claim; the other two must be zero.
        const f = truth.declaration.family;
        if ((f == .sha256 or f == .arith256_mod or T.curveOp(f) != null) and (!truth.claims[1].isZero() or !truth.claims[2].isZero())) return error.NonzeroAbsentServiceClaim;
        for (truth.claims) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalServicesClaim;
    }
}
/// Shared declaration-only preflight for legacy and wide transports. This
/// establishes size/geometry/count budgets (v2 and v3 families, bulk memory,
/// Keccak sponge), never field claims or proof validity. Both shapes provide
/// declaration/request/proof fields; no dummy Q claims or producer
/// security/profile authority are introduced for a wide proof.
pub fn validateDeclarations(cpus: anytype, truths: anytype, memory_words: u32, limits: Limits) !void {
    if (cpus.len == 0 or cpus.len > limits.max_cpus or truths.len > limits.max_truths or cpus.len > 65535 or truths.len > 65535 - cpus.len) return error.InvalidServicesWireRoster;
    if (memory_words > limits.max_memory_words or memory_words > 1 << 22) return error.InvalidMemorySidecarCount;
    var totals: [T.FAMILIES]u64 = @splat(0);
    var sponge_perms: u64 = 0;
    var sum_steps: u64 = 0;
    var proof_bytes: u64 = 0;
    var native_rows: u64 = 0;
    var ram: u64 = 2 * @as(u64, memory_words);
    for (cpus, 0..) |cpu, index| {
        const g = cpu.declaration.geometry;
        try g.validate();
        try cpu.request.cpu.validate(g.cpu_log);
        if (cpu.request.epoch != index + 1 or cpu.request.memory_epoch != cpu.request.epoch or cpu.request.division_requests > cpu.request.cpu.steps or @as(u64, cpu.request.multiplication_requests) > 2 * @as(u64, cpu.request.cpu.steps) or serviceCalls(cpu.request) > cpu.request.cpu.steps) return error.InvalidServicesWireRequest;
        const calls = cpu.request.all();
        if (cpu.request.division_requests > (@as(u32, 1) << @intCast(g.division_log)) or cpu.request.multiplication_requests > (@as(u32, 1) << @intCast(g.multiplication_log))) return error.InvalidServicesWireRequest;
        _ = try g.lsCounts(cpu.request.ls_count);
        if (g.omit_empty_division and cpu.request.division_requests != 0) return error.InvalidServicesWireRequest;
        sum_steps = try std.math.add(u64, sum_steps, cpu.request.cpu.steps);
        native_rows = try std.math.add(u64, native_rows, try rowSum(g));
        var mass16 = try g.range16Mass();
        var mass8 = try g.range8Mass();
        for (0..T.FAMILIES) |k| {
            const f: T.Family = @enumFromInt(k);
            const log = cpu.declaration.bridges.at(f);
            if ((log != null) != (calls[k] != 0) or totals[k] >= core.fields.m31.Modulus - 1) return error.InvalidServicesWireRequest;
            if (log) |l| {
                if (k == 0) {
                    _ = try A.crypto.keccak.word16_bridge.types.validateGeometry(calls[k], @intCast(1 + totals[k]), l);
                } else {
                    _ = try A.crypto.secp256k1.word16_bridge.types.validateGeometry(T.bridgeKind(f), calls[k], @intCast(1 + totals[k]), l);
                }
                const n = @as(u64, 1) << @intCast(l);
                native_rows = try std.math.add(u64, native_rows, n);
                mass16 = try std.math.add(u64, mass16, (if (k == 0) @as(u64, A.crypto.keccak.word16_bridge.layout.U16.len) else A.crypto.secp256k1.word16_bridge.layout.U16.len) * n);
                mass8 = try std.math.add(u64, mass8, (if (k == 0) @as(u64, A.crypto.keccak.word16_bridge.layout.U8.len) else A.crypto.secp256k1.word16_bridge.layout.U8.len) * n);
            }
            totals[k] = try std.math.add(u64, totals[k], calls[k]);
        }
        // Bulk geometry/mass: the same admission the receiver repeats in P.admit.
        for (T.bulk_kinds) |kind| if (cpu.declaration.bridges.bulk.at(kind)) |l| {
            if (l > 24) return error.InvalidServicesWireRequest;
            native_rows = try std.math.add(u64, native_rows, @as(u64, 1) << @intCast(l));
            mass16 = try std.math.add(u64, mass16, @as(u64, A.crypto.bulk_memory.layout.range16Count(kind)) << @intCast(l));
        } else if (cpu.request.bulk.rows(kind) != 0) return error.InvalidServicesWireRequest;
        for (T.bulk_kinds) |kind| if (cpu.declaration.bridges.bulk.at(kind)) |l| {
            _ = A.crypto.bulk_memory.types.validateGeometry(kind, cpu.request.bulk.rows(kind), l) catch return error.InvalidServicesWireRequest;
            if (cpu.request.bulk.rows(kind) == 0) return error.InvalidServicesWireRequest;
        };
        // Sponge geometry/mass: the same admission the receiver repeats in P.admit.
        for (T.sponge_kinds) |kind| if (cpu.declaration.bridges.sponge.at(kind)) |l| {
            _ = A.crypto.keccak_sponge.types.validateGeometry(kind, cpu.request.sponge.rows(kind), l) catch return error.InvalidServicesWireRequest;
            if (cpu.request.sponge.rows(kind) == 0) return error.InvalidServicesWireRequest;
            native_rows = try std.math.add(u64, native_rows, @as(u64, 1) << @intCast(l));
            mass16 = try std.math.add(u64, mass16, @as(u64, A.crypto.keccak_sponge.layout.range16Count(kind)) << @intCast(l));
            mass8 = try std.math.add(u64, mass8, @as(u64, A.crypto.keccak_sponge.layout.range8Count(kind)) << @intCast(l));
        } else if (cpu.request.sponge.rows(kind) != 0) return error.InvalidServicesWireRequest;
        sponge_perms = try std.math.add(u64, sponge_perms, cpu.request.sponge.perms);
        // LS-D64 geometry/mass: the same admission the receiver repeats in P.admit.
        _ = T.dwordCounts(cpu.declaration.bridges, cpu.request.ls_dword) catch return error.InvalidServicesWireRequest;
        for (0..T.DWORD_INSTANCES) |k| if (cpu.declaration.bridges.dwordLog(k)) |l| {
            native_rows = try std.math.add(u64, native_rows, @as(u64, 1) << @intCast(l));
            mass16 = try std.math.add(u64, mass16, @as(u64, A.memory.load_store_dword.layout.LOGICAL_U16.len) << @intCast(l));
            mass8 = try std.math.add(u64, mass8, @as(u64, A.memory.load_store_dword.layout.LOGICAL_U8.len) << @intCast(l));
        };
        if (mass16 >= core.fields.m31.Modulus or mass8 >= core.fields.m31.Modulus) return error.CombinedRangeMassExceeded;
        ram = try std.math.add(u64, ram, 58 * @as(u64, cpu.request.sponge.calls) + 36 * @as(u64, cpu.request.sponge.perms));
        ram = try std.math.add(u64, ram, 2 * (@as(u64, cpu.request.ls_count) + cpu.request.ls_dword));
        for (0..T.FAMILIES) |k| ram = try std.math.add(u64, ram, 2 * T.words(@enumFromInt(k)) * calls[k]);
        try P.bulkCounts(cpu.request.bulk);
        ram = try std.math.add(u64, ram, cpu.request.bulk.ram());
        if (cpu.proof.bytes == 0 or cpu.proof.bytes > limits.max_proof_bytes) return error.ServicesProofLimit;
        proof_bytes = try std.math.add(u64, proof_bytes, cpu.proof.bytes);
    }
    if (memory_words >= (@as(u64, 1) << @intCast(cpus[0].declaration.geometry.initialLog())) or memory_words >= (@as(u64, 1) << @intCast(cpus[cpus.len - 1].declaration.geometry.terminalLog()))) return error.InvalidServicesWireBoundary;
    if (sum_steps > limits.max_total_steps or ram >= core.fields.m31.Modulus or 50 * totals[0] >= core.fields.m31.Modulus) return error.ServicesWireBudget;
    var next: [T.FAMILIES]u64 = @splat(1);
    var previous: u8 = 0;
    var wire: u64 = 0;
    for (1..T.FAMILIES) |k| wire = try std.math.add(u64, wire, T.bridgeWires(@enumFromInt(k)) * totals[k]);
    for (truths) |truth| {
        const t = truth.declaration;
        const k = @intFromEnum(t.family);
        if (k < previous or t.calls == 0 or t.first_id != next[k]) return error.InvalidCombinedTruthSpan;
        previous = k;
        if (t.family == .keccak) {
            const policy = try keccakPolicy(t.logs[1]);
            if (t.logs[0] > 21) return error.InvalidServicesTruthGeometry;
            try A.crypto.keccak.layout.validateGeometry(t.calls, t.first_id, t.logs[0]);
            if (policy.throughputTables()) _ = try A.crypto.keccak.layout.admitThroughputRoster(&.{t.calls});
            native_rows = try std.math.add(u64, native_rows, (@as(u64, 1) << @intCast(t.logs[0])) + (@as(u64, 1) << @intCast(policy.tableLog(.chi))) + (@as(u64, 1) << @intCast(policy.tableLog(.xor5))));
        } else if (t.family == .sha256) {
            if (t.logs[0] > @import("../sha256/roster.zig").MAX_LOG or t.logs[1] != 0) return error.InvalidServicesTruthGeometry;
            try A.crypto.sha256.layout.validateGeometry(t.calls, t.first_id, t.logs[0]);
            native_rows = try std.math.add(u64, native_rows, @as(u64, 1) << @intCast(t.logs[0]));
            wire = try std.math.add(u64, wire, 4 * @as(u64, t.calls));
        } else if (T.curveOp(t.family)) |op| {
            const Cr = @import("../curves/roster.zig");
            if (t.logs[0] > Cr.MAX_LOG or t.logs[1] != 0) return error.InvalidServicesTruthGeometry;
            try Cr.validateGeometry(op, t.calls, t.first_id, t.logs[0]);
            native_rows = try std.math.add(u64, native_rows, @as(u64, 1) << @intCast(t.logs[0]));
            wire = try std.math.add(u64, wire, Cr.wireFractions(op) * @as(u64, t.calls));
        } else if (t.family == .arith256_mod) {
            if (t.logs[0] > @import("../arith256/roster.zig").MAX_LOG or t.logs[1] != 0) return error.InvalidServicesTruthGeometry;
            try A.crypto.arith256.layout.validateGeometry(t.calls, t.first_id, t.logs[0]);
            native_rows = try std.math.add(u64, native_rows, @as(u64, 1) << @intCast(t.logs[0]));
            wire = try std.math.add(u64, wire, A.crypto.arith256.layout.WIRE_FRACTIONS * @as(u64, t.calls));
        } else {
            const S = A.crypto.secp256k1;
            const program = S.program.get(@enumFromInt(k));
            const mass = try S.layout.admitRoster(&.{ .{ .kind = .product, .program = program, .calls = t.calls, .first_id = t.first_id, .log = t.logs[0] }, .{ .kind = .linear, .program = program, .calls = t.calls, .first_id = t.first_id, .log = t.logs[1] } }, &.{});
            wire = try std.math.add(u64, wire, mass.wires);
            native_rows = try std.math.add(u64, native_rows, (@as(u64, 1) << @intCast(t.logs[0])) + (@as(u64, 1) << @intCast(t.logs[1])) + 256);
        }
        next[k] = try std.math.add(u64, next[k], t.calls);
        if (truth.proof.bytes == 0 or truth.proof.bytes > limits.max_proof_bytes) return error.ServicesProofLimit;
        proof_bytes = try std.math.add(u64, proof_bytes, truth.proof.bytes);
    }
    for (next, totals, 0..) |n, total, k| if (n != total + 1 + (if (k == 0) sponge_perms else 0)) return error.InvalidCombinedTruthSpan;
    if (wire >= core.fields.m31.Modulus or proof_bytes > limits.max_total_proof_bytes or native_rows > limits.max_native_row_sum) return error.ServicesWireBudget;
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, setups: []const *const R.CpuSetup, truths: []const R.Truth, bundle: *const E.Bundle) !void {
    if (setups.len == 0 or setups.len != bundle.cpus.len or truths.len != bundle.truths.len) return error.InvalidServicesWireRoster;
    const initial = bundle.cpus[0].request.base.memory.initial;
    const terminal = bundle.cpus[bundle.cpus.len - 1].request.base.memory.terminal;
    if (initial.len != terminal.len or initial.len > 1 << 22) return error.InvalidServicesWireBoundary;
    const cpus = try a.alloc(Cpu, setups.len);
    defer a.free(cpus);
    for (setups, bundle.cpus, cpus, 0..) |setup, c, *out, index| {
        if ((index != 0 and c.request.base.memory.initial.len != 0) or (index + 1 != setups.len and c.request.base.memory.terminal.len != 0)) return error.InvalidServicesWireBoundary;
        out.* = .{ .declaration = .{ .geometry = setup.materials.geometry, .bridges = setup.bridges }, .request = CompactRequest.from(c.request), .claims = WireClaims.from(c.claims, setup.bridges), .proof = .{ .bytes = c.bytes.len, .sha256 = hash(c.bytes) } };
    }
    const tt = try a.alloc(Truth, truths.len);
    defer a.free(tt);
    for (truths, bundle.truths, tt) |t, p, *out| out.* = .{ .declaration = TruthDeclaration.from(t), .claims = p.claims, .proof = .{ .bytes = p.bytes.len, .sha256 = hash(p.bytes) } };
    var meta = Metadata{ .cpus = cpus, .truths = tt, .specs = bundle.manifest.specs, .roots = bundle.manifest.roots, .seal = bundle.manifest.digest, .memory_words = @intCast(initial.len), .cells_sha256 = undefined };
    try validate(meta, .{});
    try bundle.manifest.check(meta.specs);
    try Cells.write(dir, initial, terminal);
    meta.cells_sha256 = try hashCells(dir, meta.memory_words);
    const json = try std.json.Stringify.valueAlloc(a, meta, .{ .whitespace = .indent_2 });
    defer a.free(json);
    if (json.len > (Limits{}).max_metadata_bytes) return error.ServicesMetadataLimit;
    for (bundle.cpus, 0..) |cpu, index| {
        var buf: [64]u8 = undefined;
        try Receipt.writeExclusive(dir, try proofName(&buf, false, index), cpu.bytes);
    }
    for (bundle.truths, 0..) |truth, index| {
        var buf: [64]u8 = undefined;
        try Receipt.writeExclusive(dir, try proofName(&buf, true, index), truth.bytes);
    }
    try Receipt.writeExclusive(dir, "bundle.json", json);
    try std.posix.fsync(dir.fd);
}
fn readProof(a: std.mem.Allocator, dir: std.fs.Dir, truth: bool, index: usize, file: File) ![]u8 {
    var buf: [64]u8 = undefined;
    var f = try dir.openFile(try proofName(&buf, truth, index), .{});
    defer f.close();
    if (try f.getEndPos() != file.bytes) return error.ServicesProofChanged;
    const bytes = try f.readToEndAlloc(a, @intCast(file.bytes));
    errdefer a.free(bytes);
    if (!std.mem.eql(u8, &hash(bytes), &file.sha256)) return error.ServicesProofChanged;
    return bytes;
}
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, limits: Limits) !Loaded {
    const bytes = try dir.readFileAlloc(a, "bundle.json", limits.max_metadata_bytes);
    defer a.free(bytes);
    var parsed = try std.json.parseFromSlice(Metadata, a, bytes, .{});
    defer parsed.deinit();
    const m = parsed.value;
    try validate(m, limits);
    var manifest = try G.Manifest.init(a, m.specs, m.roots);
    errdefer manifest.deinit();
    if (!std.mem.eql(u8, &manifest.digest, &m.seal)) return error.GlobalExecutionManifestChanged;
    if (!std.mem.eql(u8, &try hashCells(dir, m.memory_words), &m.cells_sha256)) return error.ServicesCellsChanged;
    const cells = try Cells.read(a, dir, m.memory_words);
    var owns_cells = true;
    errdefer if (owns_cells) cells.deinit(a);
    const decl = try a.alloc(CpuDeclaration, m.cpus.len);
    errdefer a.free(decl);
    const td = try a.alloc(TruthDeclaration, m.truths.len);
    errdefer a.free(td);
    const cpus = try a.alloc(E.CpuEncoded, m.cpus.len);
    errdefer a.free(cpus);
    var cpu_done: usize = 0;
    errdefer for (cpus[0..cpu_done]) |p| a.free(p.bytes);
    for (m.cpus, cpus, decl, 0..) |c, *out, *d, index| {
        d.* = c.declaration;
        out.* = .{ .bytes = try readProof(a, dir, false, index, c.proof), .request = c.request.expand(if (index == 0) cells.initial else &.{}, if (index + 1 == m.cpus.len) cells.terminal else &.{}), .claims = c.claims.expand() };
        cpu_done += 1;
    }
    const tt = try a.alloc(E.TruthEncoded, m.truths.len);
    errdefer a.free(tt);
    var truth_done: usize = 0;
    errdefer for (tt[0..truth_done]) |t| a.free(t.bytes);
    for (m.truths, tt, td, 0..) |t, *out, *d, index| {
        d.* = t.declaration;
        out.* = .{ .bytes = try readProof(a, dir, true, index, t.proof), .claims = t.claims };
        truth_done += 1;
    }
    owns_cells = false;
    return .{ .cpu_declarations = decl, .truth_declarations = td, .bundle = .{ .manifest = manifest, .cpus = cpus, .truths = tt } };
}
