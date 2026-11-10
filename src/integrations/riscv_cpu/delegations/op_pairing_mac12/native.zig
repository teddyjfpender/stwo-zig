//! Conditional complete finite pairing source. Independently challenged relations
//! have separate closure checks; neither may cancel debt against the other.
//! Numerical GKR acceptance is pending until every terminal binds physical MAIN.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const G = A.crypto.bn254_pairing_mac12;
const S = G.source;
const C = G.fixture;
pub const Q = C.Q;
pub const M = C.M;
pub const Channel = core.channel.poseidon2_m31.Om31ChannelV2;
const GP = engine.lookups.gkr_prover.ForField(Q);
pub const GV = engine.lookups.gkr_verifier.ForField(Q);
const Base = @import("../../poseidon2_outer/pure_p2_native.zig");
const Framing = @import("../../poseidon2_outer/pure_p2_framing.zig");
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const Wire = @import("../../word16_global_execution/services/gkr_local/wire.zig");
pub const Family = enum { bytes, ssa };
pub const Role = C.Role;
pub const Instance = struct {
    family: Family,
    role: Role,
    row_log: u32,
    lane_log: u32,
    pub fn variables(self: @This()) !u32 {
        return self.row_log + self.lane_log;
    }
    pub fn lanes(self: @This()) usize {
        return @as(usize, 1) << @intCast(self.lane_log);
    }
    pub fn rows(self: @This()) usize {
        return @as(usize, 1) << @intCast(self.row_log);
    }
    pub fn facts(self: @This()) usize {
        return self.rows() * self.lanes();
    }
};
pub const INSTANCES = [_]Instance{
    .{ .family = .bytes, .role = .arithmetic, .row_log = 15, .lane_log = 9 },
    .{ .family = .bytes, .role = .hints, .row_log = 11, .lane_log = 6 },
    .{ .family = .bytes, .role = .table, .row_log = 8, .lane_log = 0 },
    .{ .family = .ssa, .role = .arithmetic, .row_log = 15, .lane_log = 5 },
    .{ .family = .ssa, .role = .hints, .row_log = 11, .lane_log = 0 },
    .{ .family = .ssa, .role = .frontier, .row_log = 11, .lane_log = 0 },
};
pub const MAGIC = "PAIRMAC1";
pub const Blake = ForTransport(false);
pub const Poseidon = ForTransport(true);
pub const Scope = Blake.Scope;
fn raw(channel: anytype, data: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, data[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
fn baseStatement(public: []const u256) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("closed-complete-finite-pairing-mac12/v1");
    h.update(&D.sourceDigest());
    h.update(&G.sourceDigest());
    h.update(&C.sourceDigest());
    h.update(@embedFile("native.zig"));
    h.update(@embedFile("component.zig"));
    h.update(@embedFile("projection.zig"));
    h.update(@embedFile("trace.zig"));
    for (public) |v| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, v, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
pub fn statement(public: []const u256) [32]u8 {
    return Blake.statement(public);
}
pub fn begin(scope: Scope) Channel {
    return beginFor(false, scope) catch unreachable;
}
fn beginFor(comptime poseidon: bool, scope: ForTransport(poseidon).Scope) !Channel {
    if (poseidon) {
        _ = try core.crypto.poseidon2_m31_sponge.decode(scope.fixed);
        _ = try core.crypto.poseidon2_m31_sponge.decode(scope.main);
    }
    var channel = Channel.init();
    channel.mixU32s(&.{ if (poseidon) @as(u32, 0x504d5032) else 0x504d3132, 1, 6, if (poseidon) @as(u32, 9) else 3 });
    for (INSTANCES) |i| channel.mixU32s(&.{ @intFromEnum(i.family), @intFromEnum(i.role), i.row_log, i.lane_log });
    raw(&channel, scope.statement);
    if (poseidon) {
        channel.mixRoot(scope.fixed);
        channel.mixRoot(scope.main);
    } else {
        raw(&channel, scope.fixed);
        raw(&channel, scope.main);
    }
    return channel;
}
pub fn validateArtifact(artifact: *const GV.GkrArtifact) !void {
    if (artifact.n_variables_by_instance.len != INSTANCES.len or artifact.claims_to_verify_by_instance.len != INSTANCES.len or artifact.ood_point.len != 24) return error.DenseSsaShape;
    for (INSTANCES, artifact.n_variables_by_instance, artifact.claims_to_verify_by_instance) |i, variables, claims| if (variables != try i.variables() or claims.len != 2) return error.DenseSsaShape;
}
fn receiptFor(comptime poseidon: bool, scope: ForTransport(poseidon).Scope, proof: *const GV.GkrBatchProof, marginals: []const []const Q) !core.crypto.poseidon2_m31_sponge.Digest {
    var vars: [6]u32 = undefined;
    var writer = Base.ReceiptWriter{};
    writer.tag(if (poseidon) 0x504d5032 else 0x504d3132);
    writer.integer(1);
    writer.rawDigest(scope.statement);
    if (poseidon) {
        writer.root(scope.fixed);
        writer.root(scope.main);
    } else {
        writer.rawDigest(scope.fixed);
        writer.rawDigest(scope.main);
    }
    for (INSTANCES, &vars) |i, *v| {
        v.* = try i.variables();
        writer.integer(@intFromEnum(i.family));
        writer.integer(@intFromEnum(i.role));
        writer.integer(i.row_log);
        writer.integer(i.lane_log);
    }
    try Framing.emitPayload(proof, &vars, marginals, &writer);
    return writer.finish();
}
pub fn close(a: std.mem.Allocator, proof: *const GV.GkrBatchProof) !void {
    if (proof.output_claims_by_instance.len != 6) return error.DenseSsaShape;
    try Closure.close(a, proof.output_claims_by_instance[0..3]);
    try Closure.close(a, proof.output_claims_by_instance[3..6]);
}
pub fn Reader() type {
    return struct {
        const Self = @This();
        witness: *const C.Model,
        instance: Instance,
        beta: Q,
        ssa: C.Wire,
        pub fn read(ctx: *const anyopaque, first: usize, n: []M, d: []Q) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            const i = self.instance;
            if (self.witness.columns[@intFromEnum(i.role)] == null) return error.ShapeMismatch;
            if (n.len != d.len or n.len > 512 or first > i.facts() or n.len > i.facts() - first) return error.ShapeMismatch;
            for (n, d, 0..) |*nn, *dd, j| {
                const fact = first + j;
                const physical = fact / i.lanes();
                const lane = fact % i.lanes();
                const row = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, i.row_log), i.row_log);
                var pair: struct { Q, Q } = undefined;
                if (i.family == .bytes) pair = switch (i.role) {
                    .arithmetic => blk: {
                        const v = self.witness.view(.arithmetic, row);
                        break :blk C.byteFraction(.arithmetic, Q, &v, self.beta, lane);
                    },
                    .hints => blk: {
                        const v = self.witness.view(.hints, row);
                        break :blk C.byteFraction(.hints, Q, &v, self.beta, lane);
                    },
                    .table => blk: {
                        const v = self.witness.view(.table, row);
                        break :blk C.byteFraction(.table, Q, &v, self.beta, lane);
                    },
                    else => return error.InvalidLayerStructure,
                } else pair = switch (i.role) {
                    .arithmetic => blk: {
                        const v = self.witness.view(.arithmetic, row);
                        break :blk C.ssaFraction(.arithmetic, Q, &v, self.ssa, lane);
                    },
                    .hints => blk: {
                        const v = self.witness.view(.hints, row);
                        break :blk C.ssaFraction(.hints, Q, &v, self.ssa, lane);
                    },
                    .frontier => blk: {
                        const v = self.witness.view(.frontier, row);
                        break :blk C.ssaFraction(.frontier, Q, &v, self.ssa, lane);
                    },
                    else => return error.InvalidLayerStructure,
                };
                const coordinates = pair[0].toM31Array();
                for (coordinates[1..]) |x| if (x.v != 0) return error.InvalidLayerStructure;
                nn.* = coordinates[0];
                dd.* = pair[1];
            }
        }
        pub fn source(self: *const Self) GP.MultiplicitiesSource {
            return .{ .variables = self.instance.variables() catch unreachable, .context = self, .wide_reads = true, .read_fn = read };
        }
    };
}
pub const Pending = struct {
    artifact: GV.GkrArtifact,
    beta: Q,
    ssa: C.Wire,
    eta: Q,
    digest: core.crypto.poseidon2_m31_sponge.Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
fn verifyFor(comptime poseidon: bool, a: std.mem.Allocator, scope: ForTransport(poseidon).Scope, proof: *const GV.GkrBatchProof) !Pending {
    var channel = try beginFor(poseidon, scope);
    const beta = channel.drawSecureFelt();
    const ssa = C.Wire.draw(&channel);
    var artifact = try GV.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp, .LogUp, .LogUp, .LogUp, .LogUp }, proof, &channel);
    errdefer artifact.deinit(a);
    try validateArtifact(&artifact);
    try close(a, proof);
    return .{ .artifact = artifact, .beta = beta, .ssa = ssa, .eta = channel.drawSecureFelt(), .digest = try receiptFor(poseidon, scope, proof, artifact.claims_to_verify_by_instance) };
}
pub const Unbound = struct {
    result: GP.ProveBatchResult,
    beta: Q,
    ssa: C.Wire,
    eta: Q,
    digest: core.crypto.poseidon2_m31_sponge.Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }
};
fn proveFor(comptime poseidon: bool, a: std.mem.Allocator, scope: ForTransport(poseidon).Scope, witness: *const C.Model) !Unbound {
    try witness.requireColumns();
    var channel = try beginFor(poseidon, scope);
    const beta = channel.drawSecureFelt();
    const ssa = C.Wire.draw(&channel);
    var readers: [6]Reader() = undefined;
    var sources: [6]GP.MultiplicitiesSource = undefined;
    for (INSTANCES, &readers, &sources) |instance, *r, *s| {
        r.* = .{ .witness = witness, .instance = instance, .beta = beta, .ssa = ssa };
        s.* = r.source();
    }
    var result = try GP.proveBatchSourceCheckpointedWithOptions(a, &channel, &sources, .{ .coefficient_encoding = .fixed4 });
    errdefer result.deinit(a);
    try validateArtifact(&result.artifact);
    try close(a, &result.proof);
    return .{ .result = result, .beta = beta, .ssa = ssa, .eta = channel.drawSecureFelt(), .digest = try receiptFor(poseidon, scope, &result.proof, result.artifact.claims_to_verify_by_instance) };
}
pub fn encode(a: std.mem.Allocator, proof: *const GV.GkrBatchProof) ![]u8 {
    return Wire.encodeFor(a, &INSTANCES, proof, MAGIC);
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8) !Wire.Owned {
    return Wire.decodeFor(a, &INSTANCES, bytes, MAGIC);
}

/// Only crypto-root transport varies. Arithmetic source, readers, GKR traversal,
/// source roster and closure equations are shared by both explicit suites.
fn ForTransport(comptime poseidon: bool) type {
    return struct {
        pub const Root = if (poseidon) core.crypto.poseidon2_m31_sponge.Digest else [32]u8;
        pub const Scope = struct { statement: [32]u8, fixed: Root, main: Root };
        pub const MAGIC = if (poseidon) "PAIRP2V1" else "PAIRMAC1";
        pub fn statement(public: []const u256) [32]u8 {
            if (!poseidon) return baseStatement(public);
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update("complete-finite-pairing-mac12/native-P2v2-scope36/v1\x00");
            h.update(&core.vcs_lifted.poseidon2_profile.Om31V2.identity());
            h.update(&baseStatement(public));
            return h.finalResult();
        }
        pub fn begin(scope: @This().Scope) !Channel {
            return beginFor(poseidon, scope);
        }
        pub fn receipt(scope: @This().Scope, proof: *const GV.GkrBatchProof, marginals: []const []const Q) !core.crypto.poseidon2_m31_sponge.Digest {
            return receiptFor(poseidon, scope, proof, marginals);
        }
        pub fn prove(a: std.mem.Allocator, scope: @This().Scope, witness: *const C.Model) !Unbound {
            return proveFor(poseidon, a, scope, witness);
        }
        pub fn verify(a: std.mem.Allocator, scope: @This().Scope, proof: *const GV.GkrBatchProof) !Pending {
            return verifyFor(poseidon, a, scope, proof);
        }
        pub fn encode(a: std.mem.Allocator, proof: *const GV.GkrBatchProof) ![]u8 {
            return Wire.encodeFor(a, &INSTANCES, proof, @This().MAGIC);
        }
        pub fn decode(a: std.mem.Allocator, bytes: []const u8) !Wire.Owned {
            return Wire.decodeFor(a, &INSTANCES, bytes, @This().MAGIC);
        }
    };
}
pub fn prove(a: std.mem.Allocator, scope: Scope, witness: *const C.Model) !Unbound {
    return Blake.prove(a, scope, witness);
}
pub fn verify(a: std.mem.Allocator, scope: Scope, proof: *const GV.GkrBatchProof) !Pending {
    return Blake.verify(a, scope, proof);
}
pub fn receipt(scope: Scope, proof: *const GV.GkrBatchProof, marginals: []const []const Q) !core.crypto.poseidon2_m31_sponge.Digest {
    return Blake.receipt(scope, proof, marginals);
}
