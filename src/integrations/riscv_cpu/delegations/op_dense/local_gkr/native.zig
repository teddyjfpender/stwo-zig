//! One source-owned BYTE instance for the closed public-packet fixture.
//! A verified child still requires authenticated MAIN projection and output debt.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const D = @import("stwo_riscv_frontend").rv64_air.crypto.bn254_dense;
const C = D.fixture_component;
pub const Q = C.Q;
pub const M = C.M;
pub const Channel = core.channel.poseidon2_m31.Om31ChannelV2;
const GP = engine.lookups.gkr_prover.ForField(Q);
pub const GV = engine.lookups.gkr_verifier.ForField(Q);
const Base = @import("../../../poseidon2_outer/pure_p2_native.zig");
const Framing = @import("../../../poseidon2_outer/pure_p2_framing.zig");
const Closure = @import("../../../word16_global_execution/services/gkr_local/closure.zig");
const Wire = @import("../../../word16_global_execution/services/gkr_local/wire.zig");
pub const ROW_LOG = 8;
pub const LANE_LOG = 9;
pub const VARIABLES = 17;
pub const TERMS = 355;
pub const LANES = 512;
pub const FACTS = 256 * 512;
pub const MAGIC = "DENSELG1";
pub const Instance = struct {
    pub fn variables(_: @This()) !u32 {
        return VARIABLES;
    }
};
pub const Scope = struct { statement: [32]u8, fixed: [32]u8, main: [32]u8 };
fn raw(channel: anytype, data: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, data[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn statement(comptime kind: D.spec.Kind, input: *const [D.spec.inputs(kind)]u256, output: [12]u256) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("closed-dense-byte-local-gkr/v1");
    h.update(&D.sourceDigest());
    h.update(&.{@intFromEnum(kind)});
    for (input) |v| {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, v, .little);
        h.update(&b);
    }
    for (output) |v| {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, v, .little);
        h.update(&b);
    }
    h.update(@embedFile("native.zig"));
    h.update(@embedFile("projection.zig"));
    h.update(@embedFile("component.zig"));
    return h.finalResult();
}
pub fn begin(scope: Scope) Channel {
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x444c474b, 1, 8, 9, 17, 355, 1 });
    raw(&channel, scope.statement);
    raw(&channel, scope.fixed);
    raw(&channel, scope.main);
    return channel;
}
pub fn receipt(scope: Scope, proof: *const GV.GkrBatchProof, marginals: []const []const Q) !core.crypto.poseidon2_m31_sponge.Digest {
    var writer = Base.ReceiptWriter{};
    writer.tag(0x444c474b);
    writer.integer(1);
    writer.rawDigest(scope.statement);
    writer.rawDigest(scope.fixed);
    writer.rawDigest(scope.main);
    writer.integer(VARIABLES);
    writer.integer(TERMS);
    try Framing.emitPayload(proof, &.{VARIABLES}, marginals, &writer);
    return writer.finish();
}
pub const Pending = struct {
    artifact: GV.GkrArtifact,
    beta: Q,
    eta: Q,
    digest: core.crypto.poseidon2_m31_sponge.Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, scope: Scope, proof: *const GV.GkrBatchProof) !Pending {
    var channel = begin(scope);
    const beta = channel.drawSecureFelt();
    var artifact = try GV.partiallyVerifyBatch(a, &.{.LogUp}, proof, &channel);
    errdefer artifact.deinit(a);
    try validateArtifact(&artifact);
    try Closure.close(a, proof.output_claims_by_instance);
    const digest = try receipt(scope, proof, artifact.claims_to_verify_by_instance);
    return .{ .artifact = artifact, .beta = beta, .eta = channel.drawSecureFelt(), .digest = digest };
}
pub fn validateArtifact(artifact: *const GV.GkrArtifact) !void {
    if (artifact.n_variables_by_instance.len != 1 or artifact.n_variables_by_instance[0] != VARIABLES or artifact.ood_point.len != VARIABLES or artifact.claims_to_verify_by_instance.len != 1 or artifact.claims_to_verify_by_instance[0].len != 2) return error.DenseLocalShape;
}
pub fn encode(a: std.mem.Allocator, proof: *const GV.GkrBatchProof) ![]u8 {
    return Wire.encodeFor(a, &[_]Instance{.{}}, proof, MAGIC);
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8) !Wire.Owned {
    return Wire.decodeFor(a, &[_]Instance{.{}}, bytes, MAGIC);
}
pub fn Reader(comptime kind: D.spec.Kind) type {
    return struct {
        const Self = @This();
        trace: *const D.fixture_trace.Trace(kind),
        beta: Q,
        const View = struct {
            trace: *const D.fixture_trace.Trace(kind),
            physical: usize,
            pub fn fixed(v: *const @This(), c: usize) Q {
                return Q.fromBase(v.trace.fixed[c * 256 + v.physical]);
            }
            pub fn main(v: *const @This(), c: usize) Q {
                return Q.fromBase(v.trace.main[c * 256 + v.physical]);
            }
        };
        pub fn read(ctx: *const anyopaque, first: usize, n: []M, d: []Q) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            if (n.len != d.len or n.len > 512 or first > FACTS or n.len > FACTS - first) return error.ShapeMismatch;
            for (n, d, 0..) |*nn, *dd, i| {
                const f = first + i;
                const lane = f % 512;
                const p = f / 512;
                const v = View{ .trace = self.trace, .physical = p };
                const pair = C.rangeFraction(kind, Q, &v, self.beta, lane);
                const limbs = pair[0].toM31Array();
                for (limbs[1..]) |x| if (x.v != 0) return error.InvalidLayerStructure;
                nn.* = limbs[0];
                dd.* = pair[1];
            }
        }
        pub fn source(self: *const Self) GP.MultiplicitiesSource {
            return .{ .variables = VARIABLES, .context = self, .wide_reads = true, .read_fn = read };
        }
    };
}
pub const Unbound = struct {
    result: GP.ProveBatchResult,
    beta: Q,
    eta: Q,
    digest: core.crypto.poseidon2_m31_sponge.Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }
};
pub fn prove(comptime kind: D.spec.Kind, a: std.mem.Allocator, scope: Scope, trace: *const D.fixture_trace.Trace(kind)) !Unbound {
    var channel = begin(scope);
    const beta = channel.drawSecureFelt();
    const reader = Reader(kind){ .trace = trace, .beta = beta };
    const source = reader.source();
    var result = try GP.proveBatchSourceCheckpointedWithOptions(a, &channel, &.{source}, .{ .coefficient_encoding = .fixed4 });
    errdefer result.deinit(a);
    try validateArtifact(&result.artifact);
    try Closure.close(a, result.proof.output_claims_by_instance);
    const digest = try receipt(scope, &result.proof, result.artifact.claims_to_verify_by_instance);
    return .{ .result = result, .beta = beta, .eta = channel.drawSecureFelt(), .digest = digest };
}
