//! Durable truth queries: packed Keccak cells, secp retained bytes, fixed tuple
//! tables and saved multiplicities only. No wide MAIN/Q row reconstruction.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const M = core.fields.m31.M31;
const R = @import("../roster.zig");
const Frame = @import("truth_frame.zig");
const F = @import("truth_fractions.zig");
const tuples = K.equations.lookup_tuple_authority;
const physical = A.witness.physical;
const StateCells = struct {
    row: *const K.trace.PackedRow,
    pub inline fn at(self: @This(), index: usize) M {
        return self.row.stateCell(index);
    }
};
const ParityCells = struct {
    row: *const K.trace.PackedRow,
    pub inline fn at(self: @This(), index: usize) M {
        return self.row.parityCell(index);
    }
};
pub const Provider = struct {
    source: *const R.TruthSource,
    frames: [3]Frame.Instance,
    plan: Frame.Plan,
    pub fn init(source: *const R.TruthSource, expected: [3]Frame.Instance, budget: usize) !Provider {
        const plan = try Frame.Plan.admit(&expected, budget);
        return initChecked(source, expected, plan);
    }
    /// Classic producers never materialize a row×query GKR fact matrix.
    pub fn initClassic(source: *const R.TruthSource, expected: [3]Frame.Instance) !Provider {
        for (expected) |instance| _ = try instance.variables();
        return initChecked(source, expected, .{});
    }
    fn initChecked(source: *const R.TruthSource, expected: [3]Frame.Instance, plan: Frame.Plan) !Provider {
        const actual = try Frame.forSource(source);
        for (actual, expected) |x, y| if (!std.meta.eql(x, y)) return error.TruthGkrSourceGeometryMismatch;
        switch (source.*) {
            .keccak => |s| {
                try s.permutation.validateMetadata();
                try s.chi.validateMetadata();
                try s.xor5.validateMetadata();
                if (s.permutation.fixed.len != K.layout.FIXED * s.permutation.size() or s.chi.fixed.len != 7 * s.chi.size() or s.xor5.fixed.len != 7 * s.xor5.size()) return error.InvalidTruthKeccakMetadata;
                for (s.permutation.metadata) |row| if (row.flags > 3 or row.id >= core.fields.m31.Modulus) return error.InvalidTruthKeccakMetadata;
            },
            .secp => |s| {
                try s.batch.product.validateMetadata();
                try s.batch.linear.validateMetadata();
                if (s.bytes.main.len != 256 or s.bytes.fixed.len != 3 * 256) return error.InvalidTruthByteMetadata;
            },
            else => return error.GkrV3ServiceUnsupported,
        }
        return .{ .source = source, .frames = expected, .plan = plan };
    }
    /// expected geometry must come from independently admitted receiver setup,
    /// not copied from producer declarations. This adapter alone is not a verifier.
    pub fn emit(self: Provider, instance: Frame.Instance, logical: usize, sink: anytype) !void {
        return self.emitRange(instance, logical, 0, instance.queries, sink);
    }
    /// Emits only the selected original query interval from immutable metadata.
    /// No expanded MAIN row, query matrix or callback-owned storage is created.
    pub fn emitRange(self: Provider, instance: Frame.Instance, logical: usize, first_query: usize, count: usize, sink: anytype) !void {
        if (logical >= try instance.rows()) return error.InvalidTruthGkrRow;
        var found = false;
        for (self.frames) |expected| if (std.meta.eql(instance, expected)) {
            found = true;
        };
        if (!found) return error.TruthGkrSourceGeometryMismatch;
        if (first_query > instance.queries or count > instance.queries - first_query) return error.InvalidTruthGkrQueryRange;
        if (count == 0) return;
        const end = first_query + count;
        switch (self.source.*) {
            .keccak => |s| switch (instance.role) {
                .keccak => {
                    const trace = &s.permutation;
                    const n = trace.size();
                    const index = logical % n;
                    const empty = K.trace.PackedRow{};
                    const row = if (index < trace.metadata.len) &trace.metadata[index] else &empty;
                    const next_index = (index + 1) % n;
                    const next = if (next_index < trace.metadata.len) &trace.metadata[next_index] else &empty;
                    const r = physical(logical, trace.log_size);
                    var round: [24]M = undefined;
                    var weight = M.zero();
                    for (&round, 0..) |*v, i| {
                        v.* = trace.fixed[(2 + i) * n + r];
                        weight = weight.add(v.*);
                    }
                    weight = weight.mul(M.fromCanonical(row.flags & 1)).neg();
                    const chi_end = @min(end, K.layout.STATE);
                    if (first_query < chi_end) for (first_query..chi_end) |event| sink.emitBase(.chi, tuples.chiAccessors(M, StateCells{ .row = row }, ParityCells{ .row = row }, StateCells{ .row = next }, &round, event), weight);
                    const xor_first = @max(first_query, K.layout.STATE) - K.layout.STATE;
                    const xor_end = end -| K.layout.STATE;
                    for (xor_first..xor_end) |event| sink.emitBase(.xor5, tuples.xor5Accessors(M, StateCells{ .row = row }, ParityCells{ .row = row }, event), weight);
                },
                .chi, .xor5 => {
                    const table = if (instance.role == .chi) &s.chi else &s.xor5;
                    const n = table.size();
                    const r = physical(logical, table.log_size);
                    var tuple: [6]M = undefined;
                    for (&tuple, 0..) |*v, c| v.* = table.fixed[c * n + r];
                    sink.emitBase(if (instance.role == .chi) .chi else .xor5, tuple, M.fromCanonical(table.multiplicities[logical]));
                },
                else => return error.TruthGkrSourceGeometryMismatch,
            },
            .secp => |s| switch (instance.role) {
                .product, .linear => {
                    const trace = if (instance.role == .product) &s.batch.product else &s.batch.linear;
                    const active = logical < @as(usize, trace.calls) * trace.program.rows(trace.kind == .product);
                    const byte_count = S.layout.metadataByteCount(trace.kind);
                    const skip: usize = if (instance.byte_policy == .canonical_inputs) 64 else 0;
                    for (first_query..end) |query| sink.emitBase(.byte, [1]M{if (active) M.fromCanonical(trace.lookup_bytes[logical * byte_count + skip + query]) else M.zero()}, M.one());
                },
                .bytes => sink.emitBase(.byte, [1]M{M.fromCanonical(@intCast(logical))}, s.bytes.main[physical(logical, 8)].neg()),
                else => return error.TruthGkrSourceGeometryMismatch,
            },
            else => return error.GkrV3ServiceUnsupported,
        }
    }
};
