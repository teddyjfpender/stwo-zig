//! Explicit diagnostic only. Retains narrow native metadata across interaction
//! publication, then invokes the unchanged committed-row AIR authority. It is
//! never a replacement for PCS/OODS verification or a proof acceptance check.
const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const S = @import("rv64_keccak_sources.zig");
const K = rv.crypto.keccak;
const L = K.layout;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const physical = rv.witness.physical;
pub const Family = enum { permutation, chi, xor5, bridge };
pub const Failure = struct { family: Family, logical_row: usize, constraint: usize, value: Q };
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    permutation: []K.trace.PackedRow,
    chi: []u32,
    xor5: []u32,
    bridge: []K.bridge.trace.Call,
    /// Call before Source.generate auto-retires the packed metadata.
    pub fn init(a: std.mem.Allocator, trace: *const S.Trace) !Snapshot {
        try trace.permutation.validateMetadata();
        try trace.chi.validateMetadata();
        try trace.xor5.validateMetadata();
        try trace.bridge.validateMetadata();
        const permutation = try a.dupe(K.trace.PackedRow, trace.permutation.metadata);
        errdefer a.free(permutation);
        const chi = try a.dupe(u32, trace.chi.multiplicities);
        errdefer a.free(chi);
        const xor5 = try a.dupe(u32, trace.xor5.multiplicities);
        errdefer a.free(xor5);
        return .{ .allocator = a, .permutation = permutation, .chi = chi, .xor5 = xor5, .bridge = try a.dupe(K.bridge.trace.Call, trace.bridge.metadata) };
    }
    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.permutation);
        self.allocator.free(self.chi);
        self.allocator.free(self.xor5);
        self.allocator.free(self.bridge);
        self.* = undefined;
    }
    pub fn inspect(self: *const Snapshot, trace: *const S.Trace, challenges: K.equations.Challenges, bridge_challenges: K.bridge.equations.Challenges, claims: S.Claims) !?Failure {
        // Shallow diagnostic views borrow both owners; never deinit these views.
        var permutation = trace.permutation;
        permutation.metadata = self.permutation;
        var chi = trace.chi;
        chi.multiplicities = self.chi;
        var xor5 = trace.xor5;
        xor5.multiplicities = self.xor5;
        var bridge = trace.bridge;
        bridge.metadata = self.bridge;
        try permutation.validateMetadata();
        try chi.validateMetadata();
        try xor5.validateMetadata();
        try bridge.validateMetadata();
        if (try inspectPermutation(self.allocator, &permutation, challenges, claims.permutation)) |failure| return failure;
        if (try inspectTable(&chi, challenges, claims.chi)) |failure| return failure;
        if (try inspectTable(&xor5, challenges, claims.xor5)) |failure| return failure;
        return inspectBridge(self.allocator, &bridge, bridge_challenges, claims.bridge);
    }
};
fn secure(data: []const M, n: usize, row: usize, column: usize) Q {
    return Q.fromM31(data[column * n + row], data[(column + 1) * n + row], data[(column + 2) * n + row], data[(column + 3) * n + row]);
}
fn inspectPermutation(a: std.mem.Allocator, trace: *const K.trace.Trace, ch: K.equations.Challenges, claim: Q) !?Failure {
    const n = trace.size();
    if (trace.fixed.len != L.FIXED * n or trace.interaction.len != L.INTERACTION * n) return error.InvalidKeccakDiagnosticShape;
    const scratch = try a.create(K.component.Scratch);
    defer a.destroy(scratch);
    const residuals = try a.alloc(Q, L.CONSTRAINTS);
    defer a.free(residuals);
    for (0..n) |logical| {
        const row = physical(logical, trace.log_size);
        const previous = physical((logical + n - 1) % n, trace.log_size);
        for (&scratch.fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + row]);
        const main = try trace.metadataRow(logical);
        for (&scratch.main, main) |*v, b| v.* = Q.fromBase(b);
        for (&scratch.shifted, L.MASK_OFFSETS[1..]) |*shifted, offset| {
            const target: usize = @intCast(@mod(@as(isize, @intCast(logical)) + offset, @as(isize, @intCast(n))));
            const native = try trace.metadataRow(target);
            for (shifted, native[0..L.STATE]) |*v, b| v.* = Q.fromBase(b);
        }
        const prior = try trace.metadataRow((logical + n - 1) % n);
        for (&scratch.previous_header, prior[L.ACTIVE_A..]) |*v, b| v.* = Q.fromBase(b);
        for (&scratch.interaction, 0..) |*v, batch| v.* = secure(trace.interaction, n, row, 4 * batch);
        var sink = rv.evaluation.Sink{ .values = residuals };
        K.equations.emit(scratch.row(), &scratch.interaction, secure(trace.interaction, n, previous, L.INTERACTION - 4), claim, ch, .{ .calls = trace.calls, .first_id = trace.first_call_id }, &sink);
        if (sink.count != residuals.len) return error.InvalidKeccakDiagnosticShape;
        for (residuals, 0..) |value, constraint| if (!value.isZero()) return .{ .family = .permutation, .logical_row = logical, .constraint = constraint, .value = value };
    }
    return null;
}
fn inspectTable(trace: *const K.tables.Trace, ch: K.equations.Challenges, claim: Q) !?Failure {
    const n = trace.size();
    if (trace.fixed.len != 7 * n or trace.interaction.len != 4 * n or trace.multiplicities.len != n) return error.InvalidKeccakDiagnosticShape;
    const component = K.component.Component{ .kind = trace.kind, .log_size = trace.log_size, .challenges = ch, .claim = claim };
    for (0..n) |logical| {
        const row = physical(logical, trace.log_size);
        const previous = physical((logical + n - 1) % n, trace.log_size);
        var tuple: [6]Q = undefined;
        for (&tuple, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + row]);
        const value = K.component.tableResidual(&component, &tuple, Q.fromBase(trace.fixed[6 * n + row]), Q.fromBase(M.fromCanonical(trace.multiplicities[logical])), secure(trace.interaction, n, row, 0), secure(trace.interaction, n, previous, 0));
        if (!value.isZero()) return .{ .family = if (trace.kind == .chi) .chi else .xor5, .logical_row = logical, .constraint = 0, .value = value };
    }
    return null;
}
fn inspectBridge(a: std.mem.Allocator, trace: *const K.bridge.trace.Trace, ch: K.bridge.equations.Challenges, claim: Q) !?Failure {
    const B = K.bridge.layout;
    const n = trace.size();
    if (trace.fixed.len != B.FIXED * n or trace.interaction.len != B.INTERACTION * n) return error.InvalidKeccakDiagnosticShape;
    const residuals = try a.alloc(Q, B.CONSTRAINTS);
    defer a.free(residuals);
    for (0..n) |logical| {
        const row = physical(logical, trace.log_size);
        const previous = physical((logical + n - 1) % n, trace.log_size);
        var fixed: [B.FIXED]Q = undefined;
        var main: [B.MAIN]Q = undefined;
        var prior: [B.PREVIOUS_MAIN]Q = undefined;
        var header: [2]Q = undefined;
        var interaction: [B.BATCHES]Q = undefined;
        for (&fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + row]);
        const current = try trace.metadataRow(logical);
        const shifted = try trace.metadataRow((logical + n - 1) % n);
        for (&main, current) |*v, b| v.* = Q.fromBase(b);
        for (&prior, shifted[0..B.PREVIOUS_MAIN]) |*v, b| v.* = Q.fromBase(b);
        for (&header, shifted[B.ACTIVE..][0..2]) |*v, b| v.* = Q.fromBase(b);
        for (&interaction, 0..) |*v, batch| v.* = secure(trace.interaction, n, row, 4 * batch);
        var sink = rv.evaluation.Sink{ .values = residuals };
        K.bridge.equations.emit(.{ .fixed = &fixed, .main = &main, .previous_main = &prior, .previous_header = &header }, &interaction, secure(trace.interaction, n, previous, B.INTERACTION - 4), claim, ch, .{ .calls = trace.calls, .first_id = trace.first_id }, &sink);
        if (sink.count != residuals.len) return error.InvalidKeccakDiagnosticShape;
        for (residuals, 0..) |value, constraint| if (!value.isZero()) return .{ .family = .bridge, .logical_row = logical, .constraint = constraint, .value = value };
    }
    return null;
}
