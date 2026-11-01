//! Compact global tuple projection for truth stage2. Reuses the original MAIN
//! column-source and tuple algebra; never reconstructs a wide Q/OM MAIN row.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const M = core.fields.m31.M31;
const R = @import("../roster.zig");
const Frame = @import("truth_frame.zig");
const physical = A.witness.physical;
const PackedCells = struct {
    row: *const K.trace.PackedRow,
    pub inline fn at(self: @This(), index: usize) M {
        if (index < K.layout.STATE) return self.row.stateCell(index);
        if (index < K.layout.ACTIVE_A) return self.row.parityCell(index - K.layout.STATE);
        return M.fromCanonical(switch (index) {
            K.layout.ACTIVE_A => self.row.flags & 1,
            K.layout.ACTIVE_B => (self.row.flags >> 1) & 1,
            K.layout.BASE_ID => self.row.id,
            else => unreachable,
        });
    }
};
const SecpCells = struct {
    sources: []const S.interaction.Source,
    active: bool,
    id: M,
    bytes: []const u8,
    pub inline fn at(self: @This(), index: usize) M {
        return S.interaction.Prepared.sourceValue(self.sources[index], self.active, self.id, self.bytes);
    }
};
pub const Provider = struct {
    allocator: std.mem.Allocator,
    source: *const R.TruthSource,
    product_columns: []S.interaction.Source = &.{},
    linear_columns: []S.interaction.Source = &.{},
    pub fn init(allocator: std.mem.Allocator, source: *const R.TruthSource, budget: usize) !Provider {
        var out = Provider{ .allocator = allocator, .source = source };
        switch (source.*) {
            .keccak => |s| {
                try s.permutation.validateMetadata();
                if (s.permutation.fixed.len != K.layout.FIXED * s.permutation.size()) return error.InvalidTruthGlobalMetadata;
                for (s.permutation.metadata) |row| if (row.flags > 3 or row.id >= core.fields.m31.Modulus) return error.InvalidTruthGlobalMetadata;
            },
            .secp => |s| {
                const bytes = (S.layout.main(.product) + S.layout.main(.linear)) * @sizeOf(S.interaction.Source);
                if (bytes > budget) return error.TruthGlobalMetadataBudgetExceeded;
                try s.batch.product.validateMetadata();
                try s.batch.linear.validateMetadata();
                out.product_columns = try S.interaction.columnSources(allocator, .product);
                errdefer allocator.free(out.product_columns);
                out.linear_columns = try S.interaction.columnSources(allocator, .linear);
            },
        }
        return out;
    }
    pub fn deinit(self: *Provider) void {
        self.allocator.free(self.product_columns);
        self.allocator.free(self.linear_columns);
        self.* = undefined;
    }
    pub fn emit(self: *const Provider, role: Frame.Role, logical: usize, sink: anytype) !void {
        switch (self.source.*) {
            .keccak => |s| {
                if (role != .keccak or logical >= s.permutation.size()) return error.InvalidTruthGlobalRole;
                const trace = &s.permutation;
                const n = trace.size();
                const empty = K.trace.PackedRow{};
                const packet_row = if (logical < trace.metadata.len) &trace.metadata[logical] else &empty;
                const cells = PackedCells{ .row = packet_row };
                const r = physical(logical, trace.log_size);
                var fixed: [K.layout.FIXED]M = undefined;
                for (&fixed, 0..) |*v, c| v.* = trace.fixed[c * n + r];
                const weight = K.equations.ioActiveAccessors(M, cells, &fixed);
                for (0..K.layout.IO_LANES) |lane| sink.emitIo(K.equations.ioTupleAccessors(M, cells, &fixed, lane), weight);
            },
            .secp => |s| {
                if (role != .product and role != .linear) return error.InvalidTruthGlobalRole;
                const trace = if (role == .product) &s.batch.product else &s.batch.linear;
                const n = trace.size();
                if (logical >= n) return error.InvalidTruthGlobalRole;
                const per = trace.program.rows(trace.kind == .product);
                const active = logical < @as(usize, trace.calls) * per;
                const count = S.layout.metadataByteCount(trace.kind);
                const cells = SecpCells{ .sources = if (role == .product) self.product_columns else self.linear_columns, .active = active, .id = M.fromCanonical(if (active) trace.first_id + @as(u32, @intCast(logical / per)) else 0), .bytes = if (active) trace.lookup_bytes[logical * count ..][0..count] else &.{} };
                const r = physical(logical, trace.log_size);
                var fixed: [S.layout.FIXED]M = undefined;
                for (&fixed, 0..) |*v, c| v.* = trace.fixed[c * n + r];
                for (0..3) |event| sink.emitWire(S.equations.wireTupleAccessors(M, trace.kind, trace.program, cells, &fixed, event), S.equations.wireCoefficientAccessors(M, cells, &fixed, event));
            },
        }
    }
};
