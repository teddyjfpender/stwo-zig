//! Reconstruct every original frame from independent admitted geometry and
//! decoded claim proposals. Serialized routing offsets/steps do not exist.
const std = @import("std");
const Types = @import("block_v6_mixed_claim_types_v1.zig");
const Bus = Types.Bus;
pub fn Admission(comptime family: Types.Family) type {
    return switch (family) {
        .native => @import("../prover/block_v6_partitioned_recursive_admission_v1.zig").Prepared,
        .range16, .ram_lanes, .program_table, .native_lookup => Bus.Provider.Definition(@field(Bus.Provider.Family, @tagName(family))).Prepared,
        .caller_arithmetic, .caller_fused, .source_raw, .source_fold => Bus.Auxiliary.Definition(@field(Bus.Auxiliary.Family, @tagName(family))).Admission.Prepared,
    };
}
pub const Input = union(Types.Family) {
    native: *const Admission(.native),
    range16: *const Admission(.range16),
    ram_lanes: *const Admission(.ram_lanes),
    program_table: *const Admission(.program_table),
    native_lookup: *const Admission(.native_lookup),
    caller_arithmetic: *const Admission(.caller_arithmetic),
    caller_fused: *const Admission(.caller_fused),
    source_raw: *const Admission(.source_raw),
    source_fold: *const Admission(.source_fold),
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    children: []Bus.Child,
    pub fn values(self: *const Owned) Bus.Values {
        return .{ .children = self.children };
    }
    pub fn deinit(self: *Owned) void {
        for (self.children) |*child| child.deinit();
        self.allocator.free(self.children);
        self.* = undefined;
    }
};
pub fn reconstruct(a: std.mem.Allocator, records: []const Types.Record, expected: []const Bus.Expected, inputs: []const Input) !Owned {
    _ = try Bus.rosterDigest(expected);
    if (records.len != inputs.len or records.len != expected.len) return error.UntrustedMixedClaimRoster;
    const children = try a.alloc(Bus.Child, records.len);
    var initialized: usize = 0;
    errdefer {
        for (children[0..initialized]) |*child| child.deinit();
        a.free(children);
    }
    for (records, inputs, expected, children) |record, input, pin, *child| {
        try Types.require(record, pin);
        if (std.meta.activeTag(input) != std.meta.activeTag(record.claim)) return error.UntrustedMixedClaimAdmission;
        child.* = switch (input) {
            .native => |admitted| blk: {
                if (record.index != admitted.native.index) return error.UntrustedMixedClaimAdmission;
                break :blk .{ .native = .{ .index = record.index, .value = try Bus.Native.Values.init(a, admitted, record.claim.native) } };
            },
            inline .range16, .ram_lanes, .program_table, .native_lookup => |admitted, tag| blk: {
                const family = @field(Bus.Provider.Family, @tagName(tag));
                const D = Bus.Provider.Definition(family);
                if (record.index != D.index(admitted)) return error.UntrustedMixedClaimAdmission;
                break :blk .{ .provider = @unionInit(Bus.Provider.Child, @tagName(tag), try D.values(admitted, try D.proposal(admitted, @field(record.claim, @tagName(tag))))) };
            },
            .caller_arithmetic => |admitted| blk: {
                if (record.index != admitted.binding.execution_index) return error.UntrustedMixedClaimAdmission;
                const D = Bus.Auxiliary.Definition(.caller_arithmetic);
                const claims = record.claim.caller_arithmetic;
                const values = try D.Bus.Values.fromCaller(admitted, .{ .binding = admitted.binding, .open_sum = claims.componentSum() }, claims);
                break :blk .{ .auxiliary = .{ .index = record.index, .value = .{ .caller_arithmetic = values } } };
            },
            inline .caller_fused, .source_raw, .source_fold => |admitted, tag| blk: {
                const index = switch (tag) {
                    .caller_fused => admitted.binding.execution_index,
                    .source_raw => admitted.pin.raw.page.index,
                    .source_fold => admitted.pin.page.index,
                    else => unreachable,
                };
                if (record.index != index) return error.UntrustedMixedClaimAdmission;
                const family = @field(Bus.Auxiliary.Family, @tagName(tag));
                const values = try Bus.Auxiliary.Definition(family).Bus.Values.init(a, admitted, @field(record.claim, @tagName(tag)));
                break :blk .{ .auxiliary = .{ .index = record.index, .value = @unionInit(Bus.Auxiliary.Value, @tagName(tag), values) } };
            },
        };
        initialized += 1;
    }
    try (Bus.Values{ .children = children }).requireRoster(expected);
    return .{ .allocator = a, .children = children };
}
