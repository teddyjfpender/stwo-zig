//! Deterministic PUBLIC derivation from original typed B5CT admission. Neither
//! register-window SHA nor public-data hash alone is a source-proof receipt.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const H = @import("block_v5_heterogeneous_policy_v1.zig");
const F = @import("block_v5_heterogeneous_child_frames_v1.zig");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Native = @import("../prover/block_v5_native_capacity_recursive_admission_v1.zig");
const Fields = @import("block_v5_global_public_fields_v1.zig");
const Windows = @import("../prover/block_v5_register_windows_v1.zig");
pub const NativeInfo = struct { child: u32, admitted: *const Native.Prepared };
pub const TermKind = enum(u32) { native_compensation, register_compensation, terminal_program_boundary };
pub const Terms = [3]Q;
fn derivedTerms(a: std.mem.Allocator, policy: Policy, index: u32, relations: anytype) !Terms {
    _ = a;
    const p = (try policy.native(index)).admitted;
    const state = try relations.getExact(.registers_state);
    const memory = try relations.getExact(.memory_access);
    const Elements = @import("../air/relation_challenges.zig").RelationElements;
    const native = .{
        .registers_state = Elements(2){ .z = state.z, .alpha = state.alpha, .alpha_powers = state.alpha_powers[0..2].* },
        .memory_access = Elements(7){ .z = memory.z, .alpha = memory.alpha, .alpha_powers = memory.alpha_powers[0..7].* },
    };
    const arithmetic = @import("../air/public_logup_arithmetic.zig");
    const registers = if (policy.windows.version == Windows.LOCAL_ZERO_VERSION) try arithmetic.nonzeroRegisterMemoryAccessSumFor(Q, &p.shape.public_data, &native) else try arithmetic.registerMemoryAccessSumFor(Q, &p.shape.public_data, &native);
    const terminal = try @import("../prover/block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(p.template.execution_profile, &p.shape.public_data, relations);
    return .{ try arithmetic.registersStateSumFor(Q, &p.shape.public_data, &native), registers, terminal.sum };
}
pub const Policy = struct {
    original: H.Policy,
    windows: Windows.Plan,
    pub const complete_source_authority = false;
    pub fn native(self: Policy, index: u32) !NativeInfo {
        var found: ?NativeInfo = null;
        for (self.original.children, self.original.expected, 0..) |child, expected, ordinal| {
            if (child.physical.kind != .native_arithmetic or child.physical.index != index) continue;
            if (found != null) return error.DuplicateGlobalPublicNative;
            switch (expected) {
                .capacity_v1 => |typed| found = .{ .child = @intCast(ordinal), .admitted = typed.admitted },
                else => return error.UnsupportedGlobalPublicNativeProtocol,
            }
        }
        return found orelse error.MissingGlobalPublicNative;
    }
    pub fn validate(self: Policy) !void {
        try self.original.validate();
        try self.windows.validate();
        const descriptor = self.original.plan.meta.sources[@intFromEnum(Coverage.SourceKind.register_windows)];
        if (descriptor.count != self.windows.windows.len or !std.meta.eql(descriptor.identity, try self.windows.digest())) return error.UntrustedGlobalPublicWindows;
        for (self.windows.windows, 0..) |window, index| {
            const info = try self.native(@intCast(index));
            const p = info.admitted;
            try p.validate(p.template_id);
            if (p.sealed.register_custody_mode != 1 or !std.meta.eql(p.sealed.register_endpoint_plan_digest, descriptor.identity)) return error.UntrustedGlobalPublicWindows;
            try self.windows.requireNative(p.shape);
            try window.requirePublic(@intCast(index), p.pin.context.first_cycle, &p.shape.public_data);
            _ = try self.digestCells(@intCast(index));
        }
    }
    /// Normative reusable admission then Values.mix framing, not equal-value
    /// root search. Both legacy/default APIs remain untouched by this extension.
    pub fn digestCells(self: Policy, index: u32) !u32 {
        const info = try self.native(index);
        const child = &self.original.children[info.child];
        // Admission header/config/key; Values header; sealed/template/instance/
        // fixed/main roots; public-data digest. Config is one felt invocation.
        if (child.frames.len <= 9 or child.frames[9].operation != .root) return error.UntrustedGlobalPublicDigestSource;
        const expected = @import("../prover/block_v5_native_public_admission_v1.zig").publicDigest(&info.admitted.shape.public_data);
        if (!std.meta.eql(child.frames[9].operation.root, expected)) return error.UntrustedGlobalPublicDigestSource;
        return child.frames[9].first;
    }
    pub fn sealedCells(self: Policy) !struct { child: u32, first: u32 } {
        const info = try self.native(0);
        const child = &self.original.children[info.child];
        if (child.frames.len <= 4 or child.frames[4].operation != .root or !std.meta.eql(child.frames[4].operation.root, info.admitted.sealed.digest)) return error.UntrustedGlobalPublicDigestSource;
        return .{ .child = info.child, .first = child.frames[4].first };
    }
};
pub const Owner = struct {
    allocator: std.mem.Allocator,
    policy: Policy,
    fields: []Fields.Fields,
    /// Deterministic public proposals, NOT proof receipts. The same-parent AIR
    /// additionally proves each equality using original bytes and B5SS draws.
    terms: []Terms,
    pub fn deinit(self: *Owner) void {
        for (self.fields) |*field| field.deinit();
        self.allocator.free(self.fields);
        self.allocator.free(self.terms);
        self.* = undefined;
    }
    /// Fresh receiver reconstructs all canonical tuple fields from exact
    /// hash-bound completion metadata. The tuple is not a private witness.
    pub fn validate(self: *const Owner) !void {
        try self.policy.validate();
        if (self.fields.len != self.policy.windows.windows.len or self.terms.len != self.fields.len) return error.UntrustedGlobalPublicWindows;
        var channel = (try self.policy.native(0)).admitted.sealed.sharedChannel();
        const relations = try @import("air/universal_challenges.zig").UniversalRelations.draw(self.allocator, &channel);
        for (self.fields, 0..) |*field, index| {
            const p = (try self.policy.native(@intCast(index))).admitted;
            try field.validate(&p.shape.public_data, p.template.execution_profile, p.pin.context.first_cycle, p.pin.context.last_cycle);
            if (!std.mem.eql(u32, self.fields[0].borrowed_input, field.borrowed_input)) return error.UntrustedGlobalPublicInputSharing;
            const expected = try derivedTerms(self.allocator, self.policy, @intCast(index), &relations);
            for (self.terms[index], expected) |actual, required| if (!actual.eql(required)) return error.UntrustedGlobalPublicTerm;
        }
    }
};
pub fn init(a: std.mem.Allocator, policy: Policy, limits: Fields.Limits) !Owner {
    try policy.validate();
    const fields = try a.alloc(Fields.Fields, policy.windows.windows.len);
    errdefer a.free(fields);
    var made: usize = 0;
    errdefer for (fields[0..made]) |*field| field.deinit();
    for (fields, 0..) |*field, index| {
        const p = (try policy.native(@intCast(index))).admitted;
        field.* = try Fields.init(a, &p.shape.public_data, p.template.execution_profile, p.pin.context.first_cycle, p.pin.context.last_cycle, limits);
        made += 1;
        if (!std.mem.eql(u32, fields[0].borrowed_input, field.borrowed_input)) return error.UntrustedGlobalPublicInputSharing;
    }
    const terms = try a.alloc(Terms, fields.len);
    errdefer a.free(terms);
    var channel = (try policy.native(0)).admitted.sealed.sharedChannel();
    const relations = try @import("air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    for (terms, 0..) |*value, index| value.* = try derivedTerms(a, policy, @intCast(index), &relations);
    return .{ .allocator = a, .policy = policy, .fields = fields, .terms = terms };
}
