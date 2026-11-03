//! Device generation of the original RAM/KIO/Wire inverse/prefix witness.
//! The receiver-owned slot plan and shared manifest challenges are inputs;
//! neither relation membership nor claims may be supplied by a device worker.
const std = @import("std");
const D = @import("stwo_prover_api").device_pcs;
const O = @import("stwo_core").fields.om31.OM31;
const Source = @import("source_authority.zig");
const Global = @import("global_cpu.zig");
const Manifest = @import("manifest.zig");
pub const Shared = Manifest.Shared;
pub const Item = struct {
    descriptor: Source.Descriptor,
    log_size: u32,
    fixed: []const D.Column,
    fixed_offset: usize = 0,
    main: []const D.Column,
    sponge_first_id: u32 = 0,
};
pub const Witness = struct {
    columns: []const D.TraceColumn,
    claims: []const O,
    owner: *anyopaque,
    release_fn: *const fn (*anyopaque) void,
    pub fn deinit(self: *Witness) void {
        self.release_fn(self.owner);
        self.* = undefined;
    }
    pub fn validate(self: Witness, item: Item) !void {
        const layout = Global.layout(item.descriptor.origin);
        if (self.columns.len != layout.width() or self.claims.len != Global.claimCount(item.descriptor.origin)) return error.InvalidDeviceGlobalWitness;
        for (self.columns) |column| {
            try column.validate();
            if (column.log_size != item.log_size or column.device == null or column.host.len != 0 or column.encoding != .evaluations) return error.InvalidDeviceGlobalWitness;
        }
        for (self.claims) |claim| for (claim.toM31Array()) |word| {
            if (word.v >= @import("stwo_core").fields.m31.Modulus) return error.NoncanonicalWideCpuClaim;
        };
    }
};
pub const Stage = struct {
    context: *anyopaque,
    generate: *const fn (*anyopaque, std.mem.Allocator, D.Scope, Item, Manifest.Shared, usize) anyerror!Witness,
};

test "global device handoff rejects host witness fallback and wrong physical claim count" {
    const Noop = struct {
        fn release(_: *anyopaque) void {}
    };
    const item = Item{ .descriptor = .{ .origin = .{ .core = .ls } }, .log_size = 5, .fixed = &.{}, .main = &.{} };
    var data: [32]D.M = @splat(D.M.zero());
    var columns: [16]D.TraceColumn = @splat(.{ .log_size = 5, .encoding = .evaluations, .host = &data });
    const claims = [_]O{O.zero()};
    var witness = Witness{ .columns = &columns, .claims = &claims, .owner = @ptrFromInt(4096), .release_fn = Noop.release };
    try std.testing.expectError(error.InvalidDeviceGlobalWitness, witness.validate(item));
    for (&columns) |*column| column.* = .{ .log_size = 5, .encoding = .evaluations, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 1, .generation = 2 } };
    try witness.validate(item);
    witness.claims = &.{};
    try std.testing.expectError(error.InvalidDeviceGlobalWitness, witness.validate(item));
    witness.claims = &claims;
    columns[0].encoding = .coefficients;
    try std.testing.expectError(error.InvalidDeviceGlobalWitness, witness.validate(item));
}
