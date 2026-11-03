//! Proof-scoped ownership for deferred device Eq/prefix binding. This is a
//! pending physical binding obligation, never an accepting execution receipt.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const D = @import("stwo_prover_api").device_pcs;
const Frame = @import("frame.zig");
const Receipt = @import("receipt.zig");
const O = core.fields.om31.OM31;
const Artifact = engine.lookups.gkr_verifier.ForField(O).GkrArtifact;
pub const Request = struct {
    scope: Receipt.Scope,
    receipt_digest: [32]u8,
    instances: []const Frame.Instance,
    artifact: *const Artifact,
    eta: O,
    deferred: bool,
};
fn integer(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}
fn secure(hash: *std.crypto.hash.sha2.Sha256, value: O) !void {
    for (value.toM31Array()) |coordinate| {
        if (coordinate.v >= core.fields.m31.Modulus) return error.DeviceBindingAuthorityMismatch;
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, coordinate.v, .little);
        hash.update(&bytes);
    }
}
/// Bind every callback/retry to the native verifier's exact terminal authority.
pub fn authority(request: Request) ![32]u8 {
    const artifact = request.artifact;
    if (request.instances.len != artifact.claims_to_verify_by_instance.len or request.instances.len != artifact.n_variables_by_instance.len) return error.DeviceBindingAuthorityMismatch;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64/device-binding-authority/v1\x00");
    hash.update(&request.receipt_digest);
    try secure(&hash, request.eta);
    integer(&hash, artifact.ood_point.len);
    for (artifact.ood_point) |point| try secure(&hash, point);
    for (request.instances, artifact.claims_to_verify_by_instance, artifact.n_variables_by_instance) |instance, claims, variables| {
        _ = try Frame.splitPoint(instance, artifact.ood_point, variables);
        if (claims.len != 2) return error.DeviceBindingAuthorityMismatch;
        const origin = Frame.originWords(instance.origin);
        for (origin) |word| integer(&hash, word);
        integer(&hash, instance.row_log);
        integer(&hash, instance.terms);
        integer(&hash, instance.fixed_offset);
        integer(&hash, instance.main_offset);
        integer(&hash, variables);
        for (claims) |claim| try secure(&hash, claim);
    }
    return hash.finalResult();
}
pub const Completion = struct { columns: []D.Column, retained_bytes: usize };
pub const Owner = struct {
    context: *anyopaque,
    scope: Receipt.Scope,
    receipt_digest: [32]u8,
    authority_digest: [32]u8,
    retained_bytes: usize,
    columns: []D.Column = &.{},
    finalized: bool = false,
    finalize_fn: *const fn (*anyopaque, std.mem.Allocator, Request) anyerror!Completion,
    release_fn: *const fn (*anyopaque) void,
    pub fn finalize(self: *Owner, a: std.mem.Allocator, request: Request) !void {
        if (!std.meta.eql(self.scope, request.scope) or !std.mem.eql(u8, &self.receipt_digest, &request.receipt_digest)) return error.DeviceBindingScopeMismatch;
        if (!std.mem.eql(u8, &self.authority_digest, &(try authority(request)))) return error.DeviceBindingAuthorityMismatch;
        if (self.finalized) return;
        const completed = try self.finalize_fn(self.context, a, request);
        errdefer a.free(completed.columns);
        if (completed.columns.len != try std.math.mul(usize, request.instances.len, 16)) return error.DeviceBindingColumnShape;
        for (request.instances, 0..) |instance, i| for (completed.columns[i * 16 ..][0..16]) |column| {
            const device = column.device orelse return error.DeviceBindingColumnShape;
            if (column.log_size != instance.row_log or column.coefficients.len != 0 or device.count != try instance.rows() or device.context_token == 0 or device.generation == 0) return error.DeviceBindingColumnShape;
        };
        self.columns = completed.columns;
        self.retained_bytes = completed.retained_bytes;
        self.finalized = true;
    }
    pub fn deinit(self: *Owner, a: std.mem.Allocator) void {
        self.release_fn(self.context);
        a.free(self.columns);
        self.* = undefined;
    }
};

test "device binding ownership rejects changed authority and finalizes atomically" {
    const a = std.testing.allocator;
    const Fake = struct {
        bad: bool = false,
        released: bool = false,
        fn complete(ctx: *anyopaque, allocator: std.mem.Allocator, _: Request) !Completion {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const columns = try allocator.alloc(D.Column, 16);
            for (columns) |*column| column.* = .{ .log_size = 5, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 7, .generation = 8 } };
            if (self.bad) columns[15].device.?.count = 31;
            return .{ .columns = columns, .retained_bytes = 16 * 32 * 4 };
        }
        fn release(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.released = true;
        }
    };
    const instances = [_]Frame.Instance{.{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 }};
    var point: [5]O = @splat(O.one());
    var claims = [_]O{ O.zero(), O.one() };
    var claim_slices = [_][]O{&claims};
    var variables = [_]usize{5};
    const artifact = Artifact{ .ood_point = &point, .claims_to_verify_by_instance = &claim_slices, .n_variables_by_instance = &variables };
    const request = Request{ .scope = .{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 }, .receipt_digest = @splat(4), .instances = &instances, .artifact = &artifact, .eta = O.one(), .deferred = false };
    var fake = Fake{ .bad = true };
    var owner = Owner{ .context = &fake, .scope = request.scope, .receipt_digest = request.receipt_digest, .authority_digest = try authority(request), .retained_bytes = 8 * 32 * 4, .finalize_fn = Fake.complete, .release_fn = Fake.release };
    defer owner.deinit(a);
    try std.testing.expectError(error.DeviceBindingColumnShape, owner.finalize(a, request));
    try std.testing.expect(!owner.finalized and owner.columns.len == 0 and !fake.released);
    fake.bad = false;
    try owner.finalize(a, request);
    try std.testing.expect(owner.finalized and owner.columns.len == 16);
    var changed = request;
    changed.scope.ordinal += 1;
    try std.testing.expectError(error.DeviceBindingScopeMismatch, owner.finalize(a, changed));
    changed = request;
    changed.eta = O.zero();
    try std.testing.expectError(error.DeviceBindingAuthorityMismatch, owner.finalize(a, changed));
    point[0] = O.zero();
    try std.testing.expectError(error.DeviceBindingAuthorityMismatch, owner.finalize(a, request));
}
