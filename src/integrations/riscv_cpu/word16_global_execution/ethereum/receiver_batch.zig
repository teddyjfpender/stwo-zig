//! Verify durable bundles in a clean process with bounded verifier-owned setup.
//! Every item re-admits its pinned request and checks every proof and endpoint.
const std = @import("std");
const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
const Setup = @import("receiver_setup.zig");

const Item = struct { request: []const u8, proof: []const u8 };
const Manifest = struct {
    schema: []const u8,
    setup_bytes: usize,
    fixed_setup_bytes: usize,
    request_bytes: usize,
    requests: []const Item,

    fn validate(self: Manifest) !void {
        if (!std.mem.eql(u8, self.schema, "rv64-cpu-receiver-inputs/v1")) return error.InvalidReceiverBatchSchema;
        if (self.requests.len == 0 or self.requests.len > 32) return error.InvalidReceiverBatchCount;
        if (self.setup_bytes == 0 or self.setup_bytes > 4 << 30 or self.fixed_setup_bytes == 0 or self.fixed_setup_bytes > self.setup_bytes or self.request_bytes == 0 or self.request_bytes > 16 << 30)
            return error.InvalidReceiverBatchBudget;
        for (self.requests) |item| {
            if (item.request.len == 0 or item.proof.len == 0 or
                std.mem.indexOfScalar(u8, item.request, 0) != null or std.mem.indexOfScalar(u8, item.proof, 0) != null) return error.InvalidReceiverBatchItem;
        }
    }
};

pub fn run(comptime Main: type, recycler: *Main.Recycler, profile: Candidate.Profile, args: []const [:0]u8) !void {
    if (args.len != 3) return error.ExpectedReceiverBatchManifest;
    const a = recycler.allocator();
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 64 << 10);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Manifest, a, raw, .{});
    defer parsed.deinit();
    const manifest = parsed.value;
    try manifest.validate();
    var session = try Setup.Session.init(a, manifest.setup_bytes, manifest.fixed_setup_bytes, Candidate.configFor(profile));
    defer session.deinit();
    const fixed = try std.fmt.allocPrintSentinel(a, "{d}", .{manifest.fixed_setup_bytes}, 0);
    defer a.free(fixed);
    const live = try std.fmt.allocPrintSentinel(a, "{d}", .{manifest.request_bytes}, 0);
    defer a.free(live);
    const profile_name = try a.dupeZ(u8, profile.name());
    defer a.free(profile_name);
    var selector = "--security-profile".*;
    var mode = "verify-candidate".*;
    for (manifest.requests) |item| {
        const request = try a.dupeZ(u8, item.request);
        defer a.free(request);
        const proof = try a.dupeZ(u8, item.proof);
        defer a.free(proof);
        try Main.runNativeReceiverArgs(recycler, &.{ args[0], &selector, profile_name, &mode, request, proof, fixed, live }, &session);
    }
}

test "receiver batch bounds independently owned setup and rejects unknown fields" {
    const a = std.testing.allocator;
    const raw = "{\"schema\":\"rv64-cpu-receiver-inputs/v1\",\"setup_bytes\":2048,\"fixed_setup_bytes\":1024,\"request_bytes\":4096,\"requests\":[{\"request\":\"r\",\"proof\":\"p\"}]}";
    const parsed = try std.json.parseFromSlice(Manifest, a, raw, .{});
    defer parsed.deinit();
    try parsed.value.validate();
    var invalid = parsed.value;
    invalid.setup_bytes = 512;
    try std.testing.expectError(error.InvalidReceiverBatchBudget, invalid.validate());
    invalid = parsed.value;
    invalid.requests = &.{.{ .request = "request\x00ignored", .proof = "p" }};
    try std.testing.expectError(error.InvalidReceiverBatchItem, invalid.validate());
    const injected = raw[0 .. raw.len - 1] ++ ",\"setup_directory\":\"producer-cache\"}";
    try std.testing.expectError(error.UnknownField, std.json.parseFromSlice(Manifest, a, injected, .{}));
}
