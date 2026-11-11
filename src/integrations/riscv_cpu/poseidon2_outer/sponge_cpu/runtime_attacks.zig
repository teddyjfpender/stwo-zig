//! Reuses one retained actual-small bundle; never re-executes or re-proves it.
const std = @import("std");
const Runtime = @import("runtime.zig");
const Codec = @import("wire.zig");
const Receiver = @import("receiver.zig");
const O = @import("stwo_core").fields.om31.OM31;
pub const State = struct {
    path: []const u8,
    controls: u32 = 0,
    fn reject(a: std.mem.Allocator, source: Runtime.SourceDirectory, bundle: *const Codec.Bundle) !void {
        var result = Receiver.verify(a, source.inventory, source.authority.cpu, source.authority.detached, source.authority.catalogs, source.authority.catalog.miller, bundle);
        if (result) |*closed| {
            closed.deinit(a);
            return error.AcceptedDetachedMutation;
        } else |_| {}
    }
    pub fn run(raw: ?*anyopaque, a: std.mem.Allocator, source: Runtime.SourceDirectory) !void {
        const self: *State = @ptrCast(@alignCast(raw.?));
        var dir = try std.fs.cwd().openDir(self.path, .{});
        defer dir.close();
        const bytes = try dir.readFileAlloc(a, "detached-op.bin", 64 << 20);
        defer a.free(bytes);
        var bundle = try Codec.decode(a, bytes, source.inventory.execution, source.inventory.workers.len, .{});
        defer bundle.deinit(a);
        // Every attack uses the SAME independently rebuilt source keys.
        const all = bundle.fragments;
        defer bundle.fragments = all;
        bundle.fragments = all[0 .. all.len - 1];
        try reject(a, source, &bundle);
        self.controls += 1;
        bundle.fragments = all;
        std.mem.swap(Codec.Fragment, &all[0], &all[1]);
        try reject(a, source, &bundle);
        self.controls += 1;
        std.mem.swap(Codec.Fragment, &all[0], &all[1]);
        {
            const W = @import("../pure_p2_worker_protocol.zig").W;
            var native = try W.Wire.decodeProofBytesBinary(a, all[0].native);
            defer native.deinit(a);
            const sample = &native.commitment_scheme_proof.sampled_values.items[1][0][0];
            sample.* = sample.add(O.one());
            const changed = try W.Wire.encodeProofBytesBinary(a, native);
            defer a.free(changed);
            const original = all[0].native;
            all[0].native = changed;
            defer all[0].native = original;
            try reject(a, source, &bundle);
            self.controls += 1;
        }
        {
            const N = @import("native.zig");
            var local = try N.decode(a, source.inventory.rosters[0].instances, all[0].local);
            defer local.deinit();
            local.proof.output_claims_by_instance[0][0] = local.proof.output_claims_by_instance[0][0].add(O.one());
            const changed = try N.encode(a, source.inventory.rosters[0].instances, &local.proof);
            defer a.free(changed);
            const original = all[0].local;
            all[0].local = changed;
            defer all[0].local = original;
            try reject(a, source, &bundle);
            self.controls += 1;
        }
        const before0 = all[0].claims[0];
        const before1 = all[1].claims[0];
        all[0].claims[0] = before0.add(O.one());
        all[1].claims[0] = before1.sub(O.one());
        try reject(a, source, &bundle);
        self.controls += 1;
        all[0].claims[0] = before0;
        all[1].claims[0] = before1;
        const execution = bundle.execution;
        bundle.execution[0] ^= 1;
        try reject(a, source, &bundle);
        self.controls += 1;
        bundle.execution = execution;
        // Framing authority refuses before owned allocation.
        try std.testing.expectError(error.DetachedWireLimit, Codec.decode(std.testing.failing_allocator, bytes, source.inventory.execution, source.inventory.workers.len, .{ .bytes = bytes.len - 1 }));
        self.controls += 1;
        // The restored positive control must still fresh-verify unchanged.
        var positive = try Receiver.verify(a, source.inventory, source.authority.cpu, source.authority.detached, source.authority.catalogs, source.authority.catalog.miller, &bundle);
        defer positive.deinit(a);
    }
};
