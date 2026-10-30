//! Explicit bounded Keccak batch identity. Metadata admission is not proof
//! verification: the receiver must reconstruct fixed owners/clocks, prove all
//! original arithmetic and RAM constraints and close every native window.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("block_v7_execution_epoch_v1.zig");
const Native = @import("block_v7_native_source_v1.zig");
const Owners = @import("block_v7_keccak_window_layout_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Authority = @import("../air/guest_precompile/keccakf_authority.zig");
const S = core.proof_suites.Blake3;
pub const TAG: u32 = 0x42374b42; // B7KB: distinct from every original caller.
pub const VERSION: u32 = 1;
pub const Limits = Owners.Limits;
pub const Window = struct {
    execution_index: u32,
    native_identity: [32]u8,
    frame: @import("../air/block/memory_event.zig").Frame,
    calls: u32,
};
pub const Geometry = struct {
    first_call_index: u32 = 0,
    call_count: u32,
    log_size: u32,
    n_rows: u32,
    x0_local_custody_version: u32 = 0,
};
pub const Pin = struct {
    index: u32,
    windows: []const Window,
    geometry: Geometry,
    roots: [2][32]u8,
    access_root: [32]u8,
    config: core.pcs.PcsConfig,

    pub fn ownerLayout(self: Pin, a: std.mem.Allocator, limits: Limits) !Owners.Owned {
        if (self.windows.len == 0 or self.windows.len > limits.max_windows or self.windows.len > 64 or self.geometry.first_call_index != 0 or self.geometry.x0_local_custody_version != 1) return error.InvalidKeccakBatchSource;
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        var frames: [64]Owners.Window = undefined;
        for (self.windows, frames[0..self.windows.len]) |window, *frame| {
            if (std.mem.allEqual(u8, &window.native_identity, 0)) return error.InvalidKeccakBatchNativeIdentity;
            frame.* = .{ .index = window.execution_index, .frame = window.frame, .calls = window.calls };
        }
        var owner = try Owners.Owned.derive(a, frames[0..self.windows.len], limits);
        errdefer owner.deinit();
        const slots = try std.math.divCeil(usize, owner.calls, Authority.geometry.operations_per_slot);
        const rows = try std.math.mul(usize, slots, Authority.geometry.rows_per_slot);
        if (self.geometry.call_count != owner.calls or self.geometry.log_size != owner.log_size or self.geometry.n_rows != rows) return error.UntrustedKeccakBatchGeometry;
        return owner;
    }

    pub fn entry(self: Pin, a: std.mem.Allocator, natives: []const Native.Pin, limits: Limits) !E.Entry {
        var owner = try self.ownerLayout(a, limits);
        defer owner.deinit();
        var ch = S.Channel{};
        ch.mixU32s(&.{ TAG, VERSION, 0, self.index, @intCast(self.windows.len), self.geometry.first_call_index, self.geometry.call_count, self.geometry.log_size, self.geometry.n_rows, self.geometry.x0_local_custody_version });
        self.config.mixInto(&ch);
        ch.mixRoot(Authority.execution_semantic_digest);
        // These are protocol geometry, not a producer-selected component mask:
        // one owner selector/window, eight clock bytes, three control planes,
        // 50 RAM-word slots, packed mode1 and split2 for the shared bridge.
        ch.mixU32s(&.{ 1, 8, 3, 50, 1, 2, Authority.geometry.operations_per_slot, Authority.geometry.rows_per_slot });
        for (self.windows) |window| {
            if (window.execution_index >= natives.len) return error.MissingKeccakBatchNative;
            const native = natives[window.execution_index];
            const native_entry = try native.entry(a);
            if (native.index != window.execution_index or !std.meta.eql(native_entry.identity, window.native_identity) or !std.meta.eql(native.frame, window.frame) or native.template.external_retirements != window.calls or !std.meta.eql(native.template.config, self.config)) return error.UntrustedKeccakBatchNative;
            ch.mixU32s(&.{ window.execution_index, window.calls, window.frame.cycle_count });
            ch.mixU64(window.frame.global_first_cycle);
            native_entry.mix(&ch);
        }
        return E.Entry.init(.caller_fused, self.index, ch.digestBytes(), &(self.roots ++ .{self.access_root}));
    }

    pub fn require(self: Pin, a: std.mem.Allocator, natives: []const Native.Pin, epoch: E.Epoch, entries: []const E.Entry, limits: Limits) !E.Entry {
        if (!std.meta.eql(self.config, epoch.config) or natives.len != epoch.counts[@intFromEnum(E.Family.native)]) return error.UntrustedKeccakBatchEpoch;
        const own = try self.entry(a, natives, limits);
        try epoch.requireEntry(entries, own);
        for (self.windows) |window| try epoch.requireEntry(entries, try natives[window.execution_index].entry(a));
        return own;
    }
};
pub const Drawn = struct { epoch: E.Drawn, relations: Profile.Relations, channel: S.Channel };
pub fn draw(a: std.mem.Allocator, epoch: E.Epoch, entry: E.Entry) !Drawn {
    try entry.validate();
    if (entry.family != .caller_fused) return error.InvalidKeccakBatchEntryFamily;
    const shared = try epoch.draw(a);
    var ch = shared.channel;
    ch.mixU32s(&.{ TAG, VERSION, 1 });
    entry.mix(&ch);
    const relations = try Profile.Relations.drawAfterVm(a, &ch, shared.word.universal_prefix);
    return .{ .epoch = shared, .relations = relations, .channel = ch };
}
/// The owner must absorb EVERY original physical arithmetic, lookup, control
/// and RAM claim after this prefix, before either interaction commitment.
/// Aggregate exported sums cannot substitute for that physical claim frame.
pub fn claimPrefix(ch: *S.Channel, entry: E.Entry) !void {
    try entry.validate();
    if (entry.family != .caller_fused) return error.InvalidKeccakBatchEntryFamily;
    ch.mixU32s(&.{ TAG, VERSION, 2 });
    entry.mix(ch);
}
