//! Additive experimental raw-Blake modulo-M31 profiles. Neither profile is
//! selected by an existing prover/verifier. Legacy rejection sampling is unchanged.
const std = @import("std");
const B = @import("blake2s.zig");
const M = @import("../fields/m31.zig");
const Q = @import("../fields/qm31.zig").QM31;
const O = @import("../fields/om31.zig").OM31;
pub const Profile = struct {
    degree: u32,
    values_per_block: u32,
    pub fn tag(self: Profile) [8]u32 {
        return .{ 0x5354574f, 0x524d3331, 1, M.Modulus, 32, 8, self.degree, self.values_per_block };
    }
    pub fn identity(self: Profile) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-native-raw-u32-mod-m31/v1\x00");
        for (self.tag()) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            hash.update(&bytes);
        }
        return hash.finalResult();
    }
};
pub const qm31_profile = Profile{ .degree = 4, .values_per_block = 2 };
pub const om31_profile = Profile{ .degree = 8, .values_per_block = 1 };
/// Exact max point mass per coordinate is3/2^32. Relative to uniform M31
/// its density is3p/2^32 <3/2. These are bounds, not a security certificate.
pub const MAX_PREIMAGES: u32 = 3;
pub const RAW_ORDER: u64 = @as(u64, 1) << 32;
pub fn reduceWords(words: [8]u32) [8]M.M31 {
    var out: [8]M.M31 = undefined;
    for (&out, words) |*v, word| v.* = M.M31.fromU64(word);
    return out;
}
fn initInner(profile: Profile) B.Blake2sChannel {
    var inner: B.Blake2sChannel = .{};
    inner.mixU32s(&profile.tag());
    return inner;
}
pub const Qm31Channel = struct {
    pub const SecureField = Q;
    inner: B.Blake2sChannel,
    pub const profile = qm31_profile;
    pub fn init() Qm31Channel {
        return .{ .inner = initInner(profile) };
    }
    pub fn verifyPowNonce(self: Qm31Channel, n_bits: u32, nonce: u64) bool {
        return self.inner.verifyPowNonce(n_bits, nonce);
    }
    pub fn grind(self: Qm31Channel, n_bits: u32) u64 {
        return self.inner.grind(n_bits);
    }
    pub fn grindWithWorkerCount(self: Qm31Channel, n_bits: u32, workers: usize) u64 {
        return self.inner.grindWithWorkerCount(n_bits, workers);
    }
    pub fn digestBytes(self: Qm31Channel) [32]u8 {
        return self.inner.digestBytes();
    }
    pub fn mixU32s(self: *Qm31Channel, values: []const u32) void {
        self.inner.mixU32s(values);
    }
    pub fn mixU64(self: *Qm31Channel, value: u64) void {
        self.inner.mixU64(value);
    }
    pub fn mixFelts(self: *Qm31Channel, values: []const Q) void {
        self.inner.mixFelts(values);
    }
    pub fn drawU32s(self: *Qm31Channel) [8]u32 {
        return self.inner.drawU32s();
    }
    pub fn drawSecureFelt(self: *Qm31Channel) Q {
        const words = reduceWords(self.drawU32s());
        return Q.fromM31Array(words[0..4].*);
    }
    pub fn drawSecureFelts(self: *Qm31Channel, a: std.mem.Allocator, count: usize) ![]Q {
        const out = try a.alloc(Q, count);
        var at: usize = 0;
        while (at < count) {
            const words = reduceWords(self.drawU32s());
            out[at] = Q.fromM31Array(words[0..4].*);
            at += 1;
            if (at < count) {
                out[at] = Q.fromM31Array(words[4..8].*);
                at += 1;
            }
        }
        return out;
    }
};
/// Opt-in producer observation, scoped to one exact channel object/thread.
/// The observer never supplies transcript values or alters channel authority.
pub const Om31Checkpoint = struct { digest: [32]u8, draws: u32 };
pub const Om31Event = union(enum) {
    mix_words: []const u32,
    mix_felts: []const O,
    draw_raw: [8]u32,
    draw_om31: [8]u32,
};
pub const Om31Observer = struct {
    context: *anyopaque,
    target: ?*const anyopaque = null,
    start: *const fn (*anyopaque, Om31Checkpoint) void,
    record: *const fn (*anyopaque, Om31Event, Om31Checkpoint) void,
    before_pcs: *const fn (*anyopaque, Om31Checkpoint) anyerror!void,
    finish: *const fn (*anyopaque) anyerror!void,
    destroy: *const fn (*anyopaque) void,
};
pub threadlocal var om31_observer: ?*Om31Observer = null;
pub fn om31Checkpoint(channel: *const Om31Channel) Om31Checkpoint {
    return .{ .digest = channel.inner.digest, .draws = channel.inner.n_draws };
}
pub fn beforeDeviceOm31Pcs(channel: *const Om31Channel) !void {
    if (om31_observer) |observer| if (observer.target == @as(*const anyopaque, @ptrCast(channel))) {
        try observer.before_pcs(observer.context, om31Checkpoint(channel));
        observer.target = null; // CPCS owns the already-resident suffix.
    };
}
pub const Om31Channel = struct {
    pub const SecureField = O;
    inner: B.Blake2sChannel,
    pub const profile = om31_profile;
    pub fn init() Om31Channel {
        return .{ .inner = initInner(profile) };
    }
    pub fn verifyPowNonce(self: Om31Channel, n_bits: u32, nonce: u64) bool {
        return self.inner.verifyPowNonce(n_bits, nonce);
    }
    pub fn grind(self: Om31Channel, n_bits: u32) u64 {
        return self.inner.grind(n_bits);
    }
    pub fn grindWithWorkerCount(self: Om31Channel, n_bits: u32, workers: usize) u64 {
        return self.inner.grindWithWorkerCount(n_bits, workers);
    }
    pub fn digestBytes(self: Om31Channel) [32]u8 {
        return self.inner.digestBytes();
    }
    pub fn mixU32s(self: *Om31Channel, values: []const u32) void {
        self.inner.mixU32s(values);
        self.observe(.{ .mix_words = values });
    }
    pub fn mixU64(self: *Om31Channel, value: u64) void {
        self.inner.mixU64(value);
        const words = [_]u32{ @truncate(value), @truncate(value >> 32) };
        self.observe(.{ .mix_words = &words });
    }
    pub fn mixFelts(self: *Om31Channel, values: []const O) void {
        var hash = @import("../vcs/blake2_hash.zig").Blake2sHasher.init();
        hash.update(&self.inner.digest);
        for (values) |value| hash.update(&value.toBytesLe());
        self.inner.updateDigest(hash.finalize());
        self.observe(.{ .mix_felts = values });
    }
    pub fn drawU32s(self: *Om31Channel) [8]u32 {
        const words = self.inner.drawU32s();
        self.observe(.{ .draw_raw = words });
        return words;
    }
    pub fn drawSecureFelt(self: *Om31Channel) O {
        const value = O.fromM31Array(reduceWords(self.inner.drawU32s()));
        var words: [8]u32 = undefined;
        for (&words, value.toM31Array()) |*word, field| word.* = field.v;
        self.observe(.{ .draw_om31 = words });
        return value;
    }
    fn observe(self: *const Om31Channel, event: Om31Event) void {
        if (om31_observer) |observer| if (observer.target == @as(*const anyopaque, @ptrCast(self))) observer.record(observer.context, event, om31Checkpoint(self));
    }
    pub fn drawSecureFelts(self: *Om31Channel, a: std.mem.Allocator, count: usize) ![]O {
        const out = try a.alloc(O, count);
        for (out) |*value| value.* = self.drawSecureFelt();
        return out;
    }
};
test {
    _ = @import("raw_mod_m31_test.zig");
}

test "OM31 observer is object-scoped and secure draws are not double recorded" {
    const Sink = struct {
        count: usize = 0,
        secure: usize = 0,
        fn start(_: *anyopaque, _: Om31Checkpoint) void {}
        fn record(raw: *anyopaque, event: Om31Event, _: Om31Checkpoint) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.count += 1;
            if (event == .draw_om31) self.secure += 1;
        }
        fn before(_: *anyopaque, _: Om31Checkpoint) !void {}
        fn finish(_: *anyopaque) !void {}
        fn destroy(_: *anyopaque) void {}
    };
    var channel = Om31Channel.init();
    var reference = channel;
    var other = channel;
    var sink: Sink = .{};
    var observer = Om31Observer{ .context = &sink, .target = &channel, .start = Sink.start, .record = Sink.record, .before_pcs = Sink.before, .finish = Sink.finish, .destroy = Sink.destroy };
    const previous = om31_observer;
    om31_observer = &observer;
    defer om31_observer = previous;
    _ = other.drawSecureFelt();
    try std.testing.expectEqual(@as(usize, 0), sink.count);
    try std.testing.expectEqual(reference.drawSecureFelt(), channel.drawSecureFelt());
    channel.mixU32s(&.{ 0xffffffff, M.Modulus, 7 });
    reference.mixU32s(&.{ 0xffffffff, M.Modulus, 7 });
    const values = try channel.drawSecureFelts(std.testing.allocator, 2);
    defer std.testing.allocator.free(values);
    for (values) |value| try std.testing.expectEqual(reference.drawSecureFelt(), value);
    try std.testing.expectEqual(@as(usize, 4), sink.count);
    try std.testing.expectEqual(@as(usize, 3), sink.secure);
    try std.testing.expectEqualSlices(u8, &reference.inner.digest, &channel.inner.digest);
    try std.testing.expectEqual(reference.inner.n_draws, channel.inner.n_draws);
}
