//! Single parity completion/peer state and exact recursive comparison helpers.
const api = jobs.api;
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const std = @import("std");

pub const PeerCopy = *const fn (*anyopaque, c_int, *const anyopaque, c_int, usize, *anyopaque) callconv(.c) c_int;

/// Legacy outputs live on the legacy pool's GPU; the job worker is on another
/// GPU. A parity job first mirrors them into its own arena on its exec stream.
pub const Peer = struct {
    copy: PeerCopy,
    source_device: c_int,
    pub fn mirror(self: Peer, e: *api.Enqueue, dst: [*]u32, src: [*]const u32, words: usize) !void {
        if (self.copy(dst, @intCast(e.device()), src, self.source_device, words * 4, e.stream()) != 0) return error.ParityPeerCopyFailed;
    }
    /// Replace every device input by an arena mirror (host inputs untouched).
    pub fn mirrorInputs(self: Peer, e: *api.Enqueue, comptime T: type, inputs: []const T, logs: []const u32, out: []T) !void {
        var words: usize = 0;
        for (inputs, logs) |input, log| if (input.device != null) {
            words += @as(usize, 1) << @intCast(log);
        };
        @memcpy(out, inputs);
        if (words == 0) return;
        const buffer = try e.alloc(words);
        var at: usize = 0;
        for (inputs, logs, out) |input, log, *o| if (input.device) |d| {
            const n = @as(usize, 1) << @intCast(log);
            try self.mirror(e, buffer.ptr + at, d, n);
            o.* = .{ .device = buffer.ptr + at };
            at += n;
        };
    }
    pub fn deviceWords(comptime T: type, inputs: []const T, logs: []const u32) usize {
        var words: usize = 64;
        for (inputs, logs) |input, log| if (input.device != null) {
            words += @as(usize, 1) << @intCast(log);
        };
        return words;
    }
};

/// NG.GkrJob with the legacy device columns mirrored into the job arena.
pub const Compare = *const fn (*anyopaque, u32, [*]const u32, [*]const u32, u64, [*]u32) callconv(.c) c_int;

pub const Done = struct {
    done: bool = false,
    result: anyerror!void = {},
    receipt: api.Receipt = .{},
    pub fn call(raw: *anyopaque, c: api.Completion) void {
        const d: *@This() = @ptrCast(@alignCast(raw));
        d.receipt = c.receipt;
        d.result = c.result;
        @atomicStore(bool, &d.done, true, .release);
    }
};

// ---------------------------------------------------------------------------
// OODS point + mask sampling + enqueue-only PCS (native_pcs.enqueueOpening) at
// the legacy PCS stage, every native proof (CPU segments and truths). The
// device channel starts at the legacy pre-OODS checkpoint (the PCS request's
// channel minus the OODS draw), draws the OODS felt, builds the OODS and base
// points on device and runs the PCS seeded from the device state. The framing
// is built at a PLACEHOLDER point (mask offsets only: challenge independent).
// finish decodes with the legacy decoder; proof and post-PCS channel must equal
// the legacy PCS result.

/// Structural equality of proof values. Polynomials compare their logical
/// coefficients (`coeffs[0..len]`); ownership flags are not proof content.
pub fn deepEql(x: anytype, y: @TypeOf(x)) bool {
    const T = @TypeOf(x);
    switch (@typeInfo(T)) {
        .pointer => |p| {
            if (p.size != .slice) return deepEql(x.*, y.*);
            if (x.len != y.len) return false;
            for (x, y) |u, v| if (!deepEql(u, v)) return false;
            return true;
        },
        .array => {
            for (x, y) |u, v| if (!deepEql(u, v)) return false;
            return true;
        },
        .@"struct" => |s| {
            if (comptime @hasField(T, "coeffs") and @hasField(T, "len")) {
                if (x.len != y.len or x.len > x.coeffs.len or y.len > y.coeffs.len) return false;
                return deepEql(x.coeffs[0..x.len], y.coeffs[0..y.len]);
            }
            inline for (s.fields) |f| {
                if (comptime std.mem.startsWith(u8, f.name, "owns")) continue;
                if (!deepEql(@field(x, f.name), @field(y, f.name))) return false;
            }
            return true;
        },
        else => return std.meta.eql(x, y),
    }
}

pub fn env(name: []const u8) ?[]const u8 {
    return std.posix.getenv(name);
}
pub fn envBytes(name: []const u8, default: usize) !usize {
    const text = env(name) orelse return default;
    return std.fmt.parseUnsigned(usize, text, 10) catch error.InvalidParityEnvironment;
}

pub var native_beta = std.atomic.Value(u32).init(0);

pub fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}
