//! ProofLayout / ProofSlab (spec §3.4). A layout is computed on the host from
//! class geometry and the PCS profile before enqueue; it fixes the word offset
//! of every proof field. Kernels and D2D copies write fields straight into the
//! device slab; `finish` sees it after one pinned D2H and `encodePhysical`
//! re-creates exactly today's bytes.
//!
//! Byte identity strategy: today's resident PCS ends with one compact readback
//! (`pcs_pipeline.cuh` final_readback_encode) — a 14-word header followed by
//! fixed-order planes (status, channel state, trace roots, ordered sampled
//! values, PoW nonce, FRI last layer, raw queries, per FRI layer {root, values,
//! paths}, per trace {values, paths}). `PcsGeometry.layout` reproduces that
//! plane order and `encodePcsResult` the exact word image, so the existing host
//! decoder (pcs_native.zig → assembly) consumes it unchanged.
const std = @import("std");
const api = @import("api.zig");

pub const Kind = enum(u8) {
    status,
    channel_state,
    root,
    claims,
    sampled_values,
    pow_nonce,
    fri_last_layer,
    query_positions,
    fri_root,
    fri_values,
    fri_paths,
    trace_values,
    trace_paths,
    gkr_section,
    snapshot,
    opaque_words,
};

pub const Field = struct {
    kind: Kind,
    index: u32 = 0,
    offset: usize,
    words: usize,
};

pub const max_fields = 512;

pub const ProofLayout = struct {
    fields: [max_fields]Field = undefined,
    count: usize = 0,
    words: usize = 0,

    pub fn add(self: *ProofLayout, kind: Kind, index: u32, words: usize) !usize {
        if (self.count == max_fields) return error.ProofLayoutTooManyFields;
        if (self.find(kind, index) != null) return error.DuplicateProofField;
        const offset = self.words;
        self.words = try std.math.add(usize, self.words, words);
        self.fields[self.count] = .{ .kind = kind, .index = index, .offset = offset, .words = words };
        self.count += 1;
        return offset;
    }
    pub fn find(self: *const ProofLayout, kind: Kind, index: u32) ?Field {
        for (self.fields[0..self.count]) |f| if (f.kind == kind and f.index == index) return f;
        return null;
    }
    pub fn get(self: *const ProofLayout, kind: Kind, index: u32) !Field {
        return self.find(kind, index) orelse error.MissingProofField;
    }
    pub fn slice(self: *const ProofLayout) []const Field {
        return self.fields[0..self.count];
    }
};

pub const ProofSlab = struct {
    device: api.DeviceBuffer,
    layout: ?*const ProofLayout = null,
    /// Device words of one field (kernels take these pointers directly).
    pub fn field(self: *const ProofSlab, kind: Kind, index: u32) !api.DeviceBuffer {
        const layout = self.layout orelse return error.ProofSlabHasNoLayout;
        const f = try layout.get(kind, index);
        return self.device.slice(f.offset, f.words);
    }
    pub fn bind(self: *ProofSlab, layout: *const ProofLayout) !void {
        if (layout.words > self.device.words) return error.ProofLayoutExceedsSlab;
        self.layout = layout;
    }
};

/// Host words of one field from the pinned slab view.
pub fn read(view: api.SlabView, kind: Kind, index: u32) ![]const u32 {
    const layout = view.layout orelse return error.ProofSlabHasNoLayout;
    const f = try layout.get(kind, index);
    if (f.offset + f.words > view.words.len) return error.ProofSlabTruncated;
    return view.words[f.offset..][0..f.words];
}

/// Today's bytes of a word-image section: the fields in layout order,
/// little-endian u32 words (the representation every existing readback uses).
pub fn encodePhysical(a: std.mem.Allocator, layout: *const ProofLayout, words: []const u32) ![]u8 {
    if (words.len < layout.words) return error.ProofSlabTruncated;
    const out = try a.alloc(u8, layout.words * 4);
    var at: usize = 0;
    for (layout.slice()) |f| {
        for (words[f.offset..][0..f.words]) |w| {
            std.mem.writeInt(u32, out[at..][0..4], w, .little);
            at += 4;
        }
    }
    return out;
}

/// Geometry of the resident PCS (the inputs `pcs_pipeline.cuh` sizes planes from).
pub const PcsGeometry = struct {
    pub const Trace = struct { columns: u32, log: u32 };
    pub const FriLayer = struct { count: u32, steps: u32, leaf: u32 };
    source_count: u32,
    term_count: u32,
    group_count: u32,
    source_group_count: u32,
    sample_count: u32,
    log: u32,
    queries: u32,
    degree: u32,
    last_layer_log: u32,
    traces: []const Trace,
    fri: []const FriLayer,

    pub fn friValueWords(self: PcsGeometry, l: FriLayer) usize {
        return (@as(usize, self.queries) << @intCast(l.steps)) * 8;
    }
    pub fn friPathWords(self: PcsGeometry, l: FriLayer) usize {
        return (@as(usize, self.queries) << @intCast(l.steps - l.leaf)) * (@ctz(l.count) - l.leaf) * 8;
    }
    /// Slab layout in today's readback order.
    pub fn layout(self: PcsGeometry) !ProofLayout {
        var out: ProofLayout = .{};
        _ = try out.add(.status, 0, 1);
        _ = try out.add(.channel_state, 0, 16);
        for (self.traces, 0..) |_, t| _ = try out.add(.root, @intCast(t), 8);
        _ = try out.add(.sampled_values, 0, @as(usize, self.sample_count) * 8);
        _ = try out.add(.pow_nonce, 0, 2);
        _ = try out.add(.fri_last_layer, 0, 8);
        _ = try out.add(.query_positions, 0, self.queries);
        for (self.fri, 0..) |l, i| {
            _ = try out.add(.fri_root, @intCast(i), 8);
            _ = try out.add(.fri_values, @intCast(i), self.friValueWords(l));
            _ = try out.add(.fri_paths, @intCast(i), self.friPathWords(l));
        }
        for (self.traces, 0..) |t, i| {
            _ = try out.add(.trace_values, @intCast(i), @as(usize, t.columns) * self.queries);
            _ = try out.add(.trace_paths, @intCast(i), @as(usize, self.queries) * t.log * 8);
        }
        return out;
    }
    /// The 14-word header of today's PCS result (`out_header`).
    pub fn header(self: PcsGeometry, step: u32) [14]u32 {
        return .{ 0x52564d4f, 2, 0, self.source_count, self.term_count, self.group_count, self.source_group_count, @intCast(self.traces.len), self.sample_count, @intCast(self.fri.len), self.log, self.queries, self.degree, step };
    }
};

/// Exactly today's `Result.words` of the resident PCS: header ‖ slab planes.
pub fn encodePcsResult(a: std.mem.Allocator, geometry: PcsGeometry, layout: *const ProofLayout, words: []const u32, step: u32) ![]u32 {
    if (words.len < layout.words) return error.ProofSlabTruncated;
    const out = try a.alloc(u32, 14 + layout.words);
    @memcpy(out[0..14], &geometry.header(step));
    var at: usize = 14;
    for (layout.slice()) |f| {
        @memcpy(out[at..][0..f.words], words[f.offset..][0..f.words]);
        at += f.words;
    }
    return out;
}

test {
    _ = @import("slab_test.zig");
}
