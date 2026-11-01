//! Committed curve/field truth columns and private interaction publication.
//! Packets are untrusted advice; their truth is the AIR plus Wire35 closure.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../memory/closed_ram/mod.zig");
const spec = @import("spec.zig");
const Base = @import("layout.zig");
const Native = @import("native.zig").Native;
const EqOf = @import("equations.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;

pub fn fixed(a: std.mem.Allocator, log: u32) ![]M {
    if (log < Base.MIN_LOG or log > Base.MAX_LOG) return error.InvalidCurveGeometry;
    const n = @as(usize, 1) << @intCast(log);
    const out = try a.alloc(M, Base.FIXED * n);
    for (0..n) |row| {
        const p = R.trace.physical(row, log);
        out[Base.ROW * n + p] = M.fromCanonical(@intCast(row));
        out[Base.FIRST * n + p] = M.fromCanonical(@intFromBool(row == 0));
        out[Base.LAST * n + p] = M.fromCanonical(@intFromBool(row == n - 1));
        out[Base.BYTE * n + p] = M.fromCanonical(@intCast(row & 0xff));
    }
    return out;
}

pub fn externalTuple(kind: u32, id: u32, wire: usize, bytes: [32]u8) [Base.WIRE_ARITY]Q {
    var t: [Base.WIRE_ARITY]Q = undefined;
    t[0] = Q.fromBase(M.fromCanonical(kind));
    t[1] = Q.fromBase(M.fromCanonical(id));
    t[2] = Q.fromBase(M.fromCanonical(@intCast(wire)));
    for (t[3..], bytes) |*v, b| v.* = Q.fromBase(M.fromCanonical(b));
    return t;
}

pub fn Trace(comptime op: spec.Op) type {
    return struct {
        pub const N = Native(op);
        pub const L = N.L;
        const Eq = EqOf.Equations(op);

        /// Native row `r` of a trace over `packets`: active rows, then zero
        /// padding. MULT is the BYTE multiplicity of value r on rows 0..255.
        pub fn nativeRow(row: *N.Row, packets: []const N.Packet, counts: *const [256]u64, r: usize) !void {
            if (r < packets.len) {
                _ = try N.fill(row, &packets[r]);
            } else @memset(row, 0);
            row[L.MULT] = if (r < 256) @intCast(counts[r]) else 0;
        }
        /// BYTE multiplicities of the whole trace (padding rows are all zero
        /// except the encoded constants of their queries).
        pub fn byteCounts(packets: []const N.Packet, n: usize) ![256]u64 {
            var counts: [256]u64 = @splat(0);
            var row: N.Row = undefined;
            for (packets) |*packet| {
                _ = try N.fill(&row, packet);
                for (L.QUERIES) |q| counts[row[q.column] + q.addend] += 1;
            }
            const padding: u64 = n - packets.len;
            for (L.QUERIES) |q| counts[q.addend] += padding;
            var mass: u64 = 0;
            for (counts) |c| mass += c;
            if (mass != @as(u64, L.BYTE_QUERIES) * n or mass >= core.fields.m31.Modulus) return error.CurveLookupMassExceeded;
            return counts;
        }

        pub const Source = struct {
            pub const OP = op;
            allocator: std.mem.Allocator,
            log_size: u32,
            first_id: u32,
            /// Copied narrow advice: survives MAIN release for interaction work.
            packets: []N.Packet,
            counts: [256]u64,
            fixed: []M,
            owns_fixed: bool = true,
            main: []M,
            owns_main: bool = true,
            main_allocator: ?std.mem.Allocator = null,
            interaction: []M = &.{},

            pub fn init(a: std.mem.Allocator, packets: []const N.Packet, first_id: u32, log: u32) !Source {
                try L.validateGeometry(packets.len, first_id, log);
                const n = @as(usize, 1) << @intCast(log);
                const copy = try a.dupe(N.Packet, packets);
                errdefer a.free(copy);
                const counts = try byteCounts(packets, n);
                const f = try fixed(a, log);
                errdefer a.free(f);
                const main = try a.alloc(M, L.MAIN * n);
                errdefer a.free(main);
                var row: N.Row = undefined;
                for (0..n) |r| {
                    const p = R.trace.physical(r, log);
                    try nativeRow(&row, packets, &counts, r);
                    for (row, 0..) |v, c| main[c * n + p] = M.fromCanonical(v);
                }
                return .{ .allocator = a, .log_size = log, .first_id = first_id, .packets = copy, .counts = counts, .fixed = f, .main = main };
            }
            pub fn size(self: *const Source) usize {
                return @as(usize, 1) << @intCast(self.log_size);
            }
            pub fn releaseMain(self: *Source) !void {
                if (self.owns_main) (self.main_allocator orelse self.allocator).free(self.main);
                self.main = &.{};
                self.owns_main = false;
            }
            pub fn deinit(self: *Source) void {
                self.releaseMain() catch {};
                const a = self.allocator;
                if (self.owns_fixed) a.free(self.fixed);
                a.free(self.packets);
                a.free(self.interaction);
                self.* = undefined;
            }
            pub fn validateMetadata(self: *const Source) !void {
                try L.validateGeometry(self.packets.len, self.first_id, self.log_size);
                if (self.fixed.len != Base.FIXED * self.size()) return error.InvalidCurveMetadata;
            }
            /// Publishes both cumulative chains from copied advice alone and
            /// returns the Wire35 claim (the BYTE chain closes to zero).
            pub fn generateInteraction(self: *Source, ch: EqOf.Challenges) !Q {
                if (self.interaction.len != 0) return error.InvalidCurvePhase;
                try self.validateMetadata();
                const n = self.size();
                const out = try self.allocator.alloc(M, L.INTERACTION * n);
                errdefer self.allocator.free(out);
                var table: [256]Q = undefined;
                for (&table, 0..) |*t, v| t.* = try ch.bytes.sub(Q.fromBase(M.fromCanonical(@intCast(v)))).inv();
                var bytes_total = Q.zero();
                var wire_total = Q.zero();
                var row: N.Row = undefined;
                for (0..n) |r| {
                    const p = R.trace.physical(r, self.log_size);
                    try nativeRow(&row, self.packets, &self.counts, r);
                    for (0..L.BYTE_BATCHES) |b| {
                        for (0..2) |i| {
                            const index = 2 * b + i;
                            if (index < L.BYTE_QUERIES) {
                                const q = L.QUERIES[index];
                                bytes_total = bytes_total.add(table[row[q.column] + q.addend]);
                            } else if (index == L.BYTE_QUERIES) {
                                bytes_total = bytes_total.sub(table[r & 0xff].mul(Q.fromBase(M.fromCanonical(row[L.MULT]))));
                            }
                        }
                        R.trace.store(out, n, p, 4 * b, bytes_total);
                    }
                    if (r < self.packets.len) {
                        const before = &self.packets[r];
                        const after = try N.after(before);
                        for (0..L.WIRE_BATCHES) |w| {
                            for (0..2) |i| {
                                const id = 2 * w + i;
                                if (id >= L.WIRE_FRACTIONS) continue;
                                const inv = try ch.wire.denominator(&externalTuple(L.PROGRAM_KIND, self.first_id + @as(u32, @intCast(r)), id, N.wireBytes(before, &after, id))).inv();
                                wire_total = if (id >= L.COORDS) wire_total.add(inv) else wire_total.sub(inv);
                            }
                            R.trace.store(out, n, p, L.WIRE_FIRST + 4 * w, wire_total);
                        }
                    } else for (0..L.WIRE_BATCHES) |w| R.trace.store(out, n, p, L.WIRE_FIRST + 4 * w, wire_total);
                }
                if (!bytes_total.isZero()) return error.InvalidCurveByteCounts;
                // C[r] = S_r - claim: the last cumulative entry is zero and the
                // claim enters once at FIRST, exactly as the constraint states.
                for (0..L.WIRE_BATCHES) |w| R.trace.center(out, n, L.WIRE_FIRST + 4 * w, wire_total);
                self.interaction = out;
                return wire_total;
            }
        };
    };
}
