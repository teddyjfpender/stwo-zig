//! NEW enclosing-parent public grammar. It never changes original child replay.
//! Fresh final admission reconstructs all original PublicData and full clocks
//! from the independently admitted typed policy, not from proof-carried spans.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Wide = @import("block_v5_wide_original_child_source_v1.zig");
const Fields = @import("block_v5_global_public_fields_v1.zig");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const TAG: u32 = 0x42355750; // B5WP: not an old H/open/native transcript.
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT: u32 = 4_300_211;
pub const ORIGINAL_FIRST: u32 = 28;
pub fn addCarries(left: u64, right: u64) ![4]u8 {
    _ = try std.math.add(u64, left, right);
    var previous: u32 = 0;
    var out: [4]u8 = undefined;
    for (&out, 0..) |*carry, index| {
        const shift: u6 = @intCast(16 * index);
        const sum = @as(u32, @intCast((left >> shift) & 65535)) + @as(u32, @intCast((right >> shift) & 65535)) + previous;
        previous = sum >> 16;
        carry.* = @intCast(previous);
    }
    return out;
}

pub const Limits = struct { fields: Fields.Limits = .{}, max_cells: usize = 64 << 20 };
pub const Coordinate = struct { first_cell: u32, word_count: u32 };
fn bytes(word: u32) [4]M {
    var out: [4]M = undefined;
    for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
    return out;
}
pub fn ForSubtype(comptime subtype: Coverage.Subtype) type {
    if (subtype != .native_v3 and subtype != .capacity_v1) @compileError("wide native public fields require a genuine native arithmetic child; providers/fused have no substitute span");
    const Stack = Wide.ForSubtype(subtype);
    return struct {
        pub const Values = struct {
            allocator: std.mem.Allocator,
            allocation_owner: ?*Budget,
            source: *const Stack.Source,
            fields: Fields.Fields,
            max_cells: usize,
            steps: u32,
            add_carries: [4]u8,
            increment_carries: [4]u8,
            pub const complete_source_authority = false;
            pub const requires_new_parent_key = true;
            pub fn init(a: std.mem.Allocator, source: *const Stack.Source, limits: Limits) !Values {
                try source.validate();
                const prepared = source.policy.admitted;
                const span = source.span orelse return error.MissingWideNativeSpan;
                const owner = Budget.fromAllocator(a);
                if (owner) |value| _ = value.retain();
                errdefer if (owner) |value| value.destroy();
                var fields = try Fields.init(a, &prepared.shape.public_data, prepared.template.execution_profile, span.first_cycle, span.last_cycle, limits.fields);
                errdefer fields.deinit();
                const out = Values{ .allocator = a, .allocation_owner = owner, .source = source, .fields = fields, .max_cells = limits.max_cells, .steps = prepared.shape.public_data.clock - 1, .add_carries = try addCarries(span.first_cycle, prepared.shape.public_data.clock - 1), .increment_carries = try @import("air/block_v5_recursive_u64_span_v1.zig").carries(prepared.shape.public_data.clock - 1) };
                try out.validate();
                return out;
            }
            pub fn deinit(self: *Values) void {
                const owner = self.allocation_owner;
                self.fields.deinit();
                self.* = undefined;
                if (owner) |value| value.destroy();
            }
            pub fn validate(self: *const Values) !void {
                try self.source.validate();
                const prepared = self.source.policy.admitted;
                const span = self.source.span orelse return error.MissingWideNativeSpan;
                try self.fields.validate(&prepared.shape.public_data, prepared.template.execution_profile, span.first_cycle, span.last_cycle);
                if (self.steps != prepared.shape.public_data.clock - 1 or !std.meta.eql(self.add_carries, try addCarries(span.first_cycle, self.steps)) or !std.meta.eql(self.increment_carries, try @import("air/block_v5_recursive_u64_span_v1.zig").carries(self.steps))) return error.MutatedWideNativePublic;
                const total = try self.cellCount();
                if (total > self.max_cells or total >= core.fields.m31.Modulus) return error.WideNativePublicResourceLimit;
                // Normative original framing, never an equal-value root search.
                const digest = try self.source.frameAt(9);
                if (digest.operation != .root or !std.meta.eql(digest.operation.root, self.fields.source_digest)) return error.UntrustedWideNativeDigestSource;
            }
            pub fn fieldsFirst(self: *const Values) !u32 {
                return std.math.add(u32, ORIGINAL_FIRST + 10, self.source.cell_count);
            }
            pub fn cellCount(self: *const Values) !u32 {
                return std.math.add(u32, try self.auxFirst(), 9);
            }
            pub fn auxFirst(self: *const Values) !u32 {
                return std.math.add(u32, try self.fieldsFirst(), self.fields.word_count);
            }
            pub fn expectedDigest(self: *const Values) !Coordinate {
                return .{ .first_cell = try std.math.add(u32, ORIGINAL_FIRST + 2, self.source.cell_count), .word_count = 8 };
            }
            pub fn originalCell(self: *const Values, coordinate: u32) !u32 {
                if (coordinate >= self.source.cell_count) return error.InvalidWideOriginalCoordinate;
                return std.math.add(u32, ORIGINAL_FIRST, coordinate);
            }
            pub fn firstCycle(self: *const Values) !Coordinate {
                return .{ .first_cell = try std.math.add(u32, try self.fieldsFirst(), self.fields.layout.cycles), .word_count = 2 };
            }
            pub fn lastCycle(self: *const Values) !Coordinate {
                const first = try self.firstCycle();
                return .{ .first_cell = try std.math.add(u32, first.first_cell, 2), .word_count = 2 };
            }
            pub fn clock(self: *const Values) !Coordinate {
                return .{ .first_cell = try std.math.add(u32, try self.fieldsFirst(), self.fields.layout.pc_clock + 2), .word_count = 1 };
            }
            pub fn originalDigest(self: *const Values) !Coordinate {
                const frame = try self.source.frameAt(9);
                return .{ .first_cell = try self.originalCell(frame.first), .word_count = 8 };
            }
            pub fn cell(self: *const Values, coordinate: u32) ![4]M {
                if (coordinate >= try self.cellCount()) return error.InvalidWideOriginalCoordinate;
                if (coordinate < 4) return bytes(([_]u32{ TAG, VERSION, @intFromEnum(subtype), self.source.policy.physical.index })[coordinate]);
                if (coordinate < ORIGINAL_FIRST) {
                    const slot = (coordinate - 4) / 8;
                    const limb = (coordinate - 4) % 8;
                    const root = switch (slot) {
                        0 => self.source.policy.key_id,
                        1 => self.source.public_input_digest,
                        2 => self.source.policy.source_seal,
                        else => unreachable,
                    };
                    return bytes(std.mem.readInt(u32, root[4 * @as(usize, limb) ..][0..4], .little));
                }
                const offset = coordinate - ORIGINAL_FIRST;
                if (offset < self.source.cell_count) return self.source.cell(offset);
                const after = offset - self.source.cell_count;
                if (after < 2) return bytes(if (after == 0) @intFromEnum(self.fields.profile) else self.fields.word_count);
                if (after < 10) return bytes(std.mem.readInt(u32, self.fields.source_digest[4 * @as(usize, after - 2) ..][0..4], .little));
                const field_word = after - 10;
                if (field_word < self.fields.word_count) return self.fields.bytes(field_word);
                const auxiliary = field_word - self.fields.word_count;
                return bytes(if (auxiliary == 0) self.steps else if (auxiliary < 5) self.add_carries[auxiliary - 1] else self.increment_carries[auxiliary - 5]);
            }
            /// Serialize ONLY the new enclosing parent's public input. Original
            /// verifier transcript replay continues through source.replayPublic.
            pub fn mixParent(self: *const Values, channel: anytype) !void {
                try self.validate();
                channel.mixU32s(&.{ TAG, VERSION, @intFromEnum(subtype), self.source.policy.physical.index });
                channel.mixRoot(self.source.policy.key_id);
                channel.mixRoot(self.source.public_input_digest);
                channel.mixRoot(self.source.policy.source_seal);
                try self.source.mix(channel);
                channel.mixU32s(&.{ @intFromEnum(self.fields.profile), self.fields.word_count });
                channel.mixRoot(self.fields.source_digest);
                for (self.fields.chunks) |chunk| channel.mixU32s(chunk.words);
                channel.mixU32s(&.{ self.steps, self.add_carries[0], self.add_carries[1], self.add_carries[2], self.add_carries[3], self.increment_carries[0], self.increment_carries[1], self.increment_carries[2], self.increment_carries[3] });
            }
            pub fn publicIdentity(self: *const Values) ![32]u8 {
                var channel = core.channel.blake3.Channel{};
                try self.mixParent(&channel);
                return channel.digestBytes();
            }
        };
    };
}
