//! Experimental typed sparse providers for the three large native range tables.
//! Not yet admitted by the execution roster. Every row, including padding,
//! proves membership independently of its signed original-table multiplicity.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const schema = @import("../../air/lookups/tables/schema.zig");
const M = core.fields.m31.M31;
pub fn Provider(comptime kind: schema.Kind) type {
    if (kind != .range_check_20 and kind != .range_check_8_11 and kind != .range_check_8_8_4) @compileError("unsupported compact range provider");
    return struct {
        pub const tuple_len = schema.arity(kind);
        pub const high_bits = if (kind == .range_check_8_11) 3 else 4;
        const extra_bytes = if (kind == .range_check_20) 2 else if (kind == .range_check_8_11) 1 else 0;
        pub const bit_start = tuple_len + extra_bytes;
        pub const multiplicity_index = bit_start + high_bits;
        pub const PHYSICAL_MAIN_COLUMN_COUNT = multiplicity_index + 1;
        pub const PREPROCESSED_COLUMN_COUNT = 0;
        pub const LOGICAL_INPUT_COUNT = PHYSICAL_MAIN_COLUMN_COUNT;
        pub const DIRECT_CONSTRAINT_COUNT = high_bits + 1;
        pub const RELATION_EVENT_COUNT = 2;
        pub const LOOKUP_BATCH_SIZE: u8 = 2;
        pub const INTERACTION_BATCH_COUNT = 1;
        pub const INTERACTION_COLUMN_COUNT = 4;
        pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
        pub const SEMANTIC_DIGEST: [32]u8 = blk: {
            const hex = switch (kind) {
                .range_check_20 => "17ac250be4dec81345bfbf03372781b3b8bde9b78c58672c86c2dcdb26e8d90a",
                .range_check_8_11 => "ca6eb5fdbcfdc22eeb1aa355572559b98a74349788dbd95cc18a585c14ab77ea",
                .range_check_8_8_4 => "7417b12e404ba59efb4af7a38448df998d851b6555b55e4a3e4cdb6fdc2bea89",
                else => unreachable,
            };
            var bytes: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&bytes, hex) catch @compileError("invalid compact range identity");
            break :blk bytes;
        };
        pub const Row = [LOGICAL_INPUT_COUNT]M;
        pub const Definition = struct {
            arena: lang.ir.Arena,
            events: [2]lang.types.EffectId,
            pub fn deinit(self: *@This()) void {
                self.arena.deinit();
            }
            pub fn validate(self: *const @This()) !void {
                try lang.validate.validate(&self.arena);
                if (!std.mem.eql(u8, &(try lang.digest.computeIdentity(&self.arena)).bytes, &SEMANTIC_DIGEST)) return error.InvalidCompactRangeIdentity;
            }
        };
        pub fn build(a: std.mem.Allocator) !Definition {
            var result = try buildRaw(a);
            errdefer result.deinit();
            try result.validate();
            return result;
        }
        pub fn computeSemanticDigest(a: std.mem.Allocator) ![32]u8 {
            var result = try buildRaw(a);
            defer result.deinit();
            return (try lang.digest.computeIdentity(&result.arena)).bytes;
        }
        fn buildRaw(a: std.mem.Allocator) !Definition {
            var arena = lang.ir.Arena.init(a);
            errdefer arena.deinit();
            const span = lang.source.SourceSpan.generated();
            var ids: [LOGICAL_INPUT_COUNT]lang.types.ValueId = undefined;
            for (&ids, 0..) |*id, i| {
                const ty: lang.types.Type = if (i == multiplicity_index) .felt else if (i >= bit_start) .bit else if (kind == .range_check_20 and i == 0) .uint20 else if (kind == .range_check_8_11 and i == 1) .{ .bounded_uint = .{ .bits = 11, .representation = .canonical_field } } else if (kind == .range_check_8_8_4 and i == 2) .{ .bounded_uint = .{ .bits = 4, .representation = .canonical_field } } else .byte;
                var name: [80]u8 = undefined;
                id.* = try arena.input(try std.fmt.bufPrint(&name, "compact_{s}.value_{d}", .{ @tagName(kind), i }), ty, span);
            }
            const zero = try arena.constantField(0, span);
            const one = try arena.constantField(1, span);
            var high = zero;
            for (0..high_bits) |i| {
                const bit = ids[bit_start + i];
                var name: [32]u8 = undefined;
                _ = try arena.assertZero(try std.fmt.bufPrint(&name, "high_bit_{d}", .{i}), try arena.mul(bit, try arena.sub(bit, one, span), span), null, .semantic, span);
                high = try arena.add(high, try arena.mul(bit, try arena.constantField(@as(u32, 1) << @intCast(i), span), span), span);
            }
            const lo = ids[if (kind == .range_check_20) 1 else 0];
            const hi = ids[if (kind == .range_check_20 or kind == .range_check_8_11) 2 else 1];
            const reconstructed = if (kind == .range_check_20)
                try arena.add(lo, try arena.add(try arena.mul(hi, try arena.constantField(256, span), span), try arena.mul(high, try arena.constantField(65536, span), span), span), span)
            else if (kind == .range_check_8_11)
                try arena.add(hi, try arena.mul(high, try arena.constantField(256, span), span), span)
            else
                high;
            _ = try arena.assertZero("tuple_reconstruction", try arena.sub(ids[if (kind == .range_check_20) 0 else if (kind == .range_check_8_11) 1 else 2], reconstructed, span), null, .semantic, span);
            const domain: @import("../../air/lang/relation.zig").Domain = switch (kind) {
                .range_check_20 => .range_check_20,
                .range_check_8_11 => .range_check_8_11,
                .range_check_8_8_4 => .range_check_8_8_4,
                else => unreachable,
            };
            const events = try effects.appendGroup(2, &arena, .{
                .{ .domain = domain, .role = .request, .values = ids[0..tuple_len], .weight = ids[multiplicity_index] },
                .{ .domain = .range_check_8_8, .role = .request, .values = &.{ lo, hi }, .weight = one },
            }, span);
            return .{ .arena = arena, .events = events };
        }
        pub fn logicalRow(tuple: []const M, multiplicity: M) !Row {
            _ = try schema.indexBase(kind, tuple);
            var row: Row = @splat(M.zero());
            @memcpy(row[0..tuple_len], tuple);
            const high: u32 = switch (kind) {
                .range_check_20 => blk: {
                    row[1] = M.fromCanonical(tuple[0].toU32() & 255);
                    row[2] = M.fromCanonical((tuple[0].toU32() >> 8) & 255);
                    break :blk tuple[0].toU32() >> 16;
                },
                .range_check_8_11 => blk: {
                    row[2] = M.fromCanonical(tuple[1].toU32() & 255);
                    break :blk tuple[1].toU32() >> 8;
                },
                .range_check_8_8_4 => tuple[2].toU32(),
                else => unreachable,
            };
            for (0..high_bits) |i| row[bit_start + i] = M.fromCanonical((high >> @intCast(i)) & 1);
            row[multiplicity_index] = multiplicity;
            return row;
        }
    };
}
