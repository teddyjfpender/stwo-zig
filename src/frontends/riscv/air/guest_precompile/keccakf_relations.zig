//! Profile-local typed relations for the Keccak-f extension.
//!
//! IDs append to the unchanged twelve-relation base registry only inside the
//! future Keccak profile.  The profile owns three independent challenge pairs:
//! packed-state I/O, chi-row lookup, and xor5 normalization.  Keeping the tables
//! on distinct buses prevents an arity-compatible forged table row from
//! cancelling against guest memory I/O.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_challenges = @import("../relation_challenges.zig");
const base_relation = @import("../lang/relation.zig");
const types = @import("../lang/types.zig");
const authority = @import("keccakf_authority.zig");

pub const io_schema_numeric_id: u16 = base_relation.BASE_RELATION_COUNT;
pub const chi_schema_numeric_id: u16 = io_schema_numeric_id + 1;
pub const xor5_schema_numeric_id: u16 = chi_schema_numeric_id + 1;
pub const relation_count: usize = base_relation.BASE_RELATION_COUNT + 3;

pub const state_chunk_bits: usize = 30;
pub const state_chunk_count: usize =
    std.math.divCeil(usize, authority.width_bits, state_chunk_bits) catch unreachable;
pub const final_state_chunk_bits: usize =
    authority.width_bits - state_chunk_bits * (state_chunk_count - 1);
pub const io_arity: usize = 1 + 2 * state_chunk_count;
pub const chi_arity: usize = 6;
pub const xor5_arity: usize = 6;
pub const IoTuple = [io_arity]M31;
pub const ChiTuple = [chi_arity]M31;
pub const Xor5Tuple = [xor5_arity]M31;
pub fn IoTupleFor(comptime S: type) type {
    return [io_arity]S;
}
pub fn ChiTupleFor(comptime S: type) type {
    return [chi_arity]S;
}
pub fn Xor5TupleFor(comptime S: type) type {
    return [xor5_arity]S;
}

pub const Schema = struct {
    id: types.RelationSchemaId,
    version: u16,
    name: []const u8,
    fields: []const base_relation.FieldSpec,
    request_is_unit: bool,
    supply_is_weighted: bool,
};

const io_fields: [io_arity]base_relation.FieldSpec = blk: {
    var fields: [io_arity]base_relation.FieldSpec = undefined;
    fields[0] = .{ .exact = .felt };
    for (0..2) |state_index| for (0..state_chunk_count) |chunk| {
        const bits = if (chunk + 1 == state_chunk_count)
            final_state_chunk_bits
        else
            state_chunk_bits;
        fields[1 + state_index * state_chunk_count + chunk] = .{
            .exact = types.Type.boundedField(bits) catch unreachable,
        };
    };
    break :blk fields;
};
const table_fields = [_]base_relation.FieldSpec{
    .{ .exact = .felt },
} ** 6;

pub const io_schema = Schema{
    .id = @enumFromInt(io_schema_numeric_id),
    .version = 1,
    .name = "stwo.riscv.guest_keccakf_state_io",
    .fields = &io_fields,
    .request_is_unit = true,
    .supply_is_weighted = false,
};
pub const chi_schema = Schema{
    .id = @enumFromInt(chi_schema_numeric_id),
    .version = 2,
    .name = "stwo.riscv.guest_keccakf_chi",
    .fields = &table_fields,
    .request_is_unit = true,
    .supply_is_weighted = true,
};
pub const xor5_schema = Schema{
    .id = @enumFromInt(xor5_schema_numeric_id),
    .version = 2,
    .name = "stwo.riscv.guest_keccakf_xor5",
    .fields = &table_fields,
    .request_is_unit = true,
    .supply_is_weighted = true,
};

pub const Relations = struct {
    base: base_challenges.Relations,
    io: base_challenges.RelationElements(io_arity),
    chi: base_challenges.RelationElements(chi_arity),
    xor5: base_challenges.RelationElements(xor5_arity),

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !Relations {
        const base = try base_challenges.Relations.draw(allocator, channel);
        const extension = try channel.drawSecureFelts(allocator, 6);
        defer allocator.free(extension);
        if (extension.len != 6) return error.InvalidChallengeDraw;
        return .{
            .base = base,
            .io = .init(extension[0], extension[1]),
            .chi = .init(extension[2], extension[3]),
            .xor5 = .init(extension[4], extension[5]),
        };
    }

    pub fn dummy() Relations {
        return .{
            .base = .dummy(),
            .io = .dummy(),
            .chi = .dummy(),
            .xor5 = .dummy(),
        };
    }
};

pub fn Event(comptime arity: usize) type {
    return struct {
        role: types.RelationRole,
        coefficient: M31,
        tuple: [arity]M31,

        const Self = @This();

        pub fn unitRequest(tuple: [arity]M31) Self {
            return .{ .role = .request, .coefficient = M31.one(), .tuple = tuple };
        }

        pub fn unitEmit(tuple: [arity]M31) Self {
            return .{ .role = .emit, .coefficient = M31.one(), .tuple = tuple };
        }

        pub fn weightedEmit(tuple: [arity]M31, multiplicity: M31) Self {
            return .{ .role = .emit, .coefficient = multiplicity, .tuple = tuple };
        }

        pub fn padding() Self {
            return .{ .role = .request, .coefficient = M31.zero(), .tuple = @splat(M31.zero()) };
        }

        pub fn validate(self: Self) Error!void {
            if (self.role != .request and self.role != .emit)
                return error.InvalidRole;
            if (self.role == .request and
                !self.coefficient.isZero() and !self.coefficient.isOne())
            {
                return error.InvalidRequestMultiplicity;
            }
            if (self.coefficient.isZero()) for (self.tuple) |value| {
                if (!value.isZero()) return error.InvalidPadding;
            };
        }

        pub fn term(self: Self, relation: anytype) Error!QM31 {
            try self.validate();
            if (self.coefficient.isZero()) return QM31.zero();
            const denominator = relation.combineBase(self.tuple);
            const inverse = denominator.inv() catch return error.ZeroDenominator;
            const magnitude = inverse.mulM31(self.coefficient);
            return if (self.role == .request) magnitude.neg() else magnitude;
        }
    };
}

pub const IoEvent = Event(io_arity);
pub const ChiEvent = Event(chi_arity);
pub const Xor5Event = Event(xor5_arity);

pub const Error = error{
    CallIndexOutOfRange,
    InvalidPadding,
    InvalidRequestMultiplicity,
    InvalidRole,
    ZeroDenominator,
};

pub fn ioTuple(
    call_index: usize,
    input: authority.State,
    output: authority.State,
) Error!IoTuple {
    if (call_index >= authority.candidate.maximum_calls)
        return error.CallIndexOutOfRange;
    var tuple: IoTuple = undefined;
    tuple[0] = M31.fromCanonical(@intCast(call_index));
    packState(input, tuple[1 .. 1 + state_chunk_count]);
    packState(output, tuple[1 + state_chunk_count ..]);
    return tuple;
}

fn packState(state: authority.State, destination: []M31) void {
    std.debug.assert(destination.len == state_chunk_count);
    for (destination, 0..) |*value, chunk| {
        const first_bit = chunk * state_chunk_bits;
        const bits = @min(state_chunk_bits, authority.width_bits - first_bit);
        var packed_value: u32 = 0;
        for (0..bits) |offset| {
            const absolute = first_bit + offset;
            const lane = absolute / authority.lane_bits;
            const z = absolute % authority.lane_bits;
            packed_value |= @as(u32, authority.bit(
                state,
                lane % 5,
                lane / 5,
                z,
            )) << @intCast(offset);
        }
        value.* = M31.fromCanonical(packed_value);
    }
}

pub fn chiTuple(table_row: u32) authority.Error!ChiTuple {
    const entry = try authority.compactChiTableEntry(table_row);
    return .{
        M31.fromCanonical(entry.theta[0]),
        M31.fromCanonical(entry.theta[1]),
        M31.fromCanonical(entry.theta[2]),
        M31.fromCanonical(entry.iota),
        M31.fromCanonical(entry.output),
        M31.zero(),
    };
}

pub fn xor5Tuple(table_row: u32) authority.Error!Xor5Tuple {
    const entry = try authority.compactXor5TableEntry(table_row);
    var tuple: Xor5Tuple = undefined;
    for (entry.input, tuple[0..5]) |value, *destination|
        destination.* = M31.fromCanonical(value);
    tuple[5] = M31.fromCanonical(entry.output);
    return tuple;
}

comptime {
    if (relation_count != 15 or state_chunk_count != 54 or
        final_state_chunk_bits != 10 or io_fields.len != io_arity or
        table_fields.len != chi_arity or chi_arity != xor5_arity)
    {
        @compileError("Keccak-f relation geometry drifted");
    }
}
