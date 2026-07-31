//! Sharp SM83 ISA boundary.

pub const authority = @import("authority.zig");
pub const decoder = @import("decode.zig");

pub const Condition = decoder.Condition;
pub const DecodeError = decoder.DecodeError;
pub const DecodedOpcode = decoder.DecodedOpcode;
pub const Family = decoder.Family;
pub const Instruction = decoder.Instruction;
pub const Operand = decoder.Operand;
pub const Operation = decoder.Operation;
pub const base_table = decoder.base_table;
pub const cb_table = decoder.cb_table;
pub const decode = decoder.decode;

test {
    _ = authority;
    _ = decoder;
}
