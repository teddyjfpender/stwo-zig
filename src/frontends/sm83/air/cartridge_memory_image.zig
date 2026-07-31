//! Canonical mutable cartridge-memory image types.

const memory = @import("../memory.zig");
const cartridge = @import("../cartridge/mod.zig");

pub const SramImage = struct {
    bytes: []const u8,

    pub fn init(
        bytes: []const u8,
    ) error{InvalidSramLength}!SramImage {
        if (bytes.len != cartridge.header.RAM_SIZE)
            return error.InvalidSramLength;
        return .{ .bytes = bytes };
    }
};

pub const Images = struct {
    system: memory.Image,
    sram: SramImage,
};
