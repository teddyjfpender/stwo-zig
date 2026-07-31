//! Validated borrowed cartridge input and RTC-free MBC3 semantics.

const std = @import("std");

pub const header = @import("header.zig");
pub const mbc3 = @import("mbc3.zig");

pub const Header = header.Header;
pub const State = mbc3.State;
pub const ReadTarget = mbc3.ReadTarget;
pub const WriteTarget = mbc3.WriteTarget;

pub const Cartridge = struct {
    bytes: []const u8,
    header: Header,

    pub fn init(bytes: []const u8) header.ValidationError!Cartridge {
        return .{
            .bytes = bytes,
            .header = try Header.parse(bytes),
        };
    }

    pub fn digest(self: Cartridge) [32]u8 {
        var output: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.bytes, &output, .{});
        return output;
    }

    pub fn readPhysical(self: Cartridge, offset: mbc3.RomOffset) u8 {
        return self.bytes[offset];
    }
};

test "cartridge facade validates borrows hashes and reads physical ROM" {
    var bytes = [_]u8{0} ** header.ROM_SIZE;
    bytes[header.CARTRIDGE_TYPE_OFFSET] =
        header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
    bytes[header.ROM_SIZE_CODE_OFFSET] = header.ROM_SIZE_CODE_1_MIB;
    bytes[header.RAM_SIZE_CODE_OFFSET] = header.RAM_SIZE_CODE_32_KIB;
    bytes[header.HEADER_CHECKSUM_OFFSET] = header.headerChecksum(&bytes);
    const global_checksum = header.globalChecksum(&bytes);
    std.mem.writeInt(
        u16,
        bytes[header.GLOBAL_CHECKSUM_OFFSET..header.HEADER_END][0..2],
        global_checksum,
        .big,
    );

    const cartridge = try Cartridge.init(&bytes);
    try std.testing.expectEqual(
        header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY,
        cartridge.header.cartridge_type,
    );
    try std.testing.expectEqual(@as(u8, 0), cartridge.readPhysical(0xfffff));
    try std.testing.expect(!std.mem.allEqual(u8, &cartridge.digest(), 0));
}

test {
    _ = header;
    _ = mbc3;
}
