//! Receiver-owned native suite choice. No value is hydrated from a proof/bundle.
//! Production remains q70/P26/fold1; fold4 is a separate explicit experiment.
const std = @import("std");
const core = @import("stwo_core");
const Legacy = @import("stwo_riscv_frontend").rv64_air.protocol;
pub const Suite = struct {
    pcs: core.pcs.PcsConfig,
    pub fn production() Suite {
        return .{ .pcs = Legacy.config() };
    }
    pub fn experimentalFold4() Suite {
        var value = production();
        value.pcs.fri_config.fold_step = 4;
        return value;
    }
    pub fn validate(self: Suite) !void {
        if (!self.eql(production()) and !self.eql(experimentalFold4())) return error.UnsupportedWord16PcsSuite;
    }
    pub fn requireProduction(self: Suite) !void {
        try self.validate();
        if (!self.eql(production())) return error.UnsupportedHistoricalPcsSuite;
    }
    pub fn eql(self: Suite, other: Suite) bool {
        return std.meta.eql(self.pcs, other.pcs);
    }
    pub fn config(self: Suite) core.pcs.PcsConfig {
        return self.pcs;
    }
    pub fn identity(self: Suite) ![32]u8 {
        try self.validate();
        var channel = Legacy.Channel{};
        channel.mixU32s(&.{ 0x57313653, 1 });
        self.pcs.mixInto(&channel);
        return channel.digestBytes();
    }
};
