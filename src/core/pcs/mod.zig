const fri = @import("../fri.zig");
const qm31 = @import("../fields/qm31.zig");
pub const utils = @import("utils.zig");
pub const quotients = @import("quotients.zig");

const FriConfig = fri.FriConfig;
const QM31 = qm31.QM31;
pub const TreeVec = utils.TreeVec;

pub const TreeSubspan = struct {
    tree_index: usize,
    col_start: usize,
    col_end: usize,
};

pub const PcsConfig = struct {
    pow_bits: u32,
    fri_config: FriConfig,

    pub inline fn securityBits(self: PcsConfig) u32 {
        return self.pow_bits + self.fri_config.securityBits();
    }

    pub fn mixInto(self: PcsConfig, channel: anytype) void {
        const packed_config = QM31.fromU32Unchecked(
            self.pow_bits,
            self.fri_config.log_blowup_factor,
            @as(u32, @intCast(self.fri_config.n_queries)),
            self.fri_config.log_last_layer_degree_bound,
        );
        channel.mixFelts(&[_]QM31{packed_config});
    }

    pub fn default() PcsConfig {
        return .{
            .pow_bits = 10,
            .fri_config = FriConfig.default(),
        };
    }
};

test "pcs config: security bits" {
    const cfg = PcsConfig{
        .pow_bits = 42,
        .fri_config = FriConfig.init(10, 10, 70) catch unreachable,
    };
    try @import("std").testing.expectEqual(@as(u32, 742), cfg.securityBits());
}
