pub const CanonicCoset = @import("canonic.zig").CanonicCoset;
pub const CircleDomain = @import("domain.zig").CircleDomain;
pub const MAX_CIRCLE_DOMAIN_LOG_SIZE = @import("domain.zig").MAX_CIRCLE_DOMAIN_LOG_SIZE;
pub const MIN_CIRCLE_DOMAIN_LOG_SIZE = @import("domain.zig").MIN_CIRCLE_DOMAIN_LOG_SIZE;

test "circle poly: canonic domain is canonic" {
    const domain = CanonicCoset.new(4).circleDomain();
    try @import("std").testing.expect(domain.isCanonic());
}

test "circle poly: bit-reverse indices preserve repeated doubling relation" {
    const std = @import("std");
    const utils = @import("../../utils.zig");

    const log_domain_size: u32 = 7;
    const log_small_domain_size: u32 = 5;
    const domain = CanonicCoset.new(log_domain_size);
    const small_domain = CanonicCoset.new(log_small_domain_size);
    const n_folds = log_domain_size - log_small_domain_size;
    const n: usize = @as(usize, 1) << @intCast(log_domain_size);
    const fold_div: usize = @as(usize, 1) << @intCast(n_folds);

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const point = domain.at(utils.bitReverseIndex(i, log_domain_size));
        const small_point = small_domain.at(utils.bitReverseIndex(i / fold_div, log_small_domain_size));
        try std.testing.expect(point.repeatedDouble(n_folds).eql(small_point));
    }
}
