const std = @import("std");
const circle = @import("../../circle.zig");
const domain = @import("domain.zig");

const CirclePointM31 = circle.CirclePointM31;
const CirclePointIndex = circle.CirclePointIndex;
const Coset = circle.Coset;

pub const CanonicCoset = struct {
    coset_value: Coset,

    pub fn new(log_size: u32) CanonicCoset {
        std.debug.assert(log_size > 0);
        return .{ .coset_value = Coset.odds(log_size) };
    }

    pub inline fn coset(self: CanonicCoset) Coset {
        return self.coset_value;
    }

    pub fn halfCoset(self: CanonicCoset) Coset {
        return Coset.halfOdds(self.logSize() - 1);
    }

    pub fn circleDomain(self: CanonicCoset) domain.CircleDomain {
        return domain.CircleDomain.new(self.halfCoset());
    }

    pub inline fn logSize(self: CanonicCoset) u32 {
        return self.coset_value.log_size;
    }

    pub inline fn size(self: CanonicCoset) usize {
        return self.coset_value.size();
    }

    pub inline fn initialIndex(self: CanonicCoset) CirclePointIndex {
        return self.coset_value.initial_index;
    }

    pub inline fn stepSize(self: CanonicCoset) CirclePointIndex {
        return self.coset_value.step_size;
    }

    pub inline fn step(self: CanonicCoset) CirclePointM31 {
        return self.coset_value.step;
    }

    pub fn indexAt(self: CanonicCoset, index: usize) CirclePointIndex {
        return self.coset_value.indexAt(index);
    }

    pub fn at(self: CanonicCoset, index: usize) CirclePointM31 {
        return self.coset_value.at(index);
    }
};
