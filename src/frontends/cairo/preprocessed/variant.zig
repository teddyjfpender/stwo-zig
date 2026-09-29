//! Protocol metadata for the pinned public fixed-column variants.
pub const Variant = enum {
    canonical,
    canonical_without_pedersen,
    canonical_small,

    pub fn columnCount(self: Variant) usize {
        return switch (self) {
            .canonical => 161,
            .canonical_without_pedersen => 105,
            .canonical_small => 156,
        };
    }

    pub fn traceCellCount(self: Variant) u64 {
        return switch (self) {
            .canonical => 543_100_528,
            .canonical_without_pedersen => 73_338_480,
            .canonical_small => 10_161_776,
        };
    }

    pub fn maxLogSize(self: Variant) u32 {
        return switch (self) {
            .canonical, .canonical_without_pedersen => 25,
            .canonical_small => 20,
        };
    }
};
