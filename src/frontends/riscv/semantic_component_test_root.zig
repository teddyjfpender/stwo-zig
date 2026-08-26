//! Focused gate for the production semantic component and its prepared-domain
//! evaluator.  This root keeps stack/resource debugging out of the complete
//! frontend package's multi-gigabyte edit loop.

test {
    _ = @import("air/semantic_component_test.zig");
}
