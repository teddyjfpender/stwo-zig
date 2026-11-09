//! Focused gate for the memory-hash prepared-domain evaluator.
//!
//! This keeps cross-host stack/resource certification out of the complete
//! frontend package's multi-thousand-test edit loop.

test {
    _ = @import("air/memory_commitment/hash_component_prepared_test.zig");
}
