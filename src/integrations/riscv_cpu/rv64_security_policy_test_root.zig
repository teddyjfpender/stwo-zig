//! Additive claim-accounting suite. It does not alter native acceptance.
test {
    _ = @import("word16_execution/security_policy_test.zig");
    _ = @import("word16_execution/security_authority_test.zig");
}
