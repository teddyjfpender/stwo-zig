//! Supported Merkle domain encodings shared by commitment operations.

const std = @import("std");

const plain_domain_prefix_bytes: u32 = 0;
const prefixed_domain_prefix_bytes: u32 = 64;

pub fn validDomainPrefixBytes(value: u32) bool {
    return value == plain_domain_prefix_bytes or value == prefixed_domain_prefix_bytes;
}

/// Direct quotient commitments admit the actual three runtime families.
/// BLAKE3's canonical unseeded framing cannot be relabeled as a seeded mode.
pub fn validDirectCommitmentParameters(family: u32, prefix: u32, leaf: [8]u32, node: [8]u32) bool {
    if (!validDomainPrefixBytes(prefix) or family < 1 or family > 3) return false;
    if (family == 3) {
        if (prefix != 0) return false;
        for (leaf) |word| if (word != 0) return false;
        for (node) |word| if (word != 0) return false;
    }
    return true;
}

test "Metal lifted Merkle protocol mode accepts only supported encodings" {
    try std.testing.expect(validDomainPrefixBytes(plain_domain_prefix_bytes));
    try std.testing.expect(validDomainPrefixBytes(prefixed_domain_prefix_bytes));
    try std.testing.expect(!validDomainPrefixBytes(1));
    try std.testing.expect(!validDomainPrefixBytes(63));
    try std.testing.expect(!validDomainPrefixBytes(65));
}
