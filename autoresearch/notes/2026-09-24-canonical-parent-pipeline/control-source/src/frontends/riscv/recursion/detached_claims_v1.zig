//! Shared detached claim encoding and interaction-work transcript step.
//! Null preserves legacy bytes; a present zero nonce is never absence.
pub fn jsonStringify(self: anytype, writer: anytype) !void {
    try writer.beginObject();
    try writer.objectField("values");
    try writer.write(self.values);
    try writer.objectField("poseidon_partials");
    try writer.write(self.poseidon_partials);
    if (self.interaction_pow) |nonce| {
        try writer.objectField("interaction_pow");
        try writer.write(nonce);
    }
    try writer.endObject();
}

pub fn mixInteractionPow(channel: anytype, key: anytype, nonce: ?u64) !void {
    const bits = key.profile.interactionPowBits();
    if (bits == 0) {
        if (nonce != null) return error.UnexpectedDetachedInteractionPow;
        return;
    }
    const value = nonce orelse return error.MissingDetachedInteractionPow;
    if (!channel.verifyPowNonce(bits, value)) return error.InvalidDetachedInteractionPow;
    channel.mixU64(value);
}
