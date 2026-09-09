//! Semantic payload roles emitted by the supported detached verifier protocols.
//! Planning channels observe these roles; ordinary channels emit identical bytes.
pub const Source = enum {
    admission_header,
    key_identity,
    expected,
    claims_header,
    claims,
    boundary_header,
    boundary,
    partials,
    expected_u32,
};

pub fn begin(channel: anytype, source: Source) void {
    if (@hasDecl(@TypeOf(channel.*), "beginDetachedPayload")) channel.beginDetachedPayload(source);
}
