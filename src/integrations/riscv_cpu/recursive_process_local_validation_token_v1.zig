//! Nonserializable validation token and counters for cold verifier owners.
//!
//! The token is meaningful only while the exact process-local allocations in
//! its snapshot remain alive. It cannot replace a cold verifier on restart,
//! cannot be encoded, and grants no authority from a digest alone.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;

const token_domain =
    "stwo-zig/recursive-process-local-validation-token/v1\x00";

pub const Error = error{InvalidProcessLocalValidationToken};

pub const SnapshotV1 = struct {
    authority_kind_sha256: [32]u8,
    source_content_sha256: [32]u8,
    session_identity_sha256: [32]u8,
    retained_statement_identity_sha256: [32]u8,
    fresh_statement_identity_sha256: [32]u8,
    capture_identity_sha256: [32]u8,
    claims_identity_sha256: [32]u8,
    query_identity_sha256: [32]u8,
    geometry_identity_sha256: [32]u8,
    node_public_identity_sha256: [32]u8,
    graph_capture_identity_sha256: [32]u8,
    graph_layout_identity_sha256: [32]u8,
    graph_circuit_identity_sha256: [32]u8,
    owner_anchor_ptr: usize,
    proof_ptr: usize,
    proof_len: usize,
    commitment_ptr: usize,
    commitment_len: usize,
    query_ptr: usize,
    query_len: usize,
    graph_node_ptr: usize,
    graph_node_len: usize,
    graph_binding_ptr: usize,
    graph_binding_len: usize,
    graph_input_ptr: usize,
    graph_input_len: usize,
    graph_output_ptr: usize,
    graph_output_len: usize,

    pub fn validate(self: SnapshotV1) Error!void {
        inline for (.{
            self.authority_kind_sha256,
            self.source_content_sha256,
            self.session_identity_sha256,
            self.retained_statement_identity_sha256,
            self.fresh_statement_identity_sha256,
            self.capture_identity_sha256,
            self.claims_identity_sha256,
            self.query_identity_sha256,
            self.geometry_identity_sha256,
            self.node_public_identity_sha256,
            self.graph_capture_identity_sha256,
            self.graph_layout_identity_sha256,
            self.graph_circuit_identity_sha256,
        }) |identity| if (std.mem.allEqual(u8, &identity, 0))
            return error.InvalidProcessLocalValidationToken;
        inline for (.{
            self.owner_anchor_ptr,
            self.proof_ptr,
            self.proof_len,
            self.commitment_ptr,
            self.commitment_len,
            self.query_ptr,
            self.query_len,
            self.graph_node_ptr,
            self.graph_node_len,
            self.graph_binding_ptr,
            self.graph_binding_len,
            self.graph_input_ptr,
            self.graph_input_len,
            self.graph_output_ptr,
            self.graph_output_len,
        }) |value| if (value == 0)
            return error.InvalidProcessLocalValidationToken;
    }
};

pub const TokenV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    snapshot: SnapshotV1,
    seal_sha256: [32]u8,

    pub fn init(snapshot: SnapshotV1) Error!TokenV1 {
        try snapshot.validate();
        const result = TokenV1{
            .snapshot = snapshot,
            .seal_sha256 = snapshotIdentity(snapshot),
        };
        try result.validateAgainst(snapshot);
        return result;
    }

    pub fn validateAgainst(
        self: *const TokenV1,
        snapshot: SnapshotV1,
    ) Error!void {
        try snapshot.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.meta.eql(self.snapshot, snapshot) or
            !std.mem.eql(
                u8,
                &self.seal_sha256,
                &snapshotIdentity(snapshot),
            )) return error.InvalidProcessLocalValidationToken;
    }
};

pub const CounterSnapshotV1 = struct {
    q193_cold_verifications: u64,
    transcript_replays: u64,
    graph_records: u64,
    full_audits: u64,
    token_checks: u64,
    graph_view_borrows: u64,
    q193_cold_verification_ns: u64,
    transcript_replay_ns: u64,
    graph_record_ns: u64,
    full_audit_ns: u64,
    token_check_ns: u64,
    graph_view_borrow_ns: u64,
};

pub const PhaseV1 = enum {
    q193_cold_verification,
    transcript_replay,
    graph_record,
    full_audit,
    token_check,
    graph_view_borrow,
};

pub const CountersV1 = struct {
    q193_cold_verifications: std.atomic.Value(u64) = .init(0),
    transcript_replays: std.atomic.Value(u64) = .init(0),
    graph_records: std.atomic.Value(u64) = .init(0),
    full_audits: std.atomic.Value(u64) = .init(0),
    token_checks: std.atomic.Value(u64) = .init(0),
    graph_view_borrows: std.atomic.Value(u64) = .init(0),
    q193_cold_verification_ns: std.atomic.Value(u64) = .init(0),
    transcript_replay_ns: std.atomic.Value(u64) = .init(0),
    graph_record_ns: std.atomic.Value(u64) = .init(0),
    full_audit_ns: std.atomic.Value(u64) = .init(0),
    token_check_ns: std.atomic.Value(u64) = .init(0),
    graph_view_borrow_ns: std.atomic.Value(u64) = .init(0),

    pub fn record(
        self: *const CountersV1,
        phase: PhaseV1,
    ) void {
        const mutable = @constCast(self);
        const counter = switch (phase) {
            .q193_cold_verification => &mutable.q193_cold_verifications,
            .transcript_replay => &mutable.transcript_replays,
            .graph_record => &mutable.graph_records,
            .full_audit => &mutable.full_audits,
            .token_check => &mutable.token_checks,
            .graph_view_borrow => &mutable.graph_view_borrows,
        };
        _ = counter.fetchAdd(1, .monotonic);
    }

    /// Records one phase and its process-local wall duration. Timings are
    /// diagnostics only; no admission or verifier decision consumes them.
    pub fn recordTimed(
        self: *const CountersV1,
        phase: PhaseV1,
        elapsed_ns: u64,
    ) void {
        self.record(phase);
        const mutable = @constCast(self);
        const counter = switch (phase) {
            .q193_cold_verification => &mutable.q193_cold_verification_ns,
            .transcript_replay => &mutable.transcript_replay_ns,
            .graph_record => &mutable.graph_record_ns,
            .full_audit => &mutable.full_audit_ns,
            .token_check => &mutable.token_check_ns,
            .graph_view_borrow => &mutable.graph_view_borrow_ns,
        };
        _ = counter.fetchAdd(elapsed_ns, .monotonic);
    }

    pub fn snapshot(self: *const CountersV1) CounterSnapshotV1 {
        return .{
            .q193_cold_verifications = self.q193_cold_verifications.load(.acquire),
            .transcript_replays = self.transcript_replays.load(.acquire),
            .graph_records = self.graph_records.load(.acquire),
            .full_audits = self.full_audits.load(.acquire),
            .token_checks = self.token_checks.load(.acquire),
            .graph_view_borrows = self.graph_view_borrows.load(.acquire),
            .q193_cold_verification_ns = self.q193_cold_verification_ns.load(.acquire),
            .transcript_replay_ns = self.transcript_replay_ns.load(.acquire),
            .graph_record_ns = self.graph_record_ns.load(.acquire),
            .full_audit_ns = self.full_audit_ns.load(.acquire),
            .token_check_ns = self.token_check_ns.load(.acquire),
            .graph_view_borrow_ns = self.graph_view_borrow_ns.load(.acquire),
        };
    }
};

/// Heap-stable process-local anchor owned by one cold verifier result. The
/// pointer to this value is sealed into `TokenV1`, so moving an outer Zig
/// struct cannot accidentally retarget a verifier capability. This type has
/// deliberately no codec and must be destroyed with its cold owner.
pub const ValidatedOwnerV1 = struct {
    token: TokenV1,
    counters: CountersV1 = .{},

    pub fn init(snapshot: SnapshotV1) Error!ValidatedOwnerV1 {
        return .{ .token = try TokenV1.init(snapshot) };
    }
};

fn snapshotIdentity(value: SnapshotV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(token_domain);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    inline for (std.meta.fields(SnapshotV1)) |field| {
        const item = @field(value, field.name);
        if (comptime field.type == [32]u8)
            hash.update(&item)
        else
            hashInt(&hash, field.type, item);
    }
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        @hasDecl(TokenV1, "encode") or @hasDecl(TokenV1, "decode") or
        @hasDecl(ValidatedOwnerV1, "encode") or
        @hasDecl(ValidatedOwnerV1, "decode"))
    {
        @compileError("process-local validation token contract drifted");
    }
}
