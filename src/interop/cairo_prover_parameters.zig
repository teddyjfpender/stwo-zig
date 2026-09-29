//! `ProverParameters`: how a Cairo run is proved (not what is proved).
//!
//! `crates/common/src/prover_params.rs` at
//! https://github.com/starkware-libs/proving 5a7c5ede4299c91a61df19a07cba4f7502c14230,
//! as carried by a circuit registry's `cairo_prover_params`.
//!
//! This file is the one definition of the type. It is injected as a
//! single-file module (like `felt_json.zig`) into both packages that need it:
//! the circuit-recursion wire package, whose `registry.zig` reads and writes
//! the serde JSON, and the Cairo frontend, whose leaf lane
//! (`proving/leaf_lane.zig`) proves under it. Neither package depends on the
//! other. Parsing lives only in `registry.zig`.

const core = @import("stwo_core");

pub const FriConfig = core.pcs.config_v2.FriConfigV2;

pub const ChannelHash = enum { blake2s, blake2s_m31, poseidon252 };

pub const PreprocessedTraceVariant = enum { canonical, canonical_without_pedersen, canonical_small };

/// serde: `"auto"`, `"at_least_preprocessed"` or `{"fixed": n}`.
pub const LiftingSizePolicy = union(enum) {
    /// Trace trees at the trace domain, the preprocessed tree at its own.
    auto,
    /// Every tree at the given height (which includes the blowup).
    fixed: u32,
    /// Every tree at `max(trace domain, preprocessed domain)`.
    at_least_preprocessed,
};

/// `stwo_cairo_common::prover_params::ProverParameters`.
pub const ProverParameters = struct {
    channel_hash: ChannelHash,
    channel_salt: u32,
    fri_config: FriConfig,
    preprocessed_trace: PreprocessedTraceVariant,
    store_polynomials_coefficients: bool,
    include_all_preprocessed_columns: bool,
    /// `Option<usize>` upstream.
    opt_n_id_to_big_components: ?u64,
    lifting_size_policy: LiftingSizePolicy,
};
