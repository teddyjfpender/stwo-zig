//! Typed V2-only authority components for one resumed segment leaf.
//!
//! This file deliberately does not reuse frozen universal roster row 10.
//! The V2 statement wire is variable length and its public LogUp publication
//! contains 55 words, so both sources have versioned, independently sealed
//! typed programs.  The outer authority driver owns trace geometry and uses
//! these programs only after authenticating `segment_leaf_authority_v2`.
const shard_0 = @import("segment_leaf_outer_air_v2_contract.zig");
const shard_1 = @import("segment_leaf_outer_air_v2_public_log_up.zig");
const shard_2 = @import("segment_leaf_outer_air_v2_statement_semantics_v2.zig");
const shard_3 = @import("segment_leaf_outer_air_v2_support.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const Statement = shard_0.Statement;
pub const PublicLogUp = shard_1.PublicLogUp;
/// Versioned row-11 consumer for a resumed-segment statement.
///
/// The appended V2 boundary `Statement` source owns the statement-word
/// emission that frozen row 10 used to perform, so this component consumes it
/// directly and never re-emits the same tuple. In the same row it consumes
/// every ProgramV2 statement payload:
///
/// * item 0: the eight verifier-owned statement-header limbs;
/// * item 1: the sixteen limbs of the eight-word wire identity;
/// * item 2: every canonical wire word.
///
/// The wire-identity limbs are range checked and recombined against the exact
/// `CONTEXT_SCOPE` digest words. Structurally encoded u16 wire words are also
/// range checked. Full wire-hash and statement-authority sponge closure are a
/// separate, explicitly fail-closed capability of the outer driver.
pub const StatementSemanticsV2 = shard_2.StatementSemanticsV2;
