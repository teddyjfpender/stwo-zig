//! Commit-path fusion control plane (Workstream D).
//!
//! The commit path (final NTT stage → leaf pack → blake2s Merkle) is the second
//! largest phase of a real Cairo prove (round-8 SN_PIE_2: commits 10.4 s / 29 %).
//! This module is the *switch fabric* for the three fusion lanes that attack it:
//!
//! 1. **`NttHash`** — fuse the final NTT stage output directly into blake2s leaf hashing, skipping
//!    the separate pack pass and one full LDE read/write round trip (`rfft.cu` + `blake2s.cu`).
//! 2. **`LayerPair`** — hash two Merkle tree levels per kernel launch (`blake2s.cu`
//!    `commit_on_two_layers_using_previous`).
//! 3. **`TwiddleRegen`** — regenerate M31 twiddles in-kernel (trade shift-add compute for
//!    twiddle-load bandwidth), keeping the twiddle-cache path as the fallback.
//!
//! # Soundness / correctness contract
//!
//! Commit ORDER is Fiat-Shamir-fixed. These lanes change *execution fusion only* —
//! never the hash function, never the commit order, never the bytes of any Merkle
//! root. Each lane is byte-identical-to-the-reference **by construction** (it
//! computes exactly the same values, just with fewer global-memory round trips /
//! fewer launches). The correctness gates are the conformance testkit, the
//! CUDA-vs-SIMD commitment-prefix hash, and the Cairo e2e proof (see
//! `gpu_benchmarks/KNOWN_ISSUES.md` §4 for why the *prefix* hash — not full proof
//! byte-equality — is the PIE-lane gate today).
//!
//! # Kill switch / bisection contract
//!
//! - `STWO_CUDA_FUSED_COMMIT` is the master kill switch. **Default OFF** — with it unset (or `0`)
//!   every lane below is disabled and the commit path is byte-identical to today's code, because
//!   the fused code paths are simply not taken. It stays OFF until the pod gates pass, per the
//!   session contract.
//! - When the master is ON, each lane defaults ON but is **independently toggleable** to OFF via
//!   its own variable, so the integration agent can bisect a regression to a single lane
//!   (`STWO_CUDA_FUSED_COMMIT_NTT_HASH`, `STWO_CUDA_FUSED_COMMIT_LAYER_PAIR`,
//!   `STWO_CUDA_FUSED_COMMIT_TWIDDLE_REGEN`). Setting any of these to `0` disables only that lane;
//!   the master `=0` disables all of them regardless of the per-lane values (a hard global kill).

/// The three independently-toggleable commit-path fusion lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FusionLane {
    /// Fuse the final NTT stage output into blake2s leaf hashing.
    NttHash,
    /// Hash two Merkle tree levels per kernel launch.
    LayerPair,
    /// Regenerate M31 twiddles in-kernel instead of loading the cached table.
    TwiddleRegen,
}

impl FusionLane {
    /// The per-lane environment variable name.
    const fn env_var(self) -> &'static str {
        match self {
            FusionLane::NttHash => "STWO_CUDA_FUSED_COMMIT_NTT_HASH",
            FusionLane::LayerPair => "STWO_CUDA_FUSED_COMMIT_LAYER_PAIR",
            FusionLane::TwiddleRegen => "STWO_CUDA_FUSED_COMMIT_TWIDDLE_REGEN",
        }
    }
}

/// The master kill-switch environment variable name.
const MASTER_ENV_VAR: &str = "STWO_CUDA_FUSED_COMMIT";

/// Interpret a boolean environment value with an explicit `default` for the
/// unset case. Falsy tokens (`0`, empty, `false`, `off`, `no`, case-insensitive,
/// surrounding whitespace ignored) are `false`; everything else is `true`.
///
/// Pure so the semantics can be unit-tested without mutating process-global env
/// (the same discipline as `jit::parse_max_kernel_instrs`).
fn interpret_bool(raw: Option<&str>, default: bool) -> bool {
    match raw {
        None => default,
        Some(value) => {
            let v = value.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
    }
}

/// Whether the master commit-fusion switch is on. Default OFF.
fn master_enabled_from(raw: Option<&str>) -> bool {
    interpret_bool(raw, false)
}

/// Pure lane-resolution used by both the live check and the unit tests.
///
/// A lane is enabled iff the master is on AND the lane is not explicitly disabled.
/// When the master is on, a lane defaults ON (so flipping the single master switch
/// enables the whole fused commit path); an explicit `0` on the lane var carves it
/// back out for bisection. Master OFF forces every lane off regardless.
fn lane_enabled_from(master_raw: Option<&str>, lane_raw: Option<&str>) -> bool {
    master_enabled_from(master_raw) && interpret_bool(lane_raw, true)
}

/// Live check: is the master commit-fusion switch on?
pub(crate) fn master_enabled() -> bool {
    master_enabled_from(std::env::var(MASTER_ENV_VAR).ok().as_deref())
}

/// Live check: is `lane` enabled for this process? Reads the master switch and the
/// lane's own variable. Cheap enough to call per commit phase (a handful of times
/// per prove); not on any per-row hot path.
pub(crate) fn lane_enabled(lane: FusionLane) -> bool {
    lane_enabled_from(
        std::env::var(MASTER_ENV_VAR).ok().as_deref(),
        std::env::var(lane.env_var()).ok().as_deref(),
    )
}

/// All three lanes, for iteration/reporting.
const ALL_LANES: [FusionLane; 3] = [
    FusionLane::NttHash,
    FusionLane::LayerPair,
    FusionLane::TwiddleRegen,
];

/// Emit, exactly once per process, the resolved commit-fusion configuration to
/// stderr — so an operator (or the integration agent bisecting a regression) can
/// confirm from the pod log which lanes actually took effect for a given
/// `STWO_CUDA_FUSED_COMMIT*` environment. No-op and silent when the master switch
/// is off (the default), so a normal prove prints nothing.
pub(crate) fn log_selected_lanes_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if !master_enabled() {
            return;
        }
        let active: Vec<&'static str> = ALL_LANES
            .into_iter()
            .filter(|&lane| lane_enabled(lane))
            .map(FusionLane::env_var)
            .collect();
        eprintln!(
            "stwo commit-fusion: {MASTER_ENV_VAR}=on; active lanes: [{}]",
            active.join(", ")
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpret_bool_unset_uses_default() {
        assert!(!interpret_bool(None, false));
        assert!(interpret_bool(None, true));
    }

    #[test]
    fn interpret_bool_falsy_tokens() {
        for token in ["0", "", "false", "off", "no", " 0 ", "OFF", "False", "No"] {
            assert!(
                !interpret_bool(Some(token), true),
                "token {token:?} should be falsy"
            );
        }
    }

    #[test]
    fn interpret_bool_truthy_tokens() {
        for token in ["1", "true", "on", "yes", "enabled", " 1 ", "TRUE"] {
            assert!(
                interpret_bool(Some(token), false),
                "token {token:?} should be truthy"
            );
        }
    }

    #[test]
    fn master_defaults_off() {
        assert!(!master_enabled_from(None));
        assert!(!master_enabled_from(Some("0")));
        assert!(master_enabled_from(Some("1")));
    }

    #[test]
    fn master_off_forces_every_lane_off() {
        // Even with a lane explicitly enabled, master=off (unset or 0) kills it.
        assert!(!lane_enabled_from(None, Some("1")));
        assert!(!lane_enabled_from(Some("0"), Some("1")));
        assert!(!lane_enabled_from(Some("0"), None));
    }

    #[test]
    fn master_on_enables_lanes_by_default() {
        // Flipping the single master switch turns on the whole fused commit path.
        assert!(lane_enabled_from(Some("1"), None));
    }

    #[test]
    fn lane_independently_disableable_when_master_on() {
        // The integration agent bisects: master on, one lane carved out.
        assert!(!lane_enabled_from(Some("1"), Some("0")));
        assert!(!lane_enabled_from(Some("1"), Some("off")));
        // Other lanes (lane_raw = None) stay on.
        assert!(lane_enabled_from(Some("1"), None));
    }

    #[test]
    fn lane_env_var_names_are_distinct_and_prefixed() {
        let names = [
            FusionLane::NttHash.env_var(),
            FusionLane::LayerPair.env_var(),
            FusionLane::TwiddleRegen.env_var(),
        ];
        for name in names {
            assert!(name.starts_with(MASTER_ENV_VAR));
            // Each lane var is a strict extension of the master var (shared prefix
            // kill: grepping the master name finds all lanes).
            assert_ne!(name, MASTER_ENV_VAR);
        }
        // Distinct.
        assert_ne!(names[0], names[1]);
        assert_ne!(names[1], names[2]);
        assert_ne!(names[0], names[2]);
    }
}
