//! Explicit native-only derivation diagnostics. Never compiled into the guest.
extern crate std;
use alloc::vec::Vec;
use core::cell::RefCell;
use std::time::Instant;

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Phase {
    InputDecode,
    WitnessParse,
    Derivation,
    PreimageHash,
    BlobBatch,
    BlobEvaluation,
    FrDecode,
    FrFold,
    FrSparse,
    G1Decode,
    G1Msm,
    KzgFinalProof,
    Evm,
}
const N: usize = 13;
const NAMES: [&str; N] = [
    "input_decode",
    "witness_parse",
    "derivation",
    "preimage_hash",
    "blob_batch",
    "blob_evaluation",
    "fr_decode",
    "fr_fold",
    "fr_sparse",
    "g1_decode",
    "g1_msm",
    "kzg_final_proof",
    "evm_and_output_root",
];
#[derive(Default, serde::Serialize)]
pub struct Counts {
    pub preimage_hashes: u64,
    pub preimage_bytes: u64,
    pub preimage_keccak_permutations: u64,
    pub blobs: u64,
    pub blob_scalars: u64,
    pub dense_blobs: u64,
    pub sparse_blobs: u64,
    pub dense_fold_multiplications: u64,
    pub dense_fold_squares: u64,
    pub sparse_multiplications: u64,
    pub sparse_inversions: u64,
}
#[derive(Default, Clone, Copy)]
struct Time {
    calls: u64,
    inclusive: u64,
    exclusive: u64,
}
struct Frame {
    phase: usize,
    start: Instant,
    children: u64,
}
struct State {
    times: [Time; N],
    stack: Vec<Frame>,
    counts: Counts,
}
std::thread_local! {static STATE:RefCell<Option<State>>=const{RefCell::new(None)};}
#[derive(serde::Serialize)]
pub struct Row {
    phase: &'static str,
    calls: u64,
    inclusive_ns: u64,
    exclusive_ns: u64,
}
#[derive(serde::Serialize)]
pub struct FieldOps {
    pub limbs: usize,
    pub modulus_hex: alloc::string::String,
    pub multiply: u64,
    pub square: u64,
    pub canonical_decode: u64,
    pub inverse_requests: u64,
    pub modeled_montgomery_packets: u64,
}
#[derive(serde::Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub native_only: bool,
    pub elapsed_ns: u64,
    pub rows: Vec<Row>,
    pub counts: Counts,
    pub field_ops: Vec<FieldOps>,
}
pub struct Scope(bool);
impl Scope {
    pub fn enter(phase: Phase) -> Self {
        Self(STATE.with_borrow_mut(|state| {
            let Some(s) = state else { return false };
            s.stack.push(Frame {
                phase: phase as usize,
                start: Instant::now(),
                children: 0,
            });
            true
        }))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if !self.0 {
            return;
        }
        STATE.with_borrow_mut(|state| {
            let s = state.as_mut().expect("census scope outside recorder");
            let frame = s.stack.pop().expect("census stack");
            let ns = frame.start.elapsed().as_nanos() as u64;
            let t = &mut s.times[frame.phase];
            t.calls += 1;
            t.inclusive += ns;
            t.exclusive += ns.saturating_sub(frame.children);
            if let Some(parent) = s.stack.last_mut() {
                parent.children += ns;
            }
        });
    }
}
pub fn note(update: impl FnOnce(&mut Counts)) {
    STATE.with_borrow_mut(|state| {
        if let Some(s) = state {
            update(&mut s.counts)
        }
    })
}
pub fn record<T>(f: impl FnOnce() -> T) -> (T, Report) {
    use ark_ff::MontConfig;
    assert!(
        !ark_bls12_381::FrConfig::CANONICAL_REPRESENTATION,
        "Montgomery branch census requires control representation"
    );
    STATE.with_borrow_mut(|s| {
        assert!(s.is_none(), "nested native census");
        *s = Some(State {
            times: [Time::default(); N],
            stack: Vec::new(),
            counts: Counts::default(),
        })
    });
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            STATE.with_borrow_mut(|s| {
                s.take();
            });
            let _ = ark_ff::operation_census::finish();
        }
    }
    ark_ff::operation_census::begin();
    let guard = Guard;
    let start = Instant::now();
    let value = f();
    let elapsed_ns = start.elapsed().as_nanos() as u64;
    let state = STATE.with_borrow_mut(|s| s.take().unwrap());
    assert!(state.stack.is_empty());
    let field_ops = ark_ff::operation_census::finish()
        .into_iter()
        .map(|r| {
            use core::fmt::Write;
            let mut modulus_hex = alloc::string::String::new();
            for limb in r.modulus[..r.limbs].iter().rev() {
                write!(&mut modulus_hex, "{limb:016x}").unwrap();
            }
            FieldOps {
                limbs: r.limbs,
                modulus_hex,
                multiply: r.counts.mul,
                square: r.counts.square,
                canonical_decode: r.counts.decode,
                inverse_requests: r.counts.inverse,
                modeled_montgomery_packets: r.counts.mul + r.counts.square + r.counts.decode,
            }
        })
        .collect();
    drop(guard);
    let rows = state
        .times
        .iter()
        .enumerate()
        .map(|(i, t)| Row {
            phase: NAMES[i],
            calls: t.calls,
            inclusive_ns: t.inclusive,
            exclusive_ns: t.exclusive,
        })
        .collect();
    (
        value,
        Report {
            schema: "op-native-derivation-phase-census-v1",
            native_only: true,
            elapsed_ns,
            rows,
            counts: state.counts,
            field_ops,
        },
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nesting_and_disabled_scopes() {
        let _disabled = Scope::enter(Phase::Derivation);
        let (value, r) = record(|| {
            let _a = Scope::enter(Phase::Derivation);
            {
                let _b = Scope::enter(Phase::PreimageHash);
                note(|c| c.preimage_hashes += 1);
            }
            7
        });
        assert_eq!(value, 7);
        assert_eq!(r.counts.preimage_hashes, 1);
        assert_eq!(r.rows[Phase::Derivation as usize].calls, 1);
        assert!(
            r.rows[Phase::Derivation as usize].inclusive_ns
                >= r.rows[Phase::PreimageHash as usize].inclusive_ns
        );
    }
    #[test]
    fn conversion_is_one_packet_and_identity_products_are_skipped() {
        use ark_bls12_381::Fr;
        use ark_ec::AdditiveGroup;
        use ark_ff::{BigInt, Field, PrimeField};
        let (_, r) = record(|| {
            let a = Fr::from_bigint(BigInt([2, 0, 0, 0])).unwrap();
            let b = Fr::from_bigint(BigInt([3, 0, 0, 0])).unwrap();
            let c = a * b;
            let d = c.square();
            assert_eq!(d.into_bigint().0, [36, 0, 0, 0]);
            let _ = a * Fr::ONE;
            let _ = a * Fr::ZERO;
        });
        let row = r.field_ops.iter().find(|r| r.limbs == 4).unwrap();
        assert_eq!(row.canonical_decode, 2);
        assert_eq!(row.multiply, 1);
        assert_eq!(row.square, 1);
        assert_eq!(row.modeled_montgomery_packets, 4);
    }
}
