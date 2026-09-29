//! `air-programs`: the circuit AIR's eleven `FrameworkEval`s recorded into the `STWZEVA/1`
//! evaluation-program bundle (`circuit_air.air_programs_v1.bin`), the prover-side constraint code
//! of design §4.2.
//!
//! The recorder, lowering, parameter classification and bundle encoding are the shared sources of
//! `tools/stwo-eval-program-abi`, the same ones `tools/stwo-cairo-air-compiler` records the Cairo
//! AIR with. The components are built exactly as `CircuitComponents::new` builds them (one
//! `TraceLocationAllocator` over the preprocessed column ids, constructors in `ComponentList`
//! order), once with lookup elements drawn from a seeded channel and once with probe elements, so
//! the proof-dependent extension constants become `LookupZ`, `LookupAlphaPower*` and
//! `ClaimedSumScaled` runtime parameters.
//!
//! The instance is the multiverifier of the recursive-tree test registry
//! (`crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json`): component sizes
//! `eq 20, qm31_ops 23, triple_xor 20, m31_to_u32 21, blake_g_gate 23` and the preprocessed layout
//! `layout_from_component_sizes` gives them. A bundle is specific to its sizes only through
//! `trace_log_size`, `evaluation_log_size`, `denominator_inverses` and `preprocessed_indices`;
//! consumers retarget it (`eval_program.zig` `Program.setDomainLogSize`). The claimed sums are
//! fixed distinct values: they become the `ClaimedSumScaled` parameter, so no emitted byte depends
//! on them.

use anyhow::{Result, ensure};
use circuit_common::finalize::ComponentSizes;
use circuit_common::preprocessed::layout_from_component_sizes;
use circuit_prover::circuit_air::components::{
    blake_g_gate, eq, m_31_to_u_32, qm_31_ops, range_check_16, triple_xor, verify_bitwise_xor_4,
    verify_bitwise_xor_7, verify_bitwise_xor_8, verify_bitwise_xor_9, verify_bitwise_xor_12,
};
use circuit_verifier::circuit_components::{COMPONENT_NAMES, PerComponent};
use circuit_verifier::relations::CommonLookupElements;
use circuit_verifier::statement::{all_circuit_components, circuit_component_log_sizes};
use stwo::core::fields::qm31::QM31;
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

use crate::eval_program_abi::bundle::{self, CapturedComponent};
use crate::eval_program_abi::capture::{Summary, lower_component};
use crate::eval_program_abi::{abi_fixture, parameters::LookupProbe};
use crate::goldens;

/// The lookup seeds of `tools/stwo-cairo-air-compiler` (`main.rs`).
const LOOKUP_SEED: [u32; 4] = [11, 13, 17, 19];
const PROBE_LOOKUP_SEED: [u32; 4] = [23, 29, 31, 37];

/// The recorded instance: the `recursive_tree_multiverifier` registry entry.
fn instance_sizes() -> ComponentSizes {
    let entry = goldens::REGISTRY_ENTRIES
        .iter()
        .find(|entry| entry.name == "recursive_tree_multiverifier")
        .expect("golden registry entry");
    let [eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate] = entry.gates;
    ComponentSizes {
        eq: 1 << eq,
        qm31_ops: 1 << qm31_ops,
        m31_to_u32: 1 << m31_to_u32,
        triple_xor: 1 << triple_xor,
        blake_g_gate: 1 << blake_g_gate,
    }
}

/// A distinct claimed sum per component, in `ComponentList` order.
fn claimed_sum(index: u32) -> QM31 {
    QM31::from_u32_unchecked(1009 + index, 2003 + index, 3001 + index, 4001 + index)
}

/// Captures the eleven components; `lookup`/`probe` carry the two lookup-element draws.
fn capture_all(
    ids: &[PreProcessedColumnId],
    log_sizes: &PerComponent<u32>,
    lookup: &LookupProbe<CommonLookupElements>,
    probe: &LookupProbe<CommonLookupElements>,
) -> Result<Vec<CapturedComponent>> {
    let allocator = &mut TraceLocationAllocator::new_with_preprocessed_columns(ids);
    let probe_allocator = &mut TraceLocationAllocator::new_with_preprocessed_columns(ids);
    let mut summary = Summary::default();
    let mut captured = Vec::new();
    let mut index = 0u32;

    macro_rules! capture {
        ($name:ident, $module:ident, $eval:expr) => {{
            let eval = |lookup: &LookupProbe<CommonLookupElements>| {
                #[allow(clippy::redundant_closure_call)]
                ($eval)(lookup.elements.clone())
            };
            let component = $module::Component::new(allocator, eval(lookup), claimed_sum(index));
            let probe_component =
                $module::Component::new(probe_allocator, eval(probe), claimed_sum(index));
            ensure!(
                COMPONENT_NAMES[index as usize] == stringify!($name),
                "component {} is out of ComponentList order",
                stringify!($name)
            );
            let (component, report) = lower_component(
                stringify!($name),
                0,
                &component,
                &probe_component,
                lookup,
                probe,
                &mut summary,
            )?;
            eprintln!("{report}");
            captured.push(component);
            index += 1;
        }};
    }

    capture!(eq, eq, |common_lookup_elements| eq::Eval {
        log_size: log_sizes.eq,
        common_lookup_elements,
    });
    capture!(qm31_ops, qm_31_ops, |common_lookup_elements| {
        qm_31_ops::Eval {
            claim: qm_31_ops::Claim {
                log_size: log_sizes.qm31_ops,
            },
            common_lookup_elements,
        }
    });
    capture!(triple_xor, triple_xor, |common_lookup_elements| {
        triple_xor::Eval {
            claim: triple_xor::Claim {
                log_size: log_sizes.triple_xor,
            },
            common_lookup_elements,
        }
    });
    capture!(m_31_to_u_32, m_31_to_u_32, |common_lookup_elements| {
        m_31_to_u_32::Eval {
            claim: m_31_to_u_32::Claim {
                log_size: log_sizes.m_31_to_u_32,
            },
            common_lookup_elements,
        }
    });
    capture!(blake_g_gate, blake_g_gate, |common_lookup_elements| {
        blake_g_gate::Eval {
            claim: blake_g_gate::Claim {
                log_size: log_sizes.blake_g_gate,
            },
            common_lookup_elements,
        }
    });
    capture!(
        verify_bitwise_xor_8,
        verify_bitwise_xor_8,
        |common_lookup_elements| {
            verify_bitwise_xor_8::Eval {
                claim: verify_bitwise_xor_8::Claim {},
                common_lookup_elements,
            }
        }
    );
    capture!(
        verify_bitwise_xor_12,
        verify_bitwise_xor_12,
        |common_lookup_elements| {
            verify_bitwise_xor_12::Eval {
                claim: verify_bitwise_xor_12::Claim {},
                common_lookup_elements,
            }
        }
    );
    capture!(
        verify_bitwise_xor_4,
        verify_bitwise_xor_4,
        |common_lookup_elements| {
            verify_bitwise_xor_4::Eval {
                claim: verify_bitwise_xor_4::Claim {},
                common_lookup_elements,
            }
        }
    );
    capture!(
        verify_bitwise_xor_7,
        verify_bitwise_xor_7,
        |common_lookup_elements| {
            verify_bitwise_xor_7::Eval {
                claim: verify_bitwise_xor_7::Claim {},
                common_lookup_elements,
            }
        }
    );
    capture!(
        verify_bitwise_xor_9,
        verify_bitwise_xor_9,
        |common_lookup_elements| {
            verify_bitwise_xor_9::Eval {
                claim: verify_bitwise_xor_9::Claim {},
                common_lookup_elements,
            }
        }
    );
    capture!(range_check_16, range_check_16, |common_lookup_elements| {
        range_check_16::Eval {
            claim: range_check_16::Claim {},
            common_lookup_elements,
        }
    });

    ensure!(
        index as usize == COMPONENT_NAMES.len()
            && captured.len() == COMPONENT_NAMES.len()
            && summary.components == captured.len(),
        "captured {} of {} circuit components",
        captured.len(),
        COMPONENT_NAMES.len()
    );
    eprintln!(
        "complete: components={} constraints={} base_insts={} ext_insts={} ext_params={}",
        summary.components,
        summary.constraints,
        summary.base_instructions,
        summary.extension_instructions,
        summary.extension_parameters
    );
    Ok(captured)
}

pub fn run() -> Result<Vec<u8>> {
    abi_fixture::check()?;
    let layout = layout_from_component_sizes(&instance_sizes());
    let ids: Vec<PreProcessedColumnId> = layout.keys().cloned().collect();
    let log_sizes = circuit_component_log_sizes(&all_circuit_components::<QM31>(), &layout);
    let lookup = LookupProbe::from_seed(&LOOKUP_SEED, CommonLookupElements::draw)?;
    let probe = LookupProbe::from_seed(&PROBE_LOOKUP_SEED, CommonLookupElements::draw)?;
    let captured = capture_all(&ids, &log_sizes, &lookup, &probe)?;
    bundle::encode(&captured)
}

#[cfg(test)]
mod tests {
    /// The ABI byte-compare gate: the committed fixture bytes are what this pin encodes.
    #[test]
    fn abi_fixture_matches_the_committed_bytes() {
        crate::eval_program_abi::abi_fixture::check().unwrap();
    }
}
