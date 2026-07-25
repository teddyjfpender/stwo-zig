//! Direct pinned-upstream State Machine oracle adapter.

use crate::model::{ProveMode, StateMachineStatement};
use anyhow::{anyhow, bail, Result};
use num_traits::Zero;
use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, prove_ex, CommitmentSchemeProver};
use stwo_constraint_framework::{Relation, TraceLocationAllocator};
use stwo_examples::state_machine::components::{
    StateMachineComponents, StateMachineElements, StateMachineOp0Component,
    StateMachineOp1Component, StateMachineStatement0, StateMachineStatement1, StateTransitionEval,
};
use stwo_examples::state_machine::gen::{gen_interaction_trace, gen_trace};

const PROOF_COMMITMENTS: usize = 4;

pub(crate) fn state_machine_prove(
    config: PcsConfig,
    log_n_rows: u32,
    initial_state: [M31; 2],
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(StateMachineStatement, StarkProof<Blake2sMerkleHasher>)> {
    if log_n_rows < 5 || log_n_rows >= 31 {
        bail!("invalid state_machine log_n_rows {log_n_rows}");
    }
    let m = log_n_rows - 1;
    let (intermediate, final_state) = transition_states(log_n_rows, initial_state);

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    scheme.tree_builder().commit(&mut channel);
    let stmt0 = StateMachineStatement0 { n: log_n_rows, m };
    stmt0.mix_into(&mut channel);

    let trace0 = gen_trace(log_n_rows, initial_state, 0);
    let trace1 = gen_trace(m, intermediate, 1);
    let mut main = Vec::with_capacity(4);
    main.extend(trace0.iter().cloned());
    main.extend(trace1.iter().cloned());
    let mut builder = scheme.tree_builder();
    builder.extend_evals(main);
    builder.commit(&mut channel);

    let lookup_elements = StateMachineElements::draw(&mut channel);
    let (interaction0, x_claim) = gen_interaction_trace(&trace0, 0, &lookup_elements);
    let (interaction1, y_claim) = gen_interaction_trace(&trace1, 1, &lookup_elements);
    let stmt1 = StateMachineStatement1 {
        x_axis_claimed_sum: x_claim,
        y_axis_claimed_sum: y_claim,
    };
    stmt1.mix_into(&mut channel);

    let mut interactions = Vec::with_capacity(8);
    interactions.extend(interaction0);
    interactions.extend(interaction1);
    let mut builder = scheme.tree_builder();
    builder.extend_evals(interactions);
    builder.commit(&mut channel);

    let components = make_components(log_n_rows, lookup_elements, x_claim, y_claim);
    let component_provers = components.component_provers();
    let proof = match prove_mode {
        ProveMode::Prove => {
            prove::<SimdBackend, Blake2sMerkleChannel>(&component_provers, &mut channel, scheme)?
        }
        ProveMode::ProveEx => {
            prove_ex::<SimdBackend, Blake2sMerkleChannel>(
                &component_provers,
                &mut channel,
                scheme,
                include_all_preprocessed_columns,
            )?
            .proof
        }
    };

    Ok((
        StateMachineStatement {
            public_input: [initial_state, final_state],
            stmt0_n: log_n_rows,
            stmt0_m: m,
            stmt1_x_axis_claimed_sum: x_claim,
            stmt1_y_axis_claimed_sum: y_claim,
        },
        proof,
    ))
}

pub(crate) fn state_machine_verify(
    config: PcsConfig,
    statement: StateMachineStatement,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    validate_statement(statement)?;
    if proof.0.commitments.len() != PROOF_COMMITMENTS {
        bail!("invalid proof shape: expected exactly {PROOF_COMMITMENTS} commitments");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);
    let mut scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    scheme.commit(proof.0.commitments[0], &[], &mut channel);

    let stmt0 = StateMachineStatement0 {
        n: statement.stmt0_n,
        m: statement.stmt0_m,
    };
    stmt0.mix_into(&mut channel);
    let n = statement.stmt0_n;
    let m = statement.stmt0_m;
    scheme.commit(proof.0.commitments[1], &[n, n, m, m], &mut channel);

    let lookup_elements = StateMachineElements::draw(&mut channel);
    verify_endpoint_equation(statement, &lookup_elements)?;
    let stmt1 = StateMachineStatement1 {
        x_axis_claimed_sum: statement.stmt1_x_axis_claimed_sum,
        y_axis_claimed_sum: statement.stmt1_y_axis_claimed_sum,
    };
    stmt1.mix_into(&mut channel);
    scheme.commit(
        proof.0.commitments[2],
        &[n, n, n, n, m, m, m, m],
        &mut channel,
    );

    let components = make_components(
        n,
        lookup_elements,
        statement.stmt1_x_axis_claimed_sum,
        statement.stmt1_y_axis_claimed_sum,
    );
    verify(&components.components(), &mut channel, &mut scheme, proof)
        .map_err(|error| anyhow!("state_machine verify failed: {error}"))
}

fn make_components(
    n: u32,
    lookup_elements: StateMachineElements,
    x_claim: SecureField,
    y_claim: SecureField,
) -> StateMachineComponents {
    let locations = &mut TraceLocationAllocator::default();
    let component0 = StateMachineOp0Component::new(
        locations,
        StateTransitionEval {
            log_n_rows: n,
            lookup_elements: lookup_elements.clone(),
            claimed_sum: x_claim,
        },
        x_claim,
    );
    let component1 = StateMachineOp1Component::new(
        locations,
        StateTransitionEval {
            log_n_rows: n - 1,
            lookup_elements,
            claimed_sum: y_claim,
        },
        y_claim,
    );
    StateMachineComponents {
        component0,
        component1,
    }
}

fn transition_states(log_n_rows: u32, initial: [M31; 2]) -> ([M31; 2], [M31; 2]) {
    let mut intermediate = initial;
    intermediate[0] += M31::from_u32_unchecked(1 << log_n_rows);
    let mut final_state = intermediate;
    final_state[1] += M31::from_u32_unchecked(1 << (log_n_rows - 1));
    (intermediate, final_state)
}

fn validate_statement(statement: StateMachineStatement) -> Result<()> {
    if statement.stmt0_n < 5 || statement.stmt0_n >= 31 {
        bail!("invalid state_machine statement n");
    }
    if statement.stmt0_m != statement.stmt0_n - 1 {
        bail!("invalid state_machine statement m");
    }
    Ok(())
}

fn verify_endpoint_equation(
    statement: StateMachineStatement,
    elements: &StateMachineElements,
) -> Result<()> {
    let initial: SecureField = elements.combine(&statement.public_input[0]);
    let final_state: SecureField = elements.combine(&statement.public_input[1]);
    if initial.is_zero() || final_state.is_zero() {
        bail!("degenerate state_machine endpoint denominator");
    }
    let claims = statement.stmt1_x_axis_claimed_sum + statement.stmt1_y_axis_claimed_sum;
    if claims * initial * final_state != final_state - initial {
        bail!("state_machine statement not satisfied");
    }
    Ok(())
}
