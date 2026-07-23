use crate::cli::{pcs_config_from_wire, pcs_config_to_wire};
use crate::model::{
    BlakeStatement, BlakeStatementWire, FriLayerWire, FriProofWire, MerkleDecommitmentWire,
    PlonkStatement, PlonkStatementWire, PoseidonStatement, PoseidonStatementWire, ProofWire,
    Qm31Wire, StateMachineStatement, StateMachineStatementWire, StateMachineStmt0Wire,
    StateMachineStmt1Wire, WideFibonacciStatement, WideFibonacciStatementWire, XorStatement,
    XorStatementWire,
};
use anyhow::{anyhow, bail, Result};
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::{SecureField, QM31};
use stwo::core::fri::{FriLayerProof, FriProof};
use stwo::core::pcs::quotients::CommitmentSchemeProof;
use stwo::core::pcs::TreeVec;
use stwo::core::poly::line::LinePoly;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted;

pub(crate) fn checked_m31(value: u32) -> Result<M31> {
    if value >= P {
        bail!("non-canonical m31 value {value}");
    }
    Ok(M31::from_u32_unchecked(value))
}

pub(crate) fn qm31_to_wire(value: SecureField) -> Qm31Wire {
    let arr = value.to_m31_array();
    [arr[0].0, arr[1].0, arr[2].0, arr[3].0]
}

pub(crate) fn qm31_from_wire(value: Qm31Wire) -> Result<SecureField> {
    Ok(QM31::from_m31(
        checked_m31(value[0])?,
        checked_m31(value[1])?,
        checked_m31(value[2])?,
        checked_m31(value[3])?,
    ))
}

pub(crate) fn proof_to_wire(proof: &StarkProof<Blake2sMerkleHasher>) -> Result<ProofWire> {
    let pcs_proof = &proof.0;

    let commitments = pcs_proof
        .commitments
        .iter()
        .map(|hash| hash.0)
        .collect::<Vec<_>>();

    let sampled_values = pcs_proof
        .sampled_values
        .0
        .iter()
        .map(|tree| {
            tree.iter()
                .map(|col| col.iter().copied().map(qm31_to_wire).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let decommitments = pcs_proof
        .decommitments
        .0
        .iter()
        .map(|decommitment| MerkleDecommitmentWire {
            hash_witness: decommitment
                .hash_witness
                .iter()
                .map(|hash| hash.0)
                .collect(),
        })
        .collect::<Vec<_>>();

    let queried_values = pcs_proof
        .queried_values
        .0
        .iter()
        .map(|tree| {
            tree.iter()
                .map(|col| col.iter().map(|value| value.0).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let first_layer = fri_layer_to_wire(&pcs_proof.fri_proof.first_layer);
    let inner_layers = pcs_proof
        .fri_proof
        .inner_layers
        .iter()
        .map(fri_layer_to_wire)
        .collect::<Vec<_>>();
    let last_layer_poly = pcs_proof
        .fri_proof
        .last_layer_poly
        .iter()
        .copied()
        .map(qm31_to_wire)
        .collect::<Vec<_>>();

    Ok(ProofWire {
        config: pcs_config_to_wire(pcs_proof.config),
        commitments,
        sampled_values,
        decommitments,
        queried_values,
        proof_of_work: pcs_proof.proof_of_work,
        fri_proof: FriProofWire {
            first_layer,
            inner_layers,
            last_layer_poly,
        },
    })
}

pub(crate) fn wire_to_proof(wire: ProofWire) -> Result<StarkProof<Blake2sMerkleHasher>> {
    let config = pcs_config_from_wire(&wire.config)?;

    let commitments = wire
        .commitments
        .into_iter()
        .map(Blake2sHash)
        .collect::<Vec<_>>();

    let sampled_values = wire
        .sampled_values
        .into_iter()
        .map(|tree| {
            tree.into_iter()
                .map(|col| {
                    col.into_iter()
                        .map(qm31_from_wire)
                        .collect::<Result<Vec<_>>>()
                })
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;

    let decommitments = wire
        .decommitments
        .into_iter()
        .map(
            |decommitment| MerkleDecommitmentLifted::<Blake2sMerkleHasher> {
                hash_witness: decommitment
                    .hash_witness
                    .into_iter()
                    .map(Blake2sHash)
                    .collect(),
            },
        )
        .collect::<Vec<_>>();

    let queried_values = wire
        .queried_values
        .into_iter()
        .map(|tree| {
            tree.into_iter()
                .map(|col| col.into_iter().map(checked_m31).collect::<Result<Vec<_>>>())
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;

    let fri_proof = FriProof {
        first_layer: wire_to_fri_layer(wire.fri_proof.first_layer)?,
        inner_layers: wire
            .fri_proof
            .inner_layers
            .into_iter()
            .map(wire_to_fri_layer)
            .collect::<Result<Vec<_>>>()?,
        last_layer_poly: LinePoly::new(
            wire.fri_proof
                .last_layer_poly
                .into_iter()
                .map(qm31_from_wire)
                .collect::<Result<Vec<_>>>()?,
        ),
    };

    Ok(StarkProof(CommitmentSchemeProof {
        config,
        commitments: TreeVec::new(commitments),
        sampled_values: TreeVec::new(sampled_values),
        decommitments: TreeVec::new(decommitments),
        queried_values: TreeVec::new(queried_values),
        proof_of_work: wire.proof_of_work,
        fri_proof,
    }))
}

pub(crate) fn fri_layer_to_wire(layer: &FriLayerProof<Blake2sMerkleHasher>) -> FriLayerWire {
    FriLayerWire {
        fri_witness: layer
            .fri_witness
            .iter()
            .copied()
            .map(qm31_to_wire)
            .collect(),
        decommitment: MerkleDecommitmentWire {
            hash_witness: layer
                .decommitment
                .hash_witness
                .iter()
                .map(|hash| hash.0)
                .collect(),
        },
        commitment: layer.commitment.0,
    }
}

pub(crate) fn wire_to_fri_layer(layer: FriLayerWire) -> Result<FriLayerProof<Blake2sMerkleHasher>> {
    Ok(FriLayerProof {
        fri_witness: layer
            .fri_witness
            .into_iter()
            .map(qm31_from_wire)
            .collect::<Result<Vec<_>>>()?,
        decommitment: MerkleDecommitmentLifted::<Blake2sMerkleHasher> {
            hash_witness: layer
                .decommitment
                .hash_witness
                .into_iter()
                .map(Blake2sHash)
                .collect(),
        },
        commitment: Blake2sHash(layer.commitment),
    })
}

pub(crate) fn state_machine_statement_to_wire(
    statement: StateMachineStatement,
) -> StateMachineStatementWire {
    StateMachineStatementWire {
        public_input: [
            [
                statement.public_input[0][0].0,
                statement.public_input[0][1].0,
            ],
            [
                statement.public_input[1][0].0,
                statement.public_input[1][1].0,
            ],
        ],
        stmt0: StateMachineStmt0Wire {
            n: statement.stmt0_n,
            m: statement.stmt0_m,
        },
        stmt1: StateMachineStmt1Wire {
            x_axis_claimed_sum: qm31_to_wire(statement.stmt1_x_axis_claimed_sum),
            y_axis_claimed_sum: qm31_to_wire(statement.stmt1_y_axis_claimed_sum),
        },
    }
}

pub(crate) fn state_machine_statement_from_wire(
    wire: &StateMachineStatementWire,
) -> Result<StateMachineStatement> {
    Ok(StateMachineStatement {
        public_input: [
            [
                checked_m31(wire.public_input[0][0])?,
                checked_m31(wire.public_input[0][1])?,
            ],
            [
                checked_m31(wire.public_input[1][0])?,
                checked_m31(wire.public_input[1][1])?,
            ],
        ],
        stmt0_n: wire.stmt0.n,
        stmt0_m: wire.stmt0.m,
        stmt1_x_axis_claimed_sum: qm31_from_wire(wire.stmt1.x_axis_claimed_sum)?,
        stmt1_y_axis_claimed_sum: qm31_from_wire(wire.stmt1.y_axis_claimed_sum)?,
    })
}

pub(crate) fn xor_statement_to_wire(statement: XorStatement) -> Result<XorStatementWire> {
    Ok(XorStatementWire {
        log_size: statement.log_size,
        log_step: statement.log_step,
        offset: statement.offset as u64,
    })
}

pub(crate) fn xor_statement_from_wire(wire: &XorStatementWire) -> Result<XorStatement> {
    let offset: usize = wire
        .offset
        .try_into()
        .map_err(|_| anyhow!("xor offset out of range"))?;
    Ok(XorStatement {
        log_size: wire.log_size,
        log_step: wire.log_step,
        offset,
    })
}

pub(crate) fn wide_fibonacci_statement_to_wire(
    statement: WideFibonacciStatement,
) -> WideFibonacciStatementWire {
    WideFibonacciStatementWire {
        log_n_rows: statement.log_n_rows,
        sequence_len: statement.sequence_len,
    }
}

pub(crate) fn wide_fibonacci_statement_from_wire(
    wire: &WideFibonacciStatementWire,
) -> Result<WideFibonacciStatement> {
    Ok(WideFibonacciStatement {
        log_n_rows: wire.log_n_rows,
        sequence_len: wire.sequence_len,
    })
}

pub(crate) fn plonk_statement_to_wire(statement: PlonkStatement) -> PlonkStatementWire {
    PlonkStatementWire {
        log_n_rows: statement.log_n_rows,
    }
}

pub(crate) fn plonk_statement_from_wire(wire: &PlonkStatementWire) -> Result<PlonkStatement> {
    Ok(PlonkStatement {
        log_n_rows: wire.log_n_rows,
    })
}

pub(crate) fn poseidon_statement_to_wire(statement: PoseidonStatement) -> PoseidonStatementWire {
    PoseidonStatementWire {
        log_n_instances: statement.log_n_instances,
    }
}

pub(crate) fn poseidon_statement_from_wire(
    wire: &PoseidonStatementWire,
) -> Result<PoseidonStatement> {
    Ok(PoseidonStatement {
        log_n_instances: wire.log_n_instances,
    })
}

pub(crate) fn blake_statement_to_wire(statement: BlakeStatement) -> BlakeStatementWire {
    BlakeStatementWire {
        log_n_rows: statement.log_n_rows,
        n_rounds: statement.n_rounds,
    }
}

pub(crate) fn blake_statement_from_wire(wire: &BlakeStatementWire) -> Result<BlakeStatement> {
    Ok(BlakeStatement {
        log_n_rows: wire.log_n_rows,
        n_rounds: wire.n_rounds,
    })
}
