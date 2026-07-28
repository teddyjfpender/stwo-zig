use super::protocol::CLAIM_FIELD_NAMES;
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactProofGeometryV1 {
    pub total_words: usize,
    pub interaction_claim_words: usize,
    pub sampled_value_words: usize,
    pub decommitment_offset_words: usize,
    pub decommitment_used_words: usize,
    pub raw_query_count: u32,
    pub unique_query_count: u32,
}

/// Fully decoded compact sections prior to claim/STARK reconstruction.
pub struct ValidatedCompactSectionsV1 {
    pub protocol: CompactProtocolV1,
    pub statement: CompactStatementV1,
    pub proof_geometry: CompactProofGeometryV1,
}

/// Canonical Cairo claim types reconstructed from the compact Metal boundary.
pub struct ReconstructedClaimsV1 {
    pub cairo_claim: CairoClaim,
    pub interaction_pow: u64,
    pub interaction_claim: CairoInteractionClaim,
}

pub type ReconstructedStarkProofV1 = StarkProof<Blake2sMerkleHasher>;
pub type ReconstructedCairoProofV1 = CairoProofForRustVerifier<Blake2sMerkleHasher>;

#[derive(Clone, Copy)]
pub(super) struct CompactProofOffsetsV1 {
    pub(super) interaction_start: usize,
    pub(super) interaction_pow_start: usize,
    pub(super) sampled_start: usize,
    pub(super) fri_commitments_start: usize,
    pub(super) final_line_start: usize,
    pub(super) query_pow_start: usize,
    pub(super) decommitment_start: usize,
}

#[derive(Clone, Copy)]
pub(super) struct DecommitTreeMetaV1 {
    pub(super) values_offset: usize,
    pub(super) values_count: usize,
    pub(super) fri_witness_offset: usize,
    pub(super) fri_witness_count: usize,
    pub(super) hash_witness_offset: usize,
    pub(super) hash_witness_count: usize,
    pub(super) query_count: usize,
}

pub fn validate_compact_sections_v1(
    protocol_bytes: &[u8],
    statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<ValidatedCompactSectionsV1, CompactCodecError> {
    let protocol = CompactProtocolV1::decode(protocol_bytes)?;
    let statement = CompactStatementV1::decode(statement_bytes)?;
    let proof_geometry = validate_compact_proof_v1(proof_bytes, &protocol, &statement)?;
    Ok(ValidatedCompactSectionsV1 {
        protocol,
        statement,
        proof_geometry,
    })
}

/// Inverts cairo-air's flattened claim representation and decodes the compact
/// interaction sums into the exact pinned Rust verifier types.
pub fn reconstruct_claims_v1(
    proof_bytes: &[u8],
    protocol: &CompactProtocolV1,
    statement: &CompactStatementV1,
) -> Result<ReconstructedClaimsV1, CompactCodecError> {
    validate_compact_proof_v1(proof_bytes, protocol, statement)?;

    let mut claim_fields = Map::new();
    claim_fields.insert(
        "public_data".to_owned(),
        serde_json::to_value(&statement.public_data).map_err(|error| {
            invalid_statement(format!("failed to encode canonical public data: {error}"))
        })?,
    );
    let mut interaction_fields = Map::new();
    let mut expected_claimed_sums = Vec::with_capacity(protocol.interaction_sum_count as usize);
    let mut active_index = 0_usize;
    let offsets = compact_proof_offsets(protocol);
    let mut interaction_word = offsets.interaction_start;

    for (field_index, name) in CLAIM_FIELD_NAMES.iter().enumerate() {
        let first_slot = claim_field_first_slot(field_index);
        if field_index == 49 {
            let slot_count = statement.component_enable_bits
                [MEMORY_BIG_START..MEMORY_BIG_START + MEMORY_BIG_COUNT]
                .iter()
                .take_while(|&&enabled| enabled)
                .count();
            let mut log_sizes = Vec::with_capacity(slot_count);
            let mut claimed_sums = Vec::with_capacity(slot_count);
            for _ in 0..slot_count {
                log_sizes.push(statement.component_log_sizes[active_index]);
                active_index += 1;
                claimed_sums.push(read_qm31(proof_bytes, interaction_word)?);
                expected_claimed_sums.push(*claimed_sums.last().unwrap());
                interaction_word += 4;
            }
            let claimed_sum = claimed_sums
                .iter()
                .copied()
                .fold(QM31::default(), |total, value| total + value);
            claim_fields.insert(
                (*name).to_owned(),
                object_with("big_log_sizes", serde_json::to_value(log_sizes).unwrap()),
            );
            let mut interaction = Map::new();
            interaction.insert(
                "big_claimed_sums".to_owned(),
                serde_json::to_value(claimed_sums).unwrap(),
            );
            interaction.insert(
                "claimed_sum".to_owned(),
                serde_json::to_value(claimed_sum).unwrap(),
            );
            interaction_fields.insert((*name).to_owned(), Value::Object(interaction));
            continue;
        }

        if !statement.component_enable_bits[first_slot] {
            claim_fields.insert((*name).to_owned(), Value::Null);
            interaction_fields.insert((*name).to_owned(), Value::Null);
            continue;
        }

        let log_size = statement.component_log_sizes[active_index];
        active_index += 1;
        let claim = match fixed_log_size(field_index) {
            Some(expected) if log_size != expected => {
                return Err(invalid_statement(format!(
                    "component {name} has fixed log size {expected}, found {log_size}"
                )))
            }
            Some(_) => Value::Object(Map::new()),
            None => object_with("log_size", Value::from(log_size)),
        };
        claim_fields.insert((*name).to_owned(), claim);

        let claimed_sum = read_qm31(proof_bytes, interaction_word)?;
        expected_claimed_sums.push(claimed_sum);
        interaction_word += 4;
        interaction_fields.insert(
            (*name).to_owned(),
            object_with("claimed_sum", serde_json::to_value(claimed_sum).unwrap()),
        );
    }

    if active_index != statement.component_log_sizes.len()
        || interaction_word != offsets.interaction_pow_start
    {
        return Err(invalid_proof(
            "claim reconstruction did not consume the authenticated component geometry",
        ));
    }

    let cairo_claim: CairoClaim =
        serde_json::from_value(Value::Object(claim_fields)).map_err(|error| {
            invalid_statement(format!(
                "failed to reconstruct canonical CairoClaim: {error}"
            ))
        })?;
    let interaction_claim: CairoInteractionClaim =
        serde_json::from_value(Value::Object(interaction_fields)).map_err(|error| {
            invalid_proof(format!(
                "failed to reconstruct canonical CairoInteractionClaim: {error}"
            ))
        })?;
    let flat_claim = cairo_claim.flatten_claim();
    if flat_claim.component_enable_bits != statement.component_enable_bits
        || flat_claim.component_log_sizes != statement.component_log_sizes
    {
        return Err(invalid_statement(
            "canonical CairoClaim does not re-flatten to the authenticated statement",
        ));
    }
    if interaction_claim.flatten_interaction_claim() != expected_claimed_sums {
        return Err(invalid_proof(
            "canonical CairoInteractionClaim does not re-flatten to the compact proof",
        ));
    }
    let interaction_pow = read_proof_word(proof_bytes, offsets.interaction_pow_start)? as u64
        | (read_proof_word(proof_bytes, offsets.interaction_pow_start + 1)? as u64) << 32;

    Ok(ReconstructedClaimsV1 {
        cairo_claim,
        interaction_pow,
        interaction_claim,
    })
}

/// Translates the compact proof payload into Stwo's exact pinned proof type.
/// `sample_shape` is authenticated statement/AIR metadata: one sample count per
/// column in each authenticated commitment tree. Callers must derive it from the
/// canonical Cairo component graph, never from the flattened proof payload.
pub fn reconstruct_stark_proof_v1(
    proof_bytes: &[u8],
    protocol: &CompactProtocolV1,
    statement: &CompactStatementV1,
    sample_shape: &[Vec<usize>],
) -> Result<ReconstructedStarkProofV1, CompactCodecError> {
    validate_compact_proof_v1(proof_bytes, protocol, statement)?;
    validate_sample_shape(protocol, sample_shape)?;
    let offsets = compact_proof_offsets(protocol);

    let commitments = (0..protocol.commitment_count as usize)
        .map(|index| read_hash(proof_bytes, index * HASH_WORDS))
        .collect::<Result<Vec<_>, _>>()?;

    let mut sampled_values = Vec::with_capacity(protocol.sampled_tree_count as usize);
    let mut sample_word = offsets.sampled_start;
    for tree in sample_shape {
        let mut columns = Vec::with_capacity(tree.len());
        for &count in tree {
            let mut samples = Vec::with_capacity(count);
            for _ in 0..count {
                samples.push(read_qm31(proof_bytes, sample_word)?);
                sample_word += 4;
            }
            columns.push(samples);
        }
        sampled_values.push(columns);
    }
    if sample_word != offsets.fri_commitments_start {
        return Err(invalid_proof(
            "sample shape did not consume the authenticated sampled-value payload",
        ));
    }

    let mut decommitments = Vec::with_capacity(protocol.commitment_count as usize);
    let mut queried_values = Vec::with_capacity(protocol.commitment_count as usize);
    for tree_index in 0..protocol.commitment_count as usize {
        let meta = read_decommit_meta(proof_bytes, offsets.decommitment_start, tree_index)?;
        let expected_columns = protocol.trace_tree_column_counts[tree_index] as usize;
        if meta.values_count != meta.query_count * expected_columns {
            return Err(invalid_proof(format!(
                "trace tree {tree_index} opening shape drifted during reconstruction"
            )));
        }
        let mut columns = Vec::with_capacity(expected_columns);
        for column_index in 0..expected_columns {
            let mut column = Vec::with_capacity(meta.query_count);
            for query_index in 0..meta.query_count {
                let relative = meta.values_offset + column_index * meta.query_count + query_index;
                column.push(read_decommit_m31(
                    proof_bytes,
                    offsets.decommitment_start,
                    relative,
                )?);
            }
            columns.push(column);
        }
        queried_values.push(columns);
        decommitments.push(MerkleDecommitmentLifted {
            hash_witness: read_decommit_hashes(
                proof_bytes,
                offsets.decommitment_start,
                meta.hash_witness_offset,
                meta.hash_witness_count,
            )?,
        });
    }

    let mut fri_layers = Vec::with_capacity(protocol.fri_tree_count as usize);
    for round in 0..protocol.fri_tree_count as usize {
        let meta = read_decommit_meta(
            proof_bytes,
            offsets.decommitment_start,
            protocol.commitment_count as usize + round,
        )?;
        let mut fri_witness = Vec::with_capacity(meta.fri_witness_count);
        for index in 0..meta.fri_witness_count {
            fri_witness.push(read_decommit_qm31(
                proof_bytes,
                offsets.decommitment_start,
                meta.fri_witness_offset + index * 4,
            )?);
        }
        fri_layers.push(FriLayerProof {
            fri_witness,
            decommitment: MerkleDecommitmentLifted {
                hash_witness: read_decommit_hashes(
                    proof_bytes,
                    offsets.decommitment_start,
                    meta.hash_witness_offset,
                    meta.hash_witness_count,
                )?,
            },
            commitment: read_hash(
                proof_bytes,
                offsets.fri_commitments_start + round * HASH_WORDS,
            )?,
        });
    }
    let first_layer = fri_layers.remove(0);
    let mut final_coefficients = Vec::with_capacity(protocol.final_line_coefficient_count as usize);
    for index in 0..protocol.final_line_coefficient_count as usize {
        final_coefficients.push(read_qm31(
            proof_bytes,
            offsets.final_line_start + index * 4,
        )?);
    }
    let last_layer_poly = LinePoly::new(final_coefficients);
    let proof_of_work = read_proof_word(proof_bytes, offsets.query_pow_start)? as u64
        | (read_proof_word(proof_bytes, offsets.query_pow_start + 1)? as u64) << 32;

    Ok(StarkProof(CommitmentSchemeProof {
        config: PcsConfig {
            pow_bits: protocol.query_pow_bits,
            fri_config: FriConfig::new(
                protocol.log_last_layer_degree_bound,
                protocol.log_blowup_factor,
                protocol.query_count as usize,
                protocol.fri_fold_step,
            ),
            lifting_log_size: protocol.fri_lifting_log_size,
        },
        commitments: TreeVec::new(commitments),
        sampled_values: TreeVec::new(sampled_values),
        decommitments: TreeVec::new(decommitments),
        queried_values: TreeVec::new(queried_values),
        proof_of_work,
        fri_proof: FriProof {
            first_layer,
            inner_layers: fri_layers,
            last_layer_poly,
        },
    }))
}

/// Derives the OODS sample cardinalities from the pinned Cairo AIR component
/// graph. Only the cardinalities are used; challenge values cannot affect the
/// component masks' shape.
pub fn derive_sample_shape_v1(
    protocol: &CompactProtocolV1,
    claim: &CairoClaim,
    interaction_claim: &CairoInteractionClaim,
    preprocessed_trace_variant: PreProcessedTraceVariant,
) -> Result<Vec<Vec<usize>>, CompactCodecError> {
    let mut shape_channel = Blake2sChannel::default();
    let lookup_elements = CommonLookupElements::draw(&mut shape_channel);
    let preprocessed = preprocessed_trace_variant.to_preprocessed_trace();
    let cairo_components = CairoComponents::new(
        claim,
        &lookup_elements,
        interaction_claim,
        &preprocessed.ids(),
    );
    let components = Components {
        components: cairo_components.components(),
        n_preprocessed_columns: protocol.trace_tree_column_counts[0] as usize,
    };
    let max_log_degree_bound = components
        .composition_log_degree_bound()
        .checked_sub(1)
        .ok_or_else(|| invalid_statement("invalid Cairo composition degree bound"))?;
    let point = CirclePoint::<QM31>::get_random_point(&mut shape_channel);
    let mut shape: Vec<Vec<usize>> = components
        .mask_points(point, max_log_degree_bound, false)
        .0
        .into_iter()
        .map(|tree| tree.into_iter().map(|samples| samples.len()).collect())
        .collect();
    protocol.validate_max_log_degree_bound(max_log_degree_bound)?;
    shape.push(vec![1; protocol.trace_tree_column_counts[3] as usize]);
    validate_sample_shape(protocol, &shape)?;
    Ok(shape)
}

/// Reconstructs the complete canonical Cairo proof object. This function does
/// not itself verify the proof; callers must pass the result to pinned
/// `verify_cairo` and fail closed on any panic or verification error.
pub fn reconstruct_cairo_proof_v1(
    proof_bytes: &[u8],
    protocol: &CompactProtocolV1,
    statement: &CompactStatementV1,
) -> Result<ReconstructedCairoProofV1, CompactCodecError> {
    let claims = reconstruct_claims_v1(proof_bytes, protocol, statement)?;
    let sample_shape = derive_sample_shape_v1(
        protocol,
        &claims.cairo_claim,
        &claims.interaction_claim,
        protocol.preprocessed_trace_variant,
    )?;
    let stark_proof = reconstruct_stark_proof_v1(proof_bytes, protocol, statement, &sample_shape)?;
    Ok(CairoProofForRustVerifier {
        claim: claims.cairo_claim,
        interaction_pow: claims.interaction_pow,
        interaction_claim: claims.interaction_claim,
        stark_proof,
        channel_salt: protocol.channel_salt,
        preprocessed_trace_variant: protocol.preprocessed_trace_variant,
    })
}

fn validate_sample_shape(
    protocol: &CompactProtocolV1,
    sample_shape: &[Vec<usize>],
) -> Result<(), CompactCodecError> {
    if sample_shape.len() != protocol.sampled_tree_count as usize {
        return Err(invalid_statement(
            "sample shape tree count does not match the authenticated protocol",
        ));
    }
    let mut samples = 0_usize;
    for (tree_index, tree) in sample_shape.iter().enumerate() {
        let expected = protocol.trace_tree_column_counts[tree_index] as usize;
        if tree.len() != expected {
            return Err(invalid_statement(format!(
                "sample tree {tree_index} has {} columns, expected {expected}",
                tree.len()
            )));
        }
        samples = tree.iter().try_fold(samples, |total, &count| {
            total.checked_add(count).ok_or_else(length_overflow)
        })?;
    }
    if samples.checked_mul(4).ok_or_else(length_overflow)? != protocol.sampled_value_words as usize
    {
        return Err(invalid_statement(
            "sample shape does not match the authenticated sampled-value word count",
        ));
    }
    Ok(())
}
