//! Independent host proofs for the one-read wide relation lane.

use num_traits::Zero;

use super::*;

fn lookup_use(tuple_words: u32) -> RelationUseDescriptor {
    RelationUseDescriptor {
        tuple_kind: RelationTupleKind::LookupWords,
        tuple_arg: 0,
        tuple_words,
        relation_id: 1,
        multiplicity_kind: RelationMultiplicityKind::One,
        multiplicity_arg: 0,
        negative: false,
    }
}

#[test]
fn audited_generated_wide_shapes_enter_the_one_read_lane() {
    // Machine-generated `stwo-cairo/.../relation_table.rs` for relation graph
    // 0x73963831c53df4a2 contains exactly these >32-word uses. Keep component
    // labels so regeneration drift becomes an explicit coverage review.
    const GENERATED_WIDE_USES: &[(&str, usize, u32)] = &[
        ("blake_compress_opcode", 37, 36),
        ("blake_round", 30, 36),
        ("ec_op_builtin", 9, 126),
        ("partial_ec_mul_generic", 157, 126),
        ("partial_ec_mul_window_bits_18", 65, 58),
        ("partial_ec_mul_window_bits_18", 65, 73),
        ("partial_ec_mul_window_bits_9", 65, 58),
        ("partial_ec_mul_window_bits_9", 65, 87),
        ("pedersen_aggregator_window_bits_18", 6, 73),
        ("pedersen_aggregator_window_bits_9", 6, 87),
        ("pedersen_points_table_window_bits_18", 1, 58),
        ("pedersen_points_table_window_bits_9", 1, 58),
        ("poseidon_3_partial_rounds_chain", 9, 43),
        ("poseidon_aggregator", 14, 33),
        ("poseidon_aggregator", 14, 43),
        ("poseidon_full_round_chain", 6, 33),
    ];
    let mut audited_batches = Vec::with_capacity(GENERATED_WIDE_USES.len());
    for &(component, columns, width) in GENERATED_WIDE_USES {
        let batch = RelationBatchProgram {
            source_layout: RelationSourceLayout::LookupWords { words: width },
            columns: vec![
                RelationColumnDescriptor {
                    uses: vec![lookup_use(width)],
                };
                columns
            ],
            instances: vec![RelationRowExtent::Exact {
                n_real_rows: 8,
                padded_rows: 8,
                source_offset_rows: 0,
            }],
        };
        assert!(
            relation_batch_fused_eligible(&batch),
            "generated wide relation escaped the one-read lane: {component} \
             columns={columns} width={width}"
        );
        audited_batches.push(batch);
    }
    let audited_program = RelationKernelProgram {
        relation_graph_hash: 0x7396_3831_c53d_f4a2,
        template_use_count: audited_batches
            .iter()
            .map(|batch| batch.columns.len())
            .sum(),
        max_alpha_powers: RELATION_FUSED_MAX_TUPLE_WORDS,
        batches: audited_batches,
    };
    audited_program.validate().unwrap();
    let compact = audited_program
        .requirements_for_mode(RelationLaunchMode::Fused)
        .unwrap();
    assert!(
        compact
            .instances
            .iter()
            .all(|instance| instance.denominator_words == 1),
        "every audited generated-wide instance must use a sentinel, not a slab"
    );
}

fn oracle_word(state: &mut u64) -> M31 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    M31::from_u32_unchecked(((*state >> 32) as u32) % (M31_MODULUS as u32))
}

fn oracle_secure(state: &mut u64) -> SecureField {
    SecureField::from_m31_array(core::array::from_fn(|_| oracle_word(state)))
}

fn signed_oracle_multiplicity(value: M31, negative: bool) -> M31 {
    if negative && value.0 != 0 {
        M31::from_u32_unchecked(M31_MODULUS as u32 - value.0)
    } else {
        value
    }
}

/// Independent CPU model of the wide CUDA lane. It deliberately uses a
/// prefix/reverse Montgomery schedule rather than mirroring the device's tree
/// indexing. Every row tile contains every column for its rows, so no chain
/// state crosses a tile boundary.
fn wide_lane_cpu(
    fractions: &[Vec<(SecureField, SecureField)>],
) -> Result<Vec<Vec<SecureField>>, &'static str> {
    let rows = fractions.len();
    let columns = fractions.first().map_or(0, Vec::len);
    if rows == 0 || columns == 0 || columns > RELATION_FUSED_ONE_READ_MAX_COLUMNS {
        return Err("invalid wide shape");
    }
    let tile_rows = (512 / columns).min(REDUCTION_BLOCK);
    let mut output = vec![vec![SecureField::zero(); columns]; rows];
    for first_row in (0..rows).step_by(tile_rows) {
        let last_row = (first_row + tile_rows).min(rows);
        let tile = &fractions[first_row..last_row];
        let mut denominators = tile
            .iter()
            .flat_map(|row| row.iter().map(|fraction| fraction.1))
            .collect::<Vec<_>>();
        if denominators.iter().any(SecureField::is_zero) {
            return Err("zero LogUp denominator");
        }
        let mut prefixes = Vec::with_capacity(denominators.len());
        let mut product = SecureField::from(1u32);
        for denominator in &denominators {
            prefixes.push(product);
            product *= *denominator;
        }
        let mut running = SecureField::from(1u32) / product;
        for index in (0..denominators.len()).rev() {
            let denominator = denominators[index];
            denominators[index] = running * prefixes[index];
            running *= denominator;
        }
        for (tile_row, row) in tile.iter().enumerate() {
            let mut accumulated = SecureField::zero();
            for (column, (numerator, _)) in row.iter().enumerate() {
                accumulated += *numerator * denominators[tile_row * columns + column];
                output[first_row + tile_row][column] = accumulated;
            }
        }
    }
    Ok(output)
}

fn oracle_combine(
    state: &mut u64,
    alpha_powers: &[SecureField],
    z: SecureField,
    mutate_source: bool,
    row: usize,
    column: usize,
    use_index: usize,
) -> SecureField {
    let mut denominator = -z;
    let width = alpha_powers.len();
    for (word, alpha_power) in alpha_powers.iter().enumerate() {
        let mut value = oracle_word(state);
        if mutate_source && row == 0 && column == 0 && use_index == 0 && word + 1 == width {
            value = M31::from_u32_unchecked((value.0 + 1) % (M31_MODULUS as u32));
        }
        denominator += SecureField::from(value) * *alpha_power;
    }
    denominator
}

fn randomized_wide_case(
    width: usize,
    arity: usize,
    columns: usize,
    seed: u64,
    mutate_source: bool,
) -> (Vec<Vec<SecureField>>, Vec<Vec<SecureField>>) {
    let tile_rows = (512 / columns).min(REDUCTION_BLOCK);
    let rows = tile_rows + 2; // Force at least one row-tile boundary.
    let mut state = seed;
    let alpha = oracle_secure(&mut state);
    assert!(!alpha.is_zero());
    let mut alpha_powers = Vec::with_capacity(width);
    let mut power = SecureField::from(1u32);
    for _ in 0..width {
        alpha_powers.push(power);
        power *= alpha;
    }
    let z = oracle_secure(&mut state);
    let mut fractions = vec![Vec::with_capacity(columns); rows];
    let mut reference = vec![Vec::with_capacity(columns); rows];
    for row in 0..rows {
        for column in 0..columns {
            let denominator_a =
                oracle_combine(&mut state, &alpha_powers, z, mutate_source, row, column, 0);
            let raw_a = if row == 0 && column == 0 {
                M31::from_u32_unchecked(1)
            } else {
                oracle_word(&mut state)
            };
            let multiplicity_a = signed_oracle_multiplicity(raw_a, (row + column) % 2 == 1);
            assert!(!denominator_a.is_zero());
            if arity == 1 {
                let numerator = SecureField::from(multiplicity_a);
                fractions[row].push((numerator, denominator_a));
                reference[row].push(numerator / denominator_a);
                continue;
            }

            let denominator_b =
                oracle_combine(&mut state, &alpha_powers, z, mutate_source, row, column, 1);
            // Keep the changed-source discriminator independent of use B;
            // other cases exercise zeros and both multiplicity signs.
            let raw_b = if row == 0 && column == 0 {
                M31::from_u32_unchecked(0)
            } else {
                oracle_word(&mut state)
            };
            let multiplicity_b = signed_oracle_multiplicity(raw_b, (row + 2 * column) % 3 == 1);
            assert!(!denominator_b.is_zero());
            let numerator = SecureField::from(multiplicity_b) * denominator_a
                + SecureField::from(multiplicity_a) * denominator_b;
            let denominator = denominator_a * denominator_b;
            fractions[row].push((numerator, denominator));
            reference[row].push(
                SecureField::from(multiplicity_a) / denominator_a
                    + SecureField::from(multiplicity_b) / denominator_b,
            );
        }
    }
    for row in &mut reference {
        let mut accumulated = SecureField::zero();
        for value in row {
            accumulated += *value;
            *value = accumulated;
        }
    }
    (wide_lane_cpu(&fractions).unwrap(), reference)
}

#[test]
fn randomized_oracle_covers_generated_widths_arities_and_tiles() {
    // Every generated wide column class: row tiles are respectively 3, 7, 13,
    // 17, 36, 56, 85 and 256. Cross them with every generated width and arity
    // so tree padding and the second-tile boundary are never inferred from a
    // representative subset.
    let widths = [33usize, 36, 43, 58, 73, 87, 126];
    let columns = [157usize, 65, 37, 30, 14, 9, 6, 1];
    for width in widths {
        for arity in [1usize, 2] {
            for (shape_index, shape_columns) in columns.into_iter().enumerate() {
                let seed = 0x6a09_e667_f3bc_c909
                    ^ ((width as u64) << 24)
                    ^ ((arity as u64) << 16)
                    ^ shape_index as u64;
                let (actual, reference) =
                    randomized_wide_case(width, arity, shape_columns, seed, false);
                assert_eq!(
                    actual, reference,
                    "width={width} arity={arity} columns={shape_columns}"
                );
                let (changed, changed_reference) =
                    randomized_wide_case(width, arity, shape_columns, seed, true);
                assert_eq!(changed, changed_reference);
                assert_ne!(
                    changed, actual,
                    "wide source mutation was not observed at width={width} arity={arity} \
                     columns={shape_columns}"
                );
            }
        }
    }
}

#[test]
fn zero_denominator_is_fail_closed_across_tiles() {
    let mut fractions = vec![vec![(SecureField::from(3u32), SecureField::from(5u32)); 9]; 58];
    fractions[56][4].1 = SecureField::zero();
    assert_eq!(
        wide_lane_cpu(&fractions),
        Err("zero LogUp denominator"),
        "a zero in the second row tile must reject the whole proof"
    );
}
