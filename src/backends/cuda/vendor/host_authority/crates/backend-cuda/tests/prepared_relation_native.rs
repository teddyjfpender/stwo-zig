//! Native CUDA differential for the prepared Cairo relation graph.

#![cfg(stwo_cuda_link)]

use core::ffi::c_void;

use num_traits::Zero;
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use stwo::core::utils::{bit_reverse, coset_order_to_circle_domain_order};
use stwo_backend_cuda::{
    relation_batch_fused_eligible, relation_batch_one_read_eligible, ArenaLayout, ArenaSlotId,
    ArenaSlotSpec, CudaExecContext, DeviceArena, PreparedRelationGraph, RelationBatchProgram,
    RelationChallenges, RelationColumnDescriptor, RelationGraphSlots, RelationInstanceSlots,
    RelationInstanceSources, RelationKernelProgram, RelationLaunchMode, RelationMultiplicityKind,
    RelationRowExtent, RelationSourceLayout, RelationTailMode, RelationTupleKind,
    RelationUseDescriptor, RELATION_FUSED_MAX_TUPLE_WORDS,
};
#[cfg(feature = "test-only-relation-ab")]
use stwo_backend_cuda::{
    CudaGraphExec, RelationFusedTestFunctionResources, RelationFusedTestStrategy,
};

#[cfg(feature = "test-only-relation-ab")]
#[path = "support/relation_native_ab.rs"]
mod relation_native_ab;

const SECURE_WORDS: usize = 4;
const LARGE_MEMORY_VALUE_ID_BASE: u32 = 0x4000_0000;
const WIDE_TUPLE_WORDS: u32 = 33;
const NARROW_FALLBACK_COLUMNS: usize = 513;
const ZERO_DENOMINATOR_DIFFERENTIAL_BATCH: usize = 0;
const ZERO_DENOMINATOR_DIFFERENTIAL_INSTANCE: usize = 0;
const ZERO_DENOMINATOR_DIFFERENTIAL_COLUMN: usize = 0;
const ZERO_DENOMINATOR_DIFFERENTIAL_SOURCE: usize = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
struct InstanceSnapshot {
    batch_index: usize,
    instance_index: usize,
    rows: u32,
    columns: u32,
    coordinates: Vec<Vec<u32>>,
    claimed_sum: [u32; SECURE_WORDS],
}

fn relation_use(
    tuple_kind: RelationTupleKind,
    tuple_arg: u32,
    tuple_words: u32,
    relation_id: u32,
    multiplicity_kind: RelationMultiplicityKind,
    multiplicity_arg: u32,
    negative: bool,
) -> RelationUseDescriptor {
    RelationUseDescriptor {
        tuple_kind,
        tuple_arg,
        tuple_words,
        relation_id,
        multiplicity_kind,
        multiplicity_arg,
        negative,
    }
}

fn cairo_program() -> RelationKernelProgram {
    use {RelationMultiplicityKind as Multiplicity, RelationTupleKind as Tuple};

    // Exercise all body classes in one captured graph: <=32-word
    // suffix/recompute, generated-Cairo-wide one-read, the 513-column
    // suffix/recompute fallback, and a tuple beyond the audited envelope that
    // retains the 3-stage lane.
    let wide_tuple_words = WIDE_TUPLE_WORDS;
    let fallback_tuple_words = RELATION_FUSED_MAX_TUPLE_WORDS + 1;
    let narrow_fallback_column = RelationColumnDescriptor {
        uses: vec![relation_use(
            Tuple::LookupWords,
            0,
            2,
            37,
            Multiplicity::One,
            0,
            false,
        )],
    };
    let mut program = RelationKernelProgram {
        relation_graph_hash: 0x7396_3831_c53d_f4a2,
        template_use_count: 9 + NARROW_FALLBACK_COLUMNS,
        max_alpha_powers: fallback_tuple_words,
        batches: vec![
            RelationBatchProgram {
                source_layout: RelationSourceLayout::LookupWords { words: 6 },
                columns: vec![
                    RelationColumnDescriptor {
                        uses: vec![
                            relation_use(
                                Tuple::LookupWords,
                                0,
                                3,
                                3,
                                Multiplicity::LookupWord,
                                5,
                                false,
                            ),
                            relation_use(
                                Tuple::LookupWords,
                                2,
                                3,
                                5,
                                Multiplicity::Enabler,
                                0,
                                true,
                            ),
                        ],
                    },
                    RelationColumnDescriptor {
                        uses: vec![relation_use(
                            Tuple::LookupWords,
                            1,
                            4,
                            7,
                            Multiplicity::LookupWord,
                            0,
                            false,
                        )],
                    },
                ],
                instances: vec![RelationRowExtent::Exact {
                    n_real_rows: 509,
                    padded_rows: 512,
                    source_offset_rows: 0,
                }],
            },
            RelationBatchProgram {
                source_layout: RelationSourceLayout::MemoryAddress { chunks: 2 },
                columns: vec![RelationColumnDescriptor {
                    uses: vec![
                        relation_use(
                            Tuple::MemoryAddressChunk,
                            0,
                            3,
                            11,
                            Multiplicity::MemoryAddressChunk,
                            0,
                            false,
                        ),
                        relation_use(
                            Tuple::MemoryAddressChunk,
                            1,
                            3,
                            13,
                            Multiplicity::MemoryAddressChunk,
                            1,
                            true,
                        ),
                    ],
                }],
                instances: vec![RelationRowExtent::Exact {
                    n_real_rows: 6,
                    padded_rows: 8,
                    source_offset_rows: 0,
                }],
            },
            RelationBatchProgram {
                source_layout: RelationSourceLayout::MemoryBig { value_words: 3 },
                columns: vec![RelationColumnDescriptor {
                    uses: vec![
                        relation_use(
                            Tuple::MemoryBigLimbs,
                            0,
                            3,
                            17,
                            Multiplicity::MemoryBig,
                            3,
                            false,
                        ),
                        relation_use(
                            Tuple::MemoryBigValue,
                            0,
                            5,
                            19,
                            Multiplicity::MemoryBig,
                            3,
                            true,
                        ),
                    ],
                }],
                instances: vec![
                    RelationRowExtent::Exact {
                        n_real_rows: 5,
                        padded_rows: 8,
                        source_offset_rows: 0,
                    },
                    RelationRowExtent::Exact {
                        n_real_rows: 7,
                        padded_rows: 8,
                        source_offset_rows: 8,
                    },
                ],
            },
            RelationBatchProgram {
                source_layout: RelationSourceLayout::LookupWords {
                    words: wide_tuple_words + 1,
                },
                columns: vec![RelationColumnDescriptor {
                    uses: vec![relation_use(
                        Tuple::LookupWords,
                        0,
                        wide_tuple_words,
                        29,
                        Multiplicity::LookupWord,
                        wide_tuple_words,
                        false,
                    )],
                }],
                instances: vec![RelationRowExtent::Exact {
                    n_real_rows: 13,
                    padded_rows: 16,
                    source_offset_rows: 0,
                }],
            },
            RelationBatchProgram {
                source_layout: RelationSourceLayout::LookupWords {
                    words: fallback_tuple_words + 1,
                },
                columns: vec![RelationColumnDescriptor {
                    uses: vec![relation_use(
                        Tuple::LookupWords,
                        0,
                        fallback_tuple_words,
                        31,
                        Multiplicity::LookupWord,
                        fallback_tuple_words,
                        true,
                    )],
                }],
                instances: vec![RelationRowExtent::Exact {
                    n_real_rows: 11,
                    padded_rows: 16,
                    source_offset_rows: 0,
                }],
            },
            RelationBatchProgram {
                source_layout: RelationSourceLayout::LookupWords { words: 2 },
                columns: vec![narrow_fallback_column; NARROW_FALLBACK_COLUMNS],
                instances: vec![RelationRowExtent::Exact {
                    n_real_rows: 7,
                    padded_rows: 8,
                    source_offset_rows: 0,
                }],
            },
        ],
    };
    // Exercise a non-power-of-two column batch and a three-step dependency
    // chain through the one prepared launch.
    let repeated = program.batches[0].columns[0].clone();
    program.template_use_count += repeated.uses.len();
    program.batches[0].columns.push(repeated);
    program
}

fn host_sources(seed: u32) -> Vec<Vec<Vec<u32>>> {
    let lookup = vec![(0..6 * 512)
        .map(|index| (seed + 7 + 17 * index as u32) % 1009)
        .collect()];

    let memory_address = vec![
        (0..8).map(|row| seed + 101 + row * 3).collect(),
        (0..8)
            .map(|row| if row < 6 { seed + 2 + row } else { 0 })
            .collect(),
        (0..8).map(|row| seed + 211 + row * 5).collect(),
        (0..8)
            .map(|row| if row < 6 { seed + 5 + row * 2 } else { 0 })
            .collect(),
    ];

    let memory_big = |instance: u32, n_real_rows: u32| {
        vec![
            (0..8).map(|row| seed + 307 + 31 * instance + row).collect(),
            (0..8)
                .map(|row| seed + 401 + 37 * instance + 3 * row)
                .collect(),
            (0..8)
                .map(|row| seed + 503 + 41 * instance + 5 * row)
                .collect(),
            (0..8)
                .map(|row| {
                    if row < n_real_rows {
                        seed + 3 + 7 * instance + row
                    } else {
                        0
                    }
                })
                .collect(),
        ]
    };

    // One-read wide lookup batch: 33 tuple words plus its multiplicity column.
    let wide_lookup = vec![(0..(WIDE_TUPLE_WORDS + 1) * 16)
        .map(|index| (seed + 13 + 29 * index) % 2027)
        .collect()];

    // One word beyond the audited wide envelope, retained on the 3-stage lane.
    let fallback_lookup = vec![(0..(RELATION_FUSED_MAX_TUPLE_WORDS + 2) * 16)
        .map(|index| (seed + 19 + 31 * index) % 2039)
        .collect()];

    // 513 columns force the fused suffix/recompute fallback while remaining
    // inside the <=32-word tuple envelope.
    let narrow_fallback_lookup = vec![(0..2 * 8)
        .map(|index| (seed + 23 + 37 * index) % 2053)
        .collect()];

    vec![
        lookup,
        memory_address,
        memory_big(0, 5),
        memory_big(1, 7),
        wide_lookup,
        fallback_lookup,
        narrow_fallback_lookup,
    ]
}

fn alpha_powers(alpha: SecureField, count: usize) -> Vec<SecureField> {
    let mut power = SecureField::from(1u32);
    (0..count)
        .map(|_| {
            let result = power;
            power *= alpha;
            result
        })
        .collect()
}

fn upload_sources(
    arena: &DeviceArena,
    source_slots: &[Vec<ArenaSlotId>],
    sources: &[Vec<Vec<u32>>],
) {
    assert_eq!(source_slots.len(), sources.len());
    for (slots, columns) in source_slots.iter().zip(sources) {
        assert_eq!(slots.len(), columns.len());
        for (&slot, column) in slots.iter().zip(columns) {
            assert!(column.iter().all(|&word| word < P));
            let destination = arena.bind(slot).unwrap();
            assert_eq!(destination.len_words(), column.len());
            unsafe {
                arena
                    .context()
                    .memcpy_h2d_async(
                        destination.as_void_ptr(),
                        column.as_ptr().cast::<c_void>(),
                        core::mem::size_of_val(column.as_slice()),
                    )
                    .unwrap();
            }
        }
    }
    arena.context().sync().unwrap();
}

fn read_snapshot(
    arena: &DeviceArena,
    prepared: &PreparedRelationGraph<'_>,
) -> Vec<InstanceSnapshot> {
    let mut snapshots = Vec::new();
    for output in prepared.outputs() {
        let rows = output.rows as usize;
        let mut coordinates = vec![vec![0u32; rows]; output.coordinates.len()];
        for (source, destination) in output.coordinates.iter().zip(&mut coordinates) {
            unsafe {
                arena
                    .context()
                    .memcpy_d2h_async(
                        destination.as_mut_ptr().cast(),
                        source.as_void_ptr().cast_const(),
                        core::mem::size_of_val(destination.as_slice()),
                    )
                    .unwrap();
            }
        }
        let mut claimed_sum = [0u32; SECURE_WORDS];
        unsafe {
            arena
                .context()
                .memcpy_d2h_async(
                    claimed_sum.as_mut_ptr().cast(),
                    output.claimed_sum.as_void_ptr().cast_const(),
                    core::mem::size_of_val(&claimed_sum),
                )
                .unwrap();
        }
        snapshots.push(InstanceSnapshot {
            batch_index: output.batch_index,
            instance_index: output.instance_index,
            rows: output.rows,
            columns: output.columns,
            coordinates,
            claimed_sum,
        });
    }
    arena.context().sync().unwrap();
    snapshots
}

fn tuple_word(
    sources: &[Vec<u32>],
    rows: u32,
    row: u32,
    source_offset_rows: u32,
    relation_use: RelationUseDescriptor,
    word: u32,
) -> BaseField {
    if word == 0 {
        return BaseField::from_u32_unchecked(relation_use.relation_id);
    }
    let raw = match relation_use.tuple_kind {
        RelationTupleKind::LookupWords => {
            sources[0][((relation_use.tuple_arg + word) * rows + row) as usize]
        }
        RelationTupleKind::MemoryAddressChunk => {
            if word == 1 {
                row + 1 + relation_use.tuple_arg * rows
            } else {
                sources[(relation_use.tuple_arg * 2) as usize][row as usize]
            }
        }
        RelationTupleKind::MemoryBigLimbs => {
            sources[(relation_use.tuple_arg + word - 1) as usize][row as usize]
        }
        RelationTupleKind::MemoryBigValue => {
            if word == 1 {
                (row + source_offset_rows) | LARGE_MEMORY_VALUE_ID_BASE
            } else {
                sources[(word - 2) as usize][row as usize]
            }
        }
        other => panic!("uncovered native relation tuple layout: {other:?}"),
    };
    BaseField::from_u32_unchecked(raw)
}

fn multiplicity(
    sources: &[Vec<u32>],
    rows: u32,
    row: u32,
    n_real_rows: u32,
    relation_use: RelationUseDescriptor,
) -> BaseField {
    let value = match relation_use.multiplicity_kind {
        RelationMultiplicityKind::One => BaseField::from_u32_unchecked(1),
        RelationMultiplicityKind::Enabler => {
            BaseField::from_u32_unchecked(u32::from(row < n_real_rows))
        }
        RelationMultiplicityKind::LookupWord => BaseField::from_u32_unchecked(
            sources[0][(relation_use.multiplicity_arg * rows + row) as usize],
        ),
        RelationMultiplicityKind::MemoryAddressChunk => BaseField::from_u32_unchecked(
            sources[(relation_use.multiplicity_arg * 2 + 1) as usize][row as usize],
        ),
        RelationMultiplicityKind::MemoryBig => BaseField::from_u32_unchecked(
            sources[relation_use.multiplicity_arg as usize][row as usize],
        ),
        other => panic!("uncovered native relation multiplicity layout: {other:?}"),
    };
    if relation_use.negative {
        -value
    } else {
        value
    }
}

fn combine(
    sources: &[Vec<u32>],
    rows: u32,
    row: u32,
    source_offset_rows: u32,
    relation_use: RelationUseDescriptor,
    alphas: &[SecureField],
    z: SecureField,
) -> SecureField {
    (0..relation_use.tuple_words).fold(-z, |acc, word| {
        acc + alphas[word as usize]
            * tuple_word(sources, rows, row, source_offset_rows, relation_use, word)
    })
}

fn circle_prefix_sum(mut values: Vec<SecureField>) -> Vec<SecureField> {
    bit_reverse(&mut values);
    let mut coset = Vec::with_capacity(values.len());
    for index in 0..values.len() / 2 {
        coset.extend([values[index], values[values.len() - 1 - index]]);
    }
    let mut sum = SecureField::zero();
    for value in &mut coset {
        sum += *value;
        *value = sum;
    }
    let mut output = coset_order_to_circle_domain_order(&coset);
    bit_reverse(&mut output);
    output
}

fn reference(
    program: &RelationKernelProgram,
    sources: &[Vec<Vec<u32>>],
    alphas: &[SecureField],
    z: SecureField,
) -> Vec<InstanceSnapshot> {
    let mut result = Vec::new();
    let mut source_index = 0usize;
    for (batch_index, batch) in program.batches.iter().enumerate() {
        for (instance_index, extent) in batch.instances.iter().copied().enumerate() {
            let RelationRowExtent::Exact {
                n_real_rows,
                padded_rows,
                source_offset_rows,
            } = extent
            else {
                panic!("native reference requires exact row extents")
            };
            let instance_sources = &sources[source_index];
            source_index += 1;
            let mut columns: Vec<Vec<SecureField>> = Vec::with_capacity(batch.columns.len());
            for column in &batch.columns {
                let values = (0..padded_rows)
                    .map(|row| {
                        let first = column.uses[0];
                        let denominator_a = combine(
                            instance_sources,
                            padded_rows,
                            row,
                            source_offset_rows,
                            first,
                            alphas,
                            z,
                        );
                        let multiplicity_a =
                            multiplicity(instance_sources, padded_rows, row, n_real_rows, first);
                        let (numerator, denominator) = if column.uses.len() == 2 {
                            let second = column.uses[1];
                            let denominator_b = combine(
                                instance_sources,
                                padded_rows,
                                row,
                                source_offset_rows,
                                second,
                                alphas,
                                z,
                            );
                            let multiplicity_b = multiplicity(
                                instance_sources,
                                padded_rows,
                                row,
                                n_real_rows,
                                second,
                            );
                            (
                                denominator_a * multiplicity_b + denominator_b * multiplicity_a,
                                denominator_a * denominator_b,
                            )
                        } else {
                            (SecureField::from(multiplicity_a), denominator_a)
                        };
                        assert_ne!(denominator, SecureField::zero(), "zero denominator");
                        numerator / denominator
                            + columns
                                .last()
                                .map_or(SecureField::zero(), |previous| previous[row as usize])
                    })
                    .collect();
                columns.push(values);
            }

            let claimed_sum: SecureField = columns.last().unwrap().iter().copied().sum();
            let shift = claimed_sum / BaseField::from_u32_unchecked(padded_rows);
            let last = columns.last_mut().unwrap();
            for value in last.iter_mut() {
                *value -= shift;
            }
            *last = circle_prefix_sum(core::mem::take(last));

            let coordinates = columns
                .iter()
                .flat_map(|column| {
                    (0..SECURE_WORDS).map(|coordinate| {
                        column
                            .iter()
                            .map(|value| value.to_m31_array()[coordinate].0)
                            .collect()
                    })
                })
                .collect();
            result.push(InstanceSnapshot {
                batch_index,
                instance_index,
                rows: padded_rows,
                columns: batch.columns.len().try_into().unwrap(),
                coordinates,
                claimed_sum: claimed_sum.to_m31_array().map(|coordinate| coordinate.0),
            });
        }
    }
    assert_eq!(source_index, sources.len());
    result
}

fn assert_canonical(snapshot: &[InstanceSnapshot]) {
    for instance in snapshot {
        for word in instance
            .coordinates
            .iter()
            .flatten()
            .chain(instance.claimed_sum.iter())
        {
            assert!(*word < P, "non-canonical relation output word {word:#x}");
        }
    }
}

/// Full eager / captured / mutated-replay parity flow, shared by every
/// body-lane x tail-lane combination: the 3-stage and fused bodies, under the
/// segmented and decoupled-lookback scan tails, must all match the host
/// reference byte-for-byte on the same program and fixtures.
fn run_eager_capture_and_mutated_replay(
    mode: RelationLaunchMode,
    tail: RelationTailMode,
    expected_kernel_nodes: &[u64],
    implicit_launch: bool,
    poison_zero_denominator: bool,
    same_binary_ab: bool,
) {
    #[cfg(not(feature = "test-only-relation-ab"))]
    {
        assert!(
            !same_binary_ab,
            "same-binary A/B requires --features test-only-relation-ab"
        );
        assert_ne!(
            std::env::var("STWO_RELATION_NATIVE_AB").as_deref(),
            Ok("1"),
            "STWO_RELATION_NATIVE_AB requires --features test-only-relation-ab"
        );
        assert_ne!(
            std::env::var("STWO_RELATION_ALL_ONE_READ_TEST").as_deref(),
            Ok("1"),
            "the all-one-read baseline requires --features test-only-relation-ab"
        );
    }
    let program = cairo_program();
    assert_eq!(
        program
            .batches
            .iter()
            .map(relation_batch_fused_eligible)
            .collect::<Vec<_>>(),
        vec![true, true, true, true, false, true],
        "fused and 3-stage body classification drifted"
    );
    assert_eq!(
        program
            .batches
            .iter()
            .map(relation_batch_one_read_eligible)
            .collect::<Vec<_>>(),
        vec![true, true, true, true, false, false],
        "one-read admissibility and 513-column fallback classification drifted"
    );
    let scan_probe = (1..=512)
        .map(SecureField::from)
        .collect::<Vec<SecureField>>();
    let mut linear_sum = SecureField::zero();
    let linear_scan = scan_probe
        .iter()
        .map(|&value| {
            linear_sum += value;
            linear_sum
        })
        .collect::<Vec<_>>();
    assert_ne!(
        circle_prefix_sum(scan_probe),
        linear_scan,
        "512-row fixture must detect a linear row-order scan"
    );
    let requirements = program.requirements_for_mode(mode).unwrap();
    for requirement in &requirements.instances {
        let batch = &program.batches[requirement.batch_index];
        let expected_denominator_words =
            if mode == RelationLaunchMode::Fused && relation_batch_fused_eligible(batch) {
                1
            } else {
                requirement.output_words
            };
        assert_eq!(
            requirement.denominator_words, expected_denominator_words,
            "denominator layout disagrees with {mode:?} eligibility"
        );
    }
    let mut next_id = 1u32;
    let mut id = || {
        let result = ArenaSlotId(next_id);
        next_id += 1;
        result
    };
    let slots = RelationGraphSlots {
        descriptors: id(),
        alphas: id(),
        z: id(),
        inverse_scratch: id(),
        reduction_a: id(),
        reduction_b: id(),
        scan_eval_scratch: id(),
        scan_temp_scratch: id(),
        scan_descriptors: id(),
        fraction_pointers: id(),
        fraction_geometry: id(),
        instances: requirements
            .instances
            .iter()
            .map(|instance| RelationInstanceSlots {
                source_pointers: id(),
                output_pointers: id(),
                output_coordinates: (0..instance.output_coordinate_count)
                    .map(|_| id())
                    .collect(),
                denominators: id(),
                claimed_sum: id(),
            })
            .collect(),
    };
    drop(id);

    let first_sources = host_sources(23);
    let source_slots: Vec<Vec<ArenaSlotId>> = first_sources
        .iter()
        .map(|columns| {
            columns
                .iter()
                .map(|_| {
                    let result = ArenaSlotId(next_id);
                    next_id += 1;
                    result
                })
                .collect()
        })
        .collect();
    let mut requested: Vec<_> = requirements
        .arena_slot_requirements(&slots)
        .unwrap()
        .into_iter()
        .map(|requirement| {
            (
                requirement.id,
                requirement.len_words,
                requirement.alignment_words,
            )
        })
        .collect();
    requested.extend(
        source_slots
            .iter()
            .flatten()
            .copied()
            .zip(first_sources.iter().flatten().map(Vec::len))
            .map(|(slot, len_words)| (slot, len_words, 1)),
    );
    let mut offset = 0usize;
    let mut specs = Vec::with_capacity(requested.len());
    for (slot, len_words, alignment_words) in requested {
        offset = offset.next_multiple_of(alignment_words);
        specs.push(ArenaSlotSpec {
            id: slot,
            offset_words: offset,
            len_words,
            alignment_words,
        });
        offset += len_words;
    }
    let arena = DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap();
    upload_sources(&arena, &source_slots, &first_sources);
    let device_sources = source_slots
        .iter()
        .map(|slots| RelationInstanceSources {
            columns: slots
                .iter()
                .map(|&slot| arena.bind(slot).unwrap())
                .collect(),
        })
        .collect::<Vec<_>>();

    let first_alphas = alpha_powers(
        SecureField::from_u32_unchecked(3, 5, 7, 11),
        program.max_alpha_powers as usize,
    );
    let first_z = SecureField::from_u32_unchecked(13, 17, 19, 23);
    let prepared = PreparedRelationGraph::prepare_with_mode(
        &arena,
        &program,
        mode,
        &slots,
        &device_sources,
        RelationChallenges {
            alpha_powers: &first_alphas,
            z: first_z,
        },
    )
    .unwrap();

    if mode == RelationLaunchMode::Fused {
        assert!(matches!(
            prepared.launch_with_modes(RelationLaunchMode::ThreeStage, tail),
            Err(
                stwo_backend_cuda::RelationGraphError::CompactFusedLaunchModeMismatch {
                    requested: RelationLaunchMode::ThreeStage,
                }
            )
        ));
    }
    let launch = |prepared: &PreparedRelationGraph<'_>| {
        #[cfg(feature = "test-only-relation-ab")]
        if std::env::var("STWO_RELATION_ALL_ONE_READ_TEST").as_deref() == Ok("1") {
            assert_eq!(mode, RelationLaunchMode::Fused);
            return prepared
                .launch_fused_test_strategy(RelationFusedTestStrategy::AllOneReadBaseline, tail);
        }
        if implicit_launch {
            prepared.launch()
        } else {
            prepared.launch_with_modes(mode, tail)
        }
    };
    launch(&prepared).unwrap();
    let eager = read_snapshot(&arena, &prepared);
    assert_canonical(&eager);
    assert_eq!(
        eager,
        reference(&program, &first_sources, &first_alphas, first_z)
    );
    assert_eq!(
        eager
            .iter()
            .map(|instance| (
                instance.batch_index,
                instance.instance_index,
                instance.rows,
                instance.columns,
                instance.coordinates.len(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (0, 0, 512, 3, 12),
            (1, 0, 8, 1, 4),
            (2, 0, 8, 1, 4),
            (2, 1, 8, 1, 4),
            (3, 0, 16, 1, 4),
            (4, 0, 16, 1, 4),
            (5, 0, 8, 513, 2052),
        ]
    );

    let capture = arena.context().capture().unwrap();
    launch(&prepared).unwrap();
    let graph = capture.finish().unwrap();
    assert!(
        expected_kernel_nodes.contains(&graph.kernel_nodes()),
        "relation capture node budget changed for {mode:?}/{tail:?}: expected one of \
         {expected_kernel_nodes:?}, got {}",
        graph.kernel_nodes()
    );
    arena.context().reset_telemetry();
    graph.launch(arena.context()).unwrap();
    let captured = read_snapshot(&arena, &prepared);
    let telemetry = arena.context().telemetry();
    assert_eq!(telemetry.graph_launches, 1);
    assert!(telemetry.kernel_launches > 0);
    eprintln!(
        "prepared_relation_capture: instances={} columns={} kernel_nodes={}",
        captured.len(),
        captured
            .iter()
            .map(|instance| u64::from(instance.columns))
            .sum::<u64>(),
        telemetry.kernel_launches
    );
    assert_eq!(captured, eager);

    let second_sources = host_sources(137);
    upload_sources(&arena, &source_slots, &second_sources);
    let second_alphas = alpha_powers(
        SecureField::from_u32_unchecked(29, 31, 37, 41),
        program.max_alpha_powers as usize,
    );
    let second_z = SecureField::from_u32_unchecked(43, 47, 53, 59);
    prepared
        .upload_challenges_at_transcript_boundary(RelationChallenges {
            alpha_powers: &second_alphas,
            z: second_z,
        })
        .unwrap();
    graph.launch(arena.context()).unwrap();
    let replayed = read_snapshot(&arena, &prepared);
    assert_canonical(&replayed);
    assert_eq!(
        replayed,
        reference(&program, &second_sources, &second_alphas, second_z)
    );
    assert_ne!(replayed, eager, "replay ignored mutated sources/challenges");

    #[cfg(feature = "test-only-relation-ab")]
    if same_binary_ab || std::env::var("STWO_RELATION_NATIVE_AB").as_deref() == Ok("1") {
        assert_eq!(mode, RelationLaunchMode::Fused);
        assert_eq!(tail, RelationTailMode::Segmented);
        assert!(!implicit_launch);
        assert!(!poison_zero_denominator);
        relation_native_ab::run(
            &arena,
            &prepared,
            &program,
            &source_slots,
            &second_sources,
            &second_alphas,
            second_z,
            &graph,
            expected_kernel_nodes,
        );
    }

    if poison_zero_denominator {
        assert_eq!(mode, RelationLaunchMode::Fused);
        // Force a selector-changing narrow batch's first denominator to zero.
        // The historical baseline must trap in one-read while the adaptive
        // candidate must trap in suffix/recompute on the identical fixture.
        let batch = &program.batches[ZERO_DENOMINATOR_DIFFERENTIAL_BATCH];
        let relation_use = batch.columns[ZERO_DENOMINATOR_DIFFERENTIAL_COLUMN].uses[0];
        let RelationRowExtent::Exact {
            padded_rows,
            source_offset_rows,
            ..
        } = batch.instances[ZERO_DENOMINATOR_DIFFERENTIAL_INSTANCE]
        else {
            panic!("zero-denominator differential requires an exact row extent")
        };
        let sources = &second_sources[ZERO_DENOMINATOR_DIFFERENTIAL_SOURCE];
        let mut zero_z = SecureField::zero();
        for word in 0..relation_use.tuple_words {
            zero_z += SecureField::from(tuple_word(
                sources,
                padded_rows,
                0,
                source_offset_rows,
                relation_use,
                word,
            )) * second_alphas[word as usize];
        }
        prepared
            .upload_challenges_at_transcript_boundary(RelationChallenges {
                alpha_powers: &second_alphas,
                z: zero_z,
            })
            .unwrap();
        graph.launch(arena.context()).unwrap();
        assert!(
            arena.context().sync().is_err(),
            "a zero denominator must poison the selected relation lane"
        );
        // CUDA documents an illegal-instruction trap as context-fatal. This
        // oracle already runs in an isolated child process; exit successfully
        // now so poisoned-context destructors cannot obscure the observed
        // stream error or contaminate any other native test.
        std::process::exit(0);
    }
}

#[test]
fn eager_capture_and_mutated_replay_match_cairo_reference() {
    // One pairs node + two fraction nodes (ragged inverse, global chain) +
    // five segmented tail nodes.
    run_eager_capture_and_mutated_replay(
        RelationLaunchMode::ThreeStage,
        RelationTailMode::Segmented,
        &[8],
        false,
        false,
        false,
    );
}

#[test]
fn fused_eager_capture_and_mutated_replay_match_cairo_reference() {
    // One adaptive fused node covers narrow + one-read wide instances. Three
    // per-instance fallback nodes cover only the >126-word batch, followed by
    // five segmented tail nodes.
    run_eager_capture_and_mutated_replay(
        RelationLaunchMode::Fused,
        RelationTailMode::Segmented,
        &[9],
        false,
        false,
        false,
    );
}

#[cfg(feature = "test-only-relation-ab")]
#[test]
fn fused_same_binary_selector_ab_receipt() {
    // Direct gate:
    // STWO_PARITY_REF_STWO_HEAD=<40hex> \
    // STWO_RELATION_NATIVE_AB_RECEIPT=<new.json> \
    // cargo test --release --locked -p stwo-backend-cuda \
    // --features test-only-relation-ab --test prepared_relation_native \
    // fused_same_binary_selector_ab_receipt -- --exact --nocapture --test-threads=1
    run_eager_capture_and_mutated_replay(
        RelationLaunchMode::Fused,
        RelationTailMode::Segmented,
        &[9],
        false,
        false,
        true,
    );
}

#[test]
fn scan_tail_eager_capture_and_mutated_replay_match_cairo_reference() {
    // Three 3-stage body nodes + two scan-tail kernels (lookback scan, shift
    // fixup); the partition-descriptor clear captures as a memset node, which
    // the kernel-node budget deliberately excludes.
    run_eager_capture_and_mutated_replay(
        RelationLaunchMode::ThreeStage,
        RelationTailMode::Scan,
        &[5],
        false,
        false,
        false,
    );
}

#[test]
fn fused_scan_tail_eager_capture_and_mutated_replay_match_cairo_reference() {
    // Four body nodes (adaptive fused + too-wide fallback
    // pairs/inverse/chain) + two scan-tail kernels.
    run_eager_capture_and_mutated_replay(
        RelationLaunchMode::Fused,
        RelationTailMode::Scan,
        &[6],
        false,
        false,
        false,
    );
}

#[test]
fn compact_fused_implicit_launch_matches_cairo_reference() {
    // `launch()` must honor the preparation's compact fused mode even when
    // STWO_CUDA_RELATION_FUSED is unset. The process-wide tail may be either
    // segmented (9 nodes) or scan (6); neither 3-stage topology is accepted.
    run_eager_capture_and_mutated_replay(
        RelationLaunchMode::Fused,
        RelationTailMode::Segmented,
        &[6, 9],
        true,
        false,
        false,
    );
}

#[test]
fn fused_zero_denominator_child_process() {
    if std::env::var_os("STWO_RELATION_ZERO_DENOMINATOR_CHILD").is_none() {
        return;
    }
    run_eager_capture_and_mutated_replay(
        RelationLaunchMode::Fused,
        RelationTailMode::Segmented,
        &[9],
        false,
        true,
        false,
    );
}

#[test]
fn fused_zero_denominator_poison_is_fail_closed() {
    // A device trap invalidates CUDA's process context. Run that contract test
    // in this test binary's child process so the remaining native parity suite
    // cannot inherit a poisoned primary context.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("fused_zero_denominator_child_process")
        .arg("--nocapture")
        .env("STWO_RELATION_ZERO_DENOMINATOR_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success(), "isolated zero-denominator oracle failed");
}
