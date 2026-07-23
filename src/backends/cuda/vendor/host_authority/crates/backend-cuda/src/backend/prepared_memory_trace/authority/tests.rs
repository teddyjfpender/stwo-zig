use super::*;

fn requirements() -> MemoryBaseTraceRequirements {
    MemoryBaseTraceRequirements {
        n_addrs: 7,
        raw_address_words: 7,
        address_rows: 16,
        address_count_words: 16 * 16,
        big_source_words: 32,
        big_count_words: 48,
        big_parts: [0usize, 16, 32]
            .into_iter()
            .enumerate()
            .map(
                |(part_ordinal, source_offset)| MemoryBaseTraceValuePartRequirements {
                    part_ordinal: part_ordinal as u32,
                    source_offset,
                    row_count: 16,
                },
            )
            .collect(),
        small_source_words: 16,
        small_count_words: 16,
        small_part: MemoryBaseTraceValuePartRequirements {
            part_ordinal: 0,
            source_offset: 0,
            row_count: 16,
        },
        rc99_lut_words: 1 << 18,
        rc99_count_words: 8 << 18,
    }
}

#[test]
fn sliced_v2_abi_preserves_legacy_symbols_and_seals_exact_arguments() {
    let wrapper_source = core::str::from_utf8(WRAPPER_SOURCE).unwrap();
    assert_eq!(
        MemoryBaseTraceAbi::AddressV1.entry_symbol(),
        "memory_address_base_trace_on"
    );
    assert_eq!(
        MemoryBaseTraceAbi::ValueV1.entry_symbol(),
        "memory_value_base_trace_on"
    );
    assert_eq!(
        MemoryBaseTraceAbi::AddressSlicedV2.entry_symbol(),
        "memory_address_base_trace_sliced_on"
    );
    assert_eq!(
        MemoryBaseTraceAbi::ValueSlicedV2.entry_symbol(),
        "memory_value_base_trace_sliced_on"
    );
    assert_eq!(
        MemoryBaseTraceAbi::Rc99V1.kernel_symbol(),
        "rc99_count_on_kernel"
    );
    assert_eq!(
        MemoryBaseTraceAbi::AddressSlicedV2
            .arguments()
            .iter()
            .map(|argument| argument.name)
            .collect::<Vec<_>>(),
        [
            "address_ids",
            "address_id_words",
            "multiplicities",
            "multiplicity_words",
            "column_length",
            "outputs_host",
            "stream",
        ]
    );
    assert_eq!(
        MemoryBaseTraceAbi::ValueSlicedV2
            .arguments()
            .iter()
            .map(|argument| argument.name)
            .collect::<Vec<_>>(),
        [
            "sources_host",
            "n_limbs",
            "source_slice_words",
            "multiplicities",
            "multiplicity_slice_words",
            "column_length",
            "outputs_host",
            "stream",
        ]
    );
    assert!(wrapper_source
        .contains("memory_address_base_trace_sliced_kernel<<<blocks, MW_BLOCK, 0, stream>>>"));
    assert!(wrapper_source
        .contains("memory_value_base_trace_sliced_kernel<<<blocks, MW_BLOCK, 0, stream>>>"));
    assert!(wrapper_source.contains("rc99_count_on_kernel<<<blocks, MW_BLOCK, 0, stream>>>"));
    for abi in [
        MemoryBaseTraceAbi::AddressV1,
        MemoryBaseTraceAbi::ValueV1,
        MemoryBaseTraceAbi::Rc99V1,
        MemoryBaseTraceAbi::AddressSlicedV2,
        MemoryBaseTraceAbi::ValueSlicedV2,
    ] {
        assert!(abi.source_declares_entry(WRAPPER_SOURCE));
    }
    let drifted =
        wrapper_source.replace("uint32_t source_slice_words", "uint32_t wrong_slice_words");
    assert!(!MemoryBaseTraceAbi::ValueSlicedV2.source_declares_entry(drifted.as_bytes()));
}

#[test]
fn address_sliced_geometry_is_algebraically_identical_at_boundaries() {
    let raw = (0..7).map(|word| word as u32 * 13 + 5).collect::<Vec<_>>();
    let sliced = &raw[1..];
    for index in 0..16 * 16 {
        let legacy = (index + 1 < raw.len()).then(|| raw[index + 1]).unwrap_or(0);
        let v2 = sliced.get(index).copied().unwrap_or(0);
        assert_eq!(legacy, v2, "address index {index}");
    }

    let contract = MemoryBaseTraceContract::compile(&requirements()).unwrap();
    let address = &contract.steps()[0];
    assert_eq!(address.abi(), MemoryBaseTraceAbi::AddressSlicedV2);
    assert_eq!(address.source_offset(), 1);
    assert_eq!(address.source_words(), 6);
    assert_eq!(
        address.reads()[0],
        access(MemoryBaseTraceEffectRole::AddressTable, 0, 1, 6)
    );
}

#[test]
fn value_slices_match_absolute_indexing_through_partial_and_empty_tails() {
    let source = (0..32).map(|word| word as u32 * 17 + 3).collect::<Vec<_>>();
    for (offset, rows) in [(0, 16), (16, 16), (31, 16), (32, 16), (40, 16)] {
        let readable = readable_source_words(source.len(), offset, rows);
        let sliced = (readable != 0).then(|| &source[offset..offset + readable]);
        for row in 0..rows {
            let legacy = offset
                .checked_add(row)
                .filter(|&index| index < source.len())
                .map(|index| source[index])
                .unwrap_or(0);
            let v2 = sliced
                .and_then(|values| values.get(row))
                .copied()
                .unwrap_or(0);
            assert_eq!(legacy, v2, "offset {offset}, row {row}");
        }
    }

    let contract = MemoryBaseTraceContract::compile(&requirements()).unwrap();
    let value_steps = contract.steps().iter().filter(|step| {
        matches!(
            step.kind(),
            MemoryBaseTraceStepKind::BigValue | MemoryBaseTraceStepKind::SmallValue
        )
    });
    let source_words = value_steps
        .map(|step| {
            assert_eq!(step.abi(), MemoryBaseTraceAbi::ValueSlicedV2);
            assert_eq!(step.multiplicity_words(), step.row_count());
            step.source_words()
        })
        .collect::<Vec<_>>();
    assert_eq!(source_words, [16, 16, 0, 16]);
}

#[test]
fn near_bound_count_geometry_and_overflow_fail_closed() {
    let mut shifted = requirements();
    shifted.big_parts[2].source_offset = 40;
    shifted.big_count_words = 56;
    let contract = MemoryBaseTraceContract::compile(&shifted).unwrap();
    let tail = contract
        .steps()
        .iter()
        .find(|step| {
            step.kind() == MemoryBaseTraceStepKind::BigValue && step.part_ordinal() == Some(2)
        })
        .unwrap();
    assert_eq!(tail.source_words(), 0);
    assert_eq!(tail.reads().len(), 1);
    assert_eq!(
        tail.reads()[0],
        access(MemoryBaseTraceEffectRole::ValueMultiplicity, 0, 40, 16)
    );

    let mut overflow = requirements();
    overflow.big_parts[2].source_offset = usize::MAX;
    assert_eq!(
        MemoryBaseTraceContract::compile(&overflow),
        Err(MemoryBaseTraceAuthorityError::SizeOverflow)
    );

    let mut too_many_addresses = requirements();
    too_many_addresses.n_addrs = too_many_addresses.address_count_words + 2;
    too_many_addresses.raw_address_words = too_many_addresses.n_addrs;
    assert_eq!(
        MemoryBaseTraceContract::compile(&too_many_addresses),
        Err(MemoryBaseTraceAuthorityError::InvalidCanonicalRequirements)
    );

    let mut maximum_rows = requirements();
    maximum_rows.big_parts = vec![MemoryBaseTraceValuePartRequirements {
        part_ordinal: 0,
        source_offset: 0,
        row_count: u32::MAX as usize,
    }];
    maximum_rows.big_count_words = u32::MAX as usize;
    let maximum = MemoryBaseTraceContract::compile(&maximum_rows).unwrap();
    assert_eq!(
        maximum.steps()[1].launch().grid[0],
        1 + (u32::MAX - 1) / BLOCK_THREADS
    );
}
