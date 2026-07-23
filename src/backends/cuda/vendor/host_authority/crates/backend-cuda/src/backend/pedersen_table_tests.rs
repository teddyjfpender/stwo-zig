use super::*;

const DIGEST_A: PedersenTableContentDigest = PedersenTableContentDigest::new([0xA5; 32]);
const DIGEST_B: PedersenTableContentDigest = PedersenTableContentDigest::new([0x5A; 32]);

#[test]
fn stub_build_registers_nothing() {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        assert!(!register_borrowed_pedersen_table(32, |_c, buf| {
            buf.extend(std::iter::repeat_n(0u32, 32));
        }));
        assert!(!pedersen_table_registered());
        assert!(registered_borrowed_pedersen_table().is_none());
        assert_eq!(
            pedersen_table_registration_state(),
            PedersenTableRegistrationState::Poisoned(
                PedersenTableRegistrationError::CudaUnavailable
            )
        );
    }
}

const fn geometry(
    content_digest: PedersenTableContentDigest,
    source_rows: usize,
    padded_rows: usize,
) -> RegistrationGeometry {
    RegistrationGeometry {
        content_digest,
        source_rows,
        padded_rows,
    }
}

fn table_with_geometry(
    content_digest: PedersenTableContentDigest,
    source_rows: usize,
    padded_rows: usize,
) -> RegisteredPedersenTable {
    RegisteredPedersenTable {
        columns: std::array::from_fn(|index| RegisteredPedersenColumn {
            index,
            device_address: 0x1000 + index * 0x100,
            len_words: padded_rows,
        }),
        content_digest,
        source_n_rows: source_rows,
        n_rows: padded_rows,
        registration_generation: PEDERSEN_TABLE_REGISTRATION_GENERATION,
    }
}

#[test]
fn ready_registration_reuses_without_a_second_builder() {
    let slot = RegistrationSlot::new();
    let invocations = std::cell::Cell::new(0);
    let first = slot
        .try_register(Ok(geometry(DIGEST_A, 32, 32)), |_| {
            invocations.set(invocations.get() + 1);
            Ok(table_with_geometry(DIGEST_A, 32, 32))
        })
        .unwrap();
    let second = slot
        .try_register(
            Ok(geometry(DIGEST_A, 32, 32)),
            |_| -> Result<_, PedersenTableRegistrationError> {
                panic!("ready registration invoked a second builder")
            },
        )
        .unwrap();

    assert_eq!(first, second);
    assert_eq!(invocations.get(), 1);
}

#[test]
fn ready_registration_rejects_request_geometry_drift() {
    let slot = RegistrationSlot::new();
    slot.try_register(Ok(geometry(DIGEST_A, 32, 32)), |_| {
        Ok(table_with_geometry(DIGEST_A, 32, 32))
    })
    .unwrap();

    assert_eq!(
        slot.try_register(
            Ok(geometry(DIGEST_A, 64, 64)),
            |_| -> Result<_, PedersenTableRegistrationError> {
                panic!("geometry drift invoked a second builder")
            }
        ),
        Err(PedersenTableRegistrationError::RequestGeometryMismatch {
            requested_padded_rows: 64,
            registered_padded_rows: 32,
        })
    );
}

#[test]
fn ready_registration_rejects_same_padded_different_source_without_rebuilding() {
    let slot = RegistrationSlot::new();
    let invocations = std::cell::Cell::new(0);
    slot.try_register(Ok(geometry(DIGEST_A, 17, 32)), |_| {
        invocations.set(invocations.get() + 1);
        Ok(table_with_geometry(DIGEST_A, 17, 32))
    })
    .unwrap();

    assert_eq!(
        slot.try_register(Ok(geometry(DIGEST_A, 32, 32)), |_| {
            invocations.set(invocations.get() + 1);
            Ok(table_with_geometry(DIGEST_A, 32, 32))
        }),
        Err(
            PedersenTableRegistrationError::RequestSourceRowCountMismatch {
                requested_source_rows: 32,
                registered_source_rows: 17,
                padded_rows: 32,
            }
        )
    );
    assert_eq!(invocations.get(), 1);
}

#[test]
fn content_digest_distinguishes_same_geometry_bytes() {
    let first = compute_borrowed_pedersen_table_digest(3, |column, buf| {
        buf.extend([column as u32, 7, 11]);
    })
    .unwrap();
    let second = compute_borrowed_pedersen_table_digest(3, |column, buf| {
        buf.extend([column as u32, 7, u32::from(column == 41) + 11]);
    })
    .unwrap();

    assert_ne!(first, second);
}

#[test]
fn ready_registration_rejects_same_geometry_foreign_content_digest_without_rebuilding() {
    let slot = RegistrationSlot::new();
    let invocations = std::cell::Cell::new(0);
    slot.try_register(Ok(geometry(DIGEST_A, 32, 32)), |_| {
        invocations.set(invocations.get() + 1);
        Ok(table_with_geometry(DIGEST_A, 32, 32))
    })
    .unwrap();

    assert_eq!(
        slot.try_register(Ok(geometry(DIGEST_B, 32, 32)), |_| {
            invocations.set(invocations.get() + 1);
            Ok(table_with_geometry(DIGEST_B, 32, 32))
        }),
        Err(
            PedersenTableRegistrationError::RequestContentDigestMismatch {
                requested: DIGEST_B,
                registered: DIGEST_A,
            }
        )
    );
    assert_eq!(invocations.get(), 1);
}

#[test]
fn malformed_column_poison_is_stable() {
    let slot = RegistrationSlot::new();
    let malformed = PedersenTableRegistrationError::ColumnLength {
        column: 17,
        expected: 32,
        actual: 31,
    };

    assert_eq!(
        slot.try_register(Ok(geometry(DIGEST_A, 32, 32)), |_| {
            Err(malformed.clone())
        }),
        Err(malformed.clone())
    );
    assert_eq!(
        slot.snapshot(),
        PedersenTableRegistrationState::Poisoned(malformed)
    );
    assert!(slot.ready().is_none());
}

#[test]
fn poisoned_registration_never_invokes_another_builder() {
    let slot = RegistrationSlot::new();
    let invocations = std::cell::Cell::new(0);
    let failure = PedersenTableRegistrationError::DeviceUploadReturnedNull { column: 3 };
    let first = slot.try_register(Ok(geometry(DIGEST_A, 32, 32)), |_| {
        invocations.set(invocations.get() + 1);
        Err(failure.clone())
    });
    let second = slot.try_register(Ok(geometry(DIGEST_A, 32, 32)), |_| {
        invocations.set(invocations.get() + 1);
        Ok(table_with_geometry(DIGEST_A, 32, 32))
    });

    assert_eq!(first, Err(failure.clone()));
    assert_eq!(second, Err(failure));
    assert_eq!(invocations.get(), 1);
}

#[test]
fn registered_geometry_is_ordered_and_fails_closed() {
    let table = table_with_geometry(DIGEST_A, 1 << 23, 1 << 23);

    assert_eq!(table.content_digest(), DIGEST_A);
    assert_eq!(table.source_n_rows(), 1 << 23);
    assert_eq!(
        table.registration_generation(),
        PEDERSEN_TABLE_REGISTRATION_GENERATION
    );
    assert!(table.has_exact_rows(1 << 23));
    assert!(!table.has_exact_rows(1 << 22));
    assert_eq!(table.column(0).unwrap().index(), 0);
    assert_eq!(table.column(55).unwrap().index(), 55);
    assert_eq!(table.column(55).unwrap().len_words(), 1 << 23);
    assert!(table.column(PEDERSEN_TABLE_N_COLUMNS).is_none());
    assert!(table
        .columns()
        .iter()
        .enumerate()
        .all(|(index, column)| column.index() == index));
    assert_eq!(table.validate_exact_geometry(1 << 23), Ok(()));
    assert_eq!(
        table.validate_exact_registration_geometry(DIGEST_A, 1 << 23, 1 << 23),
        Ok(())
    );

    let mut wrong_content_digest = table;
    wrong_content_digest.content_digest = DIGEST_B;
    assert!(matches!(
        wrong_content_digest.validate_exact_registration_geometry(DIGEST_A, 1 << 23, 1 << 23),
        Err(RegisteredPedersenTableError::ContentDigest { .. })
    ));

    let mut wrong_source_rows = table;
    wrong_source_rows.source_n_rows -= 1;
    assert!(matches!(
        wrong_source_rows.validate_exact_registration_geometry(DIGEST_A, 1 << 23, 1 << 23),
        Err(RegisteredPedersenTableError::SourceRowCount { .. })
    ));

    let mut wrong_rows = table;
    wrong_rows.n_rows -= 1;
    assert!(matches!(
        wrong_rows.validate_exact_geometry(1 << 23),
        Err(RegisteredPedersenTableError::RowCount { .. })
    ));

    let mut stale_generation = table;
    stale_generation.registration_generation = 0;
    assert_eq!(
        stale_generation.validate_exact_geometry(1 << 23),
        Err(RegisteredPedersenTableError::RegistrationGeneration {
            expected: PEDERSEN_TABLE_REGISTRATION_GENERATION,
            actual: 0,
        })
    );

    let mut wrong_index = table;
    wrong_index.columns[17].index = 18;
    assert!(matches!(
        wrong_index.validate_exact_geometry(1 << 23),
        Err(RegisteredPedersenTableError::ColumnIndex { position: 17, .. })
    ));

    let mut wrong_length = table;
    wrong_length.columns[31].len_words -= 1;
    assert!(matches!(
        wrong_length.validate_exact_geometry(1 << 23),
        Err(RegisteredPedersenTableError::ColumnLength { column: 31, .. })
    ));

    let mut null_pointer = table;
    null_pointer.columns[55].device_address = 0;
    assert_eq!(
        null_pointer.validate_exact_geometry(1 << 23),
        Err(RegisteredPedersenTableError::NullColumnPointer { column: 55 })
    );
}
