use super::*;

fn uuid(seed: u8) -> CudaDeviceUuid {
    CudaDeviceUuid::from_bytes([seed; CUDA_DEVICE_UUID_BYTES])
}

fn domain(seed: u8) -> IpcExchangeInstallDomain {
    IpcExchangeInstallDomain::from_digest([seed; IPC_EXCHANGE_INSTALL_DOMAIN_BYTES]).unwrap()
}

fn key() -> IpcExchangeKey {
    IpcExchangeKey::new(7, 1, 3, uuid(0x11), uuid(0x33), domain(0x77), 2_097_153, 9).unwrap()
}

fn descriptor() -> IpcExchangeDescriptor {
    IpcExchangeDescriptor {
        key: key(),
        allocation_bytes: 4 * 1024 * 1024,
        memory_handle: [0x41; CUDA_IPC_HANDLE_BYTES],
        ready_event_handle: [0x52; CUDA_IPC_HANDLE_BYTES],
        consumed_event_handle: [0x63; CUDA_IPC_HANDLE_BYTES],
    }
}

fn failure(operation: &'static str) -> CudaRuntimeError {
    CudaRuntimeError::Cuda { operation, code: 1 }
}

#[test]
fn key_and_two_mib_allocation_geometry_fail_closed() {
    assert_eq!(rounded_allocation_bytes(1).unwrap(), 2 * 1024 * 1024);
    assert_eq!(
        rounded_allocation_bytes(2 * 1024 * 1024).unwrap(),
        2 * 1024 * 1024
    );
    assert_eq!(
        rounded_allocation_bytes(2 * 1024 * 1024 + 1).unwrap(),
        4 * 1024 * 1024
    );
    assert!(IpcExchangeKey::new(1, 2, 2, uuid(1), uuid(2), domain(1), 64, 0).is_err());
    assert!(IpcExchangeKey::new(1, 1, 2, uuid(1), uuid(1), domain(1), 64, 0).is_err());
    assert!(IpcExchangeKey::new(
        1,
        1,
        2,
        CudaDeviceUuid::from_bytes([0; CUDA_DEVICE_UUID_BYTES]),
        uuid(2),
        domain(1),
        64,
        0,
    )
    .is_err());
    assert!(IpcExchangeInstallDomain::from_digest([0; IPC_EXCHANGE_INSTALL_DOMAIN_BYTES]).is_err());
    assert!(IpcExchangeKey::new(1, 1, 2, uuid(1), uuid(2), domain(1), 0, 0).is_err());
    assert!(IpcExchangeKey::new(1, 1, 2, uuid(1), uuid(2), domain(1), 64, u64::MAX).is_err());
    assert!(rounded_allocation_bytes(usize::MAX).is_err());
}

#[test]
fn descriptor_wire_image_binds_direction_devices_extent_generation_and_handles() {
    let descriptor = descriptor();
    let encoded = descriptor.encode();
    assert_eq!(IpcExchangeDescriptor::decode(&encoded).unwrap(), descriptor);

    for (offset, label) in [
        (0, "magic"),
        (8, "version"),
        (12, "direction"),
        (48, "allocation"),
    ] {
        let mut mutated = encoded;
        mutated[offset] ^= 0x80;
        assert!(
            IpcExchangeDescriptor::decode(&mutated).is_err(),
            "{label} mutation was accepted"
        );
    }

    for offset in [16, 24, 28, 32, 56, 72, 88, 120, 184, 248] {
        let mut mutated = encoded;
        mutated[offset] ^= 0x80;
        assert_ne!(IpcExchangeDescriptor::decode(&mutated).unwrap(), descriptor);
    }

    let mut legacy_v1 = encoded;
    legacy_v1[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert!(IpcExchangeDescriptor::decode(&legacy_v1).is_err());

    let mut zero_domain = encoded;
    zero_domain[88..120].fill(0);
    assert!(IpcExchangeDescriptor::decode(&zero_domain).is_err());

    let mut wrong_logical_extent = encoded;
    wrong_logical_extent[40] ^= 1;
    assert!(IpcExchangeDescriptor::decode(&wrong_logical_extent).is_err());

    let decoded = IpcExchangeDescriptor::decode(&encoded).unwrap();
    assert_eq!(decoded.key().edge_id(), 7);
    assert_eq!(decoded.key().owner_rank(), 1);
    assert_eq!(decoded.key().peer_rank(), 3);
    assert_eq!(decoded.key().logical_bytes(), 2_097_153);
    assert_eq!(decoded.key().initial_generation(), 9);
    assert_eq!(decoded.key().install_domain(), domain(0x77));
    assert_eq!(decoded.allocation_bytes(), 4 * 1024 * 1024);
    assert_eq!(encoded.len(), 312);
}

#[test]
fn peer_close_receipt_is_transportable_and_binds_the_post_reclaim_generation() {
    let receipt = IpcPeerCloseReceipt {
        key: key(),
        generation: 10,
    };
    let encoded = receipt.encode();
    assert_eq!(IpcPeerCloseReceipt::decode(&encoded).unwrap(), receipt);
    assert_eq!(receipt.key(), key());
    assert_eq!(receipt.generation(), 10);
    assert_eq!(encoded.len(), 120);

    let mut wrong_direction = encoded;
    wrong_direction[12] ^= 1;
    assert!(IpcPeerCloseReceipt::decode(&wrong_direction).is_err());

    let mut wrong_generation = encoded;
    wrong_generation[48] ^= 1;
    assert_ne!(
        IpcPeerCloseReceipt::decode(&wrong_generation).unwrap(),
        receipt
    );

    let mut wrong_install_domain = encoded;
    wrong_install_domain[88] ^= 1;
    assert_ne!(
        IpcPeerCloseReceipt::decode(&wrong_install_domain).unwrap(),
        receipt
    );

    let mut predates_descriptor = encoded;
    predates_descriptor[48..56].copy_from_slice(&8u64.to_le_bytes());
    assert!(IpcPeerCloseReceipt::decode(&predates_descriptor).is_err());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Call {
    Publish,
    Consume,
    Reclaim,
    Arm,
}

#[test]
fn mock_lifecycle_requires_consumed_ack_before_reuse_and_next_wait() {
    let mut calls = Vec::new();
    let mut owner = IpcExchangeOwnerState::Idle { generation: 9 };
    let mut imported = IpcExchangeImportState::Awaiting { generation: 9 };

    let published = owner_publish_transition(&mut owner, key(), 9, || {
        calls.push(Call::Publish);
        Ok(())
    })
    .unwrap();
    let consumed = import_consume_transition(&mut imported, key(), 9, || {
        calls.push(Call::Consume);
        Ok(())
    })
    .unwrap();
    let reclaimed = owner_reclaim_transition(&mut owner, key(), 9, || {
        calls.push(Call::Reclaim);
        Ok(())
    })
    .unwrap();
    let armed = import_arm_transition(&mut imported, key(), 10, || {
        calls.push(Call::Arm);
        Ok(())
    })
    .unwrap();

    assert_eq!(
        calls,
        [Call::Publish, Call::Consume, Call::Reclaim, Call::Arm]
    );
    assert_eq!(owner, IpcExchangeOwnerState::Idle { generation: 10 });
    assert_eq!(
        imported,
        IpcExchangeImportState::Awaiting { generation: 10 }
    );
    for (receipt, phase, generation) in [
        (published, IpcExchangePhase::Published, 9),
        (consumed, IpcExchangePhase::Consumed, 9),
        (reclaimed, IpcExchangePhase::Reclaimed, 9),
        (armed, IpcExchangePhase::Armed, 10),
    ] {
        assert_eq!(receipt.key(), key());
        assert_eq!(receipt.phase(), phase);
        assert_eq!(receipt.generation(), generation);
    }
}

#[test]
fn invalid_state_or_generation_enqueues_nothing_and_does_not_corrupt_state() {
    let mut called = false;
    let mut owner = IpcExchangeOwnerState::Idle { generation: 4 };
    assert!(owner_publish_transition(&mut owner, key(), 5, || {
        called = true;
        Ok(())
    })
    .is_err());
    assert!(!called);
    assert_eq!(owner, IpcExchangeOwnerState::Idle { generation: 4 });

    let mut imported = IpcExchangeImportState::Consumed { generation: 4 };
    assert!(import_consume_transition(&mut imported, key(), 4, || {
        called = true;
        Ok(())
    })
    .is_err());
    assert!(!called);
    assert_eq!(imported, IpcExchangeImportState::Consumed { generation: 4 });

    assert!(import_arm_transition(&mut imported, key(), 6, || {
        called = true;
        Ok(())
    })
    .is_err());
    assert!(!called);
    assert_eq!(imported, IpcExchangeImportState::Consumed { generation: 4 });
}

#[test]
fn every_enqueued_operation_failure_poison_stops_the_generation() {
    let mut owner = IpcExchangeOwnerState::Idle { generation: 1 };
    assert!(owner_publish_transition(&mut owner, key(), 1, || Err(failure("publish"))).is_err());
    assert_eq!(owner, IpcExchangeOwnerState::Poisoned);

    let mut owner = IpcExchangeOwnerState::Published { generation: 1 };
    assert!(owner_reclaim_transition(&mut owner, key(), 1, || Err(failure("reclaim"))).is_err());
    assert_eq!(owner, IpcExchangeOwnerState::Poisoned);

    let mut imported = IpcExchangeImportState::Awaiting { generation: 1 };
    assert!(
        import_consume_transition(&mut imported, key(), 1, || Err(failure("consume"))).is_err()
    );
    assert_eq!(imported, IpcExchangeImportState::Poisoned);

    let mut imported = IpcExchangeImportState::Consumed { generation: 1 };
    assert!(import_arm_transition(&mut imported, key(), 2, || Err(failure("arm"))).is_err());
    assert_eq!(imported, IpcExchangeImportState::Poisoned);
}

#[test]
fn exact_byte_and_generation_checks_cover_near_misses() {
    assert_eq!(require_bytes(64, 64), Ok(()));
    assert_eq!(
        require_bytes(64, 63),
        Err(IpcExchangeError::SizeMismatch {
            expected: 64,
            actual: 63,
        })
    );
    assert_eq!(require_generation(8, 8), Ok(()));
    assert_eq!(
        require_generation(8, 9),
        Err(IpcExchangeError::GenerationMismatch {
            expected: 8,
            actual: 9,
        })
    );
}
