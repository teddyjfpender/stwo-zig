//! Native CUDA parity and capture gate for composition extension parameters.

#![cfg(stwo_cuda_link)]

use core::ffi::c_void;

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_backend_cuda::{ArenaLayout, ArenaSlotId, ArenaSlotSpec, CudaExecContext, DeviceArena};
use stwo_backend_cuda_kernels::raw::{self, CudaSecureField};

const Z: ArenaSlotId = ArenaSlotId(1);
const ALPHA_POWERS: ArenaSlotId = ArenaSlotId(2);
const CLAIMED_SUMS: ArenaSlotId = ArenaSlotId(3);
const OUTPUTS: ArenaSlotId = ArenaSlotId(4);
const DESTINATION_POINTERS: ArenaSlotId = ArenaSlotId(5);
const SOURCE_KINDS: ArenaSlotId = ArenaSlotId(6);
const SOURCE_INDICES: ArenaSlotId = ArenaSlotId(7);
const SCALES: ArenaSlotId = ArenaSlotId(8);
const CLAIMED_SUM_POINTERS: ArenaSlotId = ArenaSlotId(9);
const SECURE_WORDS: usize = 4;
const PARAM_COUNT: usize = 5;
const ALPHA_COUNT: usize = 3;
const CLAIMED_SUM_COUNT: usize = 2;
const POINTER_WORDS: usize = core::mem::size_of::<usize>().div_ceil(core::mem::size_of::<u32>());

fn arena() -> DeviceArena {
    let requested = [
        (Z, SECURE_WORDS, SECURE_WORDS),
        (ALPHA_POWERS, ALPHA_COUNT * SECURE_WORDS, SECURE_WORDS),
        (CLAIMED_SUMS, CLAIMED_SUM_COUNT * SECURE_WORDS, SECURE_WORDS),
        (OUTPUTS, PARAM_COUNT * SECURE_WORDS, SECURE_WORDS),
        (
            DESTINATION_POINTERS,
            PARAM_COUNT * POINTER_WORDS,
            POINTER_WORDS,
        ),
        (SOURCE_KINDS, PARAM_COUNT, 1),
        (SOURCE_INDICES, PARAM_COUNT, 1),
        (SCALES, PARAM_COUNT, 1),
        (
            CLAIMED_SUM_POINTERS,
            CLAIMED_SUM_COUNT * POINTER_WORDS,
            POINTER_WORDS,
        ),
    ];
    let mut offset = 0usize;
    let mut specs = Vec::with_capacity(requested.len());
    for (id, len_words, alignment_words) in requested {
        offset = offset.next_multiple_of(alignment_words);
        specs.push(ArenaSlotSpec {
            id,
            offset_words: offset,
            len_words,
            alignment_words,
        });
        offset += len_words;
    }
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap()
}

fn upload<T>(arena: &DeviceArena, slot: ArenaSlotId, values: &[T]) {
    let destination = arena.bind(slot).unwrap();
    let bytes = core::mem::size_of_val(values);
    assert!(bytes <= destination.len_bytes());
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                values.as_ptr().cast::<c_void>(),
                bytes,
            )
            .unwrap();
    }
}

fn upload_secure_fields(arena: &DeviceArena, slot: ArenaSlotId, values: &[SecureField]) {
    let words = values
        .iter()
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect::<Vec<_>>();
    upload(arena, slot, &words);
}

fn read_outputs(arena: &DeviceArena) -> Vec<SecureField> {
    let source = arena.bind(OUTPUTS).unwrap();
    let mut words = vec![0u32; PARAM_COUNT * SECURE_WORDS];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                words.as_mut_ptr().cast(),
                source.as_void_ptr(),
                core::mem::size_of_val(words.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    words
        .chunks_exact(SECURE_WORDS)
        .map(|words| SecureField::from_u32_unchecked(words[0], words[1], words[2], words[3]))
        .collect()
}

fn launch(arena: &DeviceArena, count: usize, claimed_sum_count: usize) {
    let status = unsafe {
        raw::stwo_composition_materialize_ext_params_on(
            arena
                .bind(DESTINATION_POINTERS)
                .unwrap()
                .as_u32_ptr()
                .cast::<*mut CudaSecureField>(),
            arena.bind(SOURCE_KINDS).unwrap().as_u32_ptr(),
            arena.bind(SOURCE_INDICES).unwrap().as_u32_ptr(),
            arena.bind(SCALES).unwrap().as_u32_ptr(),
            count.try_into().unwrap(),
            arena
                .bind(Z)
                .unwrap()
                .as_u32_ptr()
                .cast::<CudaSecureField>(),
            arena
                .bind(ALPHA_POWERS)
                .unwrap()
                .as_u32_ptr()
                .cast::<CudaSecureField>(),
            ALPHA_COUNT.try_into().unwrap(),
            if claimed_sum_count == 0 {
                core::ptr::null()
            } else {
                arena
                    .bind(CLAIMED_SUM_POINTERS)
                    .unwrap()
                    .as_u32_ptr()
                    .cast::<*const CudaSecureField>()
            },
            claimed_sum_count.try_into().unwrap(),
            arena.context().stream_raw().as_ptr(),
        )
    };
    assert_eq!(status, 0);
}

fn expected(
    z: SecureField,
    alpha_powers: &[SecureField; ALPHA_COUNT],
    claimed_sums: &[SecureField; CLAIMED_SUM_COUNT],
) -> Vec<SecureField> {
    let scales = [1, 3, 5, 7, 11].map(BaseField::from_u32_unchecked);
    vec![
        z * scales[0],
        alpha_powers[0] * scales[1],
        alpha_powers[2] * scales[2],
        claimed_sums[0] * scales[3],
        claimed_sums[1] * scales[4],
    ]
}

#[test]
fn materializes_all_sources_and_replays_with_new_values() {
    let arena = arena();
    let outputs = arena.bind(OUTPUTS).unwrap();
    let destinations = (0..PARAM_COUNT)
        .map(|index| unsafe {
            outputs
                .as_u32_ptr()
                .add(index * SECURE_WORDS)
                .cast::<CudaSecureField>()
        })
        .collect::<Vec<_>>();
    let claimed_sums = arena.bind(CLAIMED_SUMS).unwrap();
    let claimed_sum_pointers = (0..CLAIMED_SUM_COUNT)
        .map(|index| unsafe {
            claimed_sums
                .as_u32_ptr()
                .add(index * SECURE_WORDS)
                .cast::<CudaSecureField>()
                .cast_const()
        })
        .collect::<Vec<_>>();
    upload(&arena, DESTINATION_POINTERS, &destinations);
    upload(&arena, SOURCE_KINDS, &[0u32, 1, 1, 2, 2]);
    upload(&arena, SOURCE_INDICES, &[0u32, 0, 2, 0, 1]);
    upload(&arena, SCALES, &[1u32, 3, 5, 7, 11]);
    upload(&arena, CLAIMED_SUM_POINTERS, &claimed_sum_pointers);

    let first_z = SecureField::from_u32_unchecked(2, 3, 5, 7);
    let first_alphas = [
        SecureField::from_u32_unchecked(11, 13, 17, 19),
        SecureField::from_u32_unchecked(23, 29, 31, 37),
        SecureField::from_u32_unchecked(41, 43, 47, 53),
    ];
    let first_claims = [
        SecureField::from_u32_unchecked(59, 61, 67, 71),
        SecureField::from_u32_unchecked(73, 79, 83, 89),
    ];
    upload_secure_fields(&arena, Z, &[first_z]);
    upload_secure_fields(&arena, ALPHA_POWERS, &first_alphas);
    upload_secure_fields(&arena, CLAIMED_SUMS, &first_claims);
    arena.context().sync().unwrap();
    launch(&arena, PARAM_COUNT, CLAIMED_SUM_COUNT);
    assert_eq!(
        read_outputs(&arena),
        expected(first_z, &first_alphas, &first_claims)
    );

    let capture = arena.context().capture().unwrap();
    launch(&arena, PARAM_COUNT, CLAIMED_SUM_COUNT);
    let graph = capture.finish().unwrap();
    let second_z = SecureField::from_u32_unchecked(97, 101, 103, 107);
    let second_alphas = [
        SecureField::from_u32_unchecked(109, 113, 127, 131),
        SecureField::from_u32_unchecked(137, 139, 149, 151),
        SecureField::from_u32_unchecked(157, 163, 167, 173),
    ];
    let second_claims = [
        SecureField::from_u32_unchecked(179, 181, 191, 193),
        SecureField::from_u32_unchecked(197, 199, 211, 223),
    ];
    upload_secure_fields(&arena, Z, &[second_z]);
    upload_secure_fields(&arena, ALPHA_POWERS, &second_alphas);
    upload_secure_fields(&arena, CLAIMED_SUMS, &second_claims);
    arena.context().sync().unwrap();
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        read_outputs(&arena),
        expected(second_z, &second_alphas, &second_claims)
    );

    // Components without claimed-sum parameters may omit the pointer table.
    upload(&arena, SOURCE_KINDS, &[0u32, 1, 1]);
    upload(&arena, SOURCE_INDICES, &[0u32, 0, 2]);
    upload(&arena, SCALES, &[2u32, 3, 5]);
    arena.context().sync().unwrap();
    launch(&arena, 3, 0);
    let outputs = read_outputs(&arena);
    assert_eq!(outputs[0], second_z * BaseField::from_u32_unchecked(2));
    assert_eq!(
        outputs[1],
        second_alphas[0] * BaseField::from_u32_unchecked(3)
    );
    assert_eq!(
        outputs[2],
        second_alphas[2] * BaseField::from_u32_unchecked(5)
    );
}
