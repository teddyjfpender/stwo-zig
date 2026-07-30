//! Native CUDA correctness gate for replacement-v1 row-major opcode ingress.

#![cfg(stwo_cuda_link)]

use core::ffi::c_void;

use stwo_backend_cuda::{
    witness_casm_input_requirements, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec,
    CudaExecContext, DeviceArena, PreparedWitnessCasmInputStage, WitnessCasmInputSlots,
};

fn slots() -> WitnessCasmInputSlots {
    WitnessCasmInputSlots {
        staging: ArenaSlotId(1),
        consumer_input_columns: (2..7).map(ArenaSlotId).collect(),
    }
}

fn read(arena: &DeviceArena, source: ArenaSlice) -> Vec<u32> {
    let mut result = vec![0; source.len_words()];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                result.as_mut_ptr().cast::<c_void>(),
                source.as_void_ptr().cast_const(),
                source.len_bytes(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    result
}

#[test]
fn row_major_casm_ingress_matches_host_padding_and_reuses_staging() {
    let requirements = witness_casm_input_requirements(3, true).unwrap();
    let slots = slots();
    let mut offset = 0usize;
    let specs = requirements
        .arena_slot_requirements(&slots)
        .unwrap()
        .into_iter()
        .map(|requirement| {
            offset = offset.next_multiple_of(requirement.alignment_words);
            let spec = ArenaSlotSpec {
                id: requirement.id,
                offset_words: offset,
                len_words: requirement.len_words,
                alignment_words: requirement.alignment_words,
            };
            offset += requirement.len_words;
            spec
        })
        .collect::<Vec<_>>();
    let arena = DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap();
    let stage = PreparedWitnessCasmInputStage::prepare(&arena, &requirements, &slots).unwrap();
    let columns = stage.consumer_input_columns();
    let invalid_geometry = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_witness_casm_input_scatter_on(
            stage.staging().as_u32_ptr().cast_const(),
            3,
            15,
            columns[0].as_u32_ptr(),
            columns[1].as_u32_ptr(),
            columns[2].as_u32_ptr(),
            columns[3].as_u32_ptr(),
            columns[4].as_u32_ptr(),
            arena.context().stream_raw().as_ptr(),
        )
    };
    assert_ne!(invalid_geometry, 0);

    for seed in [0, 1_000] {
        let rows = [
            seed + 11,
            seed + 12,
            seed + 13,
            seed + 21,
            seed + 22,
            seed + 23,
            seed + 31,
            seed + 32,
            seed + 33,
        ];
        let pending = unsafe { stage.ingest_and_launch(&rows).unwrap() };
        assert_eq!(stage.ingress_receipt(), None);
        arena.context().sync().unwrap();
        let receipt = unsafe { stage.acknowledge_ingress_fence(pending).unwrap() };
        assert!(stage.ingress_is_current(&receipt));
        let columns = stage
            .consumer_input_columns()
            .iter()
            .copied()
            .map(|column| read(&arena, column))
            .collect::<Vec<_>>();
        for row in 0..requirements.consumer_rows {
            let source = if row < 3 { row } else { 0 };
            assert_eq!(columns[0][row], rows[source * 3]);
            assert_eq!(columns[1][row], rows[source * 3 + 1]);
            assert_eq!(columns[2][row], rows[source * 3 + 2]);
            assert_eq!(columns[3][row], u32::from(row < 3));
            assert_eq!(columns[4][row], row as u32);
        }
    }
}
