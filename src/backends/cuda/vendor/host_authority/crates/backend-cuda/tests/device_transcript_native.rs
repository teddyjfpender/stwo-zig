//! Counted native CUDA gate for the device Blake2s transcript.
//!
//! This target is isolated from unrelated backend unit tests so hardware
//! admission cannot be blocked by stale test-only APIs elsewhere in the crate.

#![cfg(stwo_cuda_link)]

use core::ffi::c_void;

use stwo_backend_cuda::{
    ArenaLayout, ArenaSlotId, ArenaSlotSpec, Blake2sTranscriptSchedule,
    Blake2sTranscriptWorkspaceSlots, CudaExecContext, DeviceArena, DeviceTranscriptError,
    PreparedBlake2sTranscript, TranscriptArenaSlotRequirement, TranscriptBoundaryId,
    TranscriptInputBinding, TranscriptInputId, TranscriptOperation, TranscriptOutputBinding,
    TranscriptOutputId, TranscriptSegmentStart, TranscriptStart,
    BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS,
};

const A: TranscriptInputId = TranscriptInputId(1);
const ROOT: TranscriptInputId = TranscriptInputId(2);
const NONCE: TranscriptInputId = TranscriptInputId(3);
const U32S: TranscriptInputId = TranscriptInputId(4);
const U64_VALUE: TranscriptInputId = TranscriptInputId(5);
const X: TranscriptOutputId = TranscriptOutputId(10);
const Y: TranscriptOutputId = TranscriptOutputId(11);
const Z: TranscriptOutputId = TranscriptOutputId(12);
const RAW: TranscriptOutputId = TranscriptOutputId(13);

fn boundary(value: u32) -> TranscriptBoundaryId {
    TranscriptBoundaryId(value)
}

fn vector_schedule() -> Blake2sTranscriptSchedule {
    Blake2sTranscriptSchedule::new(
        TranscriptStart::Default,
        vec![
            TranscriptOperation::MixFelts {
                boundary: boundary(1),
                source: A,
                n_felts: 2,
            },
            TranscriptOperation::MixU32s {
                boundary: boundary(2),
                source: U32S,
                n_words: 3,
            },
            TranscriptOperation::MixU64 {
                boundary: boundary(3),
                source: U64_VALUE,
            },
            TranscriptOperation::AbsorbRoot {
                boundary: boundary(4),
                source: ROOT,
            },
            TranscriptOperation::DrawSecureFelt {
                boundary: boundary(5),
                output: X,
            },
            TranscriptOperation::DrawSecureFelts {
                boundary: boundary(6),
                output: Y,
                n_felts: 3,
            },
            TranscriptOperation::DrawU32s {
                boundary: boundary(7),
                output: RAW,
            },
            TranscriptOperation::AbsorbPowNonce {
                boundary: boundary(8),
                source: NONCE,
                pow_bits: 0,
            },
            TranscriptOperation::DrawQueries {
                boundary: boundary(9),
                output: Z,
                log_domain_size: 23,
                n_queries: 13,
            },
        ],
        64,
    )
    .unwrap()
}

fn upload(arena: &DeviceArena, slot: ArenaSlotId, words: &[u32]) {
    let destination = arena.bind(slot).unwrap();
    assert_eq!(destination.len_words(), words.len());
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                words.as_ptr().cast::<c_void>(),
                destination.len_bytes(),
            )
            .unwrap();
    }
}

#[test]
fn device_vectors_match_reference_in_eager_and_graph_modes() {
    assert!(
        stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT,
        "native transcript gate ran without CUDA kernels"
    );

    let schedule = vector_schedule();
    let requirements = schedule.requirements().clone();
    let workspace = Blake2sTranscriptWorkspaceSlots {
        state: ArenaSlotId(1),
        boundary_snapshots: ArenaSlotId(2),
        input_snapshots: ArenaSlotId(3),
        output_snapshots: ArenaSlotId(4),
    };
    let io_specs = [
        (ArenaSlotId(10), 8usize, BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS),
        (ArenaSlotId(11), 8usize, BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS),
        (ArenaSlotId(12), 2usize, 1usize),
        (ArenaSlotId(13), 3usize, 1usize),
        (ArenaSlotId(14), 2usize, 1usize),
        (ArenaSlotId(20), 4usize, 1usize),
        (ArenaSlotId(21), 12usize, 1usize),
        (ArenaSlotId(22), 13usize, 1usize),
        (ArenaSlotId(23), 8usize, 1usize),
    ];
    let mut specs = Vec::new();
    let mut offset = 0usize;
    for requirement in requirements
        .arena_slot_requirements(workspace)
        .unwrap()
        .into_iter()
        .chain(
            io_specs
                .into_iter()
                .map(
                    |(id, len_words, alignment_words)| TranscriptArenaSlotRequirement {
                        id,
                        len_words,
                        alignment_words,
                    },
                ),
        )
    {
        offset = offset.next_multiple_of(requirement.alignment_words);
        specs.push(ArenaSlotSpec {
            id: requirement.id,
            offset_words: offset,
            len_words: requirement.len_words,
            alignment_words: requirement.alignment_words,
        });
        offset += requirement.len_words;
    }
    let layout = ArenaLayout::new(
        offset.next_multiple_of(BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS),
        &specs,
    )
    .unwrap();
    let arena = DeviceArena::new(CudaExecContext::new().unwrap(), layout).unwrap();

    upload(&arena, ArenaSlotId(10), &[1, 2, 3, 4, 5, 6, 7, 8]);
    upload(
        &arena,
        ArenaSlotId(11),
        &[
            0x1020_3040,
            0x1020_3041,
            0x1020_3042,
            0x1020_3043,
            0x1020_3044,
            0x1020_3045,
            0x1020_3046,
            0x1020_3047,
        ],
    );
    upload(&arena, ArenaSlotId(12), &[0x5566_7788, 0x1122_3344]);
    upload(&arena, ArenaSlotId(13), &[9, 10, 11]);
    upload(&arena, ArenaSlotId(14), &[0xcafe_babe, 0x1234_5678]);
    arena.context().sync().unwrap();

    let prepared = PreparedBlake2sTranscript::prepare(
        &arena,
        schedule,
        workspace,
        &[
            TranscriptInputBinding {
                id: A,
                slice: arena.bind(ArenaSlotId(10)).unwrap(),
            },
            TranscriptInputBinding {
                id: ROOT,
                slice: arena.bind(ArenaSlotId(11)).unwrap(),
            },
            TranscriptInputBinding {
                id: NONCE,
                slice: arena.bind(ArenaSlotId(12)).unwrap(),
            },
            TranscriptInputBinding {
                id: U32S,
                slice: arena.bind(ArenaSlotId(13)).unwrap(),
            },
            TranscriptInputBinding {
                id: U64_VALUE,
                slice: arena.bind(ArenaSlotId(14)).unwrap(),
            },
        ],
        &[
            TranscriptOutputBinding {
                id: X,
                slice: arena.bind(ArenaSlotId(20)).unwrap(),
            },
            TranscriptOutputBinding {
                id: Y,
                slice: arena.bind(ArenaSlotId(21)).unwrap(),
            },
            TranscriptOutputBinding {
                id: Z,
                slice: arena.bind(ArenaSlotId(22)).unwrap(),
            },
            TranscriptOutputBinding {
                id: RAW,
                slice: arena.bind(ArenaSlotId(23)).unwrap(),
            },
        ],
    )
    .unwrap();

    prepared.launch().unwrap();
    let eager = prepared.verify_mirror().unwrap();
    assert_eq!(eager.boundaries_verified, 9);
    assert_eq!(eager.output_words_verified, 37);

    let mut capture_cursor = prepared.segment_cursor();
    capture_cursor.begin_generation(1).unwrap();
    let capture = arena.context().capture().unwrap();
    prepared
        .launch_segment(
            &mut capture_cursor,
            1,
            0..3,
            TranscriptSegmentStart::Initialize,
        )
        .unwrap();
    let graph0 = capture.finish().unwrap();
    let capture = arena.context().capture().unwrap();
    prepared
        .launch_segment(&mut capture_cursor, 1, 3..7, TranscriptSegmentStart::Resume)
        .unwrap();
    let graph1 = capture.finish().unwrap();
    let capture = arena.context().capture().unwrap();
    prepared
        .launch_segment(&mut capture_cursor, 1, 7..9, TranscriptSegmentStart::Resume)
        .unwrap();
    let graph2 = capture.finish().unwrap();
    capture_cursor.require_complete().unwrap();

    let mut replay_cursor = prepared.segment_cursor();
    replay_cursor.begin_generation(1).unwrap();
    for (range, start, graph) in [
        (0..3, TranscriptSegmentStart::Initialize, &graph0),
        (3..7, TranscriptSegmentStart::Resume, &graph1),
        (7..9, TranscriptSegmentStart::Resume, &graph2),
    ] {
        replay_cursor
            .admit_segment(prepared.schedule(), 1, range, start)
            .unwrap();
        graph.launch(arena.context()).unwrap();
    }
    replay_cursor.require_complete().unwrap();
    assert_eq!(eager, prepared.verify_mirror().unwrap());

    // U4 is fail-closed, not merely observability. Poison the first retained
    // boundary cursor after a valid replay and require the host mirror to reject
    // that exact boundary rather than accepting any device-drawn challenge.
    let poisoned_cursor = u32::MAX;
    let boundary_snapshots = arena.bind(ArenaSlotId(2)).unwrap();
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                boundary_snapshots.as_u32_ptr().add(9).cast(),
                (&poisoned_cursor as *const u32).cast(),
                core::mem::size_of::<u32>(),
            )
            .unwrap();
    }
    assert!(matches!(
        prepared.verify_mirror(),
        Err(DeviceTranscriptError::OperationOrderDivergence {
            boundary: TranscriptBoundaryId(1),
            ..
        })
    ));
}
