use super::*;
use crate::backend::exec_context::ArenaSlotId;

#[test]
fn checked_slices_bind_the_exact_local_pointer_origins() {
    let source = ArenaSlice::dangling_at_for_test(1, 100, 32);
    let partial = source_pointer(source, 31, 1).unwrap();
    assert_eq!(partial, source.as_u32_ptr().wrapping_add(31));

    let counts = ArenaSlice::dangling_at_for_test(2, 200, 56);
    let count_slice = checked_subslice("counts", counts, 40, 16).unwrap();
    assert_eq!(
        count_slice.as_u32_ptr(),
        counts.as_u32_ptr().wrapping_add(40)
    );
    assert_eq!(count_slice.len_words(), 16);

    let addresses = ArenaSlice::dangling_at_for_test(3, 300, 7);
    let from_one = checked_subslice("address ids", addresses, 1, 6).unwrap();
    assert_eq!(
        from_one.as_u32_ptr(),
        addresses.as_u32_ptr().wrapping_add(1)
    );
    assert_eq!(from_one.len_words(), 6);
}

#[test]
fn zero_read_tail_is_null_without_forming_an_out_of_bounds_pointer() {
    let source = ArenaSlice::dangling_at_for_test(4, 400, 32);
    assert!(source_pointer(source, 32, 0).unwrap().is_null());
    assert!(source_pointer(source, 40, 0).unwrap().is_null());
    assert_eq!(readable_source_words(32, 31, 16), 1);
    assert_eq!(readable_source_words(32, 32, 16), 0);
    assert_eq!(readable_source_words(32, 40, 16), 0);
}

#[test]
fn multiplicity_slice_rejects_a_single_word_overrun() {
    let counts = ArenaSlice::dangling_at_for_test(5, 500, 56);
    assert!(matches!(
        checked_subslice("counts", counts, 41, 16),
        Err(PreparedMemoryBaseTraceError::SliceTooSmall {
            role: "counts",
            required_words: 57,
            actual_words: 56,
        })
    ));

    // Keep the test sentinel import explicit so slot identity remains part of
    // the checked geometry rather than an untyped host pointer.
    assert_eq!(counts.id(), ArenaSlotId(5));
}
