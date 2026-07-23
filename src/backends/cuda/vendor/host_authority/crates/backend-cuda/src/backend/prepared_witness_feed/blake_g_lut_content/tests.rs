use super::*;

fn fixture() -> [Vec<u32>; 4] {
    BLAKE_G_DIRECT_LUT_WORDS.map(|words| {
        (0..words)
            .map(|index| ((index.wrapping_mul(17) + 11) % words) as u32)
            .collect()
    })
}

fn refs(luts: &[Vec<u32>; 4]) -> [&[u32]; 4] {
    core::array::from_fn(|index| luts[index].as_slice())
}

#[test]
fn exact_words_have_stable_nonzero_role_and_aggregate_identities() {
    let luts = fixture();
    let first = BlakeGDirectLutContentIdentity::from_host_words(refs(&luts)).unwrap();
    let second = BlakeGDirectLutContentIdentity::from_host_words(refs(&luts)).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.lut_order(), BLAKE_G_DIRECT_LUT_ORDER);
    assert_eq!(first.lut_words(), BLAKE_G_DIRECT_LUT_WORDS);
    assert_ne!(first.identity(), [0; 32]);
    assert!(first
        .ordered_lut_identities()
        .into_iter()
        .all(|identity| identity != [0; 32]));
}

#[test]
fn boundary_single_word_mutations_change_both_role_and_aggregate_identity() {
    let baseline = fixture();
    let expected = BlakeGDirectLutContentIdentity::from_host_words(refs(&baseline)).unwrap();

    for lut_index in 0..baseline.len() {
        for word_index in [
            0,
            baseline[lut_index].len() / 2,
            baseline[lut_index].len() - 1,
        ] {
            let mut mutated = baseline.clone();
            let words = mutated[lut_index].len() as u32;
            mutated[lut_index][word_index] = (mutated[lut_index][word_index] + 1) % words;
            let actual = BlakeGDirectLutContentIdentity::from_host_words(refs(&mutated)).unwrap();

            assert_ne!(actual.identity(), expected.identity());
            assert_ne!(
                actual.ordered_lut_identities()[lut_index],
                expected.ordered_lut_identities()[lut_index]
            );
            for unchanged in 0..baseline.len() {
                if unchanged != lut_index {
                    assert_eq!(
                        actual.ordered_lut_identities()[unchanged],
                        expected.ordered_lut_identities()[unchanged]
                    );
                }
            }
        }
    }
}

#[test]
fn order_and_length_substitutions_fail_closed() {
    let luts = fixture();
    let swapped = [
        luts[1].as_slice(),
        luts[0].as_slice(),
        luts[2].as_slice(),
        luts[3].as_slice(),
    ];
    assert!(matches!(
        BlakeGDirectLutContentIdentity::from_host_words(swapped),
        Err(BlakeGDirectLutContentError::LengthMismatch {
            role: BlakeGDirectLut::Xor8,
            ..
        })
    ));

    let mut shortened = refs(&luts);
    shortened[2] = &shortened[2][..shortened[2].len() - 1];
    assert!(matches!(
        BlakeGDirectLutContentIdentity::from_host_words(shortened),
        Err(BlakeGDirectLutContentError::LengthMismatch {
            role: BlakeGDirectLut::Xor7,
            ..
        })
    ));

    let expected = BlakeGDirectLutContentIdentity::from_host_words(refs(&luts)).unwrap();
    let mut reordered = luts.clone();
    let last = reordered[0].len() - 1;
    reordered[0].swap(0, last);
    let actual = BlakeGDirectLutContentIdentity::from_host_words(refs(&reordered)).unwrap();
    assert_ne!(actual.identity(), expected.identity());
    assert_ne!(
        actual.ordered_lut_identities()[0],
        expected.ordered_lut_identities()[0]
    );
}

#[test]
fn out_of_range_row_is_rejected_before_it_can_reach_cuda() {
    let mut luts = fixture();
    let index = luts[3].len() / 3;
    luts[3][index] = luts[3].len() as u32;
    assert_eq!(
        BlakeGDirectLutContentIdentity::from_host_words(refs(&luts)).unwrap_err(),
        BlakeGDirectLutContentError::RowOutOfRange {
            role: BlakeGDirectLut::Xor9,
            index,
            row: BLAKE_G_DIRECT_LUT_WORDS[3] as u32,
            row_count: BLAKE_G_DIRECT_LUT_WORDS[3],
        }
    );
}
