//! Compare the packet/normalization lowering against the unmodified registry
//! implementation. On the host, service packets use the original formula as
//! their backend; real RV64 execution is qualified separately with the AIR.
#[cfg(test)]
mod tests {
    use k256_control::elliptic_curve::{ff::PrimeField, sec1::ToEncodedPoint};
    use k256_control::{ProjectivePoint as Control, Scalar as ControlScalar};
    use k256_service::{ProjectivePoint as Service, Scalar as ServiceScalar};

    fn equal(service: Service, control: Control) {
        assert_eq!(
            service.to_affine().to_encoded_point(false).as_bytes(),
            control.to_affine().to_encoded_point(false).as_bytes()
        );
    }

    #[test]
    fn identity_inverse_double_and_repeated_add_preserve_the_registry_control() {
        let mut service = Service::IDENTITY;
        let mut control = Control::IDENTITY;
        for _ in 0..64 {
            service += Service::GENERATOR;
            control += Control::GENERATOR;
            equal(service, control);
            equal(service.double(), control.double());
            equal(service + -service, Control::IDENTITY);
            equal(service + Service::IDENTITY, control);
            equal(Service::IDENTITY + service, control);
        }
    }

    #[test]
    fn full_width_scalar_multiplication_and_mixed_point_operations_match() {
        let mut state: u64 = 0xc840_1947_9dea_1235;
        let mut previous_service = Service::GENERATOR;
        let mut previous_control = Control::GENERATOR;
        for _ in 0..24 {
            let mut bytes = [0u8; 32];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            bytes[0] &= 0x7f; // Strictly below the scalar modulus in both crates.
            let service = Service::GENERATOR * ServiceScalar::from_repr(bytes.into()).unwrap();
            let control = Control::GENERATOR * ControlScalar::from_repr(bytes.into()).unwrap();
            equal(service, control);
            equal(service + previous_service, control + previous_control);
            equal(service - previous_service, control - previous_control);
            equal(service.double(), control.double());
            equal(-service, -control);
            previous_service = service;
            previous_control = control;
        }
    }

    #[cfg(feature = "word-packets")]
    #[test]
    fn word_codec_preserves_all_limbs_and_rejects_noncanonical_field_values() {
        use k256_control::FieldElement as ControlField;
        use k256_service::FieldElement as ServiceField;
        let p0 = 0xffff_fffe_ffff_fc2f;
        let mut cases = vec![
            [0; 4],
            [1, 0, 0, 0],
            [p0 - 1, u64::MAX, u64::MAX, u64::MAX],
            [p0, u64::MAX, u64::MAX, u64::MAX],
            [p0 + 1, u64::MAX, u64::MAX, u64::MAX],
            [u64::MAX; 4],
        ];
        for bit in 0..256 {
            let mut words = [0; 4];
            words[bit / 64] = 1 << (bit % 64);
            cases.push(words);
        }
        for words in cases {
            let mut bytes = [0; 32];
            for i in 0..4 {
                bytes[8 * i..8 * i + 8].copy_from_slice(&words[3 - i].to_be_bytes());
            }
            let control = ControlField::from_bytes(&bytes.into());
            let service = ServiceField::stwo_from_words(words);
            assert_eq!(bool::from(control.is_some()), bool::from(service.is_some()));
            if bool::from(service.is_some()) {
                let service = service.unwrap();
                assert_eq!(service.stwo_to_words(), words);
                assert_eq!(service.to_bytes(), control.unwrap().to_bytes());
                // Exercise inputs above magnitude1 before normalization too.
                let added = (service + &service).normalize_weak();
                let expected = (control.unwrap() + &control.unwrap()).to_bytes();
                let packet = ServiceField::stwo_from_words(added.stwo_to_words()).unwrap();
                assert_eq!(packet.to_bytes(), expected);
            }
        }
    }

    #[cfg(feature = "vartime")]
    fn xorshift(state: &mut u64) -> u8 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state as u8
    }

    #[cfg(feature = "vartime")]
    fn scalar_pair(bytes: [u8; 32]) -> (ServiceScalar, ControlScalar) {
        (
            ServiceScalar::from_repr(bytes.into()).unwrap(),
            ControlScalar::from_repr(bytes.into()).unwrap(),
        )
    }

    /// The word-packet GLV chain must equal the registry double-scalar
    /// multiplication for every digit pattern, including zero digits,
    /// negative digits, zero scalars and the top digit alone.
    #[cfg(feature = "vartime")]
    #[test]
    fn vartime_word_lincomb_matches_the_registry_control() {
        use k256_control::elliptic_curve::ops::LinearCombinationExt as _;
        let mut state: u64 = 0x1f2e_3d4c_5b6a_7988;
        let mut scalars: Vec<[u8; 32]> = vec![[0; 32], {
            let mut one = [0; 32];
            one[31] = 1;
            one
        }];
        for fill in [0x00u8, 0x11, 0x77, 0x88, 0x8f, 0xf8, 0xff] {
            let mut bytes = [fill; 32];
            bytes[0] &= 0x7f;
            scalars.push(bytes);
        }
        for _ in 0..24 {
            let mut bytes = [0u8; 32];
            for byte in &mut bytes {
                *byte = xorshift(&mut state);
            }
            bytes[0] &= 0x7f;
            scalars.push(bytes);
        }
        let n_minus_one = (-ServiceScalar::ONE).to_bytes();
        scalars.push(n_minus_one.into());
        let mut service_point = Service::GENERATOR;
        let mut control_point = Control::GENERATOR;
        for (i, a) in scalars.iter().enumerate() {
            let b = scalars[(i * 7 + 3) % scalars.len()];
            let (sa, ca) = scalar_pair(*a);
            let (sb, cb) = scalar_pair(b);
            let service = Service::lincomb_ext(&[(Service::GENERATOR, sa), (service_point, sb)]);
            let control = Control::lincomb_ext(&[(Control::GENERATOR, ca), (control_point, cb)]);
            equal(service, control);
            equal(Service::lincomb_ext(&[(service_point, sa)]), Control::lincomb_ext(&[(control_point, ca)]));
            service_point = service + Service::GENERATOR;
            control_point = control + Control::GENERATOR;
            equal(service_point, control_point);
        }
    }

    /// Recovery without the redundant re-verification returns the signer's
    /// key, and the omitted check is shown to hold on the recovered key for
    /// both signature halves (revm normalizes high S and flips the parity).
    #[cfg(feature = "vartime")]
    #[test]
    fn ecdsa_recovery_without_reverification_is_equivalent() {
        use k256_service::ecdsa::signature::hazmat::PrehashVerifier;
        use k256_service::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
        let mut state: u64 = 0xa5a5_1234_dead_beef;
        let mut checked = 0;
        for round in 0..96 {
            let mut key = [0u8; 32];
            let mut digest = [0u8; 32];
            for byte in &mut key {
                *byte = xorshift(&mut state);
            }
            for byte in &mut digest {
                *byte = xorshift(&mut state);
            }
            key[0] &= 0x7f;
            if round % 5 == 0 {
                digest = [0xff; 32]; // prehash above the group order exercises reduction
            }
            let signing = SigningKey::from_bytes(&key.into()).unwrap();
            let (mut signature, mut recid) = signing.sign_prehash_recoverable(&digest).unwrap();
            // Keep both normalized and high-S inputs; revm normalizes before recovery.
            if round % 2 == 0 {
                if let Some(normalized) = signature.normalize_s() {
                    signature = normalized;
                    recid = RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced());
                }
            } else {
                signature = Signature::from_scalars(*signature.r(), -*signature.s()).unwrap();
                recid = RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced());
            }
            let recovered = VerifyingKey::recover_from_prehash(&digest, &signature, recid).unwrap();
            assert_eq!(recovered, *signing.verifying_key());
            // The check the patched recovery omits must hold for the recovered key.
            assert!(
                k256_service::ecdsa::hazmat::verify_prehashed(&Service::from(*recovered.as_affine()), &digest.into(), &signature).is_ok()
            );
            // The upstream API (with its low-S policy) agrees on normalized inputs.
            if signature.normalize_s().is_none() {
                assert!(recovered.verify_prehash(&digest, &signature).is_ok());
            }
            // A different parity recovers a different key or fails, exactly as upstream.
            let other = RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced());
            if let Ok(wrong) = VerifyingKey::recover_from_prehash(&digest, &signature, other) {
                assert_ne!(wrong, recovered);
                // ... and the omitted check would still have passed for it.
                assert!(k256_service::ecdsa::hazmat::verify_prehashed(&Service::from(*wrong.as_affine()), &digest.into(), &signature).is_ok());
            }
            checked += 1;
        }
        assert_eq!(checked, 96);
        // Degenerate signatures are rejected before any curve arithmetic.
        let zero = [0u8; 64];
        assert!(Signature::from_slice(&zero).is_err());
    }
}
