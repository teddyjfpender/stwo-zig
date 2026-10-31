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
}
