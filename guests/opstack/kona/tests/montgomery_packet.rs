#![cfg(feature = "montgomery-services")]
mod tests {
    use ark_ff::stwo_montgomery_service_packet as packet;
    use num_bigint::BigUint;

    fn value(words: &[u64]) -> BigUint {
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        BigUint::from_bytes_le(&bytes)
    }
    fn words<const N: usize>(value: BigUint) -> [u64; N] {
        let digits = value.to_u64_digits();
        let mut result = [0; N];
        assert!(digits.len() <= N);
        result[..digits.len()].copy_from_slice(&digits);
        result
    }
    fn exercise<const N: usize>(hex_modulus: &[u8]) {
        let m = BigUint::parse_bytes(hex_modulus, 16).unwrap();
        let modulus = words::<N>(m.clone());
        let r384 = (BigUint::from(1u8) << 384usize) % &m;
        // Both concrete field moduli are prime. This is a test oracle only;
        // the guest obtains a constrained Montgomery result, not an inverse hint.
        let inverse384 = r384.modpow(&(&m - BigUint::from(2u8)), &m);
        let r_native = (BigUint::from(1u8) << (64 * N)) % &m;
        let inverse_native = r_native.modpow(&(&m - BigUint::from(2u8)), &m);
        for index in 0..128u64 {
            let a = if index == 0 {
                BigUint::from(0u8)
            } else if index == 1 {
                &m - BigUint::from(1u8)
            } else {
                (BigUint::from(index + 1).pow(31) + &m / BigUint::from(3u8)) % &m
            };
            let b = (BigUint::from(index + 17).pow(37) + &m / BigUint::from(5u8)) % &m;
            let encoded = packet(&words::<N>(a.clone()), &words::<N>(b.clone()), &modulus);
            assert_eq!(value(&encoded[6..12]), b);
            assert_eq!(value(&encoded[12..18]), m);
            assert_eq!(encoded[18..20], [0, 0]);
            let output = (value(&encoded[..6]) * value(&encoded[6..12]) * &inverse384) % &m;
            assert_eq!(output, (a * &b * &inverse_native) % &m);
            if N == 4 {
                assert!(output.bits() <= 256);
            }
        }
    }
    #[test]
    fn stwo_montgomery_packet_preserves_four_and_six_limb_representations() {
        exercise::<4>(b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        exercise::<6>(b"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
    }
}
