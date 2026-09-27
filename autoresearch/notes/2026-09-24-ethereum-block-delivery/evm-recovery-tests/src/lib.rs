extern crate alloc;
#[path = "../../../../benchmarks/guest_runtime/ethereum/src/evm_recovery.rs"]
mod evm_recovery;
#[path = "../../../../benchmarks/guest_runtime/ethereum/src/evm_hints.rs"]
mod evm_hints;

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{SigningKey, Signature, VerifyingKey, RecoveryId};
    use revm_precompile::interface::{Crypto, DefaultCrypto};
    fn proved(sig: &[u8;64], recid:u8, msg:&[u8;32]) -> [u8;64] {
        let key=VerifyingKey::recover_from_prehash(msg,&Signature::from_slice(sig).unwrap(),RecoveryId::from_byte(recid).unwrap()).expect("invalid success hint must stop execution");
        key.to_encoded_point(false).as_bytes()[1..].try_into().unwrap()
    }
    fn high_s(sig:&[u8;64]) -> [u8;64] {
        let order:[u8;32]=[0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41];
        let mut out=*sig;let mut borrow=0i16;
        for i in (0..32).rev() {let n=order[i] as i16-sig[32+i] as i16-borrow;out[32+i]=n as u8;borrow=i16::from(n<0);}
        assert_eq!(borrow,0);out
    }
    #[test]
    fn low_high_s_and_false_negative_hints_match_revm() {
        for seed in 1..=32u8 {
            let key=SigningKey::from_bytes((&[seed;32]).into()).unwrap();let msg=[seed.wrapping_mul(7);32];
            let (sig,id)=key.sign_prehash_recoverable(&msg).unwrap();let bytes:[u8;64]=sig.to_bytes().into();
            for (sig,parity) in [(bytes,id.to_byte()),(high_s(&bytes),id.to_byte()^1)] {
                let expected=DefaultCrypto.secp256k1_ecrecover(&sig,parity,&msg).unwrap();
                assert_eq!(evm_recovery::recover(&sig,parity,&msg,true,proved).unwrap(),expected);
                assert_eq!(evm_recovery::recover(&sig,parity,&msg,false,|_,_,_|panic!("false hint used native backend")).unwrap(),expected);
            }
        }
    }
    #[test]
    fn scalar_errors_keep_software_failure_even_with_success_hint() {
        for sig in [[0u8;64],[0xff;64]] {assert!(evm_recovery::recover(&sig,0,&[0;32],true,|_,_,_|panic!("bad scalar dispatched")).is_err());}
    }
    #[test]
    fn forged_success_cannot_turn_invalid_curve_recovery_into_a_result() {
        let mut sig=[0u8;64];sig[63]=1;
        let r=(1..=100u8).find(|r|{sig[31]=*r;DefaultCrypto.secp256k1_ecrecover(&sig,0,&[0;32]).is_err()}).unwrap();sig[31]=r;
        assert!(evm_recovery::recover(&sig,0,&[0;32],false,proved).is_err());
        assert!(std::panic::catch_unwind(||evm_recovery::recover(&sig,0,&[0;32],true,proved)).is_err());
    }
    #[test]
    fn footer_bounds_padding_and_selection_are_checked() {
        use evm_hints::{decode,encode,Error};
        assert_eq!(decode(&[]).unwrap(),None);assert_eq!(decode(&[0;16]).unwrap(),None);
        let data=encode(9,&[0x55,1]);assert_eq!(decode(&data).unwrap(),Some((9,vec![0x55,1])));
        assert_eq!(decode(&data[..13]),Err(Error::Truncated));
        let mut bad=data.clone();bad[0]^=1;assert_eq!(decode(&bad),Err(Error::InvalidMagic));
        bad=data.clone();bad[13]=2;assert_eq!(decode(&bad),Err(Error::NoncanonicalPadding));
        evm_hints::initialize(&data);
        for i in 0..9 {assert_eq!(evm_hints::next(),i%2==0);}
        assert_eq!(evm_hints::finish(vec![7;43]),vec![7;43]);
    }
}

#[path = "../../../../benchmarks/guest_runtime/fast_memory_v1.rs"]
mod fast_memory;
