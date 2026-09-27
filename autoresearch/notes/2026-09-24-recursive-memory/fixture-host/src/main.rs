use eth_auth_common::Crypto;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use std::path::Path;
use tiny_keccak::{Hasher, Keccak};
struct Oracle;
impl Crypto for Oracle {
    fn keccak(d: &[u8]) -> [u8; 32] {
        let mut h = Keccak::v256();
        h.update(d);
        let mut out = [0; 32];
        h.finalize(&mut out);
        out
    }
    fn recover(d: &[u8; 32], r: &[u8; 32], s: &[u8; 32], p: u8) -> Option<[u8; 64]> {
        let sig = Signature::from_scalars(*r, *s).ok()?;
        let key = VerifyingKey::recover_from_prehash(d, &sig, RecoveryId::from_byte(p)?).ok()?;
        Some(
            key.to_encoded_point(false).as_bytes()[1..]
                .try_into()
                .unwrap(),
        )
    }
}
fn prefix(n: usize, list: bool) -> Vec<u8> {
    let short = if list { 0xc0 } else { 0x80 };
    if n < 56 {
        vec![short + n as u8]
    } else if n < 256 {
        vec![short + 56, n as u8]
    } else {
        vec![short + 57, (n >> 8) as u8, n as u8]
    }
}
fn string(x: &[u8]) -> Vec<u8> {
    if x.len() == 1 && x[0] < 128 {
        return x.to_vec();
    }
    let mut v = prefix(x.len(), false);
    v.extend(x);
    v
}
fn list(x: &[Vec<u8>]) -> Vec<u8> {
    let mut v = prefix(x.iter().map(Vec::len).sum(), true);
    for f in x {
        v.extend(f)
    }
    v
}
fn int(x: &[u8]) -> Vec<u8> {
    let first = x.iter().position(|b| *b != 0).unwrap_or(x.len());
    string(&x[first..])
}
fn hex(x: &[u8]) -> String {
    x.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let dir = Path::new(&args[1]);
    std::fs::create_dir_all(dir).unwrap();
    for n in [1usize, 2, 4, 8, 16, 32, 64] {
        let mut input = (n as u32).to_le_bytes().to_vec();
        let mut committed = Oracle::keccak(b"stwo-zisk-eth-auth-v1");
        let mut records = vec![];
        for i in 0..n {
            let mut secret = [0; 32];
            secret[31] = (i + 1) as u8;
            let key = SigningKey::from_bytes((&secret).into()).unwrap();
            let fields = vec![
                int(&[1]),
                int(&(i as u64).to_be_bytes()),
                int(&[1]),
                int(&[2]),
                int(&100000u64.to_be_bytes()),
                string(&[0x42; 20]),
                int(&[7]),
                string(&vec![i as u8; 16 + (i % 3) * 16]),
                list(&[]),
            ];
            let mut payload = vec![2];
            payload.extend(list(&fields));
            let digest = Oracle::keccak(&payload);
            let (sig, recid) = key.sign_prehash_recoverable(&digest).unwrap();
            assert!(sig.normalize_s().is_none());
            let mut signed = fields;
            signed.push(int(&[recid.to_byte()]));
            signed.push(int(&sig.to_bytes()[..32]));
            signed.push(int(&sig.to_bytes()[32..]));
            if n == 1 {
                let mut high_s = [0; 32];
                high_s[0] = 0x80;
                for (name, index, replacement) in [
                    ("bad-parity", 9, int(&[2])),
                    ("zero-r", 10, int(&[])),
                    ("high-s", 11, int(&high_s)),
                    ("bad-rlp", 1, vec![0x81, 0x01]),
                ] {
                    let mut bad_fields = signed.clone();
                    bad_fields[index] = replacement;
                    let mut bad_tx = vec![2];
                    bad_tx.extend(list(&bad_fields));
                    let mut bad_input = 1u32.to_le_bytes().to_vec();
                    bad_input.extend((bad_tx.len() as u32).to_le_bytes());
                    bad_input.extend(bad_tx);
                    assert!(eth_auth_common::run::<Oracle>(&bad_input).is_err());
                    let mut transport = (bad_input.len() as u32).to_le_bytes().to_vec();
                    transport.extend(bad_input);
                    std::fs::write(dir.join(format!("{name}.input")), transport).unwrap();
                    std::fs::write(dir.join(format!("{name}.expected")), [0; 72]).unwrap();
                }
            }
            let mut tx = vec![2];
            tx.extend(list(&signed));
            let txhash = Oracle::keccak(&tx);
            // Expected sender derives from the signing key, not the guest parser/recovery.
            let kh = Oracle::keccak(&key.verifying_key().to_encoded_point(false).as_bytes()[1..]);
            let sender = &kh[12..];
            let mut pre = committed.to_vec();
            pre.extend(txhash);
            pre.extend(sender);
            committed = Oracle::keccak(&pre);
            input.extend((tx.len() as u32).to_le_bytes());
            input.extend(&tx);
            records.push(serde_json::json!({"transaction":hex(&tx),"signing_hash":hex(&digest),"transaction_hash":hex(&txhash),"sender":hex(sender),"parity":recid.to_byte()}));
        }
        assert!(input.len() <= 16380);
        let mut expected = 1u32.to_le_bytes().to_vec();
        expected.extend((n as u32).to_le_bytes());
        expected.extend(Oracle::keccak(&input));
        expected.extend(committed);
        assert_eq!(
            eth_auth_common::run::<Oracle>(&input).unwrap().as_slice(),
            expected
        );
        let mut transport = (input.len() as u32).to_le_bytes().to_vec();
        transport.extend(&input);
        std::fs::write(dir.join(format!("batch-{n}.input")), transport).unwrap();
        std::fs::write(dir.join(format!("batch-{n}.expected")), &expected).unwrap();
        std::fs::write(dir.join(format!("batch-{n}.json")),serde_json::to_vec_pretty(&serde_json::json!({"count":n,"input_bytes":input.len(),"expected":hex(&expected),"transactions":records})).unwrap()).unwrap();
        for cut in 0..input.len() {
            assert!(eth_auth_common::run::<Oracle>(&input[..cut]).is_err());
        }
        let mut bad = input.clone();
        bad[8] = 1;
        assert!(eth_auth_common::run::<Oracle>(&bad).is_err());
        if n == 1 {
            let mut transport = (bad.len() as u32).to_le_bytes().to_vec();
            transport.extend(&bad);
            std::fs::write(dir.join("bad-type.input"), transport).unwrap();
            std::fs::write(dir.join("bad-type.expected"), [0; 72]).unwrap();
        }
        let mut bad = input.clone();
        bad.push(0);
        assert!(eth_auth_common::run::<Oracle>(&bad).is_err());
        println!(
            "qualified batch={n} bytes={} truncation/rejection checks passed",
            input.len()
        );
    }
}
